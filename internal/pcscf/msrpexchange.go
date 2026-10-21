package pcscf

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/sdp"
)

// An exchange is one offer and its answer in a session (RFC 3264), which
// pcscf anchors whichever side makes the offer and whatever carries the
// two: an INVITE, UPDATE or re-INVITE and its response, or a response to an
// INVITE without an offer and the ACK or PRACK after it (RFC 3261 §13.2.1,
// RFC 3262 §5).
//
// Each MSRP line of the offer is served by the binding that serves its
// m= line already, when the relay has the offerer's path for it, or by a
// new one (#136 AC 7). The offer goes to the other side with the relay's
// path for that side: toward rcs-as the core-side path, active, toward the
// client the client path, actpass. The answer completes each new binding
// with the answerer's path, and goes back with the relay's path, active
// toward rcs-as and passive toward the client: the client connects to the
// relay, and the relay to rcs-as (ADR 0004). Once the answer is taken, the
// new bindings replace the ones before them; when the exchange fails they
// are released and those before stay.
type exchange struct {
	offerer side
	// inResponse says the offer came in a response, with To tag tag, its
	// answer coming in an ACK or a PRACK; cseq and rseq are the response's
	// CSeq number and RSeq, 0 in a 2xx, by which that ACK or PRACK is known
	// (acknowledges).
	inResponse bool
	tag        string
	cseq, rseq uint32
	// offerIn is the offer as it came and offerOut as it went, so that a
	// retransmission goes the same (proxy Decision.OnResponse).
	offerIn, offerOut []byte
	// lines are the bindings that serve the offer's MSRP lines, by m= line
	// index, and fresh says which were made for it. dropped are the lines
	// of the session the offer no longer has with a port (RFC 3264 §8.2),
	// whose bindings go once the exchange is taken (#315 code review 5).
	lines   map[int]*anchoredLine
	fresh   map[int]bool
	dropped map[int]bool
	// answered says an answer came, in a message with To tag answerTag;
	// answerIn and answerOut are as for the offer, and failed is the Reason
	// that ends the dialog if pcscf cannot serve it. declined are the lines
	// the answer declined.
	answered            bool
	answerTag           string
	answerIn, answerOut []byte
	failed              string
	declined            map[int]bool
	// settled says the exchange is taken or given up.
	settled bool
}

// errOfferRefused is an offer pcscf will not anchor: a request carrying it
// is answered 488 (ADR 0004).
var errOfferRefused = errors.New("pcscf: an MSRP offer pcscf cannot anchor")

// offerLines reads the MSRP lines with a port of offer d from side from,
// and checks that the relay can serve them (errOfferRefused otherwise): at
// most maxMSRPLines, and most, a path the relay takes (relayTakesPath), and
// a role that lets the relay listen toward the client and connect toward
// rcs-as. A client offers active or actpass, never passive (RFC 6135
// §4.2.2); rcs-as actpass or passive, never active; and holdconn, which
// pcscf cannot answer in kind (RFC 4145 §4), is refused from either.
func offerLines(d []byte, from side, most int) (*sdp.Session, []msrpLine, error) {
	s, lines, err := msrpLines(d, true)
	if err != nil {
		return nil, nil, errOfferRefused
	}
	if len(lines) > min(maxMSRPLines, most) {
		return nil, nil, errOfferRefused
	}
	for _, l := range lines {
		ok := !l.holdconn && relayTakesPath(l.path)
		if from == clientSide {
			ok = ok && (l.setup == sdp.SetupActive || l.setup == sdp.SetupActPass)
		} else {
			ok = ok && (l.setup == sdp.SetupActPass || l.setup == sdp.SetupPassive)
		}
		if !ok {
			return nil, nil, errOfferRefused
		}
	}
	return s, lines, nil
}

// refusalOf is how a request whose offer could not be anchored for err is
// answered, and counts it: 488 for an offer pcscf or the relay will not
// take, which waiting will not change, 503 with Retry-After otherwise.
func (p *pcscf) refusalOf(err error, wait time.Duration) *refusal {
	switch {
	case errors.Is(err, errOfferRefused), errors.Is(err, errRelayInvalid):
		p.count(metricRefusedOffer, 1)
		return &refusal{status: 488, reason: "Not Acceptable Here"}
	case errors.Is(err, errBindingRate):
		p.count(metricRefusedRate, 1)
		return &refusal{status: 503, reason: "MSRP Relay Unavailable", retryAfter: strconv.Itoa(int(wait / time.Second))}
	case errors.Is(err, errBindingLimit):
		p.count(metricRefusedLimit, 1)
	default:
		p.count(metricRefusedRelay, 1)
	}
	return &refusal{status: 503, reason: "MSRP Relay Unavailable", retryAfter: retryAfter}
}

// errNoRelay is an offer that needs a binding without a relay token.
var errNoRelay = errors.New("pcscf: no msrp-relay")

// allocate makes a binding for each line in want, an endpoint path of side
// from by m= line index, after taking their share of the limits. On an
// error it holds nothing, and returns how long to wait for the rate.
func (p *pcscf) allocate(ctx context.Context, s *msrpSession, from side, want map[int][]string) (map[int]*anchoredLine, time.Duration, error) {
	if len(want) == 0 {
		return nil, 0, nil
	}
	if p.msrp.relay == nil {
		return nil, 0, errNoRelay
	}
	wait, err := p.msrp.limit.take(s.share(), len(want))
	if err != nil {
		return nil, wait, err
	}
	made := map[int]*anchoredLine{}
	fail := func(err error) (map[int]*anchoredLine, time.Duration, error) {
		s.mu.Lock()
		for _, l := range made {
			p.releaseLine(s, l)
		}
		s.mu.Unlock()
		p.msrp.limit.give(s.share(), len(want)-len(made))
		return nil, 0, err
	}
	for _, i := range sortedKeys(want) {
		paths := relayPaths{ExpiresIn: bindingExpiresIn}
		l := &anchoredLine{}
		if from == clientSide {
			paths.ClientEndpointPath, l.clientPath = want[i], want[i]
		} else {
			paths.CorePath, l.corePath = want[i], want[i]
		}
		b, err := p.msrp.relay.create(ctx, paths)
		if err != nil {
			p.relayFailed("create", err)
			return fail(err)
		}
		u, err := msrp.ParseURI(b.ClientPath)
		if err != nil {
			l.binding = b
			made[i] = l
			return fail(err)
		}
		l.binding = b
		made[i] = l
		s.mu.Lock()
		s.every = append(s.every, l)
		if s.host == "" {
			s.host = u.Host
		}
		s.mu.Unlock()
	}
	return made, 0, nil
}

// sortedKeys returns the keys of m in order, so that bindings are made in
// the order of their lines.
func sortedKeys[V any](m map[int]V) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// anchorOffer makes the exchange of offer d from side from in s, and
// returns the offer the other side gets. It calls the relay: s.answering
// may be held, s.mu must not be. On an error nothing is held, and the wait
// is the rate's (refusalOf).
func (p *pcscf) anchorOffer(ctx context.Context, s *msrpSession, from side, d []byte) (*exchange, []byte, time.Duration, error) {
	offer, lines, err := offerLines(d, from, p.msrp.limit.most(s.origin == coreSide))
	if err != nil {
		return nil, nil, 0, err
	}
	x := &exchange{offerer: from, offerIn: slices.Clone(d), lines: map[int]*anchoredLine{}, fresh: map[int]bool{},
		dropped: map[int]bool{}, declined: map[int]bool{}}
	want := map[int][]string{}
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		return nil, nil, 0, errNoRelay
	}
	offered := map[int]bool{}
	for _, l := range lines {
		offered[l.index] = true
		if cur := s.lines[l.index]; cur != nil && !cur.released && slices.Equal(cur.pathOf(from), l.path) {
			x.lines[l.index] = cur
		} else {
			want[l.index] = l.path
		}
	}
	for i := range s.lines {
		if !offered[i] {
			x.dropped[i] = true
		}
	}
	s.mu.Unlock()
	made, wait, err := p.allocate(ctx, s, from, want)
	if err != nil {
		return nil, nil, wait, err
	}
	for i, l := range made {
		x.lines[i], x.fresh[i] = l, true
	}
	paths := map[int]string{}
	for i, l := range x.lines {
		if from == clientSide {
			paths[i] = l.binding.CorePathLocal
		} else {
			paths[i] = l.binding.ClientPath
		}
	}
	if from == clientSide {
		err = towardCore(offer, paths, false)
	} else {
		err = towardClient(offer, paths, p.hostFor(s), false)
	}
	var out []byte
	if err == nil {
		out, err = offer.Marshal()
	}
	if err != nil {
		p.abort(s, x)
		return nil, nil, 0, err
	}
	x.offerOut = out
	return x, out, 0, nil
}

// anchorAnswer takes d, the answer to x from the side that did not offer,
// and returns the answer the offerer gets, or nil if none can be written,
// and the Reason that ends the dialog if pcscf cannot serve it: the relay
// failing, or an answer it cannot take, reasonRelayUnavailable (#136
// decision 6); a client that answered passive, which would have the relay
// dial it, reasonDirection (ADR 0004). A line the answer declines (port 0)
// is declined on, and its binding goes once x is taken. It calls the
// relay: s.answering may be held, s.mu must not be.
func (p *pcscf) anchorAnswer(ctx context.Context, s *msrpSession, x *exchange, d []byte) ([]byte, string) {
	from := x.offerer.other()
	ans, err := sdp.Parser{MaxSize: maxSDP}.Parse(d)
	if err != nil {
		return nil, reasonRelayUnavailable
	}
	failed := ""
	fail := func(reason string) {
		if failed == "" || reason == reasonDirection {
			failed = reason
		}
	}
	paths := map[int]string{}
	for _, i := range sortedKeys(x.lines) {
		l := x.lines[i]
		if i >= len(ans.Media) || !ans.Media[i].IsMSRP() {
			fail(reasonRelayUnavailable)
			continue
		}
		m := &ans.Media[i]
		if m.Port == 0 {
			x.declined[i] = true
			continue
		}
		path, err := m.Path()
		setup, serr := ans.MediaSetup(i)
		if errors.Is(serr, sdp.ErrNoAttribute) {
			// The RFC 4145 §4 default of an answer.
			setup, serr = sdp.SetupPassive, nil
		}
		switch {
		case err != nil || serr != nil || !relayTakesPath(path):
			fail(reasonRelayUnavailable)
		case from == coreSide && setup != sdp.SetupPassive:
			// The relay offered active, so rcs-as must listen (RFC 6135
			// §4.2.2).
			fail(reasonRelayUnavailable)
		case from == clientSide && setup == sdp.SetupPassive:
			// The client would have the relay dial it, which it never
			// does (ADR 0004).
			fail(reasonDirection)
		case from == clientSide && setup != sdp.SetupActive:
			fail(reasonRelayUnavailable)
		case !x.fresh[i]:
			// The relay has a path for this side already; it does not
			// change (docs/api/msrp-relay.yaml).
			if !slices.Equal(l.pathOf(from), path) {
				fail(reasonRelayUnavailable)
			}
		default:
			update := relayPaths{CorePath: path}
			if from == clientSide {
				update = relayPaths{ClientEndpointPath: path}
			}
			if err := p.msrp.relay.update(ctx, l.binding.ID, update); err != nil {
				p.relayFailed("update", err)
				fail(reasonRelayUnavailable)
			} else {
				s.mu.Lock()
				if from == clientSide {
					l.clientPath = path
				} else {
					l.corePath = path
				}
				s.mu.Unlock()
			}
		}
		if from == coreSide {
			// Whatever happened, the client sees the relay, never rcs-as.
			paths[i] = l.binding.ClientPath
		} else {
			paths[i] = l.binding.CorePathLocal
		}
	}
	if from == clientSide && failed == reasonDirection {
		// rcs-as learns no path of the client's that it could dial.
		return declineMSRP(d), failed
	}
	if from == coreSide {
		err = towardClient(ans, paths, p.hostFor(s), true)
	} else {
		err = towardCore(ans, paths, true)
	}
	if err != nil {
		return nil, reasonRelayUnavailable
	}
	out, err := ans.Marshal()
	if err != nil {
		return nil, reasonRelayUnavailable
	}
	return out, failed
}

// commit takes x: its bindings serve the session from now on, a line it
// declined is served by none, and the bindings they replace are released.
func (p *pcscf) commit(s *msrpSession, x *exchange) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if x.settled {
		return
	}
	x.settled = true
	if s.x == x {
		s.x = nil
	}
	for i := range x.dropped {
		if old := s.lines[i]; old != nil {
			p.releaseLine(s, old)
			delete(s.lines, i)
		}
	}
	for i, l := range x.lines {
		old := s.lines[i]
		if x.declined[i] {
			p.releaseLine(s, l)
			if old != nil {
				p.releaseLine(s, old)
			}
			delete(s.lines, i)
			continue
		}
		if old != nil && old != l {
			p.releaseLine(s, old)
		}
		s.lines[i] = l
	}
}

// abort gives x up: the bindings made for it are released, and those it
// would have replaced stay.
func (p *pcscf) abort(s *msrpSession, x *exchange) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if x.settled {
		return
	}
	x.settled = true
	if s.x == x {
		s.x = nil
	}
	for i, l := range x.lines {
		if x.fresh[i] {
			p.releaseLine(s, l)
		}
	}
}

// declineToward returns d with its MSRP lines declined, as side gets it:
// the client with every line declined and nothing of the core
// (declineAll), rcs-as with no path of the client's (declineMSRP). It is
// nil if d cannot be read.
func (p *pcscf) declineToward(to side, s *msrpSession, d []byte) []byte {
	if to == clientSide {
		host := p.hiddenHost()
		if s != nil {
			host = p.hostFor(s)
		}
		return declineAll(d, host)
	}
	return declineMSRP(d)
}
