package pcscf

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/sdp"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/dialog"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// pcscf anchors every MSRP session of its clients through msrp-relay (ADR
// 0004, #136): it rewrites the m=message lines of the session's offer and
// answer so that the client connects to the relay, and the relay to rcs-as,
// and it holds the relay's binding for as long as the session lives. A
// session it cannot anchor is refused, or ended, and never left to run end
// to end. This file covers the sessions a client sets up; the ones rcs-as
// sets up, and offers inside a dialog, are refused until #136's second
// change.
const (
	// bindingExpiresIn is how long a binding is asked for, and
	// bindingExtendEvery how often the sweep extends a live one (#136
	// decision 1): a session without a session timer lasts as long as its
	// flow does. An extension that fails is tried again at the next sweep,
	// well before the binding expires.
	bindingExpiresIn   = 1800
	bindingExtendEvery = 15 * time.Minute
	// maxSetupTime bounds how long a session that no final response ended
	// is kept: well past Timer C (proxy.DefaultTimerC).
	maxSetupTime = 10 * time.Minute
	// endAfter is how long a dialog to be ended waits for the ACK of its
	// 2xx before its BYEs go: 64*T1, the time a UAS retransmits the 2xx
	// for (RFC 3261 §13.3.1.4).
	endAfter = 32 * time.Second
	// maxMSRPLines bounds the MSRP lines of one offer: a chat, or a file
	// transfer, needs one, and each costs the relay two calls and a table
	// item (#248 security review).
	maxMSRPLines = 2
)

// Metric names of the anchoring.
const (
	metricBindings         = "msrp.bindings"
	metricRefusedLimit     = "msrp.refused.binding_limit"
	metricRefusedRate      = "msrp.refused.binding_rate"
	metricRefusedRelay     = "msrp.refused.relay"
	metricRefusedOffer     = "msrp.refused.offer"
	metricEndedLateOffer   = "msrp.ended.late_offer"
	metricEndedSecond      = "msrp.ended.second_answer"
	metricEndedRelay       = "msrp.ended.relay_failed"
	metricRelayErrors      = "msrp.relay_errors"
	metricByeFailed        = "msrp.bye_failed"
	reasonLateOffer        = `SIP;cause=488;text="MSRP offer in an answer not supported"`
	reasonSecondAnswer     = `SIP;cause=488;text="MSRP answer already given"`
	reasonRelayUnavailable = `SIP;cause=503;text="MSRP relay unavailable"`
)

// msrpKey names an anchored session: the client's flow, the Call-ID and
// the client's own tag, which is the From tag of its requests and the To
// tag of the core's.
type msrpKey struct {
	flow        transport.FlowID
	callID, tag string
}

// keyOf is the key of a session, its tag in lower case since tags compare
// without case (RFC 3261 §19.3).
func keyOf(flow transport.FlowID, callID, tag string) msrpKey {
	return msrpKey{flow: flow, callID: callID, tag: strings.ToLower(tag)}
}

// anchoredLine is an MSRP line of the offer and the binding that anchors
// it.
type anchoredLine struct {
	line     msrpLine
	binding  relayBinding
	released bool
}

// pendingEnd is a dialog of the session to be ended with a BYE on each
// side, once the ACK of its 2xx has passed or endAfter has.
type pendingEnd struct {
	ok     *sip.Response
	reason string
	at     time.Time
	// sent says its BYEs went, or its dialog ended otherwise, so a 2xx
	// retransmitted after its ACK does not end it twice.
	sent bool
}

// refusal is how an INVITE that Prepare could not anchor is answered: the
// proxy's 500 becomes it.
type refusal struct {
	status             int
	reason, retryAfter string
}

// msrpSession is a session pcscf anchors, from the offer until it ends.
//
// Once its bindings are released it serves nothing, but it stays known
// while a dialog of it is still to be ended, so that the dialog's ACK, or
// the sweep, sends its BYEs; a 2xx that comes after, as the proxy forwards
// a late one (RFC 6026 §7.2), is ended too.
type msrpSession struct {
	key   msrpKey
	lines []anchoredLine
	// host is the relay's client-side host, which an answer toward the
	// client shows in place of rcs-as's address.
	host string
	// clientInvite is the INVITE as the client sent it, and invite as it
	// went to the core, from which the BYEs that end the session are made.
	clientInvite, invite *sip.Request
	created              time.Time

	// answering lets the core's responses through one at a time, across the
	// relay calls an answer makes; mu is never held across one, so a flow
	// that closes and the sweep never wait for the relay (#248 code review
	// 5).
	answering sync.Mutex

	mu sync.Mutex
	// held is what the session took of the binding limit.
	held int
	// released says the bindings are released and the limit given back.
	released bool
	// answered says an answer came, in the response with To tag answerTag,
	// in lower case; answerIn is its description as rcs-as wrote it and
	// answerOut as the client got it, so a retransmission is rewritten the
	// same (proxy Decision.OnResponse).
	answered            bool
	answerTag           string
	answerIn, answerOut []byte
	// failed holds the Reason of an answer the relay could not serve, which
	// ends the dialog once its 2xx is answered.
	failed string
	// confirmed says the 2xx ok came, extended when the bindings were last
	// extended, and extending that an extension is under way.
	confirmed bool
	ok        *sip.Response
	extended  time.Time
	extending bool
	// clientSeq and coreSeq are the highest CSeq of the requests each side
	// sent inside the session's dialogs, which a BYE pcscf sends for that
	// side must exceed (RFC 3261 §12.2.1.1).
	clientSeq, coreSeq uint32
	// ends are the dialogs to end, by To tag in lower case.
	ends map[string]pendingEnd

	// refused is set when the session could not be anchored before it was
	// sent.
	refused atomic.Pointer[refusal]
}

// msrpAnchor is the anchoring state of a task: the relay client, nil
// without a token, the binding limit and the sessions.
//
// A session's mu may be held while mu is taken, never the other way.
type msrpAnchor struct {
	relay *relayClient
	limit *bindingLimit
	background

	mu       sync.Mutex
	sessions map[msrpKey]*msrpSession
	byFlow   map[transport.FlowID]map[msrpKey]struct{}
}

func newMSRPAnchor(ctx context.Context, relay *relayClient, limit *bindingLimit) *msrpAnchor {
	return &msrpAnchor{relay: relay, limit: limit, background: background{ctx: ctx},
		sessions: map[msrpKey]*msrpSession{}, byFlow: map[transport.FlowID]map[msrpKey]struct{}{}}
}

func (a *msrpAnchor) add(s *msrpSession) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.addLocked(s)
}

func (a *msrpAnchor) addLocked(s *msrpSession) {
	a.sessions[s.key] = s
	set := a.byFlow[s.key.flow]
	if set == nil {
		set = map[msrpKey]struct{}{}
		a.byFlow[s.key.flow] = set
	}
	set[s.key] = struct{}{}
}

// keep adds s back if no session has its key: one forgotten that has a
// dialog to end again.
func (a *msrpAnchor) keep(s *msrpSession) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sessions[s.key] == nil {
		a.addLocked(s)
	}
}

// take removes the session of key, if it is s or s is nil, and returns it.
func (a *msrpAnchor) take(key msrpKey, s *msrpSession) *msrpSession {
	a.mu.Lock()
	defer a.mu.Unlock()
	got := a.sessions[key]
	if got == nil || s != nil && got != s {
		return nil
	}
	delete(a.sessions, key)
	if delete(a.byFlow[key.flow], key); len(a.byFlow[key.flow]) == 0 {
		delete(a.byFlow, key.flow)
	}
	return got
}

func (a *msrpAnchor) get(key msrpKey) *msrpSession {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessions[key]
}

func (a *msrpAnchor) all() []*msrpSession {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*msrpSession, 0, len(a.sessions))
	for _, s := range a.sessions {
		out = append(out, s)
	}
	return out
}

// count counts n of a metric.
func (p *pcscf) count(name string, n int64) {
	if p.metrics != nil {
		p.metrics.Count(name, n)
	}
}

// refuseOffer answers an offer pcscf will not anchor with 488 (ADR 0004).
func (p *pcscf) refuseOffer() proxy.Decision {
	p.count(metricRefusedOffer, 1)
	return proxy.Decision{Status: 488, Reason: "Not Acceptable Here"}
}

// hiddenHost is the host a description toward the client shows when no
// relay binding gives one: pcscf's public name.
func (p *pcscf) hiddenHost() string {
	return cmp.Or(p.cfg.PublicHost, "0.0.0.0")
}

// anchorOriginating anchors the MSRP lines of a client's INVITE outside a
// dialog, d being where originate sends it (ADR 0004, first row):
//   - a body pcscf cannot read, more than maxMSRPLines MSRP lines, or a
//     line the relay could not serve, is 488: one that offers
//     a=setup:passive (RFC 6135 §4.2.2) or holdconn, which pcscf cannot
//     answer as it must (RFC 4145 §4), or whose path the relay would refuse
//     (relayTakesPath);
//   - without a relay token, or past the binding limits, or when the relay
//     fails, 503 with Retry-After (#136 decisions 4 to 6);
//   - otherwise each line gets a binding for the client's path, and the
//     INVITE goes to the core with the relay's core-side path, active, on
//     port 9.
//
// An INVITE without an offer is watched for an MSRP offer in its 1xx and
// 2xx, which is not supported (#136 decision 2). Neither asks for reliable
// provisional responses: one could carry an offer, answered in a PRACK,
// that pcscf does not anchor (RFC 3262 §5).
func (p *pcscf) anchorOriginating(r *proxy.Request, d proxy.Decision) proxy.Decision {
	if r.Message.Method != "INVITE" || p.msrp == nil {
		return d
	}
	part, found, err := messageSDP(&r.Message.Header, r.Message.Body)
	if err != nil {
		return p.refuseOffer()
	}
	if !found {
		return p.watchLateOffer(r, d)
	}
	_, lines, err := msrpLines(part.description(), true)
	if err != nil {
		return p.refuseOffer()
	}
	if len(lines) == 0 {
		return d
	}
	if len(lines) > min(maxMSRPLines, p.msrp.limit.most()) {
		return p.refuseOffer()
	}
	for _, l := range lines {
		if l.holdconn || l.setup != sdp.SetupActive && l.setup != sdp.SetupActPass || !relayTakesPath(l.path) {
			return p.refuseOffer()
		}
	}
	from, _ := r.Message.Header.From()
	s := &msrpSession{
		key:          keyOf(r.Source.Flow, r.Message.Header.Get("Call-ID"), from.Tag()),
		clientInvite: r.Message.Clone(),
		created:      p.now(),
		ends:         map[string]pendingEnd{},
	}
	for _, l := range lines {
		s.lines = append(s.lines, anchoredLine{line: l})
	}
	if p.msrp.relay == nil {
		p.count(metricRefusedRelay, 1)
		return p.refuse(r, 503, "MSRP Relay Unavailable")
	}
	prepare := d.Prepare
	d.Prepare = func(ctx context.Context, t proxy.Target, req *sip.Request) error {
		if prepare != nil {
			if err := prepare(ctx, t, req); err != nil {
				return err
			}
		}
		if err := without100rel(&req.Header); err != nil {
			return err
		}
		return p.allocate(ctx, s, req)
	}
	d.OnFinal = func(_ context.Context, res *sip.Response) {
		switch rf := s.refused.Load(); {
		case rf != nil && res.StatusCode == 500:
			res.StatusCode, res.Reason = rf.status, rf.reason
		case res.StatusCode == statusFlowFailed:
			// What the proxy does without OnFinal: a client must not see
			// 430 (RFC 5626 §11.5).
			res.StatusCode, res.Reason = 480, sip.DefaultReason(480)
		}
	}
	next := d.OnResponse
	d.OnResponse = func(ctx context.Context, res *sip.Response) {
		if next != nil {
			next(ctx, res)
		}
		if rf := s.refused.Load(); rf != nil && res.StatusCode == rf.status {
			if rf.retryAfter != "" {
				_ = res.Header.Set("Retry-After", rf.retryAfter)
			}
			return
		}
		p.originatingResponse(ctx, s, res)
	}
	return d
}

// without100rel takes the 100rel option out of a request's Supported and
// Require, so that the core sends no reliable provisional response (RFC
// 3262 §3), which could carry an offer pcscf does not anchor.
func without100rel(h *sip.Header) error {
	for _, name := range []string{"Supported", "Require"} {
		if !h.Has(name) {
			continue
		}
		options, err := h.Elements(name)
		if err != nil {
			return err
		}
		kept := slices.DeleteFunc(options, func(o string) bool { return strings.EqualFold(strings.TrimSpace(o), "100rel") })
		if len(kept) == len(options) {
			continue
		}
		h.Del(name)
		if len(kept) > 0 {
			if err := h.Add(name, strings.Join(kept, ", ")); err != nil {
				return err
			}
		}
	}
	return nil
}

// allocate takes s's share of the binding limits, allocates a binding for
// each line and writes the relay's core-side path into req. On an error
// nothing is held, and the INVITE is answered as s.refused says.
func (p *pcscf) allocate(ctx context.Context, s *msrpSession, req *sip.Request) error {
	wait, err := p.msrp.limit.take(s.key.flow, len(s.lines))
	switch {
	case errors.Is(err, errBindingRate):
		s.refused.Store(&refusal{status: 503, reason: "MSRP Relay Unavailable", retryAfter: strconv.Itoa(int(wait / time.Second))})
		p.count(metricRefusedRate, 1)
		return err
	case err != nil:
		s.refused.Store(&refusal{status: 503, reason: "MSRP Relay Unavailable", retryAfter: retryAfter})
		p.count(metricRefusedLimit, 1)
		return err
	}
	s.held = len(s.lines)
	fail := func(err error) error {
		if errors.Is(err, errRelayInvalid) {
			s.refused.Store(&refusal{status: 488, reason: "Not Acceptable Here"})
			p.count(metricRefusedOffer, 1)
		} else {
			s.refused.Store(&refusal{status: 503, reason: "MSRP Relay Unavailable", retryAfter: retryAfter})
			p.count(metricRefusedRelay, 1)
		}
		p.releaseSession(s)
		return err
	}
	for i := range s.lines {
		b, err := p.msrp.relay.create(ctx, relayPaths{ClientEndpointPath: s.lines[i].line.path, ExpiresIn: bindingExpiresIn})
		if err != nil {
			p.relayFailed("create", err)
			return fail(err)
		}
		s.lines[i].binding = b
	}
	u, err := msrp.ParseURI(s.lines[0].binding.ClientPath)
	if err != nil {
		return fail(err)
	}
	s.host = u.Host
	part, _, err := messageSDP(&req.Header, req.Body)
	if err != nil {
		return fail(err)
	}
	d, _, err := msrpLines(part.description(), true)
	if err != nil {
		return fail(err)
	}
	for _, l := range s.lines {
		if err := anchorLine(d, l.line.index, l.binding.CorePathLocal, sdp.SetupActive, false); err != nil {
			return fail(err)
		}
	}
	out, err := d.Marshal()
	if err != nil {
		return fail(err)
	}
	req.Body = part.with(out)
	s.invite = req.Clone()
	s.extended = p.now()
	if old := p.msrp.get(s.key); old != nil {
		// An INVITE again with the Call-ID and tag of one whose session
		// lives: that session is over.
		p.forgetSession(old)
	}
	p.msrp.add(s)
	if p.clientFlow != nil && !p.clientFlow(s.key.flow) {
		// The flow closed while the relay was asked; flowClosed may have
		// run before the session was added. Nothing goes to the core for
		// it.
		p.forgetSession(s)
		s.refused.Store(&refusal{status: 503, reason: "MSRP Relay Unavailable", retryAfter: retryAfter})
		return errFlowClosed
	}
	return nil
}

// errFlowClosed fails an INVITE whose client's flow closed while its
// session was being anchored.
var errFlowClosed = errors.New("pcscf: the client's flow closed")

// relayFailed counts and logs a failed call to the relay, by operation.
func (p *pcscf) relayFailed(op string, err error) {
	p.count(metricRelayErrors, 1)
	p.log.Warn("msrp-relay call failed", slog.String("op", op), slog.String("error", err.Error()))
}

// originatingResponse anchors the answer in res, a response from the core
// to a client's INVITE that s anchors, and keeps track of the session:
//   - the first answer, in a 1xx or 2xx (#136 decision 3), completes each
//     binding with rcs-as's path and goes to the client with the relay's
//     client path, passive; a line rcs-as declined loses its binding;
//   - a later answer the same is rewritten the same, and any other, or one
//     of another fork, or one after the bindings are released, goes to the
//     client with every line declined and its dialog is ended (#136
//     decision 3); a 2xx of another fork than the first answer's also
//     releases the bindings, which served an early dialog that 2xx ends
//     (RFC 3261 §13.2.2.4);
//   - an answer the relay cannot serve still goes to the client, its MSRP
//     lines pointing at the relay, and the dialog is ended once its 2xx is
//     answered (#136 decision 6);
//   - a final failure ends the session.
func (p *pcscf) originatingResponse(ctx context.Context, s *msrpSession, res *sip.Response) {
	code := res.StatusCode
	if code == 100 {
		return
	}
	s.answering.Lock()
	defer s.answering.Unlock()
	if code >= 300 {
		p.endSession(s)
		return
	}
	to, _ := res.Header.To()
	tag := strings.ToLower(to.Tag())
	received := res.Clone()
	part, found, err := messageSDP(&res.Header, res.Body)
	var d []byte
	if err == nil && found {
		d = part.description()
	}

	s.mu.Lock()
	first := d != nil && !s.released && !s.answered
	// A retransmission of an answer the relay could not serve goes as the
	// first did; one whose bindings were released for another cause does
	// not hand out their path again.
	same := d != nil && s.answered && tag == s.answerTag && bytes.Equal(d, s.answerIn) && (!s.released || s.failed != "")
	if first {
		s.answered, s.answerTag, s.answerIn = true, tag, slices.Clone(d)
	}
	if err != nil && !s.answered && !s.released {
		s.answered, s.answerTag, s.failed = true, tag, reasonRelayUnavailable
	}
	answerOut := s.answerOut
	s.mu.Unlock()

	other := false
	switch {
	case err != nil:
		// An answer pcscf cannot read cannot be anchored, and must not
		// reach the client as it is.
		dropBody(res)
		other = tag != s.answerTag
	case !found:
	case first:
		out, failed := p.anchorAnswer(ctx, s, d)
		s.mu.Lock()
		if s.released {
			// The flow closed while the relay was asked.
			out, failed = declineAll(d, s.host), reasonRelayUnavailable
		}
		s.answerOut, s.failed = out, failed
		s.mu.Unlock()
		setBody(res, part, out)
	case same:
		setBody(res, part, answerOut)
	default:
		setBody(res, part, declineAll(d, s.host))
		other = true
	}
	if code < 200 {
		return
	}

	s.mu.Lock()
	reason, release, releaseNow := "", false, false
	switch {
	case s.released:
		reason = cmp.Or(s.failed, reasonRelayUnavailable)
	case !s.answered:
		// A 2xx without an answer to the offer.
		s.answered, s.answerTag, s.failed = true, tag, reasonRelayUnavailable
		reason, releaseNow = s.failed, true
	case other || tag != s.answerTag:
		reason, release = reasonSecondAnswer, tag != s.answerTag && !s.confirmed
	case s.failed != "":
		// The relay cannot serve it: released before the 2xx goes on
		// (#136 decision 6), so the relay never connects for it.
		reason, releaseNow = s.failed, true
	case !s.confirmed:
		s.confirmed, s.ok = true, received
	}
	s.mu.Unlock()
	switch {
	case releaseNow:
		p.releaseNow(ctx, s)
	case release:
		p.releaseSession(s)
	}
	if reason != "" {
		p.endDialog(s, received, reason)
	}
}

// setBody makes d the description of res's body part, or drops the body
// if d is nil.
func setBody(res *sip.Response, part sdpPart, d []byte) {
	if d == nil {
		dropBody(res)
		return
	}
	res.Body = part.with(d)
}

// dropBody removes the body of res, which pcscf cannot let reach the client.
func dropBody(res *sip.Response) {
	res.Body = nil
	res.Header.Del("Content-Type")
}

// anchorAnswer completes s's bindings from rcs-as's answer d and returns the
// answer the client gets, or nil if it cannot be written, and the Reason
// that ends the dialog if the relay cannot serve it. It calls the relay:
// s.answering is held, s.mu is not.
func (p *pcscf) anchorAnswer(ctx context.Context, s *msrpSession, d []byte) ([]byte, string) {
	ans, err := sdp.Parser{MaxSize: maxSDP}.Parse(d)
	if err != nil {
		return nil, reasonRelayUnavailable
	}
	failed := ""
	anchored := map[int]string{}
	var declined []int
	for i := range s.lines {
		l := &s.lines[i]
		if l.line.index >= len(ans.Media) || !ans.Media[l.line.index].IsMSRP() {
			failed = reasonRelayUnavailable
			continue
		}
		m := &ans.Media[l.line.index]
		if m.Port == 0 {
			// rcs-as declined it: nothing to relay.
			declined = append(declined, i)
			continue
		}
		path, err := m.Path()
		if err != nil {
			failed = reasonRelayUnavailable
			continue
		}
		setup, serr := ans.MediaSetup(l.line.index)
		if errors.Is(serr, sdp.ErrNoAttribute) {
			setup, serr = sdp.SetupPassive, nil
		}
		// The relay offered active, so rcs-as must listen (RFC 6135 §4.2.2).
		if serr != nil || len(path) != 1 || setup != sdp.SetupPassive {
			failed = reasonRelayUnavailable
		} else if err := p.msrp.relay.update(ctx, l.binding.ID, relayPaths{CorePath: path}); err != nil {
			p.relayFailed("update", err)
			failed = reasonRelayUnavailable
		}
		// Whatever happened, the client sees the relay, never rcs-as.
		anchored[l.line.index] = l.binding.ClientPath
	}
	s.mu.Lock()
	for _, i := range declined {
		p.releaseLine(&s.lines[i])
	}
	s.mu.Unlock()
	if towardClient(ans, anchored, s.host) != nil {
		return nil, reasonRelayUnavailable
	}
	out, err := ans.Marshal()
	if err != nil {
		return nil, reasonRelayUnavailable
	}
	return out, failed
}

// endDialog marks the dialog of ok, a 2xx, to be ended with reason, unless
// it is already, and keeps s known until it is.
func (p *pcscf) endDialog(s *msrpSession, ok *sip.Response, reason string) {
	to, _ := ok.Header.To()
	key := strings.ToLower(to.Tag())
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ending := s.ends[key]; ending {
		return
	}
	s.ends[key] = pendingEnd{ok: ok, reason: reason, at: p.now()}
	p.msrp.keep(s)
}

// watchLateOffer forwards an INVITE without an offer as d says, and ends
// its dialog if the 2xx carries an MSRP offer, which pcscf does not
// anchor (#136 decision 2): the 1xx and 2xx with one go to the client with
// every line declined. The INVITE asks for no reliable provisional
// response.
func (p *pcscf) watchLateOffer(r *proxy.Request, d proxy.Decision) proxy.Decision {
	from, _ := r.Message.Header.From()
	key := keyOf(r.Source.Flow, r.Message.Header.Get("Call-ID"), from.Tag())
	clientInvite := r.Message.Clone()
	// s is made with the first 2xx to end and serves its retransmissions
	// and other forks' 2xx after it (#248 code review 6).
	var s *msrpSession
	var forwarded *sip.Request
	var mu sync.Mutex
	prepare := d.Prepare
	d.Prepare = func(ctx context.Context, t proxy.Target, req *sip.Request) error {
		if prepare != nil {
			if err := prepare(ctx, t, req); err != nil {
				return err
			}
		}
		if err := without100rel(&req.Header); err != nil {
			return err
		}
		mu.Lock()
		forwarded = req.Clone()
		mu.Unlock()
		return nil
	}
	next := d.OnResponse
	d.OnResponse = func(ctx context.Context, res *sip.Response) {
		if next != nil {
			next(ctx, res)
		}
		if res.StatusCode < 101 || res.StatusCode >= 300 {
			return
		}
		part, found, err := messageSDP(&res.Header, res.Body)
		if err != nil {
			dropBody(res)
		} else if !found {
			return
		} else if _, lines, err := msrpLines(part.description(), true); err == nil && len(lines) == 0 {
			return
		} else {
			setBody(res, part, declineAll(part.description(), p.hiddenHost()))
		}
		if res.StatusCode < 200 {
			return
		}
		mu.Lock()
		if s == nil {
			s = &msrpSession{key: key, clientInvite: clientInvite, invite: forwarded, created: p.now(), ends: map[string]pendingEnd{}}
		}
		ls := s
		mu.Unlock()
		p.endDialog(ls, res.Clone(), reasonLateOffer)
	}
	return d
}

// releaseLine releases the binding of l, if it has one still. s.mu of its
// session must be held; the relay is called in the background.
func (p *pcscf) releaseLine(l *anchoredLine) {
	if l.released || l.binding.ID == "" {
		return
	}
	l.released = true
	id := p.msrp.relay
	bid := l.binding.ID
	p.msrp.goRun(func(ctx context.Context) {
		if err := id.release(ctx, bid); err != nil {
			p.relayFailed("release", err)
		}
	})
}

// releaseNow is releaseSession, but waits for the relay to release each
// binding, so it is gone before the response that cannot be served goes
// on. s.mu must not be held.
func (p *pcscf) releaseNow(ctx context.Context, s *msrpSession) {
	s.mu.Lock()
	var ids []string
	for i := range s.lines {
		if l := &s.lines[i]; !l.released && l.binding.ID != "" {
			l.released = true
			ids = append(ids, l.binding.ID)
		}
	}
	p.releaseLocked(s)
	s.mu.Unlock()
	for _, id := range ids {
		if err := p.msrp.relay.release(ctx, id); err != nil {
			p.relayFailed("release", err)
		}
	}
}

// releaseSession releases every binding of s and gives back its share of
// the limit; s then serves nothing.
func (p *pcscf) releaseSession(s *msrpSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p.releaseLocked(s)
}

func (p *pcscf) releaseLocked(s *msrpSession) {
	s.released = true
	for i := range s.lines {
		p.releaseLine(&s.lines[i])
	}
	if s.held > 0 {
		p.msrp.limit.give(s.key.flow, s.held)
		s.held = 0
	}
}

// endSession releases s and forgets it once it has no dialog left to end.
func (p *pcscf) endSession(s *msrpSession) {
	p.releaseSession(s)
	p.forgetIfDone(s)
}

// forgetIfDone forgets s if it is released and has no dialog left to end.
func (p *pcscf) forgetIfDone(s *msrpSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.released {
		return
	}
	for _, e := range s.ends {
		if !e.sent {
			return
		}
	}
	p.msrp.take(s.key, s)
}

// forgetSession forgets s and releases it, whatever it has left to end.
func (p *pcscf) forgetSession(s *msrpSession) {
	p.msrp.take(s.key, s)
	p.releaseSession(s)
}

// msrpInDialog keeps track of a request inside a dialog of an anchored
// session, from the client (fromClient) or from the core over flow: a BYE
// ends its dialog, and the session with the dialog its bindings serve, and
// the ACK of a 2xx whose dialog is to be ended sends the BYEs. It reports
// false for a request pcscf does not anchor inside a dialog yet (#136's
// second change), and which is answered 488 or, an ACK, dropped: one with
// an MSRP description, or a body pcscf cannot read, in an INVITE, UPDATE,
// PRACK or ACK, and an INVITE without an offer, whose 2xx would bring one.
func (p *pcscf) msrpInDialog(flow transport.FlowID, req *sip.Request, fromClient bool) bool {
	if p.msrp == nil {
		return true
	}
	ok := true
	switch req.Method {
	case "INVITE", "UPDATE", "PRACK", "ACK":
		part, found, err := messageSDP(&req.Header, req.Body)
		switch {
		case err != nil:
			ok = false
		case found:
			_, lines, err := msrpLines(part.description(), true)
			ok = err == nil && len(lines) == 0
		default:
			ok = req.Method != "INVITE"
		}
	}
	from, _ := req.Header.From()
	to, _ := req.Header.To()
	tag, other := from.Tag(), to.Tag()
	if !fromClient {
		tag, other = other, tag
	}
	other = strings.ToLower(other)
	s := p.msrp.get(keyOf(flow, req.Header.Get("Call-ID"), tag))
	if s == nil {
		return ok
	}
	if cseq, err := req.Header.CSeq(); err == nil && req.Method != "ACK" && req.Method != "CANCEL" {
		s.mu.Lock()
		if fromClient {
			s.clientSeq = max(s.clientSeq, cseq.Seq)
		} else {
			s.coreSeq = max(s.coreSeq, cseq.Seq)
		}
		s.mu.Unlock()
	}
	switch req.Method {
	case "BYE":
		s.mu.Lock()
		// A BYE of another fork's dialog ends that dialog alone (#248 code
		// review 4).
		mine := s.answerTag == "" || other == s.answerTag
		if e, ok := s.ends[other]; ok && !e.sent {
			e.sent = true
			s.ends[other] = e
		}
		s.mu.Unlock()
		if mine {
			p.endSession(s)
		} else {
			p.forgetIfDone(s)
		}
	case "ACK":
		if fromClient {
			s.mu.Lock()
			e, due := s.ends[other]
			due = due && !e.sent
			if due {
				e.sent = true
				s.ends[other] = e
			}
			s.mu.Unlock()
			if due {
				p.sendEnd(s, e)
			}
		}
	}
	return ok
}

// sendEnd ends the dialog of e on both sides with a BYE carrying its
// Reason (ADR 0004), and the session with it if its bindings serve it.
// e is marked sent already.
func (p *pcscf) sendEnd(s *msrpSession, e pendingEnd) {
	switch e.reason {
	case reasonLateOffer:
		p.count(metricEndedLateOffer, 1)
	case reasonSecondAnswer:
		p.count(metricEndedSecond, 1)
	default:
		p.count(metricEndedRelay, 1)
	}
	to, _ := e.ok.Header.To()
	s.mu.Lock()
	mine := s.answerTag == "" || strings.EqualFold(to.Tag(), s.answerTag)
	clientSeq, coreSeq := s.clientSeq, s.coreSeq
	s.mu.Unlock()
	if mine {
		p.releaseSession(s)
	}
	p.forgetIfDone(s)
	p.msrp.goRun(func(ctx context.Context) {
		p.byeClient(s, e, coreSeq)
		p.byeCore(ctx, s, e, clientSeq)
	})
}

// byeFailed counts and logs a BYE pcscf could not send to end a dialog, or
// that was refused, by side and step: nothing that names a party.
func (p *pcscf) byeFailed(side, step string) {
	p.count(metricByeFailed, 1)
	p.log.Warn("could not end an MSRP dialog", slog.String("side", side), slog.String("step", step))
}

// byeHandler counts the BYE of side as failed if it gets a final response
// other than 2xx, or 481, which says the dialog is gone already.
func (p *pcscf) byeHandler(side string) func(*sip.Response, error) {
	return func(res *sip.Response, err error) {
		switch {
		case err != nil:
			p.byeFailed(side, "transaction")
		case res.StatusCode >= 300 && res.StatusCode != 481:
			p.byeFailed(side, strconv.Itoa(res.StatusCode))
		}
	}
}

// byeClient sends the client the BYE of the far end of e's dialog, over
// its flow: the dialog the client set up with its INVITE, from the 2xx's
// To and Contact (RFC 3261 §12.1.1), past the CSeq of the core's requests
// in it.
func (p *pcscf) byeClient(s *msrpSession, e pendingEnd, seq uint32) {
	to, err := e.ok.Header.To()
	if err != nil {
		p.byeFailed("client", "dialog")
		return
	}
	cs, err := e.ok.Header.Contact()
	if err != nil || len(cs) != 1 {
		p.byeFailed("client", "dialog")
		return
	}
	d, err := dialog.UAS(s.clientInvite, to.Tag(), cs[0].URI)
	if err != nil {
		p.byeFailed("client", "dialog")
		return
	}
	d.RouteSet = nil
	d.LocalSeq = seq
	bye, err := d.Request("BYE", p.ids)
	if err != nil || bye.Header.Set("Reason", e.reason) != nil {
		p.byeFailed("client", "request")
		return
	}
	if p.send(bye, transport.Destination{Flow: s.key.flow}, p.byeHandler("client")) != nil {
		p.byeFailed("client", "send")
	}
}

// byeCore sends the core the client's BYE for e's dialog, along the route
// set the 2xx recorded past pcscf's own values (RFC 3261 §12.1.2), past
// the CSeq of the client's requests in it. Only what the core recorded is
// followed: originate keeps no Record-Route of the client's (#248 security
// review), and a route set without pcscf's values is not followed at all.
func (p *pcscf) byeCore(ctx context.Context, s *msrpSession, e pendingEnd, seq uint32) {
	if s.invite == nil {
		p.byeFailed("core", "dialog")
		return
	}
	d, err := dialog.UAC(s.invite, e.ok)
	if err != nil {
		p.byeFailed("core", "dialog")
		return
	}
	last := -1
	for i, a := range d.RouteSet {
		if p.ownRoute(a.URI) {
			last = i
		}
	}
	if last < 0 {
		p.byeFailed("core", "route")
		return
	}
	d.RouteSet = d.RouteSet[last+1:]
	d.LocalSeq = max(d.LocalSeq, seq)
	bye, err := d.Request("BYE", p.ids)
	if err != nil || bye.Header.Set("Reason", e.reason) != nil {
		p.byeFailed("core", "request")
		return
	}
	dst, err := p.resolve.Resolve(ctx, d.NextHop())
	if err != nil {
		p.byeFailed("core", "resolve")
		return
	}
	if p.send(bye, dst, p.byeHandler("core")) != nil {
		p.byeFailed("core", "send")
	}
}

// ownRoute reports whether u is one of pcscf's own Record-Route values:
// the public name, an NLB address, or this task's core listener.
func (p *pcscf) ownRoute(u sip.URI) bool {
	if u.User == "" && p.publicHost(u.Host) {
		return true
	}
	return proxy.SameHost(u.Host, hostOf(p.cfg.CoreHost)) && u.Port == p.corePort
}

// offersMSRP reports whether req carries an MSRP offer, or a body pcscf
// cannot read for one.
func offersMSRP(req *sip.Request) bool {
	part, found, err := messageSDP(&req.Header, req.Body)
	if err != nil {
		return true
	}
	if !found {
		return false
	}
	_, lines, err := msrpLines(part.description(), true)
	return err != nil || len(lines) > 0
}

// offerless reports whether req is an INVITE without a session
// description.
func offerless(req *sip.Request) bool {
	if req.Method != "INVITE" {
		return false
	}
	_, found, err := messageSDP(&req.Header, req.Body)
	return err == nil && !found
}

// msrpFlowClosed forgets the sessions of a flow that closed (RFC 5626
// §5.3). It never waits for the relay.
func (p *pcscf) msrpFlowClosed(flow transport.FlowID) {
	if p.msrp == nil {
		return
	}
	p.msrp.mu.Lock()
	var gone []*msrpSession
	for k := range p.msrp.byFlow[flow] {
		gone = append(gone, p.msrp.sessions[k])
	}
	p.msrp.mu.Unlock()
	for _, s := range gone {
		p.forgetSession(s)
	}
	p.msrp.limit.forget(flow)
}

// sweepMSRP runs with the registry's sweep: it extends the bindings of live
// sessions every bindingExtendEvery, ends sessions whose flow is gone or
// whose setup never ended, sends the BYEs of dialogs whose ACK never came,
// and reports the bindings held.
func (p *pcscf) sweepMSRP() {
	if p.msrp == nil {
		return
	}
	now := p.now()
	for _, s := range p.msrp.all() {
		s.mu.Lock()
		var due []pendingEnd
		for tag, e := range s.ends {
			if !e.sent && !now.Before(e.at.Add(endAfter)) {
				e.sent = true
				s.ends[tag] = e
				due = append(due, e)
			}
		}
		stale := !s.confirmed && !now.Before(s.created.Add(maxSetupTime))
		extend := s.confirmed && !s.released && s.failed == "" && !s.extending && !now.Before(s.extended.Add(bindingExtendEvery))
		var ids []string
		if extend {
			s.extending = true
			for _, l := range s.lines {
				if !l.released && l.binding.ID != "" {
					ids = append(ids, l.binding.ID)
				}
			}
		}
		s.mu.Unlock()
		for _, e := range due {
			p.sendEnd(s, e)
		}
		switch {
		case p.clientFlow != nil && !p.clientFlow(s.key.flow):
			p.forgetSession(s)
			continue
		case stale:
			p.endSession(s)
			continue
		}
		if extend {
			p.msrp.goRun(func(ctx context.Context) { p.extend(ctx, s, ids, now) })
		}
	}
	p.msrp.limit.sweep()
	if p.metrics != nil {
		p.metrics.Gauge(metricBindings, int64(p.msrp.limit.held()))
	}
}

// extend extends the bindings ids of s, a sweep at now having found them
// due. Only an extension that succeeded counts, so a failed one is tried
// at the next sweep, long before the binding expires; a binding the relay
// no longer has ends the session as one it cannot serve (#136 decision 6,
// #248 code review 1).
func (p *pcscf) extend(ctx context.Context, s *msrpSession, ids []string, now time.Time) {
	var err error
	for _, id := range ids {
		if err = p.msrp.relay.update(ctx, id, relayPaths{ExpiresIn: bindingExpiresIn}); err != nil {
			p.relayFailed("update", err)
			break
		}
	}
	s.mu.Lock()
	s.extending = false
	if err == nil {
		s.extended = now
	}
	var e pendingEnd
	gone := errors.Is(err, errRelayGone) && !s.released && s.ok != nil
	if gone {
		to, _ := s.ok.Header.To()
		key := strings.ToLower(to.Tag())
		_, ending := s.ends[key]
		gone = !ending
		if gone {
			s.failed = reasonRelayUnavailable
			e = pendingEnd{ok: s.ok, reason: s.failed, at: now, sent: true}
			s.ends[key] = e
		}
	}
	s.mu.Unlock()
	if gone {
		p.sendEnd(s, e)
	}
}
