package pcscf

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
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
	// flow does.
	bindingExpiresIn   = 1800
	bindingExtendEvery = 15 * time.Minute
	// maxSetupTime bounds how long a session that no final response ended
	// is kept: well past Timer C (proxy.DefaultTimerC).
	maxSetupTime = 10 * time.Minute
	// endAfter is how long a session to be ended waits for the ACK of its
	// 2xx before its BYEs go: 64*T1, the time a UAS retransmits the 2xx
	// for (RFC 3261 §13.3.1.4).
	endAfter = 32 * time.Second
)

// Metric names of the anchoring.
const (
	metricBindings         = "msrp.bindings"
	metricRefusedLimit     = "msrp.refused.binding_limit"
	metricRefusedRelay     = "msrp.refused.relay"
	metricRefusedOffer     = "msrp.refused.offer"
	metricEndedLateOffer   = "msrp.ended.late_offer"
	metricEndedSecond      = "msrp.ended.second_answer"
	metricEndedRelay       = "msrp.ended.relay_failed"
	metricRelayErrors      = "msrp.relay_errors"
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
	// sent says its BYEs went, so a 2xx retransmitted after its ACK does
	// not end it twice.
	sent bool
}

// msrpSession is a session pcscf anchors, from the offer until it ends.
type msrpSession struct {
	key   msrpKey
	lines []anchoredLine
	// held is what the session took of the binding limit.
	held int
	// clientInvite is the INVITE as the client sent it, and invite as it
	// went to the core, from which the BYEs that end the session are made.
	clientInvite, invite *sip.Request

	mu sync.Mutex
	// answered says an answer came, in the response with To tag answerTag;
	// answerIn is its description as rcs-as wrote it and answerOut as the
	// client got it, so a retransmission is rewritten the same (proxy
	// Decision.OnResponse).
	answered            bool
	answerTag           string
	answerIn, answerOut []byte
	// failed holds the Reason of an answer the relay could not serve, which
	// ends the dialog once its 2xx is answered.
	failed string
	// confirmed says a 2xx came, and extended when the bindings were last
	// extended.
	confirmed bool
	extended  time.Time
	created   time.Time
	// ends are the dialogs to end, by To tag.
	ends map[string]pendingEnd
	// refused is set when the session could not be anchored before it was
	// sent: its 500 goes upstream as 503 with Retry-After.
	refused atomic.Bool
}

// msrpAnchor is the anchoring state of a task: the relay client, nil
// without a token, the binding limit and the sessions.
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
	a.sessions[s.key] = s
	set := a.byFlow[s.key.flow]
	if set == nil {
		set = map[msrpKey]struct{}{}
		a.byFlow[s.key.flow] = set
	}
	set[s.key] = struct{}{}
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

// anchorOriginating anchors the MSRP lines of a client's INVITE outside a
// dialog, d being where originate sends it (ADR 0004, first row):
//   - a body pcscf cannot read, an MSRP line offering a=setup:passive (RFC
//     6135 §4.2.2) or a path through relays (RFC 4976) is 488;
//   - without a relay token, or past the binding limit, or when the relay
//     fails, 503 with Retry-After: 1 (#136 decisions 4 to 6);
//   - otherwise each line gets a binding for the client's path, and the
//     INVITE goes to the core with the relay's core-side path, active, on
//     port 9.
//
// An INVITE without an offer is watched for an MSRP offer in its 2xx,
// which is not supported (#136 decision 2).
func (p *pcscf) anchorOriginating(r *proxy.Request, d proxy.Decision) proxy.Decision {
	if r.Message.Method != "INVITE" || p.msrp == nil {
		return d
	}
	part, found, err := findSDP(r.Message.Header.Get("Content-Type"), r.Message.Body)
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
	for _, l := range lines {
		if l.setup == sdp.SetupPassive || len(l.path) != 1 {
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
		return p.allocate(ctx, s, req)
	}
	d.OnFinal = func(_ context.Context, res *sip.Response) {
		switch {
		case s.refused.Load() && res.StatusCode == 500:
			res.StatusCode, res.Reason = 503, "MSRP Relay Unavailable"
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
		if s.refused.Load() && res.StatusCode == 503 {
			_ = res.Header.Set("Retry-After", retryAfter)
			return
		}
		p.originatingResponse(ctx, s, res)
	}
	return d
}

// allocate takes s's share of the binding limit, allocates a binding for
// each line and writes the relay's core-side path into req. On an error
// nothing is held, and the INVITE is answered 503.
func (p *pcscf) allocate(ctx context.Context, s *msrpSession, req *sip.Request) error {
	if err := p.msrp.limit.take(s.key.flow, len(s.lines)); err != nil {
		s.refused.Store(true)
		p.count(metricRefusedLimit, 1)
		return err
	}
	s.held = len(s.lines)
	fail := func(err error) error {
		s.refused.Store(true)
		p.count(metricRefusedRelay, 1)
		p.release(s)
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
	part, _, err := findSDP(req.Header.Get("Content-Type"), req.Body)
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
		p.endSession(old)
	}
	p.msrp.add(s)
	if p.clientFlow != nil && !p.clientFlow(s.key.flow) {
		// The flow closed while the relay was asked; flowClosed may have
		// run before the session was added.
		p.endSession(s)
	}
	return nil
}

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
//     of another fork, goes to the client with its MSRP lines declined and
//     its dialog is ended (#136 decision 3);
//   - an answer the relay cannot serve still goes to the client, its MSRP
//     lines pointing at the relay, and the dialog is ended once its 2xx is
//     answered (#136 decision 6);
//   - a final failure ends the session.
func (p *pcscf) originatingResponse(ctx context.Context, s *msrpSession, res *sip.Response) {
	code := res.StatusCode
	if code == 100 {
		return
	}
	if code >= 300 {
		p.endSession(s)
		return
	}
	to, _ := res.Header.To()
	tag := to.Tag()
	received := res.Clone()
	part, found, err := findSDP(res.Header.Get("Content-Type"), res.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case err != nil:
		// An answer pcscf cannot read cannot be anchored, and must not
		// reach the client as it is.
		dropBody(res)
		if !s.answered {
			s.answered, s.answerTag, s.failed = true, tag, reasonRelayUnavailable
		} else if !strings.EqualFold(tag, s.answerTag) {
			s.endLocked(received, reasonSecondAnswer, p.now())
		}
	case found && !s.answered:
		s.answered, s.answerTag = true, tag
		s.answerIn = slices.Clone(part.description())
		out, failed := p.anchorAnswer(ctx, s, part.description())
		s.answerOut, s.failed = out, failed
		if out == nil {
			dropBody(res)
		} else {
			res.Body = part.with(out)
		}
	case found && strings.EqualFold(tag, s.answerTag) && string(part.description()) == string(s.answerIn):
		if s.answerOut == nil {
			dropBody(res)
		} else {
			res.Body = part.with(s.answerOut)
		}
	case found:
		// Another answer, or another fork's: the bindings serve the first.
		if out := declineMSRP(part.description()); out != nil {
			res.Body = part.with(out)
		} else {
			dropBody(res)
		}
		if code >= 200 {
			s.endLocked(received, reasonSecondAnswer, p.now())
		}
		return
	}
	if code < 200 {
		return
	}
	switch {
	case !s.answered:
		// A 2xx without an answer to the offer.
		s.answered, s.answerTag, s.failed = true, tag, reasonRelayUnavailable
		p.releaseNow(ctx, s)
		s.endLocked(received, s.failed, p.now())
	case !strings.EqualFold(tag, s.answerTag):
		s.endLocked(received, reasonSecondAnswer, p.now())
	case s.failed != "":
		// The relay cannot serve it: released before the 2xx goes on
		// (#136 decision 6), so the relay never connects for it.
		p.releaseNow(ctx, s)
		s.endLocked(received, s.failed, p.now())
	case !s.confirmed:
		s.confirmed = true
	}
}

// dropBody removes the body of res, which pcscf cannot let reach the client.
func dropBody(res *sip.Response) {
	res.Body = nil
	res.Header.Del("Content-Type")
}

// anchorAnswer completes s's bindings from rcs-as's answer d and returns the
// answer the client gets, or nil if it cannot be written, and the Reason
// that ends the dialog if the relay cannot serve it.
func (p *pcscf) anchorAnswer(ctx context.Context, s *msrpSession, d []byte) ([]byte, string) {
	ans, err := sdp.Parser{MaxSize: maxSDP}.Parse(d)
	if err != nil {
		return nil, reasonRelayUnavailable
	}
	failed := ""
	for i := range s.lines {
		l := &s.lines[i]
		if l.line.index >= len(ans.Media) || !ans.Media[l.line.index].IsMSRP() {
			failed = reasonRelayUnavailable
			continue
		}
		m := &ans.Media[l.line.index]
		if m.Port == 0 {
			// rcs-as declined it: nothing to relay.
			p.releaseLine(l)
			continue
		}
		path, err := m.Path()
		setup, serr := ans.MediaSetup(l.line.index)
		if errors.Is(serr, sdp.ErrNoAttribute) {
			setup, serr = sdp.SetupPassive, nil
		}
		// The relay offered active, so rcs-as must listen (RFC 6135 §4.2.2).
		if err != nil || serr != nil || len(path) != 1 || setup != sdp.SetupPassive {
			failed = reasonRelayUnavailable
		} else if err := p.msrp.relay.update(ctx, l.binding.ID, relayPaths{CorePath: path}); err != nil {
			p.relayFailed("update", err)
			failed = reasonRelayUnavailable
		}
		// Whatever happened, the client sees the relay, never rcs-as.
		if err := anchorLine(ans, l.line.index, l.binding.ClientPath, sdp.SetupPassive, true); err != nil {
			return nil, reasonRelayUnavailable
		}
		hideOrigin(ans, l.binding.ClientPath)
	}
	out, err := ans.Marshal()
	if err != nil {
		return nil, reasonRelayUnavailable
	}
	return out, failed
}

// hideOrigin writes the relay's host, from path, as the o= address of an
// answer toward the client, which would otherwise show rcs-as's private
// address (RFC 8866 §5.2 lets it be any host the originator chooses).
func hideOrigin(s *sdp.Session, path string) {
	u, err := msrp.ParseURI(path)
	if err != nil {
		return
	}
	s.Origin.AddrType = "IP4"
	if a, err := netip.ParseAddr(u.Host); err == nil && a.Is6() {
		s.Origin.AddrType = "IP6"
	}
	s.Origin.Address = u.Host
}

// declineMSRP returns d with every MSRP line declined (port 0, RFC 3264
// §6) and its path removed, or nil if d cannot be read: the client must not
// learn a path the relay does not serve.
func declineMSRP(d []byte) []byte {
	s, err := sdp.Parser{MaxSize: maxSDP}.Parse(d)
	if err != nil {
		return nil
	}
	for i := range s.Media {
		if m := &s.Media[i]; m.IsMSRP() {
			m.Port = 0
			m.Attributes.Remove("path")
		}
	}
	out, err := s.Marshal()
	if err != nil {
		return nil
	}
	return out
}

// endLocked marks the dialog of ok, a 2xx, to be ended with reason, and the
// session's bindings, which then serve nothing, released. s.mu must be held.
func (s *msrpSession) endLocked(ok *sip.Response, reason string, now time.Time) {
	to, _ := ok.Header.To()
	key := strings.ToLower(to.Tag())
	if _, ok := s.ends[key]; ok {
		return
	}
	s.ends[key] = pendingEnd{ok: ok, reason: reason, at: now}
}

// watchLateOffer forwards an INVITE without an offer as d says, and ends
// its dialog if the 2xx carries an MSRP offer, which pcscf does not
// anchor (#136 decision 2): the 2xx goes to the client with its MSRP lines
// declined.
func (p *pcscf) watchLateOffer(r *proxy.Request, d proxy.Decision) proxy.Decision {
	from, _ := r.Message.Header.From()
	key := keyOf(r.Source.Flow, r.Message.Header.Get("Call-ID"), from.Tag())
	clientInvite := r.Message.Clone()
	var forwarded *sip.Request
	var mu sync.Mutex
	prepare := d.Prepare
	d.Prepare = func(ctx context.Context, t proxy.Target, req *sip.Request) error {
		if prepare != nil {
			if err := prepare(ctx, t, req); err != nil {
				return err
			}
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
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return
		}
		part, found, err := findSDP(res.Header.Get("Content-Type"), res.Body)
		if err != nil || !found {
			return
		}
		_, lines, err := msrpLines(part.description(), true)
		if err != nil || len(lines) == 0 {
			return
		}
		received := res.Clone()
		if out := declineMSRP(part.description()); out != nil {
			res.Body = part.with(out)
		} else {
			dropBody(res)
		}
		mu.Lock()
		invite := forwarded
		mu.Unlock()
		s := p.msrp.get(key)
		if s == nil {
			s = &msrpSession{key: key, clientInvite: clientInvite, invite: invite, created: p.now(), ends: map[string]pendingEnd{}}
			p.msrp.add(s)
		}
		s.mu.Lock()
		s.endLocked(received, reasonLateOffer, p.now())
		s.mu.Unlock()
	}
	return d
}

// releaseLine releases the binding of l, if it has one still.
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

// releaseNow is release, but waits for the relay to release each binding,
// so it is gone before the response that cannot be served goes on.
func (p *pcscf) releaseNow(ctx context.Context, s *msrpSession) {
	for i := range s.lines {
		l := &s.lines[i]
		if l.released || l.binding.ID == "" {
			continue
		}
		l.released = true
		if err := p.msrp.relay.release(ctx, l.binding.ID); err != nil {
			p.relayFailed("release", err)
		}
	}
	p.release(s)
}

// release releases every binding of s and gives back its share of the
// limit.
func (p *pcscf) release(s *msrpSession) {
	for i := range s.lines {
		p.releaseLine(&s.lines[i])
	}
	if s.held > 0 {
		p.msrp.limit.give(s.key.flow, s.held)
		s.held = 0
	}
}

// endSession forgets s and releases its bindings.
func (p *pcscf) endSession(s *msrpSession) {
	if p.msrp.take(s.key, s) == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p.release(s)
}

// msrpInDialog keeps track of a request inside a dialog of an anchored
// session, from the client (fromClient) or from the core over flow: a BYE
// ends the session, and the ACK of a 2xx whose dialog is to be ended sends
// the BYEs. It reports false for a request that offers MSRP, which pcscf
// does not anchor inside a dialog yet and which is answered 488.
func (p *pcscf) msrpInDialog(flow transport.FlowID, req *sip.Request, fromClient bool) bool {
	if p.msrp == nil {
		return true
	}
	if req.Method == "INVITE" || req.Method == "UPDATE" {
		part, found, err := findSDP(req.Header.Get("Content-Type"), req.Body)
		if err != nil {
			return false
		}
		if found {
			_, lines, err := msrpLines(part.description(), true)
			if err != nil || len(lines) > 0 {
				return false
			}
		}
	}
	from, _ := req.Header.From()
	to, _ := req.Header.To()
	tag, other := from.Tag(), to.Tag()
	if !fromClient {
		tag, other = other, tag
	}
	s := p.msrp.get(keyOf(flow, req.Header.Get("Call-ID"), tag))
	if s == nil {
		return true
	}
	switch req.Method {
	case "BYE":
		p.endSession(s)
	case "ACK":
		if fromClient {
			s.mu.Lock()
			e, ok := s.ends[strings.ToLower(other)]
			ok = ok && !e.sent
			if ok {
				e.sent = true
				s.ends[strings.ToLower(other)] = e
			}
			s.mu.Unlock()
			if ok {
				p.sendEnd(s, e)
			}
		}
	}
	return true
}

// sendEnd ends the dialog of e on both sides with a BYE carrying its
// Reason (ADR 0004), and the session with it once it has no other dialog
// to end.
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
	// The session ends with the dialog its bindings serve, or with the
	// last dialog of a session that has none.
	mine := s.answerTag == "" || strings.EqualFold(to.Tag(), s.answerTag)
	s.mu.Unlock()
	if mine {
		p.endSession(s)
	}
	p.msrp.goRun(func(ctx context.Context) {
		p.byeClient(s, e)
		p.byeCore(ctx, s, e)
	})
}

// byeClient sends the client the BYE of the far end of e's dialog, over
// its flow: the dialog the client set up with its INVITE, from the 2xx's
// To and Contact (RFC 3261 §12.1.1).
func (p *pcscf) byeClient(s *msrpSession, e pendingEnd) {
	to, err := e.ok.Header.To()
	if err != nil {
		return
	}
	cs, err := e.ok.Header.Contact()
	if err != nil || len(cs) != 1 {
		return
	}
	d, err := dialog.UAS(s.clientInvite, to.Tag(), cs[0].URI)
	if err != nil {
		return
	}
	d.RouteSet = nil
	bye, err := d.Request("BYE", p.ids)
	if err != nil || bye.Header.Set("Reason", e.reason) != nil {
		return
	}
	_ = p.send(bye, transport.Destination{Flow: s.key.flow}, func(*sip.Response, error) {})
}

// byeCore sends the core the client's BYE for e's dialog, along the route
// set the 2xx recorded, past pcscf's own values (RFC 3261 §12.1.2).
func (p *pcscf) byeCore(ctx context.Context, s *msrpSession, e pendingEnd) {
	if s.invite == nil {
		return
	}
	d, err := dialog.UAC(s.invite, e.ok)
	if err != nil {
		return
	}
	d.RouteSet = slices.DeleteFunc(d.RouteSet, func(a sip.Address) bool { return p.ownRoute(a.URI) })
	bye, err := d.Request("BYE", p.ids)
	if err != nil || bye.Header.Set("Reason", e.reason) != nil {
		return
	}
	dst, err := p.resolve.Resolve(ctx, d.NextHop())
	if err != nil {
		return
	}
	_ = p.send(bye, dst, func(*sip.Response, error) {})
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
	part, found, err := findSDP(req.Header.Get("Content-Type"), req.Body)
	if err != nil {
		return true
	}
	if !found {
		return false
	}
	_, lines, err := msrpLines(part.description(), true)
	return err != nil || len(lines) > 0
}

// msrpFlowClosed ends the sessions of a flow that closed (RFC 5626 §5.3).
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
		p.endSession(s)
	}
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
		stale := !s.confirmed && len(s.ends) == 0 && !now.Before(s.created.Add(maxSetupTime))
		extend := s.confirmed && s.failed == "" && !now.Before(s.extended.Add(bindingExtendEvery))
		if extend {
			s.extended = now
		}
		var ids []string
		if extend {
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
		if stale || p.clientFlow != nil && !p.clientFlow(s.key.flow) {
			p.endSession(s)
			continue
		}
		for _, id := range ids {
			p.msrp.goRun(func(ctx context.Context) {
				if err := p.msrp.relay.update(ctx, id, relayPaths{ExpiresIn: bindingExpiresIn}); err != nil {
					p.relayFailed("update", err)
				}
			})
		}
	}
	if p.metrics != nil {
		p.metrics.Gauge(metricBindings, int64(p.msrp.limit.held()))
	}
}
