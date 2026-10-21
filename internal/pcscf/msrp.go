package pcscf

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/dialog"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// pcscf anchors every MSRP session of its clients through msrp-relay (ADR
// 0004, #136): it rewrites the m=message lines of each offer and answer of
// the session, so that the client connects to the relay and the relay to
// rcs-as, and it holds the relay's bindings for as long as the session
// lives. A session it cannot anchor is refused, or ended, and never left to
// run end to end.
//
// This file keeps the sessions: their bindings, the dialogs to end and the
// BYEs that end them, the flows that close and the sweep. msrpexchange.go
// anchors one offer and its answer, and msrphooks.go puts the two into the
// proxy's decisions, for the sessions either side sets up and the requests
// inside them.
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
	metricEndedDirection   = "msrp.ended.direction"
	metricEndedSecond      = "msrp.ended.second_answer"
	metricEndedRelay       = "msrp.ended.relay_failed"
	metricEndedOffer       = "msrp.ended.offer_refused"
	metricEndedNoAnswer    = "msrp.ended.no_answer"
	metricEndedDeclined    = "msrp.ended.declined"
	metricRelayErrors      = "msrp.relay_errors"
	metricByeFailed        = "msrp.bye_failed"
	reasonDirection        = `SIP;cause=488;text="MSRP direction not supported"`
	reasonSecondAnswer     = `SIP;cause=488;text="MSRP answer already given"`
	reasonRelayUnavailable = `SIP;cause=503;text="MSRP relay unavailable"`
)

// side is a side of a session: the client's, or the core's, rcs-as.
type side int

const (
	clientSide side = iota
	coreSide
)

func (s side) other() side { return 1 - s }

// msrpKey names an anchored session: the client's flow and the Call-ID.
// The client has one tag in all the dialogs of a Call-ID, those of the
// forks of its INVITE included, so the two name the session whichever side
// set it up; the tag is checked once known (msrpSession.clientTag).
type msrpKey struct {
	flow   transport.FlowID
	callID string
}

func keyOf(flow transport.FlowID, callID string) msrpKey {
	return msrpKey{flow: flow, callID: callID}
}

// anchoredLine is a relay binding and the endpoint paths the relay has for
// it, each set once (docs/api/msrp-relay.yaml).
type anchoredLine struct {
	binding              relayBinding
	clientPath, corePath []string
	released             bool
	// share is the share of the limits the binding was taken from, the
	// one it goes back to.
	share share
}

// pathOf is the endpoint path of l on side s.
func (l *anchoredLine) pathOf(s side) []string {
	if s == clientSide {
		return l.clientPath
	}
	return l.corePath
}

// pendingEnd is a dialog of the session to be ended with a BYE on each
// side, once the ACK that ackFrom sends for its 2xx has passed or endAfter
// has.
type pendingEnd struct {
	// ok is the 2xx of the INVITE that set the dialog up, from which its
	// BYEs are made.
	ok      *sip.Response
	reason  string
	ackFrom side
	at      time.Time
	// sent says its BYEs went, or its dialog ended otherwise, so a 2xx
	// retransmitted after its ACK does not end it twice.
	sent bool
}

// refusal is how a request that Prepare could not anchor is answered: the
// proxy's 500 becomes it.
type refusal struct {
	status             int
	reason, retryAfter string
}

// msrpSession is a session pcscf anchors, from its INVITE until it ends.
//
// Once its bindings are released it serves nothing, but it stays known
// while a dialog of it is still to be ended, so that the dialog's ACK, or
// the sweep, sends its BYEs; a 2xx that comes after, as the proxy forwards
// a late one (RFC 6026 §7.2), is ended too.
type msrpSession struct {
	key msrpKey
	// origin is the side that sent the INVITE: initial is that INVITE as
	// it came, and forwarded as it went to the other side, from which the
	// BYEs that end a dialog are made.
	origin             side
	initial, forwarded *sip.Request
	created            time.Time

	// answering lets the responses to the session's requests through one
	// at a time, across the relay calls an offer or an answer makes; mu is
	// never held across one, so a flow that closes and the sweep never
	// wait for the relay (#248 code review 5).
	answering sync.Mutex

	mu sync.Mutex
	// clientTag is the client's tag, once known: the From tag of its
	// INVITE, or the To tag of its first response to the core's.
	clientTag string
	// host is the relay's client-side host, which a description toward
	// the client shows in place of rcs-as's address.
	host string
	// lines are the bindings that serve the session, by m= line index;
	// every holds each binding made for it, to release them all.
	lines map[int]*anchoredLine
	every []*anchoredLine
	// setup is the exchange of the INVITE that set the session up, x one
	// under way inside its dialog, and last the last one inside it whose
	// offer came in a response, kept once taken so that a retransmitted
	// ACK finds it (#315 QA F3).
	setup, x, last *exchange
	// dialogTag is the tag of the dialog the bindings serve, in lower case:
	// the To tag of the response with the first answer, or with the offer
	// to an INVITE without one.
	dialogTag string
	// released says the bindings are released and the limit given back.
	released bool
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
	// ends are the dialogs to end, by the To tag of their 2xx in lower
	// case.
	ends map[string]pendingEnd

	// refused is set when the INVITE could not be anchored before it was
	// sent.
	refused atomic.Pointer[refusal]
}

func newSession(flow transport.FlowID, origin side, invite *sip.Request, now time.Time) *msrpSession {
	s := &msrpSession{key: keyOf(flow, invite.Header.Get("Call-ID")), origin: origin, initial: invite.Clone(),
		created: now, lines: map[int]*anchoredLine{}, ends: map[string]pendingEnd{}}
	if origin == clientSide {
		from, _ := invite.Header.From()
		s.clientTag = strings.ToLower(from.Tag())
	}
	return s
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

// relayFailed counts and logs a failed call to the relay, by operation.
func (p *pcscf) relayFailed(op string, err error) {
	p.count(metricRelayErrors, 1)
	p.log.Warn("msrp-relay call failed", slog.String("op", op), slog.String("error", err.Error()))
}

// hiddenHost is the host a description toward the client shows when no
// relay binding gives one: pcscf's public name.
func (p *pcscf) hiddenHost() string {
	if p.cfg.PublicHost != "" {
		return p.cfg.PublicHost
	}
	return "0.0.0.0"
}

// hostFor is the host a description toward the client of s shows.
func (p *pcscf) hostFor(s *msrpSession) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.host != "" {
		return s.host
	}
	return p.hiddenHost()
}

// endDialog marks the dialog of ok, a 2xx, to be ended with reason once
// ackFrom's ACK has passed, unless it is already, and keeps s known until
// it is.
func (p *pcscf) endDialog(s *msrpSession, ok *sip.Response, ackFrom side, reason string) {
	to, _ := ok.Header.To()
	key := strings.ToLower(to.Tag())
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ending := s.ends[key]; ending {
		return
	}
	s.ends[key] = pendingEnd{ok: ok, reason: reason, ackFrom: ackFrom, at: p.now()}
	p.msrp.keep(s)
}

// endNow ends the session's dialog at once, with reason: its ACK, if any,
// has passed. It is the dialog the bindings serve, of the 2xx s.ok.
func (p *pcscf) endNow(s *msrpSession, reason string) {
	s.mu.Lock()
	ok := s.ok
	var e pendingEnd
	due := false
	if ok != nil {
		to, _ := ok.Header.To()
		key := strings.ToLower(to.Tag())
		if prev, ending := s.ends[key]; !ending || !prev.sent {
			e = pendingEnd{ok: ok, reason: reason, ackFrom: s.origin, at: p.now(), sent: true}
			s.ends[key] = e
			due = true
		}
	}
	s.mu.Unlock()
	if due {
		p.sendEnd(s, e)
		return
	}
	p.endSession(s)
}

// releaseLine releases the binding of l, if it has one still, and gives
// back its share of the limit. s.mu of its session must be held; the relay
// is called in the background.
func (p *pcscf) releaseLine(s *msrpSession, l *anchoredLine) {
	if l.released || l.binding.ID == "" {
		return
	}
	l.released = true
	p.msrp.limit.give(l.share, 1)
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
	for _, l := range s.every {
		if !l.released && l.binding.ID != "" {
			l.released = true
			p.msrp.limit.give(l.share, 1)
			ids = append(ids, l.binding.ID)
		}
	}
	s.released = true
	s.mu.Unlock()
	for _, id := range ids {
		if err := p.msrp.relay.release(ctx, id); err != nil {
			p.relayFailed("release", err)
		}
	}
}

// releaseSession releases every binding of s; s then serves nothing.
func (p *pcscf) releaseSession(s *msrpSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.released = true
	for _, l := range s.every {
		p.releaseLine(s, l)
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

// sendEnd ends the dialog of e on both sides with a BYE carrying its
// Reason (ADR 0004), and the session with it if its bindings serve it.
// e is marked sent already.
func (p *pcscf) sendEnd(s *msrpSession, e pendingEnd) {
	switch e.reason {
	case reasonDirection:
		p.count(metricEndedDirection, 1)
	case reasonSecondAnswer:
		p.count(metricEndedSecond, 1)
	case reasonOfferRefused:
		p.count(metricEndedOffer, 1)
	case reasonNoAnswer:
		p.count(metricEndedNoAnswer, 1)
	case reasonDeclined:
		p.count(metricEndedDeclined, 1)
	default:
		p.count(metricEndedRelay, 1)
	}
	to, _ := e.ok.Header.To()
	s.mu.Lock()
	mine := s.dialogTag == "" || strings.EqualFold(to.Tag(), s.dialogTag)
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
// its flow, past the CSeq of the core's requests in it: as the UAS of the
// client's INVITE, from the 2xx's To and Contact (RFC 3261 §12.1.1), or as
// the UAC of the core's, from the client's 2xx (§12.1.2).
func (p *pcscf) byeClient(s *msrpSession, e pendingEnd, seq uint32) {
	var d *dialog.Dialog
	var err error
	if s.origin == clientSide {
		to, cs, cerr := toAndContact(e.ok)
		if cerr != nil {
			p.byeFailed("client", "dialog")
			return
		}
		d, err = dialog.UAS(s.initial, to.Tag(), cs)
	} else {
		d, err = dialog.UAC(s.forwarded, e.ok)
	}
	if err != nil {
		p.byeFailed("client", "dialog")
		return
	}
	d.RouteSet = nil
	d.LocalSeq = max(d.LocalSeq, seq)
	bye, err := d.Request("BYE", p.ids)
	if err != nil || bye.Header.Set("Reason", e.reason) != nil {
		p.byeFailed("client", "request")
		return
	}
	if p.send(bye, transport.Destination{Flow: s.key.flow}, p.byeHandler("client")) != nil {
		p.byeFailed("client", "send")
	}
}

// toAndContact is the To and the one Contact URI of res.
func toAndContact(res *sip.Response) (sip.Address, sip.URI, error) {
	to, err := res.Header.To()
	if err != nil {
		return sip.Address{}, sip.URI{}, err
	}
	cs, err := res.Header.Contact()
	if err != nil || len(cs) != 1 {
		return sip.Address{}, sip.URI{}, errors.New("pcscf: not one Contact")
	}
	return to, cs[0].URI, nil
}

// byeCore sends the core the client's BYE for e's dialog, past the CSeq of
// the client's requests in it: as the UAC of the client's INVITE, along
// the route set the 2xx recorded below pcscf's own values (RFC 3261
// §12.1.2), or as the UAS of the core's, along the Record-Route it came
// with (§12.1.1). Only what the core recorded is followed: originate keeps
// no Record-Route of the client's (#248 security review), and a route set
// without pcscf's values is not followed at all.
func (p *pcscf) byeCore(ctx context.Context, s *msrpSession, e pendingEnd, seq uint32) {
	var d *dialog.Dialog
	var err error
	if s.origin == clientSide {
		if s.forwarded == nil {
			p.byeFailed("core", "dialog")
			return
		}
		if d, err = dialog.UAC(s.forwarded, e.ok); err != nil {
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
	} else {
		to, cs, cerr := toAndContact(e.ok)
		if cerr != nil {
			p.byeFailed("core", "dialog")
			return
		}
		if d, err = dialog.UAS(s.initial, to.Tag(), cs); err != nil {
			p.byeFailed("core", "dialog")
			return
		}
	}
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
		extend := s.confirmed && !s.released && !s.extending && !now.Before(s.extended.Add(bindingExtendEvery))
		var ids []string
		if extend {
			s.extending = true
			for _, l := range s.every {
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
	gone := errors.Is(err, errRelayGone) && !s.released
	s.mu.Unlock()
	if gone {
		p.endNow(s, reasonRelayUnavailable)
	}
}
