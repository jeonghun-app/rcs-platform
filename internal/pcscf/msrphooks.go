package pcscf

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/jeonghun-app/rcs-platform/internal/sdp"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// The anchoring in the proxy's decisions (ADR 0004): an INVITE outside a
// dialog that either side sends sets a session up (anchorInitial), and the
// requests inside its dialogs carry its later offers and answers and end
// it (anchorInDialog). An MSRP offer pcscf cannot anchor is refused, 488,
// or, in a response, which cannot be, declined and its dialog ended.

// errFlowClosed fails an INVITE whose client's flow closed while its
// session was being anchored.
var errFlowClosed = errors.New("pcscf: the client's flow closed")

// reasonOfferRefused ends a dialog whose MSRP offer came in a response and
// could not be anchored, as an offer pcscf refuses; reasonNoAnswer one
// whose offer in a response got no answer in the ACK or PRACK, and made
// bindings the relay has no answerer's path for (answerMissing).
const (
	reasonOfferRefused = `SIP;cause=488;text="MSRP offer not supported"`
	reasonNoAnswer     = `SIP;cause=488;text="MSRP answer missing"`
	// reasonDeclined ends a session whose client declined every MSRP line
	// the relay serves.
	reasonDeclined = `SIP;cause=488;text="MSRP declined"`
)

// refuseOffer answers an offer pcscf will not anchor with 488 (ADR 0004).
func (p *pcscf) refuseOffer() proxy.Decision {
	p.count(metricRefusedOffer, 1)
	return proxy.Decision{Status: 488, Reason: "Not Acceptable Here"}
}

// anchorInitial anchors the MSRP lines of an INVITE outside a dialog from
// side from, to or from the client over flow, d being where it goes (ADR
// 0004, both rows):
//   - a body pcscf cannot read, or an offer it cannot anchor (offerLines),
//     is 488;
//   - without a relay token, or past the binding limits, or when the relay
//     fails, 503 with Retry-After (#136 decisions 4 to 6);
//   - otherwise each line gets a binding for the offerer's path, and the
//     INVITE goes on with the relay's path for the other side
//     (anchorOffer).
//
// An INVITE without an offer gets one in its first reliable response
// (RFC 3261 §13.2.1, RFC 3262 §5), which is anchored the same, and its
// answer in the ACK or PRACK. An offer without MSRP lines is left alone.
func (p *pcscf) anchorInitial(r *proxy.Request, d proxy.Decision, from side, flow transport.FlowID) proxy.Decision {
	if r.Message.Method != "INVITE" || p.msrp == nil {
		return d
	}
	part, found, err := messageSDP(&r.Message.Header, r.Message.Body)
	if err != nil {
		return p.refuseOffer()
	}
	if found {
		offer, lines, err := offerLines(part.description(), from, p.msrp.limit.most(from == coreSide))
		switch {
		case err != nil:
			return p.refuseOffer()
		case len(lines) == 0 && from == clientSide && hasMSRP(offer):
			// Declined MSRP lines alone: nothing to anchor, but rcs-as
			// learns no path of the client's (#315 code review 5).
			return withDescription(d, part, declineMSRP(part.description()))
		case len(lines) == 0:
			return d
		case p.msrp.relay == nil:
			p.count(metricRefusedRelay, 1)
			return p.refuse(r, 503, "MSRP Relay Unavailable")
		}
	}
	s := newSession(flow, from, r.Message, p.now())
	prepare := d.Prepare
	d.Prepare = func(ctx context.Context, t proxy.Target, req *sip.Request) error {
		if prepare != nil {
			if err := prepare(ctx, t, req); err != nil {
				return err
			}
		}
		if !found {
			s.mu.Lock()
			s.forwarded = req.Clone()
			s.mu.Unlock()
			return nil
		}
		return p.anchorInitialOffer(ctx, s, req)
	}
	d.OnFinal = mapRefusal(d.OnFinal, &s.refused)
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
		if found {
			p.answerToInitial(ctx, s, res)
		} else {
			p.offerToInitial(ctx, s, res)
		}
	}
	return d
}

// hasMSRP reports whether s has an MSRP line, with a port or not.
func hasMSRP(s *sdp.Session) bool {
	for i := range s.Media {
		if s.Media[i].IsMSRP() {
			return true
		}
	}
	return false
}

// withDescription is d sending its request with desc in place of the
// description of its body part.
func withDescription(d proxy.Decision, part sdpPart, desc []byte) proxy.Decision {
	prepare := d.Prepare
	d.Prepare = func(ctx context.Context, t proxy.Target, req *sip.Request) error {
		if prepare != nil {
			if err := prepare(ctx, t, req); err != nil {
				return err
			}
		}
		req.Body = part.with(desc)
		return nil
	}
	return d
}

// mapRefusal is the OnFinal of a request whose Prepare may refuse it, as
// refused says: the proxy's 500 becomes the refusal, and anything else is
// final as prev, or, without one, as the proxy has it, a 430 that a client
// must not see being 480 (RFC 5626 §11.5).
func mapRefusal(prev func(context.Context, *sip.Response), refused *atomic.Pointer[refusal]) func(context.Context, *sip.Response) {
	return func(ctx context.Context, res *sip.Response) {
		if rf := refused.Load(); rf != nil && res.StatusCode == 500 {
			res.StatusCode, res.Reason = rf.status, rf.reason
			return
		}
		if prev != nil {
			prev(ctx, res)
			return
		}
		if res.StatusCode == statusFlowFailed {
			res.StatusCode, res.Reason = 480, sip.DefaultReason(480)
		}
	}
}

// anchorInitialOffer anchors the offer of req, the INVITE that sets s up as
// it goes to the other side, and makes s known. On an error nothing is
// held, and the INVITE is answered as s.refused says.
func (p *pcscf) anchorInitialOffer(ctx context.Context, s *msrpSession, req *sip.Request) error {
	part, _, err := messageSDP(&req.Header, req.Body)
	if err != nil {
		s.refused.Store(p.refusalOf(errOfferRefused, 0))
		return err
	}
	x, out, wait, err := p.anchorOffer(ctx, s, s.origin, part.description())
	if err != nil {
		s.refused.Store(p.refusalOf(err, wait))
		return err
	}
	req.Body = part.with(out)
	s.mu.Lock()
	s.forwarded = req.Clone()
	s.setup, s.x = x, x
	s.extended = p.now()
	s.mu.Unlock()
	return p.known(s)
}

// known makes s known by its key, once it holds bindings. An INVITE again
// with the Call-ID of one whose session lives ends that session. A flow
// that closed while the relay was asked, before flowClosed could find s,
// leaves nothing: s is forgotten, and errFlowClosed says nothing goes on.
func (p *pcscf) known(s *msrpSession) error {
	if old := p.msrp.get(s.key); old != nil && old != s {
		p.forgetSession(old)
	}
	p.msrp.add(s)
	if p.clientFlow != nil && !p.clientFlow(s.key.flow) {
		p.forgetSession(s)
		s.refused.Store(&refusal{status: 503, reason: "MSRP Relay Unavailable", retryAfter: retryAfter})
		return errFlowClosed
	}
	return nil
}

// reliable reports whether res is a 2xx, or a reliable provisional
// response (RFC 3262 §3): the responses that may carry an offer or answer
// to an INVITE (RFC 3261 §13.2.1).
func reliable(res *sip.Response) bool {
	if res.StatusCode >= 200 {
		return true
	}
	opts, err := res.Header.Require()
	return err == nil && slices.ContainsFunc(opts, func(o string) bool { return strings.EqualFold(o, "100rel") }) && res.Header.Has("RSeq")
}

// answerToInitial anchors the answer in res, a response to the INVITE that
// set s up with an offer, and keeps track of the session:
//   - the first answer, in a 1xx or a 2xx (#136 decision 3),
//     completes each binding and goes on with the relay's path;
//   - a later answer the same is rewritten the same, and any other, or one
//     of another fork, or one after the bindings are released, goes on
//     with its MSRP lines declined and its dialog is ended (#136 decision
//     3); a 2xx of another fork than the first answer's also releases the
//     bindings, which served an early dialog that 2xx ends (RFC 3261
//     §13.2.2.4);
//   - an answer pcscf cannot serve still goes on, its lines pointing at the
//     relay, or declined toward rcs-as if the client answered passive, and
//     the dialog is ended once its 2xx is answered (#136 decision 6, ADR
//     0004);
//   - a final failure ends the session.
func (p *pcscf) answerToInitial(ctx context.Context, s *msrpSession, res *sip.Response) {
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
	tag := p.responseTag(s, res)
	received := res.Clone()
	part, found, err := messageSDP(&res.Header, res.Body)
	var d []byte
	if err == nil && found {
		d = part.description()
	}
	s.mu.Lock()
	x := s.setup
	s.mu.Unlock()
	if x == nil {
		return
	}
	// An answer may come in any 1xx (#136 decision 3), as early media has
	// it, reliable or not; the 2xx carries the same (RFC 3261 §13.2.1).
	usable := d != nil

	s.mu.Lock()
	first := usable && !s.released && !x.answered
	// A retransmission of an answer the relay could not serve goes as the
	// first did; one whose bindings were released for another cause does
	// not hand out their path again.
	same := d != nil && x.answered && tag == x.answerTag && bytes.Equal(d, x.answerIn) && (!s.released || x.failed != "")
	if first {
		x.answered, x.answerTag, x.answerIn = true, tag, slices.Clone(d)
		s.dialogTag = tag
	}
	if err != nil && !x.answered && !s.released {
		x.answered, x.answerTag, x.failed = true, tag, reasonRelayUnavailable
		s.dialogTag = tag
	}
	answerOut := x.answerOut
	answerTag := x.answerTag
	s.mu.Unlock()

	other := false
	switch {
	case err != nil:
		// An answer pcscf cannot read cannot be anchored, and must not
		// reach the offerer as it is.
		dropBody(res)
		other = tag != answerTag
	case !found:
	case first:
		out, failed := p.anchorAnswer(ctx, s, x, d)
		s.mu.Lock()
		if s.released {
			// The flow closed while the relay was asked.
			out, failed = nil, reasonRelayUnavailable
		}
		x.answerOut, x.failed = out, failed
		s.mu.Unlock()
		if out == nil && failed == reasonRelayUnavailable {
			out = p.declineToward(s.origin, s, d)
		}
		if failed == "" {
			p.commit(s, x)
		}
		setBody(res, part, out)
	case same:
		setBody(res, part, answerOut)
	default:
		setBody(res, part, p.declineToward(s.origin, s, d))
		other = true
	}
	if code < 200 {
		return
	}
	s.mu.Lock()
	reason, release, releaseNow := "", false, false
	switch {
	case s.released:
		reason = cmp.Or(x.failed, reasonRelayUnavailable)
	case !x.answered:
		// A 2xx without an answer to the offer.
		x.answered, x.answerTag, x.failed = true, tag, reasonRelayUnavailable
		s.dialogTag = tag
		reason, releaseNow = x.failed, true
	case other || tag != x.answerTag:
		reason, release = reasonSecondAnswer, tag != x.answerTag && !s.confirmed
	case x.failed != "":
		// Released before the 2xx goes on (#136 decision 6), so the
		// relay never connects for it.
		reason, releaseNow = x.failed, true
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
		p.endDialog(s, received, s.origin, reason)
	}
}

// responseTag is the To tag of res, a response to a request of s, in lower
// case; the first one from the client is its tag.
func (p *pcscf) responseTag(s *msrpSession, res *sip.Response) string {
	to, _ := res.Header.To()
	tag := strings.ToLower(to.Tag())
	if s.origin == coreSide && tag != "" {
		s.mu.Lock()
		if s.clientTag == "" {
			s.clientTag = tag
		}
		s.mu.Unlock()
	}
	return tag
}

// offerToInitial anchors the offer in res, a response to the INVITE without
// one that s was made for, and keeps track of the session: the offer of
// the first reliable response with one goes on with the relay's path for
// the INVITE's sender, whose ACK or PRACK brings the answer; a later offer
// the same is rewritten the same, and any other, or one of another fork,
// or in an unreliable 1xx, goes on with its MSRP lines declined, a 2xx
// with one being ended as in answerToInitial. An offer pcscf cannot anchor
// goes on declined, and its 2xx is ended.
func (p *pcscf) offerToInitial(ctx context.Context, s *msrpSession, res *sip.Response) {
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
	tag := p.responseTag(s, res)
	received := res.Clone()
	part, found, err := messageSDP(&res.Header, res.Body)
	var d []byte
	if err == nil && found {
		d = part.description()
	}
	s.mu.Lock()
	x, released := s.setup, s.released
	s.mu.Unlock()
	other, failed := false, ""
	switch {
	case err != nil:
		// An offer pcscf cannot read cannot be anchored.
		dropBody(res)
		other = x != nil && tag != x.tag
		if x == nil && code >= 200 && !released {
			x = &exchange{offerer: s.origin.other(), inResponse: true, tag: tag, failed: reasonOfferRefused, settled: true}
			s.mu.Lock()
			s.setup, s.dialogTag = x, tag
			s.mu.Unlock()
		}
	case d == nil:
	case x == nil && reliable(res) && !released:
		if _, lines, err := msrpLines(d, true); err == nil && len(lines) == 0 {
			// No MSRP: nothing to anchor.
			return
		}
		nx, out, _, aerr := p.anchorOffer(ctx, s, s.origin.other(), d)
		if aerr != nil {
			failed = reasonRelayUnavailable
			if errors.Is(aerr, errOfferRefused) || errors.Is(aerr, errRelayInvalid) {
				failed = reasonOfferRefused
			}
			nx = &exchange{offerer: s.origin.other(), failed: failed, settled: true}
			out = p.declineToward(s.origin, s, d)
		}
		nx.inResponse, nx.tag = true, tag
		nx.cseq, nx.rseq = responseSeqs(res)
		s.mu.Lock()
		s.setup, s.dialogTag = nx, tag
		if aerr == nil {
			s.x = nx
			s.extended = p.now()
		}
		s.mu.Unlock()
		x = nx
		if aerr == nil && p.known(s) != nil {
			out = p.declineToward(s.origin, s, d)
		}
		setBody(res, part, out)
	case x != nil && tag == x.tag && bytes.Equal(d, x.offerIn) && x.offerOut != nil && !released:
		setBody(res, part, x.offerOut)
	default:
		setBody(res, part, p.declineToward(s.origin, s, d))
		other = true
	}
	if code < 200 || x == nil && !other {
		return
	}
	s.mu.Lock()
	reason, release := "", false
	switch {
	case x != nil && x.failed != "" && tag == x.tag:
		reason = x.failed
	case s.released:
		reason = reasonRelayUnavailable
	case other || x != nil && tag != x.tag:
		reason, release = reasonSecondAnswer, x != nil && !s.confirmed && tag != x.tag
	case !s.confirmed:
		s.confirmed, s.ok = true, received
	}
	s.mu.Unlock()
	if release {
		p.releaseSession(s)
	}
	if reason != "" {
		p.endDialog(s, received, s.origin, reason)
	}
}

// sessionOf is the session of a request inside a dialog from side from
// over flow, if pcscf anchors one: by flow and Call-ID, with the client's
// tag, once known, the request's.
func (p *pcscf) sessionOf(flow transport.FlowID, req *sip.Request, from side) *msrpSession {
	s := p.msrp.get(keyOf(flow, req.Header.Get("Call-ID")))
	if s == nil {
		return nil
	}
	f, _ := req.Header.From()
	t, _ := req.Header.To()
	tag := f.Tag()
	if from == coreSide {
		tag = t.Tag()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clientTag != "" && !strings.EqualFold(s.clientTag, tag) {
		return nil
	}
	return s
}

// dialogTagOf is the tag of the dialog of s a request from side from is
// in: the To tag of the 2xx that set it up, the core's in a session the
// client set up and the client's in one the core did.
func dialogTagOf(s *msrpSession, req *sip.Request, from side) string {
	f, _ := req.Header.From()
	t, _ := req.Header.To()
	answering := s.origin.other()
	if from == answering {
		return strings.ToLower(f.Tag())
	}
	return strings.ToLower(t.Tag())
}

// anchorInDialog anchors a request inside a dialog from side from over the
// client's flow, d being where it goes:
//   - an INVITE or UPDATE with an offer is anchored as the INVITE that set
//     the session up is, and its answer in the response; an INVITE
//     without one gets its offer in the response, and its answer in the
//     ACK (RFC 3261 §14);
//   - an ACK or PRACK with the answer to an offer in a response takes it;
//   - one offer at a time: another while one is under way is 491 (RFC
//     3261 §14.2, RFC 3311 §5.2), and an offer in a PRACK is 488, as pcscf
//     does not anchor one there (#136 part 2, question 2);
//   - a BYE ends its dialog, and the session with the dialog the bindings
//     serve, and the ACK of a 2xx whose dialog is to be ended sends the
//     BYEs.
//
// In a dialog pcscf does not anchor an MSRP description is 488, an ACK with
// one is dropped, and an offer in a response to an INVITE without one goes
// on declined: such a dialog set up without MSRP, which it cannot add.
func (p *pcscf) anchorInDialog(r *proxy.Request, d proxy.Decision, from side, flow transport.FlowID) proxy.Decision {
	if p.msrp == nil {
		return d
	}
	req := r.Message
	carries := req.Method == "INVITE" || req.Method == "UPDATE" || req.Method == "PRACK" || req.Method == "ACK"
	var part sdpPart
	var found bool
	if carries {
		var err error
		if part, found, err = messageSDP(&req.Header, req.Body); err != nil {
			return p.refuseOffer()
		}
	}
	s := p.sessionOf(flow, req, from)
	if s == nil {
		if found {
			desc, lines, err := msrpLines(part.description(), true)
			if err != nil || len(lines) > 0 {
				return p.refuseOffer()
			}
			if from == clientSide && hasMSRP(desc) {
				// Declined MSRP lines alone: rcs-as learns no path of the
				// client's from them (#315 QA round 3).
				d = withDescription(d, part, declineMSRP(part.description()))
			}
		}
		if req.Method == "INVITE" && !found {
			return p.declineResponses(d, from)
		}
		return d
	}
	p.trackSeq(s, req, from)
	switch req.Method {
	case "BYE":
		p.byeInDialog(s, req, from)
	case "ACK", "PRACK":
		return p.answerInRequest(s, r, d, from, part, found)
	case "INVITE", "UPDATE":
		if found {
			return p.offerInRequest(s, d, from, part)
		}
		if req.Method == "INVITE" {
			return p.offerInResponse(s, d, from)
		}
	}
	return d
}

// trackSeq keeps the highest CSeq each side sent in s's dialogs.
func (p *pcscf) trackSeq(s *msrpSession, req *sip.Request, from side) {
	cseq, err := req.Header.CSeq()
	if err != nil || req.Method == "ACK" || req.Method == "CANCEL" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if from == clientSide {
		s.clientSeq = max(s.clientSeq, cseq.Seq)
	} else {
		s.coreSeq = max(s.coreSeq, cseq.Seq)
	}
}

// byeInDialog takes a BYE of s's: it ends its dialog alone if that is
// another fork's (#248 code review 4), the session with it otherwise.
func (p *pcscf) byeInDialog(s *msrpSession, req *sip.Request, from side) {
	tag := dialogTagOf(s, req, from)
	s.mu.Lock()
	mine := s.dialogTag == "" || tag == s.dialogTag
	if e, ok := s.ends[tag]; ok && !e.sent {
		e.sent = true
		s.ends[tag] = e
	}
	s.mu.Unlock()
	if mine {
		p.endSession(s)
	} else {
		p.forgetIfDone(s)
	}
}

// ackPassed sends the BYEs of the dialog of an ACK from side from, if it
// is to be ended once that ACK has passed.
func (p *pcscf) ackPassed(s *msrpSession, req *sip.Request, from side) {
	tag := dialogTagOf(s, req, from)
	s.mu.Lock()
	e, due := s.ends[tag]
	due = due && !e.sent && e.ackFrom == from
	if due {
		e.sent = true
		s.ends[tag] = e
	}
	s.mu.Unlock()
	if due {
		p.sendEnd(s, e)
	}
}

// answerInRequest takes an ACK or PRACK of s from side from: one with the
// answer to the offer in a response that the other side made goes on with
// that answer anchored, the same each time it is retransmitted; any other
// description in one is refused, an ACK being dropped. An answer pcscf
// cannot serve ends the session once the ACK has gone, or with the 2xx
// after the PRACK. One without a description is answerMissing's.
func (p *pcscf) answerInRequest(s *msrpSession, r *proxy.Request, d proxy.Decision, from side, part sdpPart, found bool) proxy.Decision {
	method := r.Message.Method
	if !found {
		p.answerMissing(s, r.Message, from)
		return d
	}
	desc := part.description()
	// The ACK or PRACK of a response has its To tag: one of another fork
	// answers no offer of this one's (#315 QA F1).
	tag := toTag(r.Message)
	s.mu.Lock()
	x := s.x
	if x == nil || !x.inResponse || x.offerer != from.other() || x.tag != tag || x.settled && !bytes.Equal(x.answerIn, desc) {
		// A retransmitted ACK finds its exchange taken already.
		x = nil
		for _, past := range []*exchange{s.setup, s.x, s.last} {
			if past != nil && past.inResponse && past.offerer == from.other() && past.tag == tag && past.answered && bytes.Equal(past.answerIn, desc) {
				x = past
			}
		}
	}
	s.mu.Unlock()
	if x == nil {
		if method == "ACK" {
			p.ackPassed(s, r.Message, from)
		}
		return p.refuseOffer()
	}
	prepare := d.Prepare
	d.Prepare = func(ctx context.Context, t proxy.Target, req *sip.Request) error {
		if prepare != nil {
			if err := prepare(ctx, t, req); err != nil {
				return err
			}
		}
		out, failed, first := p.takeAnswer(ctx, s, x, desc)
		if out == nil {
			req.Body = nil
			req.Header.Del("Content-Type")
		} else {
			req.Body = part.with(out)
		}
		if method == "ACK" {
			p.ackPassed(s, req, from)
			if first && failed != "" {
				p.endNow(s, failed)
			}
		}
		return nil
	}
	return d
}

// answerMissing takes an ACK or PRACK of s from side from without a
// description. One that acknowledges the response carrying the other
// side's offer of the exchange under way, which it should have answered
// (RFC 3264 §4, RFC 3262 §5), gives that exchange up, so that the next
// offer is not 491: rcsjta acknowledges so the offer rcs-as makes in the
// 2xx of its refresh (#315 code review 1). An exchange that made bindings
// leaves the relay without the answerer's path for them, so the session
// ends with reasonNoAnswer: once the ACK has passed, or after the 2xx that
// follows the PRACK. One that made none leaves the session as it was.
func (p *pcscf) answerMissing(s *msrpSession, req *sip.Request, from side) {
	s.answering.Lock()
	s.mu.Lock()
	x := s.x
	missing := x != nil && x.inResponse && x.offerer == from.other() && x.tag == toTag(req) && !x.answered && !x.settled && acknowledges(req, x)
	fresh := missing && len(x.fresh) > 0
	if fresh {
		x.failed = reasonNoAnswer
	}
	s.mu.Unlock()
	if missing {
		p.abort(s, x)
	}
	s.answering.Unlock()
	if req.Method != "ACK" {
		return
	}
	p.ackPassed(s, req, from)
	if fresh {
		p.endNow(s, reasonNoAnswer)
	}
}

// toTag is the To tag of req in lower case, as an exchange keeps the tag of
// the response it acknowledges.
func toTag(req *sip.Request) string {
	to, _ := req.Header.To()
	return strings.ToLower(to.Tag())
}

// responseSeqs returns the CSeq number of res and its RSeq, 0 for a final
// response or one without: what the ACK or PRACK that acknowledges res
// carries (RFC 3261 §17.1.1.3, RFC 3262 §7.2).
func responseSeqs(res *sip.Response) (cseq, rseq uint32) {
	if c, err := res.Header.CSeq(); err == nil {
		cseq = c.Seq
	}
	if res.StatusCode < 200 {
		if n, err := strconv.ParseUint(strings.TrimSpace(res.Header.Get("RSeq")), 10, 32); err == nil {
			rseq = uint32(n)
		}
	}
	return cseq, rseq
}

// acknowledges reports whether req, an ACK or a PRACK, acknowledges the
// response that carried x's offer: an ACK by its INVITE's CSeq, a PRACK by
// its RAck, the response's RSeq and CSeq (RFC 3262 §7.2). An ACK of an
// earlier 2xx, sent again, is not one.
func acknowledges(req *sip.Request, x *exchange) bool {
	if req.Method == "ACK" {
		c, err := req.Header.CSeq()
		return err == nil && c.Seq == x.cseq
	}
	f := strings.Fields(req.Header.Get("RAck"))
	if len(f) != 3 || x.rseq == 0 {
		return false
	}
	rseq, err := strconv.ParseUint(f[0], 10, 32)
	if err != nil {
		return false
	}
	cseq, err := strconv.ParseUint(f[1], 10, 32)
	return err == nil && uint32(rseq) == x.rseq && uint32(cseq) == x.cseq
}

// takeAnswer takes desc, the answer to x in an ACK or PRACK, once, and
// returns what goes on, the Reason that ends the session if pcscf cannot
// serve it, and whether this was the first time.
func (p *pcscf) takeAnswer(ctx context.Context, s *msrpSession, x *exchange, desc []byte) ([]byte, string, bool) {
	s.answering.Lock()
	defer s.answering.Unlock()
	s.mu.Lock()
	if x.answered {
		out, failed := x.answerOut, x.failed
		s.mu.Unlock()
		return out, failed, false
	}
	x.answered, x.answerIn = true, slices.Clone(desc)
	released := s.released
	s.mu.Unlock()
	out, failed := []byte(nil), reasonRelayUnavailable
	if !released {
		out, failed = p.anchorAnswer(ctx, s, x, desc)
	}
	if out == nil {
		out = p.declineToward(x.offerer, s, desc)
	}
	s.mu.Lock()
	x.answerOut, x.failed = out, failed
	s.mu.Unlock()
	if failed == "" {
		p.commit(s, x)
	} else {
		p.abort(s, x)
	}
	return out, failed, true
}

// busy reports whether an exchange of s is under way, or s is over, so
// that no other offer is taken.
func busy(s *msrpSession) (under, over bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.x != nil && !s.x.settled, s.released
}

// offerInRequest anchors the offer of an INVITE or UPDATE inside s's dialog
// from side from, and its answer in the response.
func (p *pcscf) offerInRequest(s *msrpSession, d proxy.Decision, from side, part sdpPart) proxy.Decision {
	desc := part.description()
	under, over := busy(s)
	switch {
	case over:
		return p.refuseOffer()
	case under:
		return proxy.Decision{Status: 491, Reason: "Request Pending"}
	}
	if _, _, err := offerLines(desc, from, p.msrp.limit.most(from == coreSide)); err != nil {
		return p.refuseOffer()
	}
	var refused atomic.Pointer[refusal]
	var mu sync.Mutex
	var x *exchange
	prepare := d.Prepare
	d.Prepare = func(ctx context.Context, t proxy.Target, req *sip.Request) error {
		if prepare != nil {
			if err := prepare(ctx, t, req); err != nil {
				return err
			}
		}
		nx, out, wait, err := p.anchorOffer(ctx, s, from, desc)
		if err != nil {
			refused.Store(p.refusalOf(err, wait))
			return err
		}
		s.mu.Lock()
		taken := s.x != nil && !s.x.settled
		if !taken {
			s.x = nx
		}
		s.mu.Unlock()
		if taken {
			// Another offer got in meanwhile.
			p.abort(s, nx)
			refused.Store(&refusal{status: 491, reason: "Request Pending"})
			return errOfferRefused
		}
		mu.Lock()
		x = nx
		mu.Unlock()
		req.Body = part.with(out)
		return nil
	}
	d.OnFinal = mapRefusal(d.OnFinal, &refused)
	next := d.OnResponse
	d.OnResponse = func(ctx context.Context, res *sip.Response) {
		if next != nil {
			next(ctx, res)
		}
		if rf := refused.Load(); rf != nil && res.StatusCode == rf.status {
			if rf.retryAfter != "" {
				_ = res.Header.Set("Retry-After", rf.retryAfter)
			}
			return
		}
		mu.Lock()
		ex := x
		mu.Unlock()
		if ex != nil {
			p.answerInResponse(ctx, s, ex, res)
		}
	}
	return d
}

// answerInResponse anchors the answer in res, a response to the request
// inside s's dialog that made the offer of x: the first is taken, a retransmission rewritten the same, and any other
// declined. A final failure gives x up (RFC 3261 §14.1). A 2xx takes x, or,
// when its answer cannot be served or there is none, ends the session.
func (p *pcscf) answerInResponse(ctx context.Context, s *msrpSession, x *exchange, res *sip.Response) {
	code := res.StatusCode
	if code == 100 {
		return
	}
	s.answering.Lock()
	defer s.answering.Unlock()
	if code >= 300 {
		p.abort(s, x)
		return
	}
	part, found, err := messageSDP(&res.Header, res.Body)
	var d []byte
	if err == nil && found {
		d = part.description()
	}
	s.mu.Lock()
	first := d != nil && !x.answered
	same := d != nil && x.answered && bytes.Equal(d, x.answerIn)
	if first {
		x.answered, x.answerIn = true, slices.Clone(d)
	}
	answerOut := x.answerOut
	s.mu.Unlock()
	switch {
	case err != nil:
		dropBody(res)
	case d == nil:
	case first:
		out, failed := p.anchorAnswer(ctx, s, x, d)
		if out == nil {
			out = p.declineToward(x.offerer, s, d)
		}
		s.mu.Lock()
		x.answerOut, x.failed = out, failed
		s.mu.Unlock()
		setBody(res, part, out)
	case same:
		setBody(res, part, answerOut)
	default:
		setBody(res, part, p.declineToward(x.offerer, s, d))
	}
	if code < 200 {
		return
	}
	s.mu.Lock()
	failed := x.failed
	if !x.answered {
		failed = reasonRelayUnavailable
	}
	s.mu.Unlock()
	if failed == "" {
		p.commit(s, x)
		return
	}
	p.abort(s, x)
	p.endAfterRefresh(s, x.offerer, res, failed)
}

// endAfterRefresh ends s with reason after the 2xx res to a request inside
// its dialog that side from sent: once the ACK of a re-INVITE's has passed,
// at once for an UPDATE's, which has none.
func (p *pcscf) endAfterRefresh(s *msrpSession, from side, res *sip.Response, reason string) {
	if cseq, err := res.Header.CSeq(); err == nil && cseq.Method == "INVITE" {
		s.mu.Lock()
		ok := s.ok
		s.mu.Unlock()
		if ok != nil {
			to, _ := ok.Header.To()
			key := strings.ToLower(to.Tag())
			s.mu.Lock()
			if _, ending := s.ends[key]; !ending {
				s.ends[key] = pendingEnd{ok: ok, reason: reason, ackFrom: from, at: p.now()}
			}
			s.mu.Unlock()
			return
		}
	}
	p.endNow(s, reason)
}

// offerInResponse watches the responses to an INVITE without an offer
// inside s's dialog from side from: the offer of the first reliable one is
// anchored (anchorOffer) and goes on with the relay's path, its answer
// coming in the ACK or PRACK; a retransmission is rewritten the same, and
// another offer declined. An offer pcscf cannot anchor goes on declined,
// and its 2xx ends the session. rcs-as answers a refresh so (#252).
func (p *pcscf) offerInResponse(s *msrpSession, d proxy.Decision, from side) proxy.Decision {
	under, over := busy(s)
	switch {
	case over:
		return p.refuseOffer()
	case under:
		return proxy.Decision{Status: 491, Reason: "Request Pending"}
	}
	var x *exchange
	next := d.OnResponse
	d.OnResponse = func(ctx context.Context, res *sip.Response) {
		if next != nil {
			next(ctx, res)
		}
		code := res.StatusCode
		if code == 100 {
			return
		}
		s.answering.Lock()
		defer s.answering.Unlock()
		if code >= 300 {
			if x != nil {
				p.abort(s, x)
			}
			return
		}
		part, found, err := messageSDP(&res.Header, res.Body)
		switch {
		case err != nil:
			dropBody(res)
		case !found:
		case x == nil && reliable(res):
			desc := part.description()
			if _, lines, err := msrpLines(desc, true); err == nil && len(lines) == 0 {
				return
			}
			nx, out, _, aerr := p.anchorOffer(ctx, s, from.other(), desc)
			if aerr != nil {
				setBody(res, part, p.declineToward(from, s, desc))
				if code >= 200 {
					reason := reasonRelayUnavailable
					if errors.Is(aerr, errOfferRefused) || errors.Is(aerr, errRelayInvalid) {
						reason = reasonOfferRefused
					}
					p.endAfterRefresh(s, from, res, reason)
				}
				return
			}
			to, _ := res.Header.To()
			nx.inResponse, nx.tag = true, strings.ToLower(to.Tag())
			nx.cseq, nx.rseq = responseSeqs(res)
			s.mu.Lock()
			s.x, s.last = nx, nx
			s.mu.Unlock()
			x = nx
			setBody(res, part, out)
		case x != nil && bytes.Equal(part.description(), x.offerIn):
			setBody(res, part, x.offerOut)
		default:
			setBody(res, part, p.declineToward(from, s, part.description()))
		}
		if code >= 200 && x != nil {
			// An answer in the PRACK that pcscf could not serve, or none
			// at all (answerMissing), ends the session after the 2xx.
			s.mu.Lock()
			failed := x.failed
			s.mu.Unlock()
			if failed != "" {
				p.endAfterRefresh(s, from, res, failed)
			}
		}
	}
	return d
}

// declineResponses declines the MSRP lines of the responses to an INVITE
// from side from inside a dialog pcscf does not anchor.
func (p *pcscf) declineResponses(d proxy.Decision, from side) proxy.Decision {
	next := d.OnResponse
	d.OnResponse = func(ctx context.Context, res *sip.Response) {
		if next != nil {
			next(ctx, res)
		}
		part, found, err := messageSDP(&res.Header, res.Body)
		switch {
		case err != nil:
			dropBody(res)
		case found:
			if _, lines, err := msrpLines(part.description(), true); err != nil || len(lines) > 0 {
				setBody(res, part, p.declineToward(from, nil, part.description()))
			}
		}
	}
	return d
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

// dropBody removes the body of res, which pcscf cannot let reach the
// other side.
func dropBody(res *sip.Response) {
	res.Body = nil
	res.Header.Del("Content-Type")
}
