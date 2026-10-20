package messaging

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// IsComposingType is the media type of RFC 3994 is-composing indications,
// which RCS clients send in a chat session as they are, not in CPIM.
const IsComposingType = "application/im-iscomposing+xml"

// MaxIsComposingSize bounds a forwarded indication; a real one is a few
// hundred bytes.
const MaxIsComposingSize = 4 << 10

// IsComposingRate bounds the indications one leg forwards. A client sends
// one when typing starts or stops and refreshes it every tens of seconds
// (RFC 3994 §3); more is a peer keeping the other device busy.
var IsComposingRate = Rate{PerMinute: 60, Burst: 5}

// StatusTryAgain answers a message rcs-as could not store. RFC 4975 §10
// defines no code for a passing failure of the receiver; a 5xx code is not
// one a sender may take as a judgement on the message (403, 413, 415), so
// clients report the message as failed and the user can send it again.
const StatusTryAgain = 500

// StatusBusy answers a message rcs-as could not store because another
// write held what it needed past the store's retries (store.ErrBusy): a
// moment later it will go through. Like StatusTryAgain it is no verdict
// on the message.
const StatusBusy = 503

// notStored is the answer to a message the store could not take: err is
// the store's error, not a Rejection.
func notStored(err error) *msrp.StatusError {
	if errors.Is(err, store.ErrBusy) {
		return &msrp.StatusError{Code: StatusBusy, Comment: "Busy, try again"}
	}
	return &msrp.StatusError{Code: StatusTryAgain, Comment: "Try again later"}
}

// AcceptTypes is the a=accept-types of a leg in mode: CPIM, plus
// is-composing indications in a chat session. The SIP layer offers and
// answers with it.
func AcceptTypes(mode store.Mode) []string {
	if mode == store.Chat || mode == store.Group {
		return []string{cpim.ContentType, IsComposingType}
	}
	return []string{cpim.ContentType}
}

// Direction says who started a leg's SIP session.
type Direction uint8

const (
	// Originating: the user's client sent the INVITE; for a large-mode
	// session, the user sends its message on the leg.
	Originating Direction = iota + 1
	// Terminating: rcs-as sent the INVITE, to deliver to the user.
	Terminating
)

// LegParams describes one side of a session that rcs-as anchors: the MSRP
// session between rcs-as and User, for messages exchanged with Peer.
type LegParams struct {
	// Remote is the a=path of User's SDP, which names msrp-relay; empty
	// for Offer, which learns it in Leg.Answer.
	Remote []msrp.URI
	// User is the asserted identity of the client on this leg, and
	// Identities the others it may name in the CPIM From. A group leg puts
	// User in canonical form (identity.CanonicalIMPU), as the group does.
	User       string
	Identities []string
	// Peer is the other party of the conversation.
	Peer         string
	Conversation Conversation
	// Mode is Chat for a chat session and Standalone for a large-mode
	// session.
	Mode      store.Mode
	Direction Direction
	// QueueID is, for a terminating large-mode leg, the queued message it
	// was asked for (Invitation.QueueID). The leg delivers that message and
	// nothing else (one message per large-mode session); Finished then
	// tells the SIP layer to end the session.
	QueueID string
}

// Leg is an MSRP session rcs-as terminates. Messages that arrive on it go
// through the pipeline from User to Peer. A chat leg also delivers what is
// queued for User from Peer; a terminating large-mode leg delivers its one
// message; an originating large-mode leg only receives.
type Leg struct {
	e       *Engine
	session *msrp.Session
	p       LegParams

	mu       sync.Mutex
	waiting  map[string]*delivery
	answered bool
	expired  bool
	pending  msrp.Timer
	finished chan struct{}
	finish   sync.Once

	// composing is set while an is-composing indication is being
	// forwarded to this leg; others meanwhile are dropped. composingRate
	// bounds those this leg's user sends.
	composing     atomic.Bool
	composingRate *limiter
}

// delivery waits for the success report that covers a whole message
// (RFC 4975 §7.1.2), or the first failure.
type delivery struct {
	size, covered int64
	done          chan int // the outcome's status code, sent once
}

func (p LegParams) check() error {
	switch {
	case p.User == "" || p.Peer == "":
		return errors.New("messaging: a leg needs a user and a peer")
	case p.Mode != store.Chat && p.Mode != store.Standalone && p.Mode != store.Group:
		return errors.New("messaging: a leg needs a mode")
	case p.Direction != Originating && p.Direction != Terminating:
		return errors.New("messaging: a leg needs a direction")
	case (p.Mode == store.Standalone && p.Direction == Terminating) != (p.QueueID != ""):
		return errors.New("messaging: a terminating large-mode leg, and only one, names its queued message")
	}
	return nil
}

// OpenLeg creates the passive MSRP session for p when rcs-as answers an
// offer, so the peer's path is known, and makes it reachable by
// msrp-relay's connection.
func (e *Engine) OpenLeg(p LegParams) (*Leg, error) {
	if len(p.Remote) == 0 {
		return nil, errors.New("messaging: OpenLeg needs the remote path; use Offer before the answer")
	}
	l, err := e.newLeg(p)
	if err != nil {
		return nil, err
	}
	l.activate()
	return l, nil
}

// Offer creates the leg for an offer rcs-as is about to send (Deliverer.
// Invite), whose Local URI goes into the SDP. The session is reachable at
// once: the client connects to msrp-relay as soon as it has answered, and
// the relay's connection to rcs-as can arrive before the answer has come
// back through the CSCFs. Nothing is sent on the leg until Answer gives it
// the peer's path; without an answer within AnswerTimeout the leg closes.
func (e *Engine) Offer(p LegParams) (*Leg, error) {
	if len(p.Remote) != 0 {
		return nil, errors.New("messaging: Offer learns the remote path from the answer")
	}
	l, err := e.newLeg(p)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.pending = e.clock.AfterFunc(e.cfg.AnswerTimeout, func() {
		// Deciding and marking under one lock: an Answer either comes
		// first and keeps the leg, or finds it expired.
		l.mu.Lock()
		expire := !l.answered
		l.expired = expire
		l.mu.Unlock()
		if expire {
			e.metrics.Count("leg.unanswered", 1)
			l.Close()
		}
	})
	l.mu.Unlock()
	return l, nil
}

func (e *Engine) newLeg(p LegParams) (*Leg, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	if p.Mode == store.Group {
		// The group stores and names its participants in canonical form
		// (the group package), and their copies are queued under it; a
		// leg keyed otherwise would never be found for them.
		user, ok := identity.CanonicalIMPU(p.User)
		if !ok {
			return nil, errors.New("messaging: a group leg's user must be a SIP or tel URI")
		}
		p.User = user
	}
	id, err := msrp.NewSessionID(e.rand)
	if err != nil {
		return nil, err
	}
	local := msrp.URI{Host: e.cfg.MSRPHost, Port: e.cfg.MSRPPort, SessionID: id, Transport: "tcp"}
	l := &Leg{e: e, p: p, waiting: map[string]*delivery{}, finished: make(chan struct{}), composingRate: newLimiter(IsComposingRate, 1)}
	s, err := msrp.NewSession(msrp.SessionConfig{
		Local: local, Remote: p.Remote, RemoteLater: len(p.Remote) == 0, Handler: l, AcceptTypes: AcceptTypes(p.Mode),
	})
	if err != nil {
		return nil, err
	}
	l.session = s
	if err := e.registry.Add(s); err != nil {
		return nil, err
	}
	e.metrics.Count("leg.opened", 1)
	return l, nil
}

// Answer gives an offered leg the peer's path from the SDP answer, and
// puts it to work.
func (l *Leg) Answer(remote []msrp.URI) error {
	l.mu.Lock()
	if l.answered {
		l.mu.Unlock()
		return errors.New("messaging: the leg is already answered")
	}
	if l.expired {
		l.mu.Unlock()
		return errors.New("messaging: the offer expired before its answer")
	}
	select {
	case <-l.session.Done():
		l.mu.Unlock()
		return errors.New("messaging: the leg has ended")
	default:
	}
	if err := l.session.SetRemote(remote); err != nil {
		l.mu.Unlock()
		return err
	}
	if l.pending != nil {
		l.pending.Stop()
	}
	l.answered = true
	l.mu.Unlock()
	l.activate()
	return nil
}

// activate starts the leg's deliveries.
func (l *Leg) activate() {
	e := l.e
	l.mu.Lock()
	l.answered = true
	l.mu.Unlock()
	switch {
	case l.p.Mode == store.Chat || l.p.Mode == store.Group:
		// A group session is a chat session whose peer is the group's
		// conference URI.
		key := legKey{l.p.User, l.p.Peer}
		group := l.p.Mode == store.Group
		e.mu.Lock()
		e.legs[key] = append(e.legs[key], l)
		if group {
			e.groupLegs[l.p.Peer]++
		}
		delete(e.invites, inviteKey{l.p.User, l.p.Peer, l.p.Mode, ""})
		e.mu.Unlock()
		go func() {
			<-l.session.Done()
			e.mu.Lock()
			defer e.mu.Unlock()
			if group {
				if e.groupLegs[l.p.Peer]--; e.groupLegs[l.p.Peer] == 0 {
					delete(e.groupLegs, l.p.Peer)
				}
			}
			legs := e.legs[key]
			for i, x := range legs {
				if x == l {
					legs = append(legs[:i:i], legs[i+1:]...)
					break
				}
			}
			if len(legs) == 0 {
				delete(e.legs, key)
			} else {
				e.legs[key] = legs
			}
		}()
		e.kickEvent(l.p.User)
	case l.p.Direction == Terminating:
		e.mu.Lock()
		if e.closed {
			e.mu.Unlock()
			l.done()
			return
		}
		delete(e.invites, inviteKey{l.p.User, l.p.Peer, store.Standalone, l.p.QueueID})
		e.wg.Add(1)
		e.mu.Unlock()
		go func() {
			defer e.wg.Done()
			defer l.done()
			e.deliverLarge(l)
		}()
	}
}

// deliverLarge sends a terminating large-mode leg's one message.
func (e *Engine) deliverLarge(l *Leg) {
	m, ok := e.claim(e.ctx, store.Message{Recipient: l.p.User, ID: l.p.QueueID})
	if !ok {
		return
	}
	if m.Sender != l.p.Peer || m.Notification || m.Mode != store.Standalone {
		// Not the message this session was asked for.
		e.release(m)
		return
	}
	e.sendClaimed(e.ctx, l, m)
}

func (l *Leg) done() { l.finish.Do(func() { close(l.finished) }) }

// Finished is closed when a terminating large-mode leg has made its one
// delivery attempt, whatever came of it: the SIP layer then ends the
// session with a BYE. A message still queued gets a session of its own
// later. For other legs it is never closed.
func (l *Leg) Finished() <-chan struct{} { return l.finished }

// Local is the leg's MSRP URI, for a=path.
func (l *Leg) Local() msrp.URI { return l.session.Local() }

// Done is closed when the leg has ended.
func (l *Leg) Done() <-chan struct{} { return l.session.Done() }

// Close ends the leg, when its SIP session ends.
func (l *Leg) Close() error {
	l.mu.Lock()
	if l.pending != nil {
		l.pending.Stop()
	}
	l.mu.Unlock()
	return l.session.Close()
}

// HandleMessage implements msrp.Handler: a message from the leg's user to
// its peer. It returns once the message is stored, so a success report
// tells the client rcs-as has it.
func (l *Leg) HandleMessage(_ *msrp.Session, m *msrp.Message) error {
	if l.p.Mode == store.Group {
		return l.e.groupReceived(l, m)
	}
	switch m.MediaType() {
	case cpim.ContentType:
	case IsComposingType:
		if l.p.Mode == store.Chat {
			l.e.forwardComposing(l, m.Body)
			return nil
		}
		fallthrough
	default:
		// The session's accept-types refuse these first; this is the
		// same rule for a session configured otherwise.
		l.e.metrics.Count("message.rejected."+string(ReasonContentType), 1)
		return &msrp.StatusError{Code: msrp.StatusUnsupportedMediaType}
	}
	err := l.e.Submit(l.e.ctx, Origin{
		Sender: l.p.User, Identities: l.p.Identities, Recipient: l.p.Peer,
		Conversation: l.p.Conversation, Mode: l.p.Mode, CPIM: m.Body,
	})
	var r *Rejection
	switch {
	case errors.As(err, &r):
		return &msrp.StatusError{Code: r.MSRPStatus()}
	case err != nil:
		return notStored(err)
	}
	return nil
}

// forwardComposing passes an is-composing indication to the peer's open
// chat leg, as it is and without storing it: the state it reports is over
// within seconds (RFC 3994 §3), so one that cannot go now is dropped. One
// at a time per leg and IsComposingRate per sending leg, so a client
// sending them in a loop can neither make rcs-as queue them nor keep the
// other device busy.
func (e *Engine) forwardComposing(from *Leg, body []byte) {
	to := e.chatLeg(from.p.Peer, from.p.User)
	if to == nil || len(body) > MaxIsComposingSize || !from.composingRate.allow("", e.clock.Now()) ||
		!to.composing.CompareAndSwap(false, true) {
		e.metrics.Count("iscomposing.dropped", 1)
		return
	}
	body = append([]byte(nil), body...)
	go func() {
		ctx, cancel := e.withTimeout(e.ctx, e.cfg.DeliveryTimeout)
		_, err := to.session.Send(ctx, msrp.Outgoing{ContentType: IsComposingType, Body: body, FailureReport: msrp.ReportNo})
		cancel()
		to.composing.Store(false)
		if err != nil {
			e.metrics.Count("iscomposing.dropped", 1)
			return
		}
		e.metrics.Count("iscomposing.forwarded", 1)
	}()
}

// HandleReport implements msrp.Handler. It only hands the report to the
// delivery waiting for it, never blocking: the msrp package delivers the
// reports of a session's own sends on the goroutine that a further Send on
// the session may wait for (msrp.Handler).
func (l *Leg) HandleReport(_ *msrp.Session, r msrp.Report) {
	l.mu.Lock()
	defer l.mu.Unlock()
	d := l.waiting[r.MessageID]
	if d == nil {
		return
	}
	if r.Code != msrp.StatusOK {
		l.settle(r.MessageID, d, r.Code)
		return
	}
	// A receiver may confirm a message in parts; it is delivered once the
	// parts reach its end without a gap.
	if r.Range.Start <= d.covered+1 && r.Range.End > d.covered {
		d.covered = r.Range.End
	}
	if d.covered >= d.size {
		l.settle(r.MessageID, d, msrp.StatusOK)
	}
}

// settle needs l.mu.
func (l *Leg) settle(id string, d *delivery, code int) {
	delete(l.waiting, id)
	d.done <- code
}

// send delivers body on the leg and waits for its outcome: the status code
// of the success or failure report, or 0 when ctx ended or the leg closed
// first.
func (l *Leg) send(ctx context.Context, body []byte) (int, error) {
	id, err := msrp.NewMessageID(l.e.rand)
	if err != nil {
		return 0, err
	}
	d := &delivery{size: int64(len(body)), done: make(chan int, 1)}
	l.mu.Lock()
	l.waiting[id] = d
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		delete(l.waiting, id)
		l.mu.Unlock()
	}()
	_, err = l.session.Send(ctx, msrp.Outgoing{MessageID: id, ContentType: cpim.ContentType, Body: body, SuccessReport: true})
	var se *msrp.StatusError
	if errors.As(err, &se) {
		return se.Code, nil
	}
	if err != nil {
		return 0, nil
	}
	select {
	case code := <-d.done:
		return code, nil
	case <-ctx.Done():
	case <-l.session.Done():
	}
	return 0, nil
}
