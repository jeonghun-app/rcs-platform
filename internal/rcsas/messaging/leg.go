package messaging

import (
	"context"
	"errors"
	"sync"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// LegParams describes one side of a session that rcs-as anchors: the MSRP
// session between rcs-as and User, for messages exchanged with Peer.
type LegParams struct {
	// Local is the URI from LocalURI that rcs-as offered, or zero when
	// rcs-as answers an offer and a fresh one is made.
	Local msrp.URI
	// Remote is the a=path of User's SDP, which names msrp-relay.
	Remote []msrp.URI
	// User is the asserted identity of the client on this leg, and
	// Identities the others it may name in the CPIM From.
	User       string
	Identities []string
	// Peer is the other party of the conversation.
	Peer         string
	Conversation Conversation
	// Mode is Chat for a chat session and Standalone for a large-mode
	// standalone message session.
	Mode store.Mode
}

// Leg is an MSRP session rcs-as terminates. Messages that arrive on it go
// through the pipeline from User to Peer; messages queued for User from
// Peer are delivered on it.
type Leg struct {
	e       *Engine
	session *msrp.Session
	key     legKey
	p       LegParams

	mu      sync.Mutex
	waiting map[string]*delivery
}

// delivery waits for the success report that covers a whole message
// (RFC 4975 §7.1.2), or the first failure.
type delivery struct {
	size, covered int64
	done          chan int // the outcome's status code, sent once
}

// OpenLeg creates the passive MSRP session for p and makes it reachable by
// msrp-relay's connection; the SIP layer calls it when it answers an offer
// or receives an answer. Messages waiting for p.User from p.Peer are then
// delivered on it, once the relay has connected.
func (e *Engine) OpenLeg(p LegParams) (*Leg, error) {
	if p.User == "" || p.Peer == "" || p.Mode != store.Chat && p.Mode != store.Standalone {
		return nil, errors.New("messaging: a leg needs a user, a peer and a mode")
	}
	if p.Local.SessionID == "" {
		u, err := e.LocalURI()
		if err != nil {
			return nil, err
		}
		p.Local = u
	}
	l := &Leg{e: e, key: legKey{p.User, p.Peer, p.Mode}, p: p, waiting: map[string]*delivery{}}
	s, err := msrp.NewSession(msrp.SessionConfig{
		Local: p.Local, Remote: p.Remote, Handler: l, AcceptTypes: []string{cpim.ContentType},
	})
	if err != nil {
		return nil, err
	}
	l.session = s
	if err := e.registry.Add(s); err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.legs[l.key] = append(e.legs[l.key], l)
	delete(e.invites, l.key)
	e.mu.Unlock()
	go func() {
		<-s.Done()
		e.mu.Lock()
		defer e.mu.Unlock()
		legs := e.legs[l.key]
		for i, x := range legs {
			if x == l {
				legs = append(legs[:i:i], legs[i+1:]...)
				break
			}
		}
		if len(legs) == 0 {
			delete(e.legs, l.key)
		} else {
			e.legs[l.key] = legs
		}
	}()
	e.metrics.Count("leg.opened", 1)
	e.kick(p.User)
	return l, nil
}

// Local is the leg's MSRP URI, for a=path.
func (l *Leg) Local() msrp.URI { return l.session.Local() }

// Done is closed when the leg has ended.
func (l *Leg) Done() <-chan struct{} { return l.session.Done() }

// Close ends the leg, when its SIP session ends.
func (l *Leg) Close() error { return l.session.Close() }

// HandleMessage implements msrp.Handler: a message from the leg's user to
// its peer. It returns once the message is stored, so a success report
// tells the client rcs-as has it.
func (l *Leg) HandleMessage(_ *msrp.Session, m *msrp.Message) error {
	if m.MediaType() != cpim.ContentType {
		l.e.metrics.Count("message.rejected."+string(ReasonContentType), 1)
		return &msrp.StatusError{Code: msrp.StatusUnsupportedMediaType}
	}
	err := l.e.Submit(l.e.ctx, Origin{
		Sender: l.p.User, Identities: l.p.Identities, Recipient: l.p.Peer,
		Conversation: l.p.Conversation, Mode: l.p.Mode, CPIM: m.Body,
	})
	var r *Rejection
	if errors.As(err, &r) {
		return &msrp.StatusError{Code: r.MSRPStatus()}
	}
	return err
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
		l.finish(r.MessageID, d, r.Code)
		return
	}
	// A receiver may confirm a message in parts; it is delivered once the
	// parts reach its end without a gap.
	if r.Range.Start <= d.covered+1 && r.Range.End > d.covered {
		d.covered = r.Range.End
	}
	if d.covered >= d.size {
		l.finish(r.MessageID, d, msrp.StatusOK)
	}
}

// finish needs l.mu.
func (l *Leg) finish(id string, d *delivery, code int) {
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
