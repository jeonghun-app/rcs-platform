package scenario

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/anchor"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/chat"
)

// bindingLifetime is the expires_in the simulator asks for, as pcscf does
// from the session timer.
const bindingLifetime = 10 * time.Minute

// largeMessage is the size of the message that must travel in chunks: well
// over internal/msrp's 2048-octet chunks, well under its 1 MiB limit.
const largeMessage = 100 << 10

// answerLag is how long after the client starts connecting chat-core-
// originated sends pcscf's PATCH: well inside msrp-relay's RELAY_PATH_WAIT
// (2 s by default), so the relay must wait for the path to bind.
const answerLag = 300 * time.Millisecond

var errNoControl = errors.New("no relay control API configured (-relay-control, RCS_SIM_RELAY_TOKEN)")

// chatSession is one anchored chat: the client through the relay, the
// rcs-as stand-in behind it.
type chatSession struct {
	core               *chat.Core
	binding            anchor.Binding
	client, coreEnd    *chat.Endpoint
	clientConn         *chat.Client
	coreSession        *msrp.Session
	clientURI, coreURI msrp.URI
	written            atomic.Int64
}

// chatClientOriginated is the first row of ADR 0004's table: the client
// offers, so pcscf allocates with the client's path, and records rcs-as's
// path from the answer before the client connects.
func chatClientOriginated(r *run) error {
	cs := &chatSession{}
	if err := r.listenCore(cs); err != nil {
		return err
	}
	if err := r.step("allocate", func(ctx context.Context) (map[string]int64, error) {
		var err error
		cs.binding, err = r.cfg.Control.Allocate(ctx, anchor.Paths{Client: cs.clientURI}, bindingLifetime)
		return nil, err
	}); err != nil {
		return err
	}
	r.onEnd(func() { r.release(cs) })
	if err := r.step("answer", func(ctx context.Context) (map[string]int64, error) {
		if err := r.expectCore(cs); err != nil {
			return nil, err
		}
		return nil, r.cfg.Control.Complete(ctx, cs.binding.ID, anchor.Paths{Core: cs.coreURI}, 0)
	}); err != nil {
		return err
	}
	if err := r.connect(cs); err != nil {
		return err
	}
	return r.converse(cs)
}

// chatCoreOriginated is the second row: rcs-as offers, so pcscf allocates
// with rcs-as's path and records the client's from its answer. The client
// connects as soon as it has answered, so its connection reaches the relay
// before pcscf's PATCH does, and the relay waits for the path
// (RELAY_PATH_WAIT); then rcs-as speaks first.
func chatCoreOriginated(r *run) error {
	cs := &chatSession{}
	if err := r.listenCore(cs); err != nil {
		return err
	}
	if err := r.step("allocate", func(ctx context.Context) (map[string]int64, error) {
		var err error
		cs.binding, err = r.cfg.Control.Allocate(ctx, anchor.Paths{Core: cs.coreURI}, bindingLifetime)
		if err != nil {
			return nil, err
		}
		return nil, r.expectCore(cs)
	}); err != nil {
		return err
	}
	r.onEnd(func() { r.release(cs) })
	if err := r.step("connect-then-answer", func(ctx context.Context) (map[string]int64, error) {
		dialed := make(chan error, 1)
		go func() { dialed <- r.dial(ctx, cs) }()
		detail := map[string]int64{"answer_lag_ms": answerLag.Milliseconds()}
		select {
		case <-time.After(answerLag):
		case err := <-dialed:
			// The relay bound the session before it knew the client's
			// path: the wait this step is for did not happen.
			if err == nil {
				return detail, errors.New("the relay bound the session before pcscf recorded the client's path")
			}
			return detail, err
		}
		if err := r.cfg.Control.Complete(ctx, cs.binding.ID, anchor.Paths{Client: cs.clientURI}, 0); err != nil {
			<-dialed
			return detail, err
		}
		return detail, <-dialed
	}); err != nil {
		return err
	}
	if err := r.step("core-sends-first", func(ctx context.Context) (map[string]int64, error) {
		return nil, r.exchange(ctx, cs.coreEnd, cs.coreSession, cs.client, cs.clientConn.Session, []byte("the network speaks first"), false)
	}); err != nil {
		return err
	}
	return r.converse(cs)
}

// listenCore starts the rcs-as stand-in and picks both ends' URIs.
func (r *run) listenCore(cs *chatSession) error {
	return r.step("listen-core", func(context.Context) (map[string]int64, error) {
		if r.cfg.Control == nil {
			return nil, errNoControl
		}
		core, err := chat.ListenCore(r.cfg.CoreListen, r.cfg.CoreAdvertise, r.cfg.MSRP)
		if err != nil {
			return nil, fmt.Errorf("rcs-as stand-in: %w", err)
		}
		r.onEnd(func() { _ = core.Close() })
		cs.core = core
		if cs.coreURI, err = core.NewURI(r.cfg.Rand); err != nil {
			return nil, err
		}
		if cs.clientURI, err = chat.LocalURI(r.cfg.Rand); err != nil {
			return nil, err
		}
		cs.client = r.endpoint(r.cfg.Self, false)
		// The far end reads at once, so display notifications come back
		// without a scenario step for it.
		cs.coreEnd = r.endpoint(r.cfg.Peer, true)
		return nil, nil
	})
}

func (r *run) endpoint(self cpim.Address, autoDisplay bool) *chat.Endpoint {
	e := chat.NewEndpoint(self)
	e.AutoDisplay = autoDisplay
	e.Rand = r.cfg.Rand
	return e
}

// expectCore registers rcs-as's session, whose peer is the relay's core
// URI, as rcs-as does when it answers.
func (r *run) expectCore(cs *chatSession) error {
	s, err := cs.core.Expect(cs.coreURI, cs.binding.CoreLocal, cs.coreEnd)
	if err != nil {
		return err
	}
	cs.coreSession = s
	r.onEnd(func() { _ = s.Close() })
	return nil
}

// connect is the client connecting to client_path and binding the session;
// the relay opens the core leg as part of that.
func (r *run) connect(cs *chatSession) error {
	return r.step("connect", func(ctx context.Context) (map[string]int64, error) {
		return nil, r.dial(ctx, cs)
	})
}

func (r *run) dial(ctx context.Context, cs *chatSession) error {
	c, err := chat.Dial(ctx, cs.binding.ClientPath, cs.clientURI, cs.client, r.cfg.MSRP, r.cfg.TLS, func(nc net.Conn) net.Conn {
		return &countingConn{Conn: nc, written: &cs.written}
	})
	if err != nil {
		return err
	}
	cs.clientConn = c
	r.onEnd(func() { _ = c.Close() })
	return nil
}

// converse runs what every chat scenario checks once connected: messages
// both ways with their notifications, a message large enough to be chunked,
// and keep-alives on a quiet session.
func (r *run) converse(cs *chatSession) error {
	client := cs.clientConn.Session
	if err := r.step("client-to-core", func(ctx context.Context) (map[string]int64, error) {
		return nil, r.exchange(ctx, cs.client, client, cs.coreEnd, cs.coreSession, []byte("hello from the client"), true)
	}); err != nil {
		return err
	}
	if err := r.step("core-to-client", func(ctx context.Context) (map[string]int64, error) {
		return nil, r.exchange(ctx, cs.coreEnd, cs.coreSession, cs.client, client, []byte("hello from the network"), true)
	}); err != nil {
		return err
	}
	if err := r.step("chunked-message", func(ctx context.Context) (map[string]int64, error) {
		body, err := r.content(largeMessage)
		if err != nil {
			return nil, err
		}
		return map[string]int64{"bytes": largeMessage}, r.exchange(ctx, cs.client, client, cs.coreEnd, cs.coreSession, body, false)
	}); err != nil {
		return err
	}
	if r.cfg.IdleWait > 0 {
		if err := r.step("keep-alive", func(ctx context.Context) (map[string]int64, error) {
			before := cs.written.Load()
			select {
			case <-time.After(r.cfg.IdleWait):
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-client.Done():
				return nil, errors.New("the session ended while quiet")
			}
			// Quiet for IdleWait, the client must have sent a keep-alive.
			// On a loaded host its timer can run late, past IdleWait (#97),
			// so the step waits for the keep-alive itself rather than
			// judging by the clock: a client that sends none fails at the
			// step's timeout.
			for cs.written.Load() == before {
				select {
				case <-time.After(10 * time.Millisecond):
				case <-ctx.Done():
					return nil, errors.New("no keep-alive went out while the session was quiet")
				case <-client.Done():
					return nil, errors.New("the session ended while quiet")
				}
			}
			sent := cs.written.Load() - before
			// The session survives the quiet spell end to end.
			err := r.exchange(ctx, cs.client, client, cs.coreEnd, cs.coreSession, []byte("still here"), false)
			return map[string]int64{"bytes_while_quiet": sent}, err
		}); err != nil {
			return err
		}
	}
	return r.step("clean", func(context.Context) (map[string]int64, error) {
		for _, e := range []*chat.Endpoint{cs.client, cs.coreEnd} {
			e.Wait()
			if n := e.Malformed.Load(); n > 0 {
				return nil, fmt.Errorf("%d malformed messages received", n)
			}
			if n := e.Dropped.Load(); n > 0 {
				return nil, fmt.Errorf("%d events dropped", n)
			}
		}
		return nil, nil
	})
}

// exchange sends body from one end to the other and checks that it arrives
// whole, that the sender's success report comes back, and, with imdnToo,
// that the receiver's delivery and display notifications reach the sender.
// The receiver is the rcs-as stand-in (which reads at once) or the client,
// whose display notification exchange sends as the user reading.
func (r *run) exchange(ctx context.Context, from *chat.Endpoint, fs *msrp.Session, to *chat.Endpoint, ts *msrp.Session, body []byte, imdnToo bool) error {
	var d imdn.Disposition
	if imdnToo {
		d = imdn.PositiveDelivery | imdn.Display
	}
	sent, err := from.Send(ctx, fs, to.Self, "text/plain;charset=UTF-8", body, d)
	if err != nil {
		return err
	}
	var got chat.Received
	select {
	case got = <-to.Messages:
	case <-ctx.Done():
		return errors.New("the message did not arrive")
	}
	if !bytes.Equal(got.Body, body) || got.From.URI != from.Self.URI {
		return errors.New("the message arrived changed")
	}
	if err := waitReport(ctx, from, sent.MSRP); err != nil {
		return err
	}
	if !imdnToo {
		return nil
	}
	if got.Request.MessageID != sent.IMDN {
		return errors.New("the IMDN Message-ID did not survive the relay")
	}
	if !to.AutoDisplay {
		if err := to.Display(ctx, ts, got); err != nil {
			return fmt.Errorf("sending the display notification: %w", err)
		}
	}
	want := map[imdn.Status]bool{imdn.Delivered: true, imdn.Displayed: true}
	for len(want) > 0 {
		select {
		case n := <-from.Notifications:
			if n.MessageID != sent.IMDN || !want[n.Status] {
				return fmt.Errorf("unexpected %s notification", n.Status)
			}
			delete(want, n.Status)
		case <-ctx.Done():
			return fmt.Errorf("%d notifications did not arrive", len(want))
		}
	}
	return nil
}

// waitReport waits for the success report of the message sent with MSRP
// Message-ID id: the far end confirming the whole message (RFC 4975
// §7.1.3). Reports for other messages, a duplicate of an earlier one say,
// do not count.
func waitReport(ctx context.Context, e *chat.Endpoint, id string) error {
	for {
		select {
		case rep := <-e.Reports:
			if rep.MessageID != id {
				continue
			}
			if rep.Code != msrp.StatusOK {
				return fmt.Errorf("delivery failed with %d", rep.Code)
			}
			if rep.Range.End == rep.Range.Total {
				return nil
			}
		case <-ctx.Done():
			return errors.New("no success report")
		}
	}
}

// release deletes the binding, as pcscf does on BYE, and checks that it is
// gone: a client connecting to its client_path again is refused with 481.
func (r *run) release(cs *chatSession) {
	if cs.binding.ID == "" {
		return
	}
	_ = r.step("release", func(ctx context.Context) (map[string]int64, error) {
		if err := r.cfg.Control.Release(ctx, cs.binding.ID); err != nil {
			return nil, err
		}
		local, err := chat.LocalURI(r.cfg.Rand)
		if err != nil {
			return nil, err
		}
		c, err := chat.Dial(ctx, cs.binding.ClientPath, local, r.endpoint(r.cfg.Self, false), r.cfg.MSRP, r.cfg.TLS, nil)
		var se *msrp.StatusError
		switch {
		case err == nil:
			_ = c.Close()
			return nil, errors.New("the relay still binds a released session")
		case !errors.As(err, &se) || se.Code != msrp.StatusNoSession:
			return nil, fmt.Errorf("binding a released session: %w, want 481", err)
		}
		return nil, nil
	})
}

// countingConn counts what the client writes, to see keep-alives.
type countingConn struct {
	net.Conn
	written *atomic.Int64
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Add(int64(n))
	return n, err
}
