package proxy

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// ErrNoACK means the ACK for a 2xx did not come within 64*T1 of the 2xx. The
// dialog stands, but RFC 3261 §13.3.1.4 has the UAS end the session with a BYE.
var ErrNoACK = errors.New("proxy: no ACK for the 2xx")

// ErrNotAccepted means ACK was asked for a request that was not an INVITE
// answered with a 2xx.
var ErrNotAccepted = errors.New("proxy: no 2xx to an INVITE was sent")

// UAS is a request the Router handed to the service with Decision.Serve, which
// answers it itself as a user agent server: rcs-as ends sessions and messages
// as a B2BUA, and needs what a UAS core does beyond sending a response once.
// For a 2xx to an INVITE that is retransmitting it until the ACK arrives, over
// every transport (RFC 3261 §13.3.1.4 as RFC 6026 §8.1 rewrote it), and
// delivering the ACK, which belongs to no transaction, to the service rather
// than forwarding it.
type UAS struct {
	c   *respContext
	tx  *transaction.ServerTransaction
	req *Request

	mu       sync.Mutex
	answered bool
	// handed is set once a final response has been handed to the server
	// transaction; answered is set before, to refuse a second one.
	handed   bool
	accepted bool
	// The 2xx being retransmitted, and what became of it.
	ok       *sip.Response
	key      ackKey
	ack      *sip.Request
	done     chan struct{}
	ended    bool
	interval time.Duration
	timer    transaction.Timer
	giveUp   transaction.Timer
}

// ackKey matches an ACK to the 2xx it acknowledges: the dialog (Call-ID and
// both tags) and the CSeq number, which the ACK shares with its INVITE (RFC
// 3261 §13.2.2.4).
type ackKey struct {
	callID, fromTag, toTag string
	seq                    uint32
}

func ackKeyOf(h *sip.Header) (ackKey, bool) {
	from, err1 := h.From()
	to, err2 := h.To()
	cseq, err3 := h.CSeq()
	callID, err4 := h.CallID()
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || to.Tag() == "" {
		return ackKey{}, false
	}
	return ackKey{callID: callID, fromTag: from.Tag(), toTag: to.Tag(), seq: cseq.Seq}, true
}

func newUAS(c *respContext) *UAS {
	return &UAS{c: c, tx: c.tx, done: make(chan struct{})}
}

// Request returns the request as the Router saw it.
func (u *UAS) Request() *Request { return u.req }

// Source returns where the request came from.
func (u *UAS) Source() transport.Source { return u.tx.Source() }

// Respond sends a response to the request: provisional ones, then one final
// one; a second final fails with transaction.ErrState. The proxy retransmits a
// 2xx to an INVITE until its ACK arrives or 64*T1 have passed; ACK reports
// which.
//
// A transport error ends the server transaction, and the response is lost.
// transport.ErrNoFlow means the client's flow is gone, or was closed because
// the client stopped reading; transport.ErrQueueFull means the response was
// not queued but the flow stays open, as when the transport-wide budget is
// full, so the client is still reachable for the next request.
func (u *UAS) Respond(res *sip.Response) error {
	u.mu.Lock()
	if u.answered {
		u.mu.Unlock()
		return transaction.ErrState
	}
	final := res.StatusCode >= 200
	if final {
		u.answered = true
	}
	u.mu.Unlock()
	accept := final && u.c.invite && res.StatusCode < 300
	if accept {
		// Waiting for the ACK before the 2xx leaves, so an ACK that comes
		// back at once is not taken for one to forward.
		u.retransmit(res)
	}
	err := u.tx.Respond(res)
	if final {
		// Only now is the request no longer in progress for Drain, as
		// for the proxy's own answers (respContext.handed).
		u.mu.Lock()
		u.handed = true
		u.mu.Unlock()
	}
	if err != nil {
		if accept {
			u.end()
		}
		return err
	}
	if accept {
		u.mu.Lock()
		u.accepted = true
		u.mu.Unlock()
	}
	return nil
}

// handedFinal reports whether the service's final response has been handed
// to the server transaction.
func (u *UAS) handedFinal() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.handed
}

func (u *UAS) hasAnswered() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.answered
}

// retransmit starts sending the 2xx again at T1, doubling up to T2 (RFC 6026
// §8.1), until the ACK or 64*T1.
func (u *UAS) retransmit(res *sip.Response) {
	p := u.c.p
	key, ok := ackKeyOf(&res.Header)
	if !ok {
		u.end()
		return
	}
	u.mu.Lock()
	u.ok, u.key, u.interval = res, key, p.t1
	u.giveUp = p.clock.AfterFunc(64*p.t1, func() {
		u.mu.Lock()
		missing := !u.ended
		u.mu.Unlock()
		if missing {
			p.stats.acksMissing.Add(1)
		}
		u.end()
	})
	u.mu.Unlock()
	if !p.awaitACK(key, u) {
		u.end()
		return
	}
	u.arm()
}

func (u *UAS) arm() {
	p := u.c.p
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.ended {
		return
	}
	d := u.interval
	u.timer = p.clock.AfterFunc(d, func() {
		u.mu.Lock()
		if u.ended {
			u.mu.Unlock()
			return
		}
		u.interval = min(2*u.interval, p.t2)
		res := u.ok
		u.mu.Unlock()
		p.spawn(func() {
			// A failed send is retried at the next interval; the
			// transaction reports nothing more for a 2xx (RFC 6026 §7.1).
			_ = u.tx.Respond(res)
		})
		u.arm()
	})
}

// acknowledged takes the ACK of the 2xx.
func (u *UAS) acknowledged(ack *sip.Request) {
	u.mu.Lock()
	if u.ack == nil {
		u.ack = ack
	}
	u.mu.Unlock()
	u.end()
}

// end stops the retransmissions and wakes ACK.
func (u *UAS) end() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.ended {
		return
	}
	u.ended = true
	for _, t := range []transaction.Timer{u.timer, u.giveUp} {
		if t != nil {
			t.Stop()
		}
	}
	u.c.p.forgetACK(u.key, u)
	close(u.done)
}

// ACK waits for the ACK of the 2xx this UAS sent to an INVITE, and returns it,
// or ErrNoACK when 64*T1 passed without one.
func (u *UAS) ACK(ctx context.Context) (*sip.Request, error) {
	u.mu.Lock()
	accepted := u.accepted
	u.mu.Unlock()
	if !accepted {
		return nil, ErrNotAccepted
	}
	select {
	case <-u.done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.ack == nil {
		return nil, ErrNoACK
	}
	return u.ack, nil
}

// serve runs Decision.Serve and answers for the service if it returns without
// a final response: 487 if the request was cancelled meanwhile (§9.2), 500
// otherwise.
func (c *respContext) serve(in *Request) {
	u := c.uas
	u.req = in
	// A panic is answered as a return without an answer.
	c.p.hook("Serve", func() { c.dec.Serve(c.reqCtx, u) })
	if !u.hasAnswered() {
		c.mu.Lock()
		code := 500
		if c.cancelled {
			code = 487
		}
		c.mu.Unlock()
		if res, err := c.p.response(c.tx.Request(), code); err == nil {
			if err := u.Respond(res); err != nil {
				c.p.stats.upstreamErrors.Add(1)
			}
		}
	}
	c.finish()
}

// awaitACK registers u as waiting for the ACK with key. It fails if another 2xx
// of the same dialog and CSeq waits already, which a UAS does not send.
func (p *Proxy) awaitACK(key ackKey, u *UAS) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	if _, dup := p.awaiting[key]; dup {
		return false
	}
	p.awaiting[key] = u
	return true
}

func (p *Proxy) forgetACK(key ackKey, u *UAS) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.awaiting[key] == u {
		delete(p.awaiting, key)
	}
}

// takeACK returns the UAS waiting for ack, if any.
func (p *Proxy) takeACK(ack *sip.Request) *UAS {
	key, ok := ackKeyOf(&ack.Header)
	if !ok {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.awaiting[key]
}
