package transaction

import (
	"context"
	"errors"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// ServerTransaction is a server INVITE (RFC 3261 §17.2.1, RFC 6026 §7.1) or
// server non-INVITE (§17.2.2) transaction.
type ServerTransaction struct {
	machine
	invite bool
	req    *sip.Request
	src    transport.Source
	// last is the most recent response sent, which a retransmitted request is
	// answered with. It is nil after a 2xx to an INVITE, which is not
	// retransmitted from here (RFC 6026 §7.1), and after a response that did
	// not fit under the byte bound. toTag is the To tag of the last response
	// sent, kept separately so that neither needs to be.
	last  *sip.Response
	toTag string
	// size is what the request and last count against
	// MaxServerTransactionBytes, under the layer's mu.
	size int64
	// ctx ends with the transaction (see Context).
	ctx    context.Context
	cancel context.CancelCauseFunc
	// timedOut records that the layer answered 500 for a TU that did not.
	timedOut bool
}

// sameFlow reports whether a retransmission arrived the way the request did, so
// that answering it is a write on a live connection or a datagram from the same
// socket, neither of which can stall the reading goroutine. A retransmission
// that arrives another way, which a client does not do (RFC 3261 §18.1.1), is
// absorbed without an answer: answering would mean writing to the original flow,
// which may have to be redialled, from the goroutine that serves the other one.
// A UDP flow is compared by socket and address, because an expired flow comes
// back with a new FlowID.
func sameFlow(a, b transport.Source) bool {
	if a.Network != b.Network {
		return false
	}
	if a.Network == transport.UDP {
		return a.Listener == b.Listener && a.Addr == b.Addr
	}
	return a.Flow == b.Flow
}

func newServerTransaction(l *Layer, key string, req *sip.Request, src transport.Source) *ServerTransaction {
	tx := &ServerTransaction{invite: req.Method == "INVITE", req: req, src: src}
	tx.ctx, tx.cancel = context.WithCancelCause(context.Background())
	tx.machine = machine{l: l, key: key, server: true, onTimer: tx.onTimer, reliable: src.Network.Reliable(),
		onEnd: func() { tx.cancel(nil) }}
	if tx.invite {
		tx.state = Proceeding
	} else {
		tx.state = Trying
	}
	return tx
}

// start sends or schedules the 100 Trying of an INVITE (§17.2.1). It reports
// false if the 100 could not be sent, in which case the transaction has ended
// quietly: the TU never saw it, and nothing it sent could reach the client.
func (tx *ServerTransaction) start() bool {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.armFinal()
	if !tx.invite {
		return true
	}
	if tx.l.delayTrying {
		tx.arm(timerTrying, tryingDelay)
		return true
	}
	if err := tx.sendTrying(); err != nil {
		tx.terminate()
		return false
	}
	return true
}

// sendTrying sends 100 Trying. mu must be held.
func (tx *ServerTransaction) sendTrying() error {
	res, err := sip.NewResponse(tx.req, 100, "", "")
	if err != nil {
		return err
	}
	return tx.send(res, transport.NoWait)
}

// armFinal (re)starts the safety timer for the TU's final response. mu must be
// held.
func (tx *ServerTransaction) armFinal() {
	if tx.invite {
		tx.arm(timerFinal, tx.l.inviteFinal)
	} else {
		tx.arm(timerFinal, tx.l.nonInviteFinal)
	}
}

// Progress tells the transaction that its TU has started new work on the
// request, as a proxy does when it forwards to its next fork group or to a
// replacement target, so the safety timer starts again: it measures how long
// the TU has been stalled, not how long the request takes. It does nothing once
// a final response was sent.
func (tx *ServerTransaction) Progress() {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if tx.state == Trying || tx.state == Proceeding {
		tx.armFinal()
	}
}

// Context is cancelled when the transaction ends, so a TU still working on the
// request can stop. If the TU sent no final response in time and the layer
// answered 500 instead, it is cancelled at that moment and context.Cause
// reports ErrNoFinalResponse.
func (tx *ServerTransaction) Context() context.Context { return tx.ctx }

// Request returns the request that created the transaction.
func (tx *ServerTransaction) Request() *sip.Request { return tx.req }

// Source returns where the request came from, which is where responses go.
func (tx *ServerTransaction) Source() transport.Source { return tx.src }

// State returns the current state.
func (tx *ServerTransaction) State() State {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	return tx.state
}

func (tx *ServerTransaction) responseToTag() string {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	return tx.toTag
}

// send passes a response to the transport and remembers it for retransmission.
// mu must be held.
func (tx *ServerTransaction) send(res *sip.Response, opts ...transport.SendOption) error {
	if err := tx.l.sender.SendResponse(res, tx.src, opts...); err != nil {
		return err
	}
	tx.toTag = ""
	if to, err := res.Header.To(); err == nil {
		tx.toTag = to.Tag()
	}
	var before, after int64
	if tx.last != nil {
		before = responseSize(tx.last)
	}
	tx.last = res
	if tx.invite && res.StatusCode >= 200 && res.StatusCode < 300 {
		// Accepted keeps only the To tag: a large 2xx body held for Timer L
		// would be memory the byte bound does not see.
		tx.last = nil
	} else {
		after = responseSize(res)
	}
	if !tx.l.keep(tx, before, after) {
		// Sent once, not kept: a response cannot be refused, and keeping
		// every one an admitted transaction gets would let the responses
		// alone pass the bound.
		tx.last = nil
	}
	return nil
}

// failed ends the transaction after a transport failure the TU did not cause
// directly. mu must be held.
func (tx *ServerTransaction) failed(err error) func() {
	tx.terminate()
	if tx.timedOut {
		// The response that failed is the layer's 500, not the TU's.
		return nil
	}
	return func() { tx.l.tu.ServerFailed(tx, err) }
}

// Respond sends a response the TU built for this transaction's request. A 2xx to
// an INVITE moves it to Accepted, where further 2xx responses (the TU's own
// retransmissions, §13.3.1.4) are still sent; any other final response completes
// it. A response the current state does not send yields ErrState: in particular,
// a final response after the first non-2xx one is discarded (§17.2.1, §17.2.2).
//
// If the transport fails, the transaction terminates and the error is returned.
// Respond queues the response for the connection's writer, waiting for room for
// up to the transport's WriteTimeout, plus DialTimeout if the request's
// connection must be reopened (see TU).
//
// transport.ErrQueueFull means nothing was sent and the connection is still
// open; the peer's transaction times out. If a client-facing flow's own queue
// had no room within WriteTimeout, the client is not reading: the transport
// then closes the flow itself and returns transport.ErrNoFlow, so the client
// learns of the failure at once. A refusal by the transport-wide budget leaves
// the flow open. Either way this transaction has ended.
func (tx *ServerTransaction) Respond(res *sip.Response) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if res.StatusCode < 100 || res.StatusCode > 699 {
		return errors.New("transaction: status code outside 100-699")
	}
	if tx.timedOut && res.StatusCode >= 200 {
		// The layer has answered already; a second final response must not
		// reach the client.
		tx.l.lateFinals.Add(1)
		return ErrNoFinalResponse
	}
	return tx.respond(res)
}

// respond runs the state machine for a response, the TU's or the layer's own.
// mu must be held.
func (tx *ServerTransaction) respond(res *sip.Response) error {
	if tx.invite {
		return tx.respondInvite(res)
	}
	return tx.respondNonInvite(res)
}

func (tx *ServerTransaction) respondInvite(res *sip.Response) error {
	l := tx.l
	code := res.StatusCode
	switch {
	case tx.state == Proceeding:
	case tx.state == Accepted && code >= 200 && code < 300:
		return tx.sendOrTerminate(res)
	default:
		return ErrState
	}
	if err := tx.sendOrTerminate(res); err != nil {
		return err
	}
	tx.stop(timerTrying)
	switch {
	case code < 200:
		// A provisional response shows the TU is still at work, as a ringing
		// call is; the safety timer starts again.
		tx.armFinal()
	case code < 300:
		// RFC 6026 §7.1: the 2xx no longer terminates the transaction. Timer L
		// keeps absorbing INVITE retransmissions while the TU retransmits the
		// 2xx itself until its ACK arrives.
		tx.state = Accepted
		tx.stop(timerFinal)
		tx.arm(timerLinger, 64*l.t1)
	default:
		tx.stop(timerFinal)
		tx.state = Completed
		if !tx.reliable {
			tx.interval = l.t1
			tx.arm(timerRetransmit, tx.interval)
		}
		tx.arm(timerTimeout, 64*l.t1)
	}
	return nil
}

func (tx *ServerTransaction) respondNonInvite(res *sip.Response) error {
	if tx.state != Trying && tx.state != Proceeding {
		return ErrState
	}
	if err := tx.sendOrTerminate(res); err != nil {
		return err
	}
	if res.StatusCode < 200 {
		tx.state = Proceeding
		return nil
	}
	tx.stop(timerFinal)
	tx.linger(Completed, tx.unlessReliable(64*tx.l.t1))
	return nil
}

func (tx *ServerTransaction) sendOrTerminate(res *sip.Response) error {
	if err := tx.send(res); err != nil {
		tx.terminate()
		return err
	}
	return nil
}

func (tx *ServerTransaction) onTimer(id timerID) func() {
	l := tx.l
	switch id {
	case timerTrying:
		if tx.state == Proceeding && tx.last == nil {
			if err := tx.sendTrying(); err != nil {
				return tx.failed(err)
			}
		}
	case timerRetransmit:
		// Timer G (§17.2.1), unless the response was not kept.
		if tx.state != Completed || tx.last == nil {
			return nil
		}
		if err := tx.l.sender.SendResponse(tx.last, tx.src); err != nil {
			return tx.failed(err)
		}
		tx.interval = min(2*tx.interval, l.t2)
		tx.arm(timerRetransmit, tx.interval)
	case timerTimeout:
		// Timer H: the ACK never came.
		if tx.state == Completed {
			return tx.failed(ErrTimeout)
		}
	case timerLinger:
		// Timer I, J or L.
		tx.terminate()
	case timerFinal:
		tx.answerForTU()
	}
	return nil
}

// answerForTU sends the 500 for a TU that sent no final response in time, tells
// the TU through the Context, and lets the transaction end as it does after any
// final response. mu must be held.
func (tx *ServerTransaction) answerForTU() {
	if tx.state != Trying && tx.state != Proceeding {
		return
	}
	tx.timedOut = true
	tx.l.timedOut.Add(1)
	tx.cancel(ErrNoFinalResponse)
	// The To tag of a provisional the TU sent, which may have begun an early
	// dialog, keeps the 500 in it, whether or not the provisional itself was
	// kept; otherwise a new one.
	tag := tx.toTag
	if tag == "" {
		var err error
		if tag, err = tx.l.ids.Tag(); err != nil {
			tx.terminate()
			return
		}
	}
	res, err := sip.NewResponse(tx.req, 500, "", tag)
	if err != nil {
		tx.terminate()
		return
	}
	// A transport failure has terminated the transaction already.
	tx.respond(res)
}

// receive runs the state machine for a request matched to this transaction: a
// retransmission, or the ACK of an INVITE. It reports false for an ACK the TU
// must see, which the layer passes on as a stray.
func (tx *ServerTransaction) receive(req *sip.Request, from transport.Source) bool {
	tx.mu.Lock()
	var notify func()
	ok := true
	if req.Method == "ACK" {
		switch tx.state {
		case Completed:
			// The ACK for a non-2xx final response ends the retransmissions; Timer
			// I absorbs the ACK's own retransmissions (§17.2.1).
			tx.linger(Confirmed, tx.unlessReliable(tx.l.t4))
		case Accepted:
			// An ACK for the 2xx is the TU's business (RFC 6026 §7.1).
			ok = false
		}
	} else if tx.last != nil && sameFlow(from, tx.src) {
		switch tx.state {
		case Proceeding, Completed:
			// A retransmitted request is answered with the last response sent
			// (§17.2.1, §17.2.2). In Accepted the TU retransmits the 2xx, so the
			// request is absorbed (RFC 6026 §7.1).
			if err := tx.l.sender.SendResponse(tx.last, tx.src, transport.NoWait); err != nil {
				notify = tx.failed(err)
			}
		}
	}
	tx.mu.Unlock()
	if notify != nil {
		notify()
	}
	return ok
}
