package transaction

import (
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// ResponseHandler receives what a client transaction passes to the TU: each
// response the TU must see, in order, or one error after which nothing follows.
// The error is ErrTimeout when Timer B or F fires, ErrTerminated after
// Terminate, or a transport error from a retransmission.
//
// Calls for one transaction never overlap and arrive in the order the
// transaction produced them, though not always on the goroutine that produced
// them: a call made while another is running is delivered by that one when it
// returns.
type ResponseHandler func(res *sip.Response, err error)

// delivery serializes a client transaction's handler calls and drops anything
// that follows the terminal error. The state machine produces notifications
// under the transaction's lock but delivers them after releasing it, so without
// this a response produced just before Terminate could reach the TU after
// ErrTerminated. Queueing rather than holding a lock across the call also lets
// the handler call Terminate itself.
type delivery struct {
	h ResponseHandler

	mu      sync.Mutex
	queue   []event
	running bool
	ended   bool
}

type event struct {
	res *sip.Response
	err error
}

func (d *delivery) deliver(res *sip.Response, err error) {
	d.mu.Lock()
	if d.ended {
		d.mu.Unlock()
		return
	}
	d.ended = err != nil
	d.queue = append(d.queue, event{res, err})
	if d.running {
		d.mu.Unlock()
		return
	}
	d.running = true
	for len(d.queue) > 0 {
		e := d.queue[0]
		d.queue = d.queue[1:]
		d.mu.Unlock()
		d.h(e.res, e.err)
		d.mu.Lock()
	}
	d.running = false
	d.mu.Unlock()
}

// ClientTransaction is a client INVITE (RFC 3261 §17.1.1, RFC 6026 §7.2) or
// client non-INVITE (§17.1.2) transaction.
type ClientTransaction struct {
	machine
	invite bool
	req    *sip.Request
	dst    transport.Destination
	// network is the transport the first send actually used, which the ACK
	// for a non-2xx response must use too (§17.1.1.3).
	network transport.Network
	out     delivery
	// ack is the ACK for a non-2xx final response, built once and resent for
	// each retransmission of that response (§17.1.1.3).
	ack *sip.Request
}

// Request starts a client transaction for req and sends it to dst. Responses
// and the final error reach h.
//
// The TU builds the request, top Via and branch included (RFC 3261 §8.1.1.7,
// §16.6 step 8); the branch must carry the magic cookie, since responses are
// matched on it alone. An ACK is not a transaction: the TU sends the ACK for a
// 2xx straight through the transport (§13.2.2.4). If the first send fails,
// Request returns the error and h is never called.
//
// Request sends synchronously, so it can block for up to the transport's
// DialTimeout plus WriteTimeout (see TU). The layer owns req from here on; the TU
// must not change it.
func (l *Layer) Request(req *sip.Request, dst transport.Destination, h ResponseHandler) (*ClientTransaction, error) {
	if req.Method == "ACK" {
		return nil, errors.New("transaction: an ACK is not sent in a client transaction")
	}
	if h == nil {
		return nil, errors.New("transaction: nil response handler")
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if !hasMagicCookie(req) {
		return nil, errors.New("transaction: the top Via branch lacks the RFC 3261 magic cookie")
	}
	key, _ := clientKey(&req.Header)
	tx := &ClientTransaction{invite: req.Method == "INVITE", req: req, dst: dst, out: delivery{h: h}}
	tx.machine = machine{l: l, key: key, onTimer: tx.onTimer}

	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, ErrClosed
	}
	if _, dup := l.clients[key]; dup {
		l.mu.Unlock()
		return nil, ErrDuplicate
	}
	l.clients[key] = tx
	l.mu.Unlock()

	tx.mu.Lock()
	defer tx.mu.Unlock()
	network, err := l.sender.SendRequest(req, dst)
	if err != nil {
		tx.terminate()
		return nil, err
	}
	tx.network = network
	tx.reliable = network.Reliable()
	if tx.invite {
		tx.state = Calling
	} else {
		tx.state = Trying
	}
	if !tx.reliable {
		tx.interval = l.t1
		tx.arm(timerRetransmit, tx.interval)
	}
	tx.arm(timerTimeout, 64*l.t1)
	return tx, nil
}

// State returns the current state.
func (tx *ClientTransaction) State() State {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	return tx.state
}

// Request returns the request the transaction sent.
func (tx *ClientTransaction) Request() *sip.Request { return tx.req }

// Terminate ends the transaction now, and its handler receives ErrTerminated
// unless the transaction had already ended; nothing reaches the handler after
// that. Called from inside the handler, it returns before ErrTerminated is
// delivered, which happens as soon as the handler returns. RFC 3261 leaves a client INVITE
// transaction in Proceeding until a final response arrives, so the TU ends it
// itself: 64*T1 after its CANCEL went unanswered (§9.1), or when a proxy's Timer
// C fires (§16.8).
func (tx *ClientTransaction) Terminate() {
	tx.mu.Lock()
	live := tx.state != Terminated
	tx.terminate()
	tx.mu.Unlock()
	if live {
		tx.out.deliver(nil, ErrTerminated)
	}
}

// ackDestination is where the ACK for a non-2xx response goes: the same flow, or
// the same address over the transport the INVITE actually used (§17.1.1.3), which
// may be TCP for a large INVITE meant for UDP (§18.1.1).
func (tx *ClientTransaction) ackDestination() transport.Destination {
	dst := tx.dst
	if dst.Flow == "" {
		dst.Network = tx.network
	}
	return dst
}

func (tx *ClientTransaction) notify(res *sip.Response, err error) func() {
	return func() { tx.out.deliver(res, err) }
}

func (tx *ClientTransaction) onTimer(id timerID) func() {
	l := tx.l
	switch id {
	case timerRetransmit:
		// Timer A runs in Calling, Timer E in Trying and Proceeding.
		if tx.invite && tx.state != Calling || !tx.invite && tx.state != Trying && tx.state != Proceeding {
			return nil
		}
		if _, err := l.sender.SendRequest(tx.req, tx.dst); err != nil {
			tx.terminate()
			return tx.notify(nil, err)
		}
		switch {
		case tx.invite:
			// Timer A doubles without a cap (§17.1.1.2).
			tx.interval *= 2
		case tx.state == Proceeding:
			// A provisional response says the server has the request; retransmit
			// at T2 only (§17.1.2.2).
			tx.interval = l.t2
		default:
			tx.interval = min(2*tx.interval, l.t2)
		}
		tx.arm(timerRetransmit, tx.interval)
	case timerTimeout:
		// Timer B applies in Calling only; Timer F in Trying and Proceeding.
		if tx.state == Calling || (!tx.invite && (tx.state == Trying || tx.state == Proceeding)) {
			tx.terminate()
			return tx.notify(nil, ErrTimeout)
		}
	case timerLinger:
		tx.terminate()
	}
	return nil
}

// receive runs the state machine for a response matched to this transaction.
func (tx *ClientTransaction) receive(res *sip.Response) {
	tx.mu.Lock()
	var notify func()
	if tx.invite {
		notify = tx.receiveInvite(res)
	} else {
		notify = tx.receiveNonInvite(res)
	}
	tx.mu.Unlock()
	if notify != nil {
		notify()
	}
}

func (tx *ClientTransaction) receiveInvite(res *sip.Response) func() {
	l := tx.l
	code := res.StatusCode
	switch tx.state {
	case Calling, Proceeding:
		switch {
		case code < 200:
			tx.state = Proceeding
			tx.stop(timerRetransmit)
			return tx.notify(res, nil)
		case code < 300:
			// RFC 6026 §7.2: stay for Timer M so 2xx retransmissions from other
			// branches of a fork reach the TU, which ACKs each one.
			tx.stop(timerRetransmit)
			tx.stop(timerTimeout)
			tx.state = Accepted
			tx.arm(timerLinger, 64*l.t1)
			return tx.notify(res, nil)
		default:
			notify := tx.notify(res, nil)
			ack, err := buildACK(tx.req, res)
			if err == nil {
				tx.ack = ack
				_, err = l.sender.SendRequest(ack, tx.ackDestination(), transport.NoWait)
			}
			if err != nil {
				// The TU still learns the final response; the server will
				// retransmit it until Timer H and give up.
				tx.terminate()
				return notify
			}
			tx.linger(Completed, tx.unlessReliable(max(minTimerD, 64*l.t1)))
			return notify
		}
	case Accepted:
		if code >= 200 && code < 300 {
			return tx.notify(res, nil)
		}
	case Completed:
		switch {
		case code >= 300 && tx.ack != nil:
			// A retransmitted final response means the ACK was lost (§17.1.1.2).
			if _, err := l.sender.SendRequest(tx.ack, tx.ackDestination(), transport.NoWait); err != nil {
				tx.terminate()
			}
		case code >= 200 && code < 300:
			// A 2xx from another branch of a fork after a failure response:
			// the TU must ACK or BYE it, so it is passed on, not absorbed.
			return tx.notify(res, nil)
		}
	}
	return nil
}

func (tx *ClientTransaction) receiveNonInvite(res *sip.Response) func() {
	switch tx.state {
	case Trying, Proceeding:
		if res.StatusCode < 200 {
			tx.state = Proceeding
			return tx.notify(res, nil)
		}
		notify := tx.notify(res, nil)
		tx.linger(Completed, tx.unlessReliable(tx.l.t4))
		return notify
	}
	// Completed absorbs retransmitted responses (§17.1.2.2).
	return nil
}

// buildACK builds the ACK for a non-2xx final response (RFC 3261 §17.1.1.3): the
// Request-URI, Call-ID, From, CSeq number and the one top Via of the INVITE, the
// To of the response, and the INVITE's Route header fields.
func buildACK(invite *sip.Request, res *sip.Response) (*sip.Request, error) {
	vias, err := invite.Header.Elements("Via")
	if err != nil {
		return nil, err
	}
	if len(vias) == 0 {
		return nil, errors.New("transaction: INVITE has no Via")
	}
	cseq, err := invite.Header.CSeq()
	if err != nil {
		return nil, err
	}
	ack := &sip.Request{Method: "ACK", URI: invite.URI}
	h := &ack.Header
	fields := [][2]string{
		{"Via", vias[0]},
		{"Max-Forwards", "70"},
		{"From", invite.Header.Get("From")},
		{"To", res.Header.Get("To")},
		{"Call-ID", invite.Header.Get("Call-ID")},
		{"CSeq", strconv.FormatUint(uint64(cseq.Seq), 10) + " ACK"},
	}
	for _, r := range invite.Header.Values("Route") {
		fields = append(fields, [2]string{"Route", r})
	}
	for _, f := range fields {
		if err := h.Add(f[0], f[1]); err != nil {
			return nil, fmt.Errorf("transaction: building ACK: %w", err)
		}
	}
	return ack, nil
}
