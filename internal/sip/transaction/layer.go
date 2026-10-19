package transaction

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// Default timer values (RFC 3261 §17.1.1.1, table 4 of Appendix A).
const (
	DefaultT1 = 500 * time.Millisecond
	DefaultT2 = 4 * time.Second
	DefaultT4 = 5 * time.Second
)

// tryingDelay is how long a server INVITE transaction waits for the TU's own
// provisional response before sending 100 Trying itself (RFC 3261 §17.2.1).
const tryingDelay = 200 * time.Millisecond

// Defaults and bounds for the server transaction cap.
const (
	// DefaultMaxServerTransactions bounds the requests a layer holds. A server
	// transaction keeps its request until it ends, 32 s after its final
	// response over UDP (Timer J), so at a few KiB per request 20000 of them
	// is tens of MiB, comfortably inside a 1–2 GiB task.
	DefaultMaxServerTransactions = 20000
	// MaxMaxServerTransactions is the largest cap Validate accepts.
	MaxMaxServerTransactions = 1000000
	// DefaultRetryAfter is what the 503 for a request beyond the cap asks the
	// client to wait (RFC 3261 §21.5.4, §20.33).
	DefaultRetryAfter = 5 * time.Second
)

// minTimerD is the lower bound RFC 3261 §17.1.1.2 sets for Timer D over an
// unreliable transport.
const minTimerD = 32 * time.Second

// Errors reported to the TU.
var (
	// ErrTimeout means Timer B or F fired before a final response arrived, or
	// Timer H fired before the ACK for a non-2xx final response did.
	ErrTimeout = errors.New("transaction: timed out")
	// ErrState means a response was passed to a server transaction in a state
	// that does not send it, such as a second final response.
	ErrState = errors.New("transaction: not allowed in this state")
	// ErrDuplicate means a client transaction with the same branch and method
	// already exists.
	ErrDuplicate = errors.New("transaction: duplicate branch")
	// ErrClosed means the layer has been closed.
	ErrClosed = errors.New("transaction: layer closed")
	// ErrTerminated is passed to a client transaction's handler when the TU
	// ends the transaction with Terminate.
	ErrTerminated = errors.New("transaction: terminated by the TU")
)

// Sender sends messages; *transport.Transport implements it.
//
// The layer passes transport.NoWait for what it sends on behalf of a message it
// is receiving, on the goroutine that read it: the 100 Trying, the ACK for a
// failure response and the answer to a retransmission. Waiting there for room in
// a connection's send queue could deadlock with a peer that is waiting for us to
// read. What the TU originates waits, so a burst is paced by the peer.
type Sender interface {
	// SendRequest sends a request and reports the transport it used, which
	// decides whether the client transaction retransmits.
	SendRequest(req *sip.Request, dst transport.Destination, opts ...transport.SendOption) (transport.Network, error)
	// SendResponse sends a response to the request that came from src.
	SendResponse(res *sip.Response, src transport.Source, opts ...transport.SendOption) error
}

// TU is the transaction user. Its methods are called without any lock held, from
// the goroutine that delivered the message or from a timer; they must not block.
//
// While a method runs, nothing else is read from the connection the message came
// on, or from the UDP socket every UDP client shares. Layer.Request and
// ServerTransaction.Respond wait for room in a full send queue, for up to the
// transport's WriteTimeout, and for a new connection, up to DialTimeout; so a TU
// answers a busy connection, or forwards to another flow, off this goroutine.
type TU interface {
	// Request receives a request that created a server transaction. The TU
	// answers with tx.Respond.
	Request(tx *ServerTransaction)
	// Stray receives a message that belongs to no transaction: an ACK that
	// matches no INVITE transaction (an ACK for a 2xx), an ACK that matches one
	// in the Accepted state (RFC 6026 §7.1), and a response that matches no
	// client transaction.
	Stray(in transport.Inbound)
	// ServerFailed reports a server transaction that ended without delivering
	// its final response: Timer H fired before the ACK (ErrTimeout, RFC 3261
	// §17.2.1), or the transport failed on a retransmission or on a delayed 100
	// Trying the transaction sent itself (§17.2.4). Failures of a send the TU asked for
	// are returned by Respond instead.
	ServerFailed(tx *ServerTransaction, err error)
}

// Clock schedules timers. Tests inject one they advance by hand.
type Clock interface {
	// AfterFunc calls f in its own goroutine after d.
	AfterFunc(d time.Duration, f func()) Timer
}

// Timer is a scheduled call.
type Timer interface {
	// Stop prevents the call if it has not happened yet.
	Stop() bool
}

type systemClock struct{}

func (systemClock) AfterFunc(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }

// SystemClock is the real clock.
var SystemClock Clock = systemClock{}

// Config configures a Layer. Zero values take the defaults.
type Config struct {
	// T1, T2 and T4 are the RFC 3261 §17 timer bases: the round-trip estimate,
	// the cap on non-INVITE and response retransmission intervals, and how long
	// a message may stay in the network.
	T1, T2, T4 time.Duration
	// Clock runs the timers; nil is SystemClock.
	Clock Clock
	// DelayTrying makes a server INVITE transaction send 100 Trying only if the
	// TU has sent no provisional response within 200 ms, which RFC 3261 §17.2.1
	// allows and a proxy wants, since the response it is about to forward makes
	// the 100 useless. Otherwise 100 Trying is sent at once, which suits a UAS
	// core that does not know how long it will take.
	DelayTrying bool

	// MaxServerTransactions bounds the live server transactions. A request
	// that would start one more is answered with 503 Service Unavailable and a
	// Retry-After, statelessly, and never reaches the TU: every transaction
	// holds its request until it ends, so without a bound a flood of requests
	// is a flood of memory. CANCEL is exempt, since refusing one would leave
	// the INVITE it cancels running; ACK never starts a transaction. Zero takes
	// DefaultMaxServerTransactions; Validate accepts 1 to
	// MaxMaxServerTransactions.
	MaxServerTransactions int
	// RetryAfter is the Retry-After of that 503, in whole seconds rounded up;
	// zero takes DefaultRetryAfter.
	RetryAfter time.Duration
	// IDs makes the To tag of that 503; the zero value draws from crypto/rand.
	IDs sip.IDGenerator
}

// Validate reports a configuration New would refuse. A service calls it at
// start, so a bad setting stops the service with a message instead of a panic.
func (c Config) Validate() error {
	switch {
	case c.MaxServerTransactions < 0 || c.MaxServerTransactions > MaxMaxServerTransactions:
		return fmt.Errorf("transaction: MaxServerTransactions %d is outside 1..%d", c.MaxServerTransactions, MaxMaxServerTransactions)
	case c.RetryAfter < 0:
		return errors.New("transaction: negative RetryAfter")
	case c.T1 < 0 || c.T2 < 0 || c.T4 < 0:
		return errors.New("transaction: negative timer base")
	}
	return nil
}

// Layer matches messages to transactions and runs their state machines. Its
// methods are safe for concurrent use.
type Layer struct {
	sender      Sender
	tu          TU
	clock       Clock
	t1, t2, t4  time.Duration
	delayTrying bool
	maxServers  int
	retryAfter  string
	ids         sip.IDGenerator
	rejected    atomic.Uint64

	mu      sync.Mutex
	clients map[string]*ClientTransaction
	servers map[string]*ServerTransaction
	closed  bool
}

// New returns a Layer that sends through s and passes requests and failures to tu.
// It panics if cfg does not pass Validate, which a caller with configuration
// from outside should call first.
func New(s Sender, tu TU, cfg Config) *Layer {
	if err := cfg.Validate(); err != nil {
		panic(err)
	}
	if cfg.MaxServerTransactions == 0 {
		cfg.MaxServerTransactions = DefaultMaxServerTransactions
	}
	if cfg.RetryAfter == 0 {
		cfg.RetryAfter = DefaultRetryAfter
	}
	l := &Layer{
		maxServers:  cfg.MaxServerTransactions,
		retryAfter:  strconv.FormatInt(int64((cfg.RetryAfter+time.Second-1)/time.Second), 10),
		ids:         cfg.IDs,
		sender:      s,
		tu:          tu,
		clock:       cfg.Clock,
		t1:          cfg.T1,
		t2:          cfg.T2,
		t4:          cfg.T4,
		delayTrying: cfg.DelayTrying,
		clients:     make(map[string]*ClientTransaction),
		servers:     make(map[string]*ServerTransaction),
	}
	if l.clock == nil {
		l.clock = SystemClock
	}
	if l.t1 <= 0 {
		l.t1 = DefaultT1
	}
	if l.t2 <= 0 {
		l.t2 = DefaultT2
	}
	if l.t4 <= 0 {
		l.t4 = DefaultT4
	}
	return l
}

// Receive takes a message from the transport; it is the transport's Handler.
func (l *Layer) Receive(in transport.Inbound) {
	switch m := in.Message.(type) {
	case *sip.Response:
		l.receiveResponse(m, in)
	case *sip.Request:
		l.receiveRequest(m, in)
	}
}

// Close terminates every transaction without notifying the TU, and makes the
// layer refuse new ones.
func (l *Layer) Close() {
	l.mu.Lock()
	l.closed = true
	var all []*machine
	for _, tx := range l.clients {
		all = append(all, &tx.machine)
	}
	for _, tx := range l.servers {
		all = append(all, &tx.machine)
	}
	l.mu.Unlock()
	for _, m := range all {
		m.mu.Lock()
		m.terminate()
		m.mu.Unlock()
	}
}

// Len returns the number of live client and server transactions.
func (l *Layer) Len() (clients, servers int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.clients), len(l.servers)
}

func (l *Layer) receiveResponse(res *sip.Response, in transport.Inbound) {
	key, ok := clientKey(&res.Header)
	var tx *ClientTransaction
	if ok {
		l.mu.Lock()
		tx = l.clients[key]
		l.mu.Unlock()
	}
	if tx == nil {
		l.tu.Stray(in)
		return
	}
	tx.receive(res)
}

func (l *Layer) receiveRequest(req *sip.Request, in transport.Inbound) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	tx, wantTag := l.matchServer(req)
	if tx == nil && req.Method != "ACK" {
		key, err := serverKey(req, "", true)
		if err != nil {
			l.mu.Unlock()
			return
		}
		if len(l.servers) >= l.maxServers && req.Method != "CANCEL" {
			l.mu.Unlock()
			l.refuse(req, in.Source)
			return
		}
		tx = newServerTransaction(l, key, req, in.Source)
		l.servers[key] = tx
		l.mu.Unlock()
		if tx.start() {
			l.tu.Request(tx)
		}
		return
	}
	l.mu.Unlock()
	if tx != nil && wantTag != "" && tx.responseToTag() != wantTag {
		tx = nil
	}
	if tx == nil || !tx.receive(req, in.Source) {
		l.tu.Stray(in)
	}
}

// refuse answers a request beyond MaxServerTransactions with 503 and
// Retry-After, without a transaction (RFC 3261 §21.5.4). A retransmission of it
// is refused again the same way, which costs no memory. It runs on the reading
// goroutine, so it sends without waiting.
func (l *Layer) refuse(req *sip.Request, src transport.Source) {
	l.rejected.Add(1)
	tag, err := l.ids.Tag()
	if err != nil {
		return
	}
	res, err := sip.NewResponse(req, 503, "", tag)
	if err != nil {
		return
	}
	if err := res.Header.Add("Retry-After", l.retryAfter); err != nil {
		return
	}
	l.sender.SendResponse(res, src, transport.NoWait)
}

// Stats is a snapshot of the layer's gauges and counters, for metrics.
type Stats struct {
	ClientTransactions int // live
	ServerTransactions int // live, against MaxServerTransactions
	// ServerTransactionsRejected counts requests answered with 503 because
	// MaxServerTransactions server transactions were live.
	ServerTransactionsRejected uint64
}

// Stats returns the current gauges and counters.
func (l *Layer) Stats() Stats {
	c, s := l.Len()
	return Stats{ClientTransactions: c, ServerTransactions: s, ServerTransactionsRejected: l.rejected.Load()}
}

// matchServer finds the server transaction a request belongs to (RFC 3261
// §17.2.3); an ACK matches the INVITE it acknowledges. For the ACK of an RFC 2543
// element it may return a candidate and the To tag the candidate's response must
// carry, which the caller checks once l.mu is released: the transaction's own
// lock is never taken under the layer's. l.mu must be held.
func (l *Layer) matchServer(req *sip.Request) (*ServerTransaction, string) {
	key, err := serverKey(req, "", true)
	if err != nil {
		return nil, ""
	}
	if tx := l.servers[key]; tx != nil {
		return tx, ""
	}
	if req.Method != "ACK" || hasMagicCookie(req) {
		return nil, ""
	}
	// The ACK for a response to an initial INVITE carries the To tag the server
	// added, which the INVITE did not have.
	to, err := req.Header.To()
	if err != nil || to.Tag() == "" {
		return nil, ""
	}
	key, err = serverKey(req, "", false)
	if err != nil {
		return nil, ""
	}
	if tx := l.servers[key]; tx != nil {
		return tx, to.Tag()
	}
	return nil, ""
}

// InviteFor returns the INVITE server transaction a CANCEL refers to (RFC 3261
// §9.2), the one the CANCEL would match were it an INVITE.
func (l *Layer) InviteFor(cancel *sip.Request) (*ServerTransaction, bool) {
	if cancel.Method != "CANCEL" {
		return nil, false
	}
	key, err := serverKey(cancel, "INVITE", true)
	if err != nil {
		return nil, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	tx := l.servers[key]
	return tx, tx != nil
}

func (l *Layer) remove(key string, server bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if server {
		delete(l.servers, key)
	} else {
		delete(l.clients, key)
	}
}

func hasMagicCookie(req *sip.Request) bool {
	vias, err := req.Header.Via()
	return err == nil && len(vias) > 0 && vias[0].HasMagicCookie()
}

// clientKey is what a response is matched on (RFC 3261 §17.1.3): the top Via
// branch and the CSeq method, which keeps a CANCEL, which shares the INVITE's
// branch, apart from the INVITE.
func clientKey(h *sip.Header) (string, bool) {
	vias, err := h.Via()
	if err != nil || len(vias) == 0 || vias[0].Branch() == "" {
		return "", false
	}
	cseq, err := h.CSeq()
	if err != nil {
		return "", false
	}
	return vias[0].Branch() + "\x00" + cseq.Method, true
}

// serverKey is what a request is matched on (RFC 3261 §17.2.3). method, when not
// empty, replaces the request's own, which InviteFor needs; an ACK is always keyed
// as the INVITE it acknowledges.
//
// With the RFC 3261 magic cookie the key is the branch, the sent-by and the
// method. Without it the request comes from an RFC 2543 element, and the key is
// the Request-URI, the From and To tags, the Call-ID, the CSeq number, the method
// and the top Via. withToTag false leaves the To tag out, which is how the ACK
// for a response to an initial INVITE, which had no To tag, is found.
func serverKey(req *sip.Request, method string, withToTag bool) (string, error) {
	if method == "" {
		method = req.Method
	}
	if method == "ACK" {
		method = "INVITE"
	}
	vias, err := req.Header.Via()
	if err != nil {
		return "", err
	}
	if len(vias) == 0 {
		return "", errors.New("transaction: request has no Via")
	}
	top := vias[0]
	if top.HasMagicCookie() {
		return strings.Join([]string{"3261", top.Branch(), strings.ToLower(top.Host), strconv.Itoa(top.Port), method}, "\x00"), nil
	}
	from, err := req.Header.From()
	if err != nil {
		return "", err
	}
	to, err := req.Header.To()
	if err != nil {
		return "", err
	}
	toTag := ""
	if withToTag {
		toTag = to.Tag()
	}
	cseq, err := req.Header.CSeq()
	if err != nil {
		return "", err
	}
	callID, err := req.Header.CallID()
	if err != nil {
		return "", err
	}
	return strings.Join([]string{"2543", req.URI.String(), from.Tag(), toTag, callID,
		strconv.FormatUint(uint64(cseq.Seq), 10), method, top.String()}, "\x00"), nil
}
