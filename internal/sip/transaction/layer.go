package transaction

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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

// Defaults and bounds for the server transaction caps.
const (
	// DefaultMaxServerTransactions bounds how many requests a layer holds.
	DefaultMaxServerTransactions = 20000
	// MaxMaxServerTransactions is the largest count Validate accepts.
	MaxMaxServerTransactions = 1000000
	// DefaultMaxServerTransactionBytes bounds how much those requests take. A
	// server transaction holds its request, body included, until it ends,
	// which over UDP is 32 s after its final response (Timer J) and after a
	// failure response to an INVITE up to 32 s more (Timer H); the transport
	// lets a request carry a 1 MiB body by default, so the count alone would
	// allow 20 GiB. 256 MiB fits a 1–2 GiB task beside everything else.
	DefaultMaxServerTransactionBytes = 256 << 20
	// DefaultClientShare is the share of both caps requests from client-facing
	// listeners may use, so core traffic still gets in while clients press.
	DefaultClientShare = 0.8
	// DefaultRetryAfter is what the 503 for a request beyond the caps asks the
	// client to wait (RFC 3261 §21.5.4, §20.33); MaxRetryAfter is the longest
	// Validate accepts.
	DefaultRetryAfter = 5 * time.Second
	MaxRetryAfter     = time.Hour
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

	// MaxServerTransactions and MaxServerTransactionBytes bound the live
	// server transactions, by count and by the size of the requests they hold.
	// A request that would take either past its bound is answered with 503
	// Service Unavailable and a Retry-After, statelessly (RFC 3261 §8.2.7),
	// and never reaches the TU: every transaction holds its request until it
	// ends, so without a bound a flood of requests is a flood of memory. A
	// CANCEL for a live INVITE transaction is exempt, since refusing it would
	// leave that INVITE running; there is at most one per INVITE, so the live
	// transactions are at most twice the count. Any other CANCEL counts like
	// any request. ACK never starts a transaction.
	//
	// Zero takes DefaultMaxServerTransactions and
	// DefaultMaxServerTransactionBytes; Validate accepts a count of 0 or 1 to
	// MaxMaxServerTransactions and a non-negative byte bound.
	MaxServerTransactions     int
	MaxServerTransactionBytes int64
	// ClientShare is the share of both bounds that requests from client-facing
	// listeners (transport.Source.ClientFacing) may use; requests from core
	// listeners may use all of them, so a flood of clients cannot turn away
	// the core's terminating requests. Zero takes DefaultClientShare; Validate
	// accepts 0 to 1.
	ClientShare float64
	// RetryAfter is the Retry-After of the 503, in whole seconds rounded up;
	// zero takes DefaultRetryAfter, and Validate accepts up to MaxRetryAfter.
	RetryAfter time.Duration
	// IDs is the randomness of the layer: the key of the 503's To tags, drawn
	// once in New, and the To tag of a response the layer makes up otherwise.
	// The zero value draws from crypto/rand.
	IDs sip.IDGenerator
}

// Validate reports a configuration New refuses, so a service can check its
// settings before it builds anything.
func (c Config) Validate() error {
	switch {
	case c.MaxServerTransactions < 0 || c.MaxServerTransactions > MaxMaxServerTransactions:
		return fmt.Errorf("transaction: MaxServerTransactions %d is not 0 (the default) or 1..%d", c.MaxServerTransactions, MaxMaxServerTransactions)
	case c.MaxServerTransactionBytes < 0:
		return errors.New("transaction: negative MaxServerTransactionBytes")
	case c.ClientShare < 0 || c.ClientShare > 1:
		return fmt.Errorf("transaction: ClientShare %v is outside 0..1", c.ClientShare)
	case c.RetryAfter < 0 || c.RetryAfter > MaxRetryAfter:
		return fmt.Errorf("transaction: RetryAfter %v is outside 0..%v", c.RetryAfter, MaxRetryAfter)
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
	absorbed    atomic.Uint64
	// maxBytes bounds the request bytes of the server transactions; the
	// client limits are ClientShare of the bounds. tagKey keys the 503's To
	// tags.
	maxBytes                   int64
	clientServers, clientBytes int64
	tagKey                     []byte

	mu      sync.Mutex
	clients map[string]*ClientTransaction
	servers map[string]*ServerTransaction
	// serverBytes is the request size the server transactions hold.
	serverBytes int64
	closed      bool
}

// New returns a Layer that sends through s and passes requests and failures to tu.
// It fails if cfg does not pass Validate or the layer's key cannot be drawn.
func New(s Sender, tu TU, cfg Config) (*Layer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.MaxServerTransactions == 0 {
		cfg.MaxServerTransactions = DefaultMaxServerTransactions
	}
	if cfg.MaxServerTransactionBytes == 0 {
		cfg.MaxServerTransactionBytes = DefaultMaxServerTransactionBytes
	}
	if cfg.ClientShare == 0 {
		cfg.ClientShare = DefaultClientShare
	}
	if cfg.RetryAfter == 0 {
		cfg.RetryAfter = DefaultRetryAfter
	}
	src := cfg.IDs.Rand
	if src == nil {
		src = rand.Reader
	}
	key := make([]byte, sha256.Size)
	if _, err := io.ReadFull(src, key); err != nil {
		return nil, fmt.Errorf("transaction: drawing the layer key: %w", err)
	}
	l := &Layer{
		maxServers:    cfg.MaxServerTransactions,
		maxBytes:      cfg.MaxServerTransactionBytes,
		clientServers: int64(float64(cfg.MaxServerTransactions) * cfg.ClientShare),
		clientBytes:   int64(float64(cfg.MaxServerTransactionBytes) * cfg.ClientShare),
		tagKey:        key,
		retryAfter:    strconv.FormatInt(int64((cfg.RetryAfter+time.Second-1)/time.Second), 10),
		ids:           cfg.IDs,
		sender:        s,
		tu:            tu,
		clock:         cfg.Clock,
		t1:            cfg.T1,
		t2:            cfg.T2,
		t4:            cfg.T4,
		delayTrying:   cfg.DelayTrying,
		clients:       make(map[string]*ClientTransaction),
		servers:       make(map[string]*ServerTransaction),
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
	return l, nil
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
		size := requestSize(req)
		if !l.roomFor(size, in.Source) && !l.cancelsLiveInvite(req) {
			l.mu.Unlock()
			l.refuse(req, in.Source)
			return
		}
		tx = newServerTransaction(l, key, req, in.Source)
		tx.size = size
		l.servers[key] = tx
		l.serverBytes += size
		l.mu.Unlock()
		if tx.start() {
			l.tu.Request(tx)
		}
		return
	}
	l.mu.Unlock()
	if tx == nil && req.Method == "ACK" && l.acksRefusal(req) {
		// The ACK for a 503 this layer sent statelessly: RFC 3261 §8.2.7 has a
		// stateless UAS ignore it, and to the TU it would look like the ACK
		// for a 2xx.
		l.absorbed.Add(1)
		return
	}
	if tx != nil && wantTag != "" && tx.responseToTag() != wantTag {
		tx = nil
	}
	if tx == nil || !tx.receive(req, in.Source) {
		l.tu.Stray(in)
	}
}

// roomFor reports whether a new server transaction holding size bytes of
// request fits the caps, the client share of them for a request from a
// client-facing listener. l.mu must be held.
func (l *Layer) roomFor(size int64, src transport.Source) bool {
	maxCount, maxBytes := int64(l.maxServers), l.maxBytes
	if src.ClientFacing {
		maxCount, maxBytes = l.clientServers, l.clientBytes
	}
	return int64(len(l.servers)) < maxCount && l.serverBytes+size <= maxBytes
}

// cancelsLiveInvite reports whether req is a CANCEL for a live INVITE server
// transaction (RFC 3261 §9.2). l.mu must be held.
func (l *Layer) cancelsLiveInvite(req *sip.Request) bool {
	if req.Method != "CANCEL" {
		return false
	}
	key, err := serverKey(req, "INVITE", true)
	return err == nil && l.servers[key] != nil
}

// requestSize is about what a server transaction holds for req: its header
// fields, Request-URI and body.
func requestSize(req *sip.Request) int64 {
	n := int64(len(req.Method) + len(req.URI.String()) + len(req.Body) + 16)
	for _, f := range req.Header.Fields() {
		n += int64(len(f.Name) + len(f.Value) + 4)
	}
	return n
}

// refusalTag is the To tag of the 503 for req: a function of the transaction
// req would have started, so a retransmission gets the same tag (RFC 3261
// §8.2.7) and the ACK for it can be recognised without keeping any state. The
// key ignores the To tag, which the ACK carries and the request did not.
func (l *Layer) refusalTag(req *sip.Request) (string, error) {
	key, err := serverKey(req, "", false)
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, l.tagKey)
	m.Write([]byte(key))
	return hex.EncodeToString(m.Sum(nil)[:8]), nil
}

// acksRefusal reports whether an ACK that matches no transaction acknowledges a
// 503 this layer sent. A re-INVITE that was refused already had a To tag, which
// its ACK carries instead, so its ACK is not recognised and goes to the TU.
func (l *Layer) acksRefusal(ack *sip.Request) bool {
	to, err := ack.Header.To()
	if err != nil || to.Tag() == "" {
		return false
	}
	tag, err := l.refusalTag(ack)
	return err == nil && hmac.Equal([]byte(tag), []byte(to.Tag()))
}

// refuse answers a request beyond the caps with 503 and Retry-After, without a
// transaction (RFC 3261 §21.5.4, §8.2.7). A retransmission of it is refused
// again the same way, with the same To tag, which costs no memory. It runs on
// the reading goroutine, so it sends without waiting.
func (l *Layer) refuse(req *sip.Request, src transport.Source) {
	l.rejected.Add(1)
	tag, err := l.refusalTag(req)
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
	ClientTransactions     int   // live
	ServerTransactions     int   // live, against MaxServerTransactions
	ServerTransactionBytes int64 // request bytes they hold, against MaxServerTransactionBytes
	// ServerTransactionsRejected counts requests refused at the caps,
	// retransmissions of a refused request included, and including the rare
	// refusal whose 503 could not be built and was not sent.
	ServerTransactionsRejected uint64
	// RefusalAcksAbsorbed counts ACKs for those 503s, which go no further.
	RefusalAcksAbsorbed uint64
}

// Stats returns the current gauges and counters.
func (l *Layer) Stats() Stats {
	l.mu.Lock()
	c, s, b := len(l.clients), len(l.servers), l.serverBytes
	l.mu.Unlock()
	return Stats{ClientTransactions: c, ServerTransactions: s, ServerTransactionBytes: b,
		ServerTransactionsRejected: l.rejected.Load(), RefusalAcksAbsorbed: l.absorbed.Load()}
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
		if tx := l.servers[key]; tx != nil {
			l.serverBytes -= tx.size
		}
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
