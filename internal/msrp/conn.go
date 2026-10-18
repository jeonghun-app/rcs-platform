package msrp

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Defaults for Config.
const (
	// DefaultTransactionTimeout is the §7.1.1 wait for a response to a
	// request sent with Failure-Report yes.
	DefaultTransactionTimeout = 30 * time.Second
	// DefaultKeepAliveInterval is how long a session may stay quiet before
	// a bodiless SEND goes out (ADR 0003), well inside the 1800 s NLB idle
	// timeout and inside the NAT timers RCS clients see.
	DefaultKeepAliveInterval = 300 * time.Second
	// DefaultUnboundTimeout is how long a connection may carry no session.
	// The active side sends its first SEND immediately (§5.4), so a
	// connection that names no session by then is not going to.
	DefaultUnboundTimeout = 30 * time.Second
	// DefaultWriteTimeout bounds one write, so a peer that stops reading
	// cannot hold the connection, and every session on it, forever.
	DefaultWriteTimeout = 30 * time.Second
)

// Config tunes a Conn. The zero value uses the defaults.
type Config struct {
	// Clock drives every timer. Nil means the system clock. Write deadlines
	// are the exception: the operating system enforces them in real time.
	Clock Clock
	// Rand is the source for transaction ids, Message-IDs and keep-alive
	// Message-IDs. Nil means crypto/rand.
	Rand io.Reader

	TransactionTimeout time.Duration
	// KeepAliveInterval is the idle time after which a session sends a
	// bodiless SEND. Negative disables keep-alives.
	KeepAliveInterval time.Duration
	UnboundTimeout    time.Duration
	WriteTimeout      time.Duration

	MaxHeaderBytes int
	// MaxMessageSize bounds a received message and therefore a received
	// chunk, since §7.1.1 makes a receiver accept chunks of any size up to
	// the largest message it takes.
	MaxMessageSize int64
	// MaxPendingMessages bounds incomplete messages per session.
	MaxPendingMessages int
	// ChunkSize is the largest chunk sent, at most 2048 because this
	// package never interrupts a chunk (§7.1.1). Zero means
	// DefaultChunkSize.
	ChunkSize int
}

func (cfg Config) withDefaults() (Config, error) {
	if cfg.Clock == nil {
		cfg.Clock = systemClock{}
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.TransactionTimeout <= 0 {
		cfg.TransactionTimeout = DefaultTransactionTimeout
	}
	if cfg.KeepAliveInterval == 0 {
		cfg.KeepAliveInterval = DefaultKeepAliveInterval
	}
	if cfg.UnboundTimeout <= 0 {
		cfg.UnboundTimeout = DefaultUnboundTimeout
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = DefaultWriteTimeout
	}
	if cfg.MaxHeaderBytes <= 0 {
		cfg.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	if cfg.MaxMessageSize <= 0 {
		cfg.MaxMessageSize = DefaultMaxMessageSize
	}
	if cfg.MaxPendingMessages <= 0 {
		cfg.MaxPendingMessages = DefaultMaxPending
	}
	if cfg.ChunkSize == 0 {
		cfg.ChunkSize = DefaultChunkSize
	}
	if cfg.ChunkSize < 1 || cfg.ChunkSize > maxPlainChunk {
		return cfg, fmt.Errorf("msrp: chunk size %d outside 1..%d", cfg.ChunkSize, maxPlainChunk)
	}
	return cfg, nil
}

// maxPosted bounds the answers (responses and REPORTs) waiting to be
// written on one connection. A peer that leaves this much unread is not
// reading at all, and the connection is closed rather than buffering more.
const maxPosted = 1 << 20

// Errors of the connection layer.
var (
	ErrPeerNotReading   = errors.New("msrp: peer is not reading")
	ErrConnClosed       = errors.New("msrp: connection closed")
	ErrSessionClosed    = errors.New("msrp: session closed")
	ErrNoSession        = errors.New("msrp: no such session")
	ErrSessionInUse     = errors.New("msrp: session is bound to another connection")
	ErrPassive          = errors.New("msrp: the passive side cannot open a session")
	ErrUnbound          = errors.New("msrp: connection carried no session in time")
	ErrKeepAliveTimeout = errors.New("msrp: keep-alive got no response")
)

// Binder finds the session a request on a passive connection is addressed
// to, the first time that session is seen on the connection (§5.4).
//
// Bind runs on the connection's reading goroutine and may block, for
// example on a database lookup; only that connection waits. ErrNoSession
// is answered with 481 and a *StatusError with its code; any other error
// is answered with 481. A session already bound to another connection is
// refused with 506 by the Conn itself.
type Binder interface {
	Bind(c *Conn, to URI) (*Session, error)
}

// Conn is one MSRP connection carrying any number of sessions (§5.4).
//
// The active side, which dialled, adds sessions with Open. The passive
// side, which accepted, learns them from the To-Path of incoming requests
// through its Binder, so it can never send for a session before the peer
// has. Requests are matched to sessions by To-Path; responses to
// transactions by transaction id.
//
// A Conn reads on one goroutine and writes on another from construction
// until it fails or is closed; all of its methods are safe for concurrent
// use. Answers produced while reading are queued rather than written in
// place, so the reading goroutine never waits for the peer to read: two
// sides that both did so could each stop reading while writing to the
// other.
type Conn struct {
	nc      net.Conn
	cfg     Config
	passive bool
	binder  Binder
	r       *Reader

	qmu    sync.Mutex
	queue  []outFrame
	posted int
	wake   chan struct{}

	mu         sync.Mutex
	sessions   map[string]*Session
	pending    map[string]*transaction
	unboundGen uint64
	closed     bool
	err        error
	done       chan struct{}
}

// outFrame is one whole message waiting to be written. done is nil for an
// answer nobody waits for.
type outFrame struct {
	b    []byte
	done chan error
}

type transaction struct {
	mode     ReportMode
	onResult func(code int, comment string)
	timer    Timer
}

// NewActiveConn starts serving nc, a connection this side opened.
func NewActiveConn(nc net.Conn, cfg Config) (*Conn, error) {
	return newConn(nc, false, nil, cfg)
}

// NewPassiveConn starts serving nc, a connection this side accepted;
// sessions are found through b.
func NewPassiveConn(nc net.Conn, b Binder, cfg Config) (*Conn, error) {
	if b == nil {
		return nil, errors.New("msrp: a passive connection needs a Binder")
	}
	return newConn(nc, true, b, cfg)
}

func newConn(nc net.Conn, passive bool, b Binder, cfg Config) (*Conn, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	c := &Conn{
		nc:       nc,
		cfg:      cfg,
		passive:  passive,
		binder:   b,
		r:        NewReader(nc, cfg.MaxHeaderBytes),
		sessions: map[string]*Session{},
		pending:  map[string]*transaction{},
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	c.mu.Lock()
	c.armUnboundLocked()
	c.mu.Unlock()
	go c.readLoop()
	go c.writeLoop()
	return c, nil
}

// Done is closed when the connection has failed or been closed.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err returns why the connection ended, or nil while it is open.
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Close closes the connection; every session on it fails (§5.4).
func (c *Conn) Close() error {
	c.fail(ErrConnClosed)
	return nil
}

// Open binds s to this active connection and sends the bodiless SEND that
// tells the passive side which session the connection is for (§5.4). It
// returns once the peer accepted it with 200; any other answer closes s.
func (c *Conn) Open(ctx context.Context, s *Session) error {
	if c.passive {
		return ErrPassive
	}
	if err := s.attach(c); err != nil {
		return err
	}
	type result struct {
		code    int
		comment string
	}
	res := make(chan result, 1)
	err := s.sendEmpty(c, func(code int, comment string) { res <- result{code, comment} })
	if err != nil {
		s.closeWith(err)
		return err
	}
	select {
	case r := <-res:
		if r.code != StatusOK {
			err := &StatusError{Code: r.code, Comment: r.comment}
			s.closeWith(err)
			return err
		}
		return nil
	case <-ctx.Done():
		s.closeWith(ctx.Err())
		return ctx.Err()
	case <-s.done:
		return s.Err()
	}
}

func (c *Conn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// fail ends the connection once, with the first reason given.
func (c *Conn) fail(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.err = err
	sessions := make([]*Session, 0, len(c.sessions))
	for _, s := range c.sessions {
		sessions = append(sessions, s)
	}
	pending := c.pending
	c.pending = map[string]*transaction{}
	c.mu.Unlock()

	_ = c.nc.Close()
	for _, t := range pending {
		if t.timer != nil {
			t.timer.Stop()
		}
	}
	cause := err
	if !errors.Is(err, ErrConnClosed) {
		cause = fmt.Errorf("%w: %w", ErrConnClosed, err)
	}
	for _, s := range sessions {
		s.closeWith(cause)
	}
	close(c.done)
}

func (c *Conn) addSession(s *Session) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrConnClosed
	}
	if other := c.sessions[s.local.SessionID]; other != nil && other != s {
		return ErrSessionInUse
	}
	c.sessions[s.local.SessionID] = s
	c.unboundGen++
	return nil
}

func (c *Conn) removeSession(s *Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sessions[s.local.SessionID] == s {
		delete(c.sessions, s.local.SessionID)
	}
	if len(c.sessions) == 0 && !c.closed {
		c.armUnboundLocked()
	}
}

// armUnboundLocked closes the connection if it still carries no session
// after UnboundTimeout. A generation number retires timers armed before a
// session came along, so none of them needs stopping.
func (c *Conn) armUnboundLocked() {
	c.unboundGen++
	gen := c.unboundGen
	c.cfg.Clock.AfterFunc(c.cfg.UnboundTimeout, func() {
		c.mu.Lock()
		idle := c.unboundGen == gen && len(c.sessions) == 0
		c.mu.Unlock()
		if idle {
			c.fail(ErrUnbound)
		}
	})
}

func (c *Conn) readLoop() {
	for {
		m, err := c.r.ReadHeader()
		if err != nil {
			var me *MessageError
			if !errors.As(err, &me) {
				c.fail(err)
				return
			}
			err = c.respond(me.Message, me.Code)
		} else if m.IsRequest() {
			err = c.handleRequest(m)
		} else {
			c.handleResponse(m)
		}
		if err != nil {
			c.fail(err)
			return
		}
	}
}

func (c *Conn) handleResponse(m *Message) {
	c.mu.Lock()
	t := c.pending[m.TransactionID]
	if t != nil {
		delete(c.pending, m.TransactionID)
		if t.timer != nil {
			t.timer.Stop()
		}
	}
	c.mu.Unlock()
	// A 200 to a "partial" request should not exist (§7.1.4); there is
	// nobody waiting for it either way.
	if t == nil || (t.mode == ReportPartial && m.StatusCode == StatusOK) {
		return
	}
	t.onResult(m.StatusCode, m.Comment)
}

func (c *Conn) handleRequest(m *Message) error {
	// §7.3: on arrival the To-Path holds exactly one URI, which must name a
	// session on this connection.
	if len(m.ToPath) != 1 {
		return c.respond(m, StatusNoSession)
	}
	s, code := c.sessionFor(m.ToPath[0])
	if code != 0 {
		return c.respond(m, code)
	}
	return s.serve(c, m)
}

func (c *Conn) sessionFor(to URI) (*Session, int) {
	c.mu.Lock()
	s := c.sessions[to.SessionID]
	c.mu.Unlock()
	if s != nil {
		if !s.local.Equal(to) {
			return nil, StatusNoSession
		}
		return s, 0
	}
	if !c.passive {
		return nil, StatusNoSession
	}
	s, err := c.binder.Bind(c, to)
	if err == nil && (s == nil || !s.local.Equal(to)) {
		err = ErrNoSession
	}
	if err == nil {
		err = s.attach(c)
	}
	switch {
	case err == nil:
		return s, 0
	case errors.Is(err, ErrSessionInUse):
		return nil, StatusSessionInUse
	default:
		return nil, codeOf(err, StatusNoSession)
	}
}

// respond answers req with code if Failure-Report allows it.
func (c *Conn) respond(req *Message, code int) error {
	if !ShouldRespond(req, code) {
		return nil
	}
	resp, err := NewResponse(req, code, StatusText(code))
	if err != nil {
		// Nothing to address an answer to; the request is dropped.
		return nil
	}
	return c.postMessage(resp)
}

// sendRequest assigns a transaction id to m and writes it. A REPORT is
// queued like an answer, since it is never answered (§7.1.2) and is often
// produced while reading. Any other request returns once written and,
// unless Failure-Report is no, waits for its response in the background:
// onResult gets every response for "yes" and a 408 when TransactionTimeout
// passes after the write (§7.1.1, §10.4); for "partial" it gets only
// failure responses and no timer runs, though the transaction is still
// forgotten after TransactionTimeout.
func (c *Conn) sendRequest(m *Message, onResult func(code int, comment string)) error {
	tid, err := c.newTransactionID(m.Body)
	if err != nil {
		return err
	}
	m.TransactionID = tid
	b, err := m.Marshal()
	if err != nil {
		return err
	}
	if m.Method == MethodReport {
		return c.post(b)
	}
	mode := m.FailureMode()
	track := mode != ReportNo && onResult != nil
	t := &transaction{mode: mode, onResult: onResult}
	if track {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return ErrConnClosed
		}
		c.pending[tid] = t
		c.mu.Unlock()
	}
	if err := c.write(b); err != nil {
		return err
	}
	if track {
		c.mu.Lock()
		if c.pending[tid] == t {
			t.timer = c.cfg.Clock.AfterFunc(c.cfg.TransactionTimeout, func() { c.expire(tid, t) })
		}
		c.mu.Unlock()
	}
	return nil
}

func (c *Conn) expire(tid string, t *transaction) {
	c.mu.Lock()
	if c.pending[tid] != t {
		c.mu.Unlock()
		return
	}
	delete(c.pending, tid)
	c.mu.Unlock()
	if t.mode == ReportYes {
		t.onResult(StatusRequestTimeout, StatusText(StatusRequestTimeout))
	}
}

// newTransactionID picks an id that is not in flight and does not occur
// in body, so the end-line cannot appear inside the content (§7.1).
func (c *Conn) newTransactionID(body []byte) (string, error) {
	for range 8 {
		tid, err := NewTransactionID(c.cfg.Rand)
		if err != nil {
			return "", err
		}
		c.mu.Lock()
		_, busy := c.pending[tid]
		c.mu.Unlock()
		if !busy && !bodyHasBoundary(body, tid) {
			return tid, nil
		}
	}
	return "", errors.New("msrp: no usable transaction id; the random source repeats itself")
}

// postMessage queues an answer without waiting for it to be written.
func (c *Conn) postMessage(m *Message) error {
	b, err := m.Marshal()
	if err != nil {
		return err
	}
	return c.post(b)
}

func (c *Conn) post(b []byte) error {
	if c.isClosed() {
		return ErrConnClosed
	}
	return c.enqueue(outFrame{b: b})
}

// write queues b and waits until it has been written, so a sender of
// content goes no faster than the peer reads.
func (c *Conn) write(b []byte) error {
	if c.isClosed() {
		return ErrConnClosed
	}
	f := outFrame{b: b, done: make(chan error, 1)}
	if err := c.enqueue(f); err != nil {
		return err
	}
	select {
	case err := <-f.done:
		return err
	case <-c.done:
		select {
		case err := <-f.done:
			return err
		default:
			return ErrConnClosed
		}
	}
}

func (c *Conn) enqueue(f outFrame) error {
	c.qmu.Lock()
	if f.done == nil {
		if c.posted+len(f.b) > maxPosted {
			c.qmu.Unlock()
			c.fail(ErrPeerNotReading)
			return ErrPeerNotReading
		}
		c.posted += len(f.b)
	}
	c.queue = append(c.queue, f)
	c.qmu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return nil
}

// writeLoop writes queued messages one whole message at a time, so
// messages never interleave on the wire.
func (c *Conn) writeLoop() {
	for {
		select {
		case <-c.wake:
		case <-c.done:
			return
		}
		for {
			c.qmu.Lock()
			if len(c.queue) == 0 {
				c.qmu.Unlock()
				break
			}
			f := c.queue[0]
			c.queue[0] = outFrame{}
			c.queue = c.queue[1:]
			if f.done == nil {
				c.posted -= len(f.b)
			}
			c.qmu.Unlock()

			_ = c.nc.SetWriteDeadline(time.Now().Add(c.cfg.WriteTimeout))
			_, err := c.nc.Write(f.b)
			if err != nil {
				err = fmt.Errorf("%w: %w", ErrConnClosed, err)
			}
			if f.done != nil {
				f.done <- err
			}
			if err != nil {
				c.fail(err)
				return
			}
		}
	}
}
