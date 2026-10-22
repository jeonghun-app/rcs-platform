package msrp

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/panics"
)

// Defaults for Config.
const (
	// DefaultTransactionTimeout is the §7.1.1 wait for a response to a
	// request sent with Failure-Report yes.
	DefaultTransactionTimeout = 30 * time.Second
	// DefaultKeepAliveInterval is how long a session may stay quiet before
	// a bodiless SEND goes out (ADR 0003). The NLB's TLS listeners close a
	// connection idle for 350 s, a limit that cannot be raised, so this
	// stays well inside it; Config.KeepAliveInterval changes it.
	DefaultKeepAliveInterval = 240 * time.Second
	// DefaultUnboundTimeout is how long a connection may carry no session.
	// The active side sends its first SEND immediately (§5.4), so a
	// connection that names no session by then is not going to.
	DefaultUnboundTimeout = 30 * time.Second
	// DefaultWriteTimeout bounds one write, so a peer that stops reading
	// cannot hold the connection, and every session on it, forever.
	DefaultWriteTimeout = 30 * time.Second
	// DefaultReassemblyTimeout is how long an incomplete message is kept
	// without a new chunk. A sender has no reason to pause between chunks
	// for longer than a transaction may take, so this is generous.
	DefaultReassemblyTimeout = 60 * time.Second
	// DefaultMaxInFlight bounds the requests one connection waits for
	// answers to. It is sized for a relay's client connection, where
	// everything in the kernel's send and receive buffers (a few MiB, in
	// 2 KiB pieces) is in flight at once.
	DefaultMaxInFlight = 8192
	// DefaultMaxHandlerQueue bounds the events waiting for one session's
	// Handler. It absorbs bursts; what bounds memory is the session's
	// Budget, which waiting messages are charged to.
	DefaultMaxHandlerQueue = 256
	// DefaultSendWindow is how many chunks of one session Send may have
	// awaiting their 200 at once.
	DefaultSendWindow = 64
	// DefaultMaxFailedBinds: see Config.MaxFailedBinds.
	DefaultMaxFailedBinds = 3
	// DefaultMaxReassemblyLifetime gives a 1 MiB message room to arrive at
	// about 4 KiB/s.
	DefaultMaxReassemblyLifetime = 5 * time.Minute
	// DefaultProbeTimeout is how long a probe (Config.ProbeOnTimeout)
	// waits for its answer. The next hop answers a bodiless SEND itself,
	// so it needs far less than a transaction may take.
	DefaultProbeTimeout = 10 * time.Second
)

// unboundQueueBytes bounds the answers queued on a passive connection
// before its first session is bound, when all it can have sent is
// requests for sessions it does not know or malformed ones.
const unboundQueueBytes = 64 << 10

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
	// bodiless SEND; a session Open binds counts it from the answer to its
	// binding SEND. Negative disables keep-alives. A session has one
	// keep-alive out at a time, so an interval shorter than
	// TransactionTimeout makes keep-alives more frequent, never
	// overlapping; TransactionTimeout is how long an unanswered one takes
	// to close the connection, whatever the interval.
	KeepAliveInterval time.Duration
	UnboundTimeout    time.Duration
	// WriteTimeout is how long one message may take to write. A peer that
	// takes no octets for that long is not reading, and the connection is
	// closed; a slow peer that keeps reading is not.
	WriteTimeout time.Duration

	MaxHeaderBytes int
	// MaxMessageSize bounds a received message and therefore a received
	// chunk, since §7.1.1 makes a receiver accept chunks of any size up to
	// the largest message it takes.
	MaxMessageSize int64
	// MaxPendingMessages bounds incomplete messages per session.
	MaxPendingMessages int
	// MaxSessionBuffer bounds the octets of incomplete messages one
	// session holds. Zero means eight times MaxMessageSize, room for a few
	// messages arriving interleaved.
	MaxSessionBuffer int64
	// MaxConnBuffer bounds the octets the sessions on one connection hold
	// beyond their SessionReserve, together: incomplete messages, the chunk
	// being read, and complete messages waiting for their Handler. Zero
	// means 64 times MaxMessageSize.
	MaxConnBuffer int64
	// SessionReserve is the part of what a session holds that is its own
	// rather than drawn from MaxConnBuffer, so that other sessions filling
	// the shared part never leave it without room for one message of the
	// largest size (a chunk being read and the complete message after it).
	// Memory therefore grows with the number of sessions, which signalling
	// creates, not with anything a peer sends. Zero means twice
	// MaxMessageSize plus 64 KiB.
	SessionReserve int64
	// ReassemblyTimeout is how long an incomplete message waits for its
	// next chunk before it is dropped.
	ReassemblyTimeout time.Duration
	// MaxReassemblyLifetime is how long after its first chunk an incomplete
	// message is dropped, however its chunks keep coming. Zero means
	// DefaultMaxReassemblyLifetime.
	MaxReassemblyLifetime time.Duration
	// MaxQueuedBytes bounds what waits in a connection's write queue
	// without anyone waiting for it: answers, REPORTs, and what a relay
	// forwards toward a client. It is a memory bound, not the test of a
	// peer that has stopped reading (WriteTimeout is), so it is large: a
	// peer that falls this far behind while still reading is closed with
	// ErrPeerNotReading too. Zero means 16 MiB or four times
	// MaxMessageSize, whichever is more.
	MaxQueuedBytes int64
	// MaxRelayBacklog bounds what a relay has queued toward the client of
	// one bridged session (see Bridge). With a sender that windows its
	// chunks, as Send does, the backlog stays within one window; the bound
	// is for one that does not (Failure-Report no or partial), and a client
	// that falls this far behind is disconnected rather than making the
	// shared connection toward rcs-as wait. Zero means twice
	// MaxMessageSize.
	MaxRelayBacklog int64
	// SendWindow is how many chunks of one session Send may have awaiting
	// their answer at once (Failure-Report yes). It is per session, so a
	// peer that answers one session slowly, as a relay does for a slow
	// client, slows that session and not the connection. Zero means
	// DefaultSendWindow.
	SendWindow int
	// MaxHandlerQueue bounds the events (messages, reports, extension
	// requests) waiting for one session's Handler. Beyond it messages are
	// refused with 413 and reports are dropped. Zero means
	// DefaultMaxHandlerQueue.
	MaxHandlerQueue int
	// MaxFailedBinds is how many requests for unknown sessions a passive
	// connection may make in a minute, plus one for each session bound on
	// it; one more and it is closed (ErrTooManyUnknownSessions). Each costs
	// a Binder lookup. Before any bind the allowance is MaxFailedBinds
	// alone, since a peer that knows no session has nothing to do here;
	// later it grows with the sessions, which a peer may well address just
	// after they ended. Zero means DefaultMaxFailedBinds.
	MaxFailedBinds int
	// OnEvent, if set, hears about every refusal, drop and connection end
	// (see Event), for metrics. It runs on the connection's goroutines and
	// must not block.
	OnEvent func(Event)
	// Panics recovers a panic in what the connection runs for the service
	// (#445): a Handler's calls, which end as the handler's error would
	// (HandleMessage and HandleRequest answer 403, a report is dropped),
	// OnEvent and the Binder, and the reading of the peer's input, which
	// ends that connection only (EventClosed with ErrPanicked). A service
	// shares one Guard among its connections, so that its log limit holds
	// for all of them. Nil recovers, and only that.
	Panics *panics.Guard
	// MaxInFlight bounds the requests awaiting an answer on one
	// connection. A sender that reaches it waits, which slows whoever feeds
	// it (a relay stops reading its other side); every wait ends within
	// TransactionTimeout, because unanswered requests expire then.
	MaxInFlight int
	// ChunkSize is the largest chunk sent. It is at most 2048: §7.1.1
	// allows larger chunks only from a sender ready to interrupt them, and
	// this package writes every chunk whole. Cutting at 2048 is the other
	// strategy §7.1.1 allows. Zero means DefaultChunkSize.
	ChunkSize int

	// ProbeOnTimeout makes a request that times out on this connection
	// send a probe at once: a bodiless SEND on one of its sessions, which
	// the next hop answers itself without forwarding it (a relay, Bridge)
	// or as the endpoint it is. A probe unanswered within ProbeTimeout
	// fails the connection with ErrPathStalled, as an unanswered keep-alive
	// does, so that a connection whose path has stopped carrying anything
	// ends within about TransactionTimeout plus ProbeTimeout rather than at
	// a quiet session's keep-alive, and Pool dials a new one. Any answer
	// keeps it: the request that timed out was slow at the far end, which
	// a relay's per-session flow control makes it for a slow client. One
	// probe is in flight per connection at a time. It is for the
	// connection msrp-relay and rcs-as share (#517), and is off by
	// default.
	ProbeOnTimeout bool
	// ProbeTimeout is how long a probe waits; DefaultProbeTimeout if zero.
	ProbeTimeout time.Duration

	// refusalFlush is refusalFlushTimeout unless a test sets it.
	refusalFlush time.Duration
	// refusalAfter starts the flush's bound; time.After unless a test
	// sets it, to end the bound when it says rather than in real time.
	refusalAfter func(time.Duration) <-chan time.Time
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
	if cfg.MaxSessionBuffer <= 0 {
		cfg.MaxSessionBuffer = 8 * cfg.MaxMessageSize
	}
	if cfg.MaxConnBuffer <= 0 {
		cfg.MaxConnBuffer = 64 * cfg.MaxMessageSize
	}
	if cfg.ReassemblyTimeout <= 0 {
		cfg.ReassemblyTimeout = DefaultReassemblyTimeout
	}
	if cfg.MaxReassemblyLifetime <= 0 {
		cfg.MaxReassemblyLifetime = DefaultMaxReassemblyLifetime
	}
	if cfg.SessionReserve <= 0 {
		// The chunk's read buffer may run one octet past MaxMessageSize;
		// the slack keeps a whole message of that size within the reserve.
		cfg.SessionReserve = 2*cfg.MaxMessageSize + 64<<10
	}
	if cfg.MaxQueuedBytes <= 0 {
		cfg.MaxQueuedBytes = max(4*cfg.MaxMessageSize, 16<<20)
	}
	if cfg.MaxRelayBacklog <= 0 {
		cfg.MaxRelayBacklog = 2 * cfg.MaxMessageSize
	}
	if cfg.MaxHandlerQueue <= 0 {
		cfg.MaxHandlerQueue = DefaultMaxHandlerQueue
	}
	if cfg.SendWindow <= 0 {
		cfg.SendWindow = DefaultSendWindow
	}
	if cfg.MaxFailedBinds <= 0 {
		cfg.MaxFailedBinds = DefaultMaxFailedBinds
	}
	if cfg.refusalFlush <= 0 {
		cfg.refusalFlush = refusalFlushTimeout
	}
	if cfg.MaxInFlight <= 0 {
		cfg.MaxInFlight = DefaultMaxInFlight
	}
	if cfg.ChunkSize == 0 {
		cfg.ChunkSize = DefaultChunkSize
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = DefaultProbeTimeout
	}
	if cfg.ChunkSize < 1 || cfg.ChunkSize > maxPlainChunk {
		return cfg, fmt.Errorf("msrp: chunk size %d outside 1..%d", cfg.ChunkSize, maxPlainChunk)
	}
	return cfg, nil
}

// Errors of the connection layer.
var (
	ErrPeerNotReading = errors.New("msrp: peer is not reading")
	// ErrPathStalled ends a connection whose probe went unanswered
	// (Config.ProbeOnTimeout): nothing sent on it reaches the peer.
	ErrPathStalled      = errors.New("msrp: path to the peer stalled: a probe went unanswered")
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
	// writing is set while writeLoop writes a frame it took off queue;
	// written, when set, is closed once neither is left (flush).
	writing bool
	written chan struct{}

	// slots holds one token per request awaiting an answer.
	slots  chan struct{}
	budget *Budget

	// everBound is set once a session has been bound; failedBinds counts
	// refused lookups before that.
	everBound   atomic.Bool
	failedBinds int
	failWindow  time.Time

	// probing is set while a probe is in flight (Config.ProbeOnTimeout).
	probing atomic.Bool

	mu         sync.Mutex
	sessions   map[string]*Session
	pending    map[string]*transaction
	unboundGen uint64
	closed     bool
	err        error
	// closing is the reason a flush before closing gave (flush): the
	// connection ends with it whatever else fails meanwhile.
	closing error
	done    chan struct{}
}

// outFrame is one whole message waiting to be written. done is nil for an
// answer nobody waits for.
type outFrame struct {
	b    []byte
	done chan error
	// owner, when set, is the bridged session whose relay backlog the
	// frame counts toward until written.
	owner *Session
	// written, when set, hears how the write went; a frame dropped because
	// the connection failed hears ErrConnClosed.
	written func(error)
}

type transaction struct {
	mode     ReportMode
	onResult func(code int, comment string)
	timer    Timer
	slot     bool // holds one of c.slots
	// probe marks a probe, whose own timeout sends no probe.
	probe bool
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
		slots:    make(chan struct{}, cfg.MaxInFlight),
		budget:   &Budget{Limit: cfg.MaxConnBuffer},
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
	select {
	case <-s.remoteSet:
	default:
		return errors.New("msrp: an active session needs the remote path")
	}
	if err := s.attach(c); err != nil {
		return err
	}
	type result struct {
		code    int
		comment string
	}
	res := make(chan result, 1)
	err := s.sendEmpty(ctx, c, func(code int, comment string) { res <- result{code, comment} })
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
		// Armed now, the first keep-alive is a whole interval after the
		// answer.
		s.armKeepAlive(c, c.cfg.KeepAliveInterval)
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
	if c.closing != nil {
		err = c.closing
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
	c.qmu.Lock()
	dropped := c.queue
	c.queue = nil
	c.qmu.Unlock()
	var lost []*transaction
	for _, t := range pending {
		if t.timer != nil {
			t.timer.Stop()
		}
		if t.mode == ReportYes {
			lost = append(lost, t)
		}
	}
	cause := err
	if !errors.Is(err, ErrConnClosed) {
		cause = fmt.Errorf("%w: %w", ErrConnClosed, err)
	}
	for _, s := range sessions {
		s.closeWith(cause)
	}
	// The event comes first, so that whoever sees Done has heard it.
	c.emit(Event{Kind: EventClosed, Err: err})
	close(c.done)
	// Requests that can no longer be answered end as a local timeout would
	// (§10.4), so that a relay can still tell the original sender. The
	// callbacks may write to other connections, so they run apart from
	// whichever goroutine noticed the failure.
	go func() {
		for _, f := range dropped {
			if f.written != nil {
				f.written(ErrConnClosed)
			}
		}
		for _, t := range lost {
			t.onResult(StatusRequestTimeout, StatusText(StatusRequestTimeout))
		}
	}()
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
	c.everBound.Store(true)
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
	if !c.cfg.Panics.Run("read", c.read) {
		c.fail(ErrPanicked)
	}
}

// read reads and handles what the peer sends until the connection fails.
func (c *Conn) read() {
	for {
		m, err := c.r.ReadHeader()
		if err != nil {
			var me *MessageError
			if !errors.As(err, &me) {
				var cut truncated
				if c.passive && (errors.Is(err, io.EOF) || errors.As(err, &cut)) {
					c.writeQueuedForPeer(err)
				}
				c.fail(err)
				return
			}
			if !me.Message.IsRequest() {
				c.emit(Event{Kind: EventDropped, Err: ErrMalformedResponse})
			}
			err = c.respond(me.Message, me.Code)
		} else if m.IsRequest() {
			err = c.handleRequest(m)
		} else {
			c.handleResponse(m)
		}
		if err != nil {
			if errors.Is(err, ErrTooManyUnknownSessions) {
				c.flush(err)
			}
			c.fail(err)
			return
		}
	}
}

// refusalFlushTimeout bounds how long a connection closed for too many
// unknown sessions, or by the peer's half-close, goes on to deliver what it
// already owes. It is real time, like the write deadline.
const refusalFlushTimeout = 2 * time.Second

// flush lets the answers already queued reach the peer before the
// connection ends for reason (#219): it waits until they are written,
// then half-closes and reads what the peer still sends, so that closing
// does not reset the connection and discard them on the peer's side
// (RFC 1122 §4.2.2.13), until the peer closes too. Both waits together
// take at most refusalFlushTimeout. Only readLoop calls it, and nothing else
// reads the connection.
func (c *Conn) flush(reason error) {
	c.mu.Lock()
	c.closing = reason
	c.mu.Unlock()
	// One bound for both waits.
	deadline := c.flushDeadline()
	if !c.writeQueued(deadline) {
		return
	}
	cw, ok := c.nc.(interface{ CloseWrite() error })
	if !ok || cw.CloseWrite() != nil {
		return
	}
	read := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, c.nc)
		close(read)
	}()
	select {
	case <-read:
	case <-deadline:
	}
}

// writeQueuedForPeer lets a peer that has stopped sending, between
// messages or inside one (reason), read what it is owed for the requests
// it completed before the connection ends (#240), for up to the refusal
// flush's bound. reason is the end whatever fails meanwhile, as in flush:
// a peer that closed altogether resets the writes, and the end is still
// its close. Only passive connections wait: an active one, which a Pool
// shares, would take new sessions while it waits, and its peer, the side
// that half-closed in a refusal flush, discards what it reads.
func (c *Conn) writeQueuedForPeer(reason error) {
	c.mu.Lock()
	c.closing = reason
	c.mu.Unlock()
	c.writeQueued(c.flushDeadline())
}

// flushDeadline starts the bound of a flush: refusalFlush, in real time
// unless a test has set refusalAfter.
func (c *Conn) flushDeadline() <-chan time.Time {
	after := c.cfg.refusalAfter
	if after == nil {
		after = time.After
	}
	return after(c.cfg.refusalFlush)
}

// writeQueued waits until everything queued has been written, and reports
// whether it was before the connection ended or deadline came. writeLoop
// goes on writing meanwhile: a peer that has half-closed still reads.
func (c *Conn) writeQueued(deadline <-chan time.Time) bool {
	c.qmu.Lock()
	var written chan struct{}
	if len(c.queue) > 0 || c.writing {
		written = make(chan struct{})
		c.written = written
	}
	c.qmu.Unlock()
	if written == nil {
		return true
	}
	select {
	case <-written:
		return true
	case <-c.done:
	case <-deadline:
	}
	return false
}

func (c *Conn) handleResponse(m *Message) {
	c.mu.Lock()
	t := c.pending[m.TransactionID]
	if t != nil {
		delete(c.pending, m.TransactionID)
		if t.timer != nil {
			t.timer.Stop()
		}
		c.releaseSlotOf(t)
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
		return c.refuseBind(m, StatusNoSession)
	}
	s, code := c.sessionFor(m.ToPath[0])
	if code != 0 {
		return c.refuseBind(m, code)
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

// refuseBind answers a request no session on this connection takes, and
// closes a passive connection that names unknown sessions more often than
// MaxFailedBinds allows.
func (c *Conn) refuseBind(req *Message, code int) error {
	if c.passive {
		c.mu.Lock()
		if now := c.cfg.Clock.Now(); now.Sub(c.failWindow) >= time.Minute {
			c.failWindow, c.failedBinds = now, 0
		}
		c.failedBinds++
		tooMany := c.failedBinds > c.cfg.MaxFailedBinds+len(c.sessions)
		c.mu.Unlock()
		if tooMany {
			c.emit(Event{Kind: EventRefused, Method: req.Method, Code: code})
			return ErrTooManyUnknownSessions
		}
	}
	return c.respond(req, code)
}

// respond answers req with code if Failure-Report allows it.
func (c *Conn) respond(req *Message, code int) error {
	if code != StatusOK && req.IsRequest() {
		c.emit(Event{Kind: EventRefused, Method: req.Method, Code: code})
	}
	if !ShouldRespond(req, code) {
		return nil
	}
	resp, err := NewResponse(req, code, StatusText(code))
	if err != nil {
		// Nothing to address an answer to; the request is dropped.
		return nil
	}
	return c.sendMessage(context.Background(), resp, sendQueue)
}

// sendMode says whether a request may make its caller wait.
type sendMode struct {
	// queue, when set, means never wait: the request joins the bounded
	// queue of answers, and a connection that cannot take it is closed as
	// not reading (ErrPeerNotReading). It is for requests produced on a
	// reading goroutine that must not stall, such as a REPORT about what
	// was just read, or a relay forwarding from a shared connection.
	// Otherwise the caller waits for an in-flight slot and for the write,
	// so it goes no faster than the peer reads.
	queue bool
	// owner, for a queued request, is the bridged session whose backlog
	// it counts toward (MaxRelayBacklog).
	owner *Session
	// written, for a queued request, is called once it has been written
	// or dropped.
	written func(error)
	// timeout, when set, replaces TransactionTimeout for this request;
	// probe marks it as a probe (Config.ProbeOnTimeout).
	timeout time.Duration
	probe   bool
	// windowed means the request already holds a place in its session's
	// SendWindow, which bounds it. It then takes no connection slot:
	// otherwise sessions that a slow peer holds at a full window would use
	// up the connection's slots and stall every other session.
	windowed bool
}

var (
	sendWait  = sendMode{}
	sendQueue = sendMode{queue: true}
)

// sendRequest assigns a transaction id to m and sends it in the given
// mode. Unless m is a REPORT (never answered, §7.1.2) or says
// Failure-Report no, the response is awaited in the background: onResult
// gets every response for "yes" and a 408 when TransactionTimeout passes
// after the write (§7.1.1, §10.4); for "partial" it gets only failure
// responses and no timer runs, though the request is still forgotten
// after TransactionTimeout. Every awaited request holds one of MaxInFlight
// slots until then.
func (c *Conn) sendRequest(ctx context.Context, m *Message, mode sendMode, onResult func(code int, comment string)) error {
	tid, err := c.newTransactionID(m.Body.Bytes())
	if err != nil {
		return err
	}
	m.TransactionID = tid
	b, err := m.Marshal()
	if err != nil {
		return err
	}
	fr := m.FailureMode()
	track := m.Method != MethodReport && fr != ReportNo && onResult != nil
	t := &transaction{mode: fr, onResult: onResult, probe: mode.probe}
	if o := mode.owner; o != nil && o.backlog.Load()+int64(len(b)) > c.cfg.MaxRelayBacklog {
		c.fail(ErrPeerNotReading)
		return ErrPeerNotReading
	}
	if track && !mode.windowed {
		t.slot = true
		if mode.queue {
			select {
			case c.slots <- struct{}{}:
			default:
				c.fail(ErrPeerNotReading)
				return ErrPeerNotReading
			}
		} else {
			select {
			case c.slots <- struct{}{}:
			case <-c.done:
				return ErrConnClosed
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if track {
		c.mu.Lock()
		if c.closed {
			c.releaseSlotOf(t)
			c.mu.Unlock()
			return ErrConnClosed
		}
		c.pending[tid] = t
		c.mu.Unlock()
	}
	if mode.queue {
		err = c.enqueue(outFrame{b: b, owner: mode.owner, written: mode.written})
	} else {
		err = c.write(ctx, b)
	}
	if err != nil {
		if track {
			c.mu.Lock()
			if c.pending[tid] == t {
				delete(c.pending, tid)
				c.releaseSlotOf(t)
			}
			c.mu.Unlock()
		}
		return err
	}
	if track {
		// For a queued request the timer starts when it is queued, so time
		// in the queue counts against it: stricter than the §7.1.1 start at
		// the write, never looser.
		c.mu.Lock()
		if c.pending[tid] == t {
			timeout := c.cfg.TransactionTimeout
			if mode.timeout > 0 {
				timeout = mode.timeout
			}
			t.timer = c.cfg.Clock.AfterFunc(timeout, func() { c.expire(tid, t) })
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
	c.releaseSlotOf(t)
	c.mu.Unlock()
	if t.mode == ReportYes {
		t.onResult(StatusRequestTimeout, StatusText(StatusRequestTimeout))
	}
	if c.cfg.ProbeOnTimeout && !t.probe {
		c.probe()
	}
}

// probe sends a bodiless SEND on one of c's sessions, unless one is in
// flight already, and fails c with ErrPathStalled if it is not answered
// within ProbeTimeout (Config.ProbeOnTimeout).
func (c *Conn) probe() {
	if !c.probing.CompareAndSwap(false, true) {
		return
	}
	s := c.probeSession()
	if s == nil {
		// Nothing to address it to; the next timeout tries again.
		c.probing.Store(false)
		return
	}
	err := s.sendProbe(c, func(code int, _ string) {
		c.probing.Store(false)
		if code == StatusRequestTimeout {
			c.fail(ErrPathStalled)
		}
	})
	if err != nil {
		// A connection that failed meanwhile, or a write that did, which
		// fails it on its own.
		c.probing.Store(false)
	}
}

// probeSession is a session of c whose peer's path is known, nil if none.
func (c *Conn) probeSession() *Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	for _, s := range c.sessions {
		select {
		case <-s.remoteSet:
			return s
		default:
		}
	}
	return nil
}

// releaseSlotOf returns the token of a request that is no longer awaited,
// if it took one. Callers hold c.mu and have just removed the request from
// c.pending (or never added it), which keeps tokens and requests one to
// one.
func (c *Conn) releaseSlotOf(t *transaction) {
	if !t.slot {
		return
	}
	t.slot = false
	select {
	case <-c.slots:
	default:
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

// sendMessage sends a message that already has its transaction id, such
// as a response, in the given mode.
func (c *Conn) sendMessage(ctx context.Context, m *Message, mode sendMode) error {
	b, err := m.Marshal()
	if err != nil {
		return err
	}
	if mode.queue {
		return c.enqueue(outFrame{b: b, owner: mode.owner})
	}
	return c.write(ctx, b)
}

// write queues b and waits until it has been written, so a sender of
// content goes no faster than the peer reads. If ctx ends first, write
// returns at once: a message still in the queue is taken out, and one
// already being written is left to the writer, which finishes it or fails
// the connection within WriteTimeout.
func (c *Conn) write(ctx context.Context, b []byte) error {
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
	case <-ctx.Done():
		select {
		case err := <-f.done:
			return err
		default:
		}
		if c.unqueue(f) {
			return ctx.Err()
		}
		return startedError{ctx.Err()}
	}
}

// startedError is the context error of a write that had already begun and
// may still complete.
type startedError struct{ err error }

func (e startedError) Error() string { return e.err.Error() }
func (e startedError) Unwrap() error { return e.err }

func (c *Conn) unqueue(f outFrame) bool {
	c.qmu.Lock()
	defer c.qmu.Unlock()
	for i, q := range c.queue {
		if q.done == f.done {
			c.queue = append(c.queue[:i], c.queue[i+1:]...)
			return true
		}
	}
	return false
}

func (c *Conn) enqueue(f outFrame) error {
	if c.isClosed() {
		return ErrConnClosed
	}
	limit := c.cfg.MaxQueuedBytes
	if c.passive && !c.everBound.Load() {
		limit = min(limit, unboundQueueBytes)
	}
	c.qmu.Lock()
	if f.done == nil {
		if int64(c.posted+len(f.b)) > limit {
			c.qmu.Unlock()
			c.fail(ErrPeerNotReading)
			return ErrPeerNotReading
		}
		c.posted += len(f.b)
	}
	if f.owner != nil {
		f.owner.backlog.Add(int64(len(f.b)))
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
			c.writing = true
			c.qmu.Unlock()

			_ = c.nc.SetWriteDeadline(time.Now().Add(c.cfg.WriteTimeout))
			_, err := c.nc.Write(f.b)
			if f.owner != nil {
				f.owner.backlog.Add(-int64(len(f.b)))
			}
			if f.written != nil {
				f.written(err)
			}
			if err != nil {
				// Fail first, so that whoever waited for this write sees
				// the connection and its sessions already closed.
				c.fail(err)
				err = fmt.Errorf("%w: %w", ErrConnClosed, err)
			}
			if f.done != nil {
				f.done <- err
			}
			c.qmu.Lock()
			c.writing = false
			if len(c.queue) == 0 && c.written != nil {
				close(c.written)
				c.written = nil
			}
			c.qmu.Unlock()
			if err != nil {
				return
			}
		}
	}
}
