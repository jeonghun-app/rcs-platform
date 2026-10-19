package msrp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// event is one call to a session's Handler. ready, when set, holds the call
// back until the transaction it belongs to has been answered, so that a
// REPORT never overtakes the 200 for the chunk that completed the message.
// octets are charged to the connection's Budget while the event waits.
type event struct {
	run    func()
	ready  chan struct{}
	octets int64
}

// queuedReport waits for HandleReport. own marks the outcome of a chunk
// this session sent; after, if set, runs once the handler has taken it
// (it frees the chunk's window place).
type queuedReport struct {
	r     Report
	own   bool
	after func()
}

// Handler receives what arrives on an endpoint session.
//
// Nothing runs on a connection's reading goroutine. For each session,
// HandleMessage and HandleRequest calls run one at a time, in arrival
// order, on one goroutine of the session's own, and HandleReport calls run
// one at a time, in order, on another; the two kinds may overlap. So a
// handler may take its time and may call Send on any session, including
// its own and one still waiting to be bound, without holding up other
// sessions.
//
// What a slow handler holds up is its own session. Beyond
// Config.MaxHandlerQueue waiting messages, the session's messages are
// refused with 413, and REPORTs the peer sends are dropped (EventDropped
// with ErrHandlerBusy). Reports about the session's own sends are never
// dropped: while Config.SendWindow of them wait, Send waits too. For that
// reason HandleReport must not wait for a Send on its own session to
// finish; a retry belongs on another goroutine.
type Handler interface {
	// HandleMessage gets each complete message. Returning nil confirms it
	// with a success REPORT when the sender asked for one (§7.1.3). An
	// error is reported back with a failure REPORT unless the sender said
	// Failure-Report no (§7.1.4); a *StatusError chooses the code, any
	// other error is sent as 403.
	HandleMessage(s *Session, m *Message) error
	// HandleReport gets the delivery status of messages sent with Send:
	// each REPORT from the peer, each failure response and each
	// transaction timeout, all in the form of a REPORT, which §7.3.2 says
	// to read the same way as a response.
	HandleReport(s *Session, r Report)
}

// RequestHandler is implemented by a Handler that serves request methods
// other than SEND and REPORT, such as NICKNAME (RFC 7701 §7.1). Without it
// such requests get 501 (§10.9).
type RequestHandler interface {
	HandleRequest(s *Session, m *Message) (code int)
}

// Report is the delivery status of a range of a sent message.
type Report struct {
	MessageID string
	Range     ByteRange
	Code      int
	Comment   string
}

// Outgoing is a message to Send.
type Outgoing struct {
	// MessageID is generated when empty. A message resent on a new session
	// after a failure keeps its Message-ID (§5.4).
	MessageID   string
	ContentType string
	// Header holds MIME headers such as Content-Disposition.
	Header        []Field
	Body          []byte
	SuccessReport bool
	// FailureReport unset means yes.
	FailureReport ReportMode
}

// SessionConfig describes a session negotiated in SDP.
type SessionConfig struct {
	// Local is this side's URI, the one put in a=path.
	Local URI
	// Remote is the peer's a=path, the To-Path of requests sent.
	Remote []URI
	// RemoteLater lets Remote be empty until SetRemote, for a passive
	// session offered before the answer naming the peer's path arrives:
	// the peer may connect and bind first (rcs-as offering a session
	// through msrp-relay, ADR 0004). The session receives meanwhile; Send
	// and keep-alives wait for the path.
	RemoteLater bool
	// Handler receives messages and reports. A session given to Bridge has
	// none.
	Handler Handler
	// AcceptTypes are the media types from this side's a=accept-types,
	// allowing "*" and "type/*" (§8.6). Others are refused with 415. Empty
	// accepts everything.
	AcceptTypes []string
}

// Session is one MSRP session, bound to at most one connection for its
// whole life (§5.4); when the connection fails the session fails with it,
// and a replacement needs a new SDP exchange.
type Session struct {
	local URI
	// remote is written once, before remoteSet is closed, and read only
	// after it is.
	remote    []URI
	remoteSet chan struct{}
	handler   Handler
	accept    []string

	// reasm and budget are set when the session is bound; budget has the
	// connection's as its Parent.
	reasm  *Reassembler
	budget *Budget

	mu         sync.Mutex
	conn       *Conn
	closed     bool
	err        error
	bound      chan struct{}
	done       chan struct{}
	lastActive time.Time
	keepAlive  Timer
	expiry     Timer
	peer       *Session
	edge       bool // the client side of a bridge
	// events feeds the handler's goroutine; nil for a bridged session.
	events chan event
	// reports wait for HandleReport, on a goroutine of their own. Those
	// about this session's own sends are never dropped: SendWindow bounds
	// them (Send waits while as many are undelivered), as do the
	// connection's in-flight slots. Those the peer sends are dropped
	// beyond MaxHandlerQueue. reportWake tells the goroutine about new
	// ones; reportRoom tells Send that one was delivered. rmu keeps
	// HandleReport calls one at a time even after the session closed.
	reports    []queuedReport
	ownCount   int
	reportWake chan struct{}
	reportRoom chan struct{}
	rmu        sync.Mutex
	// window holds a token per chunk Send has awaiting its answer.
	window chan struct{}
	// backlog counts octets queued toward the client of a bridged edge
	// session and not yet written (Config.MaxRelayBacklog).
	backlog  atomic.Int64
	rejected []string
	// pieces are the relay's buffers for streaming SEND bodies.
	pieces [2][]byte
	// held are forwards waiting for this edge session to be bound; while
	// flushing they are being sent and new ones queue behind them.
	held       []held
	heldOctets int64
	flushing   bool
	onClose    []func()
}

// NewSession creates an unbound session.
func NewSession(cfg SessionConfig) (*Session, error) {
	if cfg.Local.SessionID == "" || !cfg.Local.valid() {
		return nil, errors.New("msrp: a session needs a local URI with a session-id")
	}
	if len(cfg.Remote) == 0 && !cfg.RemoteLater {
		return nil, errors.New("msrp: a session needs the remote path")
	}
	for _, u := range cfg.Remote {
		if !u.valid() {
			return nil, errors.New("msrp: invalid remote URI")
		}
	}
	remoteSet := make(chan struct{})
	if len(cfg.Remote) > 0 {
		close(remoteSet)
	}
	return &Session{
		local:      cfg.Local,
		remote:     append([]URI(nil), cfg.Remote...),
		remoteSet:  remoteSet,
		handler:    cfg.Handler,
		accept:     append([]string(nil), cfg.AcceptTypes...),
		bound:      make(chan struct{}),
		done:       make(chan struct{}),
		reportWake: make(chan struct{}, 1),
		reportRoom: make(chan struct{}, 1),
	}, nil
}

// Local returns this side's URI.
func (s *Session) Local() URI { return s.local }

// Remote returns the path to the peer; nil while a RemoteLater session
// waits for it.
func (s *Session) Remote() []URI {
	select {
	case <-s.remoteSet:
		return append([]URI(nil), s.remote...)
	default:
		return nil
	}
}

// SetRemote gives a RemoteLater session the peer's path, once.
func (s *Session) SetRemote(path []URI) error {
	if len(path) == 0 {
		return errors.New("msrp: a session needs the remote path")
	}
	for _, u := range path {
		if !u.valid() {
			return errors.New("msrp: invalid remote URI")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.remoteSet:
		return errors.New("msrp: the remote path is already set")
	default:
	}
	s.remote = append([]URI(nil), path...)
	close(s.remoteSet)
	return nil
}

// waitRemote waits for SetRemote on a RemoteLater session.
func (s *Session) waitRemote(ctx context.Context) error {
	select {
	case <-s.remoteSet:
		return nil
	case <-s.done:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Done is closed when the session has ended.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err returns why the session ended, or nil while it is open.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Close ends the session. Nothing is sent: MSRP sessions end in SIP.
func (s *Session) Close() error {
	s.closeWith(ErrSessionClosed)
	return nil
}

func (s *Session) closeWith(err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.err = err
	c, ka, ex, reasm, peer, hooks := s.conn, s.keepAlive, s.expiry, s.reasm, s.peer, s.onClose
	s.mu.Unlock()

	for _, t := range []Timer{ka, ex} {
		if t != nil {
			t.Stop()
		}
	}
	if reasm != nil {
		reasm.Close()
	}
	if c != nil {
		c.removeSession(s)
	}
	// Hooks (a Registry forgetting s) run before Done closes, so whoever
	// sees Done sees them done.
	for _, h := range hooks {
		h()
	}
	close(s.done)
	s.dropHeld(StatusNoSession, false)
	if peer != nil {
		peer.closeWith(fmt.Errorf("msrp: bridged session ended: %w", err))
	}
}

// whenClosed runs f after the session closes, or reports that it already
// has.
func (s *Session) whenClosed(f func()) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrSessionClosed
	}
	s.onClose = append(s.onClose, f)
	return nil
}

func (s *Session) attach(c *Conn) error {
	s.mu.Lock()
	switch {
	case s.closed:
		s.mu.Unlock()
		return ErrNoSession
	case s.conn == c:
		s.mu.Unlock()
		return nil
	case s.conn != nil:
		s.mu.Unlock()
		return ErrSessionInUse
	}
	s.conn = c
	s.lastActive = c.cfg.Clock.Now()
	s.budget = &Budget{Reserve: c.cfg.SessionReserve, Parent: c.budget}
	s.reasm = &Reassembler{
		MaxSize:     c.cfg.MaxMessageSize,
		MaxPending:  c.cfg.MaxPendingMessages,
		MaxBuffered: c.cfg.MaxSessionBuffer,
		Budget:      s.budget,
	}
	s.window = make(chan struct{}, c.cfg.SendWindow)
	flush := len(s.held) > 0
	s.flushing = flush
	if s.handler != nil {
		s.events = make(chan event, c.cfg.MaxHandlerQueue)
		go s.work(c)
		go s.workReports(c)
	}
	close(s.bound)
	s.mu.Unlock()

	if err := c.addSession(s); err != nil {
		s.closeWith(err)
		return err
	}
	s.armKeepAlive(c, c.cfg.KeepAliveInterval)
	if flush {
		s.flushHeld(c)
	}
	return nil
}

func (s *Session) touch(c *Conn) {
	s.mu.Lock()
	s.lastActive = c.cfg.Clock.Now()
	s.mu.Unlock()
}

// waitBound returns the connection once the session is bound to one.
func (s *Session) waitBound(ctx context.Context) (*Conn, error) {
	select {
	case <-s.bound:
	case <-s.done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, s.err
	}
	return s.conn, nil
}

// Send sends a message, cut into chunks of the connection's ChunkSize
// (§7.1.1). On the passive side it first waits for the peer to bind the
// session (§5.4).
//
// Send returns once every chunk is written; it does not wait for
// responses, except that at most Config.SendWindow chunks of the session
// may await theirs at once. Delivery status arrives through
// Handler.HandleReport. If the
// peer refuses a chunk while later ones are still to go, Send stops,
// since §10.5 forbids sending more of a refused message, and returns the
// refusal as a *StatusError. If ctx ends part-way, Send ends the message
// with an empty chunk flagged "#" so the peer can drop what it holds
// (§7.1).
func (s *Session) Send(ctx context.Context, out Outgoing) (string, error) {
	if out.ContentType == "" {
		return "", errors.New("msrp: a message needs a Content-Type")
	}
	c, err := s.waitBound(ctx)
	if err != nil {
		return "", err
	}
	if err := s.waitRemote(ctx); err != nil {
		return "", err
	}
	id := out.MessageID
	if id == "" {
		if id, err = NewMessageID(c.cfg.Rand); err != nil {
			return "", err
		}
	}
	chunks, err := Split(out.Body, c.cfg.ChunkSize)
	if err != nil {
		return id, err
	}
	sr := ReportUnset
	if out.SuccessReport {
		sr = ReportYes
	}

	var mu sync.Mutex
	var refused *StatusError
	for i, ch := range chunks {
		mu.Lock()
		stop := refused
		mu.Unlock()
		if stop != nil {
			return id, stop
		}
		if err := ctx.Err(); err != nil {
			if i > 0 {
				s.abandon(c, id, out, sr, ch.Range)
			}
			return id, err
		}
		r := ch.Range
		// A handler slow to take reports about this session's sends slows
		// this session's sending, rather than reports being lost.
		for s.undeliveredReports() >= c.cfg.SendWindow {
			select {
			case <-s.reportRoom:
			case <-s.done:
				return id, s.Err()
			case <-ctx.Done():
				if i > 0 {
					s.abandon(c, id, out, sr, r)
				}
				return id, ctx.Err()
			}
		}
		// Only chunks that will be answered take a place in the window:
		// with Failure-Report partial or no, no 200 would free it.
		windowed := out.FailureReport == ReportUnset || out.FailureReport == ReportYes
		if windowed {
			select {
			case s.window <- struct{}{}:
			case <-s.done:
				return id, s.Err()
			case <-ctx.Done():
				if i > 0 {
					s.abandon(c, id, out, sr, r)
				}
				return id, ctx.Err()
			}
		}
		var once sync.Once
		free := func() {
			if windowed {
				once.Do(func() { <-s.window })
			}
		}
		err := c.sendRequest(ctx, s.chunk(id, out, sr, r, ch.Data, ch.Flag), sendMode{windowed: windowed}, func(code int, comment string) {
			if code == StatusOK {
				free()
				return
			}
			mu.Lock()
			if refused == nil {
				refused = &StatusError{Code: code, Comment: comment}
			}
			mu.Unlock()
			// The window place is kept until the handler has the report.
			s.reportOwn(Report{MessageID: id, Range: r, Code: code, Comment: comment}, free)
		})
		if err != nil {
			free()
			var started startedError
			switch {
			case ctx.Err() == nil:
			case errors.As(err, &started) && ch.Flag != FlagEnd:
				// The chunk may still go out whole; end the message after it.
				s.abandon(c, id, out, sr, ByteRange{Start: r.End + 1, Total: r.Total})
			case !errors.As(err, &started) && i > 0:
				s.abandon(c, id, out, sr, r)
			}
			return id, err
		}
		s.touch(c)
	}
	return id, nil
}

// abandon ends a message that Send gives up on with an empty chunk flagged
// "#" at the first position not known to have been sent (§7.1). It is
// queued, since the caller's context has already ended.
func (s *Session) abandon(c *Conn, id string, out Outgoing, sr ReportMode, next ByteRange) {
	abort := ByteRange{Start: next.Start, End: next.Start - 1, Total: next.Total}
	_ = c.sendRequest(context.Background(), s.chunk(id, out, sr, abort, nil, FlagAbort), sendQueue, nil)
}

func (s *Session) chunk(id string, out Outgoing, sr ReportMode, r ByteRange, data []byte, flag byte) *Message {
	if data == nil {
		data = []byte{}
	}
	return &Message{
		Method:        MethodSend,
		ToPath:        s.remote,
		FromPath:      []URI{s.local},
		MessageID:     id,
		ByteRange:     &r,
		SuccessReport: sr,
		FailureReport: out.FailureReport,
		ContentType:   out.ContentType,
		Header:        out.Header,
		Body:          data,
		Continuation:  flag,
	}
}

// sendEmpty sends a bodiless SEND, the form §5.4 uses to bind a connection
// and §7.1 suggests for keeping NAT bindings alive.
func (s *Session) sendEmpty(ctx context.Context, c *Conn, onResult func(code int, comment string)) error {
	id, err := NewMessageID(c.cfg.Rand)
	if err != nil {
		return err
	}
	s.touch(c)
	return c.sendRequest(ctx, &Message{
		Method:    MethodSend,
		ToPath:    s.remote,
		FromPath:  []URI{s.local},
		MessageID: id,
		ByteRange: &ByteRange{Start: 1, End: 0, Total: 0},
	}, sendWait, onResult)
}

func (s *Session) armKeepAlive(c *Conn, after time.Duration) {
	if c.cfg.KeepAliveInterval < 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.keepAlive = c.cfg.Clock.AfterFunc(after, func() { s.keepAliveDue(c) })
}

// keepAliveDue sends a bodiless SEND if the session has been quiet for a
// whole interval (ADR 0003). An unanswered one means the path is dead, so
// the connection is closed; a refusal such as 481 ends just this session.
func (s *Session) keepAliveDue(c *Conn) {
	interval := c.cfg.KeepAliveInterval
	s.mu.Lock()
	closed := s.closed
	idle := c.cfg.Clock.Now().Sub(s.lastActive)
	s.mu.Unlock()
	if closed {
		return
	}
	select {
	case <-s.remoteSet:
	default:
		// Nothing can be addressed to the peer before its path is known.
		s.armKeepAlive(c, interval)
		return
	}
	if idle < interval {
		s.armKeepAlive(c, interval-idle)
		return
	}
	err := s.sendEmpty(context.Background(), c, func(code int, comment string) {
		switch code {
		case StatusOK:
		case StatusRequestTimeout:
			c.fail(ErrKeepAliveTimeout)
		default:
			s.closeWith(&StatusError{Code: code, Comment: comment})
		}
	})
	if err != nil {
		return
	}
	s.armKeepAlive(c, interval)
}

// armExpiry makes sure a timer will drop incomplete messages that stop
// getting chunks (Config.ReassemblyTimeout).
func (s *Session) armExpiry(c *Conn) {
	due, ok := s.reasm.NextExpiry(c.cfg.ReassemblyTimeout, c.cfg.MaxReassemblyLifetime)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.expiry != nil {
		return
	}
	s.expiry = c.cfg.Clock.AfterFunc(due.Sub(c.cfg.Clock.Now()), func() {
		now := c.cfg.Clock.Now()
		for range s.reasm.Expire(now.Add(-c.cfg.ReassemblyTimeout), now.Add(-c.cfg.MaxReassemblyLifetime)) {
			c.emit(Event{Kind: EventDropped, Method: MethodSend, Err: ErrReassemblyTimeout})
		}
		s.mu.Lock()
		s.expiry = nil
		s.mu.Unlock()
		s.armExpiry(c)
	})
}

// post hands e to the handler's goroutine, or reports that there is no
// room. Posting and closing share s.mu, so nothing is posted once the
// goroutine has begun to drain on close.
func (s *Session) post(e event) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.events == nil {
		return false
	}
	select {
	case s.events <- e:
		return true
	default:
		return false
	}
}

func (s *Session) work(c *Conn) {
	for {
		select {
		case e := <-s.events:
			if e.ready != nil {
				select {
				case <-e.ready:
				case <-s.done:
					// Closed meanwhile: nothing more reaches the handler.
					s.budget.release(e.octets)
					continue
				}
			}
			e.run()
			s.budget.release(e.octets)
		case <-s.done:
			for {
				select {
				case e := <-s.events:
					s.budget.release(e.octets)
				default:
					return
				}
			}
		}
	}
}

// workReports delivers reports in order, apart from messages so that a
// HandleMessage that sends on its own session cannot hold up the reports
// that sending waits for. On close it delivers what is left about this
// session's own sends.
func (s *Session) workReports(c *Conn) {
	for {
		select {
		case <-s.reportWake:
			s.deliverReports(false)
		case <-s.done:
			s.deliverReports(true)
			return
		}
	}
}

func (s *Session) undeliveredReports() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ownCount
}

// reportOwn hands the handler the outcome of a chunk this session sent.
// After the session has closed, its report goroutine may be gone, so the
// report is delivered on a goroutine of its own.
func (s *Session) reportOwn(r Report, after func()) {
	if s.handler == nil {
		if after != nil {
			after()
		}
		return
	}
	q := queuedReport{r: r, own: true, after: after}
	s.mu.Lock()
	if !s.closed && s.events != nil {
		s.reports = append(s.reports, q)
		s.ownCount++
		s.mu.Unlock()
		s.wakeReports()
		return
	}
	s.mu.Unlock()
	go s.hand(q)
}

func (s *Session) wakeReports() {
	select {
	case s.reportWake <- struct{}{}:
	default:
	}
}

func (s *Session) deliverReports(onlyOwn bool) {
	for {
		s.mu.Lock()
		if len(s.reports) == 0 {
			s.mu.Unlock()
			return
		}
		next := s.reports[0]
		s.reports = s.reports[1:]
		if next.own {
			s.ownCount--
		}
		s.mu.Unlock()
		if !onlyOwn || next.own {
			s.hand(next)
		}
	}
}

func (s *Session) hand(q queuedReport) {
	s.rmu.Lock()
	s.handler.HandleReport(s, q.r)
	s.rmu.Unlock()
	if q.after != nil {
		q.after()
	}
	select {
	case s.reportRoom <- struct{}{}:
	default:
	}
}

// report hands the handler a REPORT the peer sent. Those come at the
// peer's pace, so beyond MaxHandlerQueue waiting reports they are dropped
// and counted (EventDropped with ErrHandlerBusy).
func (s *Session) report(r Report) {
	if s.handler == nil {
		return
	}
	s.mu.Lock()
	c, closed := s.conn, s.closed
	room := c != nil && !closed && len(s.reports)-s.ownCount < c.cfg.MaxHandlerQueue
	if room {
		s.reports = append(s.reports, queuedReport{r: r})
	}
	s.mu.Unlock()
	switch {
	case room:
		s.wakeReports()
	case c != nil && !closed:
		c.emit(Event{Kind: EventDropped, Method: MethodReport, Err: ErrHandlerBusy})
	}
}

// serve handles one request addressed to s, read up to its headers.
func (s *Session) serve(c *Conn, m *Message) error {
	s.touch(c)
	s.mu.Lock()
	peer := s.peer
	s.mu.Unlock()
	if peer != nil && m.Method == MethodSend && m.HasBody() {
		return s.relaySend(c, peer, m)
	}

	limit, budget := c.cfg.MaxMessageSize, s.budget
	if m.Method != MethodSend {
		limit, budget = maxNonSendBody, nil
	}
	charged, err := c.r.readBodyCharged(limit, budget)
	defer budget.release(charged)
	if err != nil {
		if !errors.Is(err, ErrBodyTooLarge) {
			return err
		}
		if m.Method != MethodSend {
			return c.respond(m, StatusBadRequest)
		}
		s.reasm.Drop(m.MessageID)
		return c.respond(m, StatusMessageTooLarge)
	}
	if err := checkBody(m, int64(len(m.Body))); err != nil {
		return c.respond(m, StatusBadRequest)
	}

	switch {
	case peer != nil:
		return s.relayBuffered(c, peer, m)
	case m.Method == MethodSend:
		return s.receiveSend(c, m)
	case m.Method == MethodReport:
		s.receiveReport(m)
		return nil
	}
	rh, ok := s.handler.(RequestHandler)
	if !ok {
		return c.respond(m, StatusNotImplemented)
	}
	if !s.post(event{run: func() {
		code := rh.HandleRequest(s, m)
		if code != StatusOK {
			c.emit(Event{Kind: EventRefused, Method: m.Method, Code: code})
		}
		if !ShouldRespond(m, code) {
			return
		}
		if resp, err := NewResponse(m, code, StatusText(code)); err == nil {
			_ = c.sendMessage(context.Background(), resp, sendWait)
		}
	}}) {
		c.emit(Event{Kind: EventDropped, Method: m.Method, Err: ErrHandlerBusy})
		return c.respond(m, StatusMessageTooLarge)
	}
	return nil
}

func (s *Session) receiveSend(c *Conn, m *Message) error {
	if !m.HasBody() {
		// A bodiless SEND binds the connection or keeps it alive; it
		// carries nothing to deliver (§5.4, §7.1).
		return c.respond(m, StatusOK)
	}
	if s.handler == nil {
		return c.respond(m, StatusForbidden)
	}
	if !s.accepts(m.MediaType()) {
		s.reasm.Drop(m.MessageID)
		return c.respond(m, StatusUnsupportedMediaType)
	}
	whole, err := s.reasm.Add(m, c.cfg.Clock.Now())
	if err != nil {
		return c.respond(m, codeOf(err, StatusBadRequest))
	}
	s.armExpiry(c)
	if whole == nil {
		return c.respond(m, StatusOK)
	}
	// The complete message waits for the handler charged to the session's
	// Budget, like octets held for reassembly.
	octets := int64(len(whole.Body))
	if !s.budget.take(octets) {
		return c.respond(m, StatusMessageTooLarge)
	}
	ready := make(chan struct{})
	if !s.post(event{octets: octets, ready: ready, run: func() { s.deliver(c, whole) }}) {
		s.budget.release(octets)
		c.emit(Event{Kind: EventDropped, Method: MethodSend, Err: ErrHandlerBusy})
		return c.respond(m, StatusMessageTooLarge)
	}
	err = c.respond(m, StatusOK)
	close(ready)
	return err
}

// deliver runs on the handler's goroutine. Its REPORT is queued rather
// than waited for: waiting would hold the handler behind whatever content
// this side is sending, and the session's messages would be refused for
// it. The answer queue bounds REPORTs a peer asks for and never reads.
func (s *Session) deliver(c *Conn, whole *Message) {
	code := StatusOK
	if err := s.handler.HandleMessage(s, whole); err != nil {
		code = codeOf(err, StatusForbidden)
	}
	if ShouldReport(whole, code) {
		_ = c.sendRequest(context.Background(), NewReport(whole, s.local, *whole.ByteRange, code), sendQueue, nil)
	}
}

func (s *Session) receiveReport(m *Message) {
	// Only namespace 000 has a defined meaning (§7.3.2).
	if m.Status.Namespace != 0 {
		return
	}
	s.report(Report{MessageID: m.MessageID, Range: m.Range(), Code: m.Status.Code, Comment: m.Status.Comment})
}

func (s *Session) accepts(mediaType string) bool {
	if len(s.accept) == 0 {
		return true
	}
	for _, a := range s.accept {
		// §8.6: an entry with parameters also matches the bare type.
		a, _, _ = strings.Cut(a, ";")
		a = strings.ToLower(strings.TrimSpace(a))
		switch {
		case a == "*", a == mediaType:
			return true
		case strings.HasSuffix(a, "/*") && strings.HasPrefix(mediaType, a[:len(a)-1]):
			return true
		}
	}
	return false
}
