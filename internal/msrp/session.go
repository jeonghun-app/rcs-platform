package msrp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Handler receives what arrives on an endpoint session. Its methods run on
// connection goroutines, possibly at the same time, and should return
// quickly: while HandleMessage runs, nothing else on that connection is
// read.
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
	local   URI
	remote  []URI
	handler Handler
	accept  []string

	// reasm is used only by the goroutine reading the bound connection.
	reasm Reassembler

	mu         sync.Mutex
	conn       *Conn
	closed     bool
	err        error
	bound      chan struct{}
	done       chan struct{}
	lastActive time.Time
	keepAlive  Timer
	peer       *Session
	rejected   []string
	onClose    []func()
}

// NewSession creates an unbound session.
func NewSession(cfg SessionConfig) (*Session, error) {
	if cfg.Local.SessionID == "" || !cfg.Local.valid() {
		return nil, errors.New("msrp: a session needs a local URI with a session-id")
	}
	if len(cfg.Remote) == 0 {
		return nil, errors.New("msrp: a session needs the remote path")
	}
	for _, u := range cfg.Remote {
		if !u.valid() {
			return nil, errors.New("msrp: invalid remote URI")
		}
	}
	return &Session{
		local:   cfg.Local,
		remote:  append([]URI(nil), cfg.Remote...),
		handler: cfg.Handler,
		accept:  append([]string(nil), cfg.AcceptTypes...),
		bound:   make(chan struct{}),
		done:    make(chan struct{}),
	}, nil
}

// Local returns this side's URI.
func (s *Session) Local() URI { return s.local }

// Remote returns the path to the peer.
func (s *Session) Remote() []URI { return append([]URI(nil), s.remote...) }

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
	c, ka, peer, hooks := s.conn, s.keepAlive, s.peer, s.onClose
	s.mu.Unlock()

	if ka != nil {
		ka.Stop()
	}
	if c != nil {
		c.removeSession(s)
	}
	close(s.done)
	for _, h := range hooks {
		h()
	}
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
	s.reasm = Reassembler{MaxSize: c.cfg.MaxMessageSize, MaxPending: c.cfg.MaxPendingMessages}
	close(s.bound)
	s.mu.Unlock()

	if err := c.addSession(s); err != nil {
		s.closeWith(err)
		return err
	}
	s.armKeepAlive(c, c.cfg.KeepAliveInterval)
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
// responses. Delivery status arrives through Handler.HandleReport. If the
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
				abort := ByteRange{Start: ch.Range.Start, End: ch.Range.Start - 1, Total: ch.Range.Total}
				_ = c.sendRequest(s.chunk(id, out, sr, abort, nil, FlagAbort), nil)
			}
			return id, err
		}
		r := ch.Range
		err := c.sendRequest(s.chunk(id, out, sr, r, ch.Data, ch.Flag), func(code int, comment string) {
			if code == StatusOK {
				return
			}
			mu.Lock()
			if refused == nil {
				refused = &StatusError{Code: code, Comment: comment}
			}
			mu.Unlock()
			s.report(Report{MessageID: id, Range: r, Code: code, Comment: comment})
		})
		if err != nil {
			return id, err
		}
		s.touch(c)
	}
	return id, nil
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
func (s *Session) sendEmpty(c *Conn, onResult func(code int, comment string)) error {
	id, err := NewMessageID(c.cfg.Rand)
	if err != nil {
		return err
	}
	s.touch(c)
	return c.sendRequest(&Message{
		Method:    MethodSend,
		ToPath:    s.remote,
		FromPath:  []URI{s.local},
		MessageID: id,
		ByteRange: &ByteRange{Start: 1, End: 0, Total: 0},
	}, onResult)
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
	if idle < interval {
		s.armKeepAlive(c, interval-idle)
		return
	}
	err := s.sendEmpty(c, func(code int, comment string) {
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

func (s *Session) report(r Report) {
	if s.handler != nil {
		s.handler.HandleReport(s, r)
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

	limit := c.cfg.MaxMessageSize
	if m.Method != MethodSend {
		limit = maxNonSendBody
	}
	if err := c.r.ReadBody(limit); err != nil {
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
	if rh, ok := s.handler.(RequestHandler); ok {
		return c.respond(m, rh.HandleRequest(s, m))
	}
	return c.respond(m, StatusNotImplemented)
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
	whole, err := s.reasm.Add(m)
	if err != nil {
		return c.respond(m, codeOf(err, StatusBadRequest))
	}
	if err := c.respond(m, StatusOK); err != nil {
		return err
	}
	if whole == nil {
		return nil
	}
	code := StatusOK
	if err := s.handler.HandleMessage(s, whole); err != nil {
		code = codeOf(err, StatusForbidden)
	}
	if !ShouldReport(whole, code) {
		return nil
	}
	return c.sendRequest(NewReport(whole, s.local, *whole.ByteRange, code), nil)
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
		a = strings.ToLower(a)
		switch {
		case a == "*", a == mediaType:
			return true
		case strings.HasSuffix(a, "/*") && strings.HasPrefix(mediaType, a[:len(a)-1]):
			return true
		}
	}
	return false
}
