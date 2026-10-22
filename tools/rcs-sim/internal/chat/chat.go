// Package chat plays both ends of an RCS chat session over MSRP: the
// client, which connects through msrp-relay as a device behind NAT does, and
// a stand-in for rcs-as, which the relay connects to (ADR 0004). Both speak
// RCS chat content as a client does: CPIM messages (RFC 3862) carrying an
// IMDN request (RFC 5438), answered with delivery and display notifications.
//
// The MSRP work (chunking, reports, keep-alive, connection binding) is
// internal/msrp's, the same code rcs-as and the relay run. Nothing here
// logs, and errors never carry a session id, which is what lets a
// connection into a session (RFC 4975 §14.1).
package chat

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/content"
	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/safeerr"
)

// queueLength bounds each channel an Endpoint delivers on; a scenario reads
// them as it goes, so this is only slack.
const queueLength = 256

// Received is a chat message an Endpoint got.
type Received struct {
	From        cpim.Address
	ContentType string
	Body        []byte
	// Request is what the sender asked to be notified of.
	Request imdn.Request
}

// Endpoint is one end of a chat session: an msrp.Handler that unwraps CPIM,
// answers IMDN requests and hands everything else to the scenario.
type Endpoint struct {
	// Self is this end's address, the CPIM From of what it sends.
	Self cpim.Address
	// AutoDisplay sends a display notification as soon as one is asked
	// for, as if the user read every message at once. Otherwise Display
	// sends it.
	AutoDisplay bool
	// Rand supplies message ids; crypto/rand when nil.
	Rand io.Reader
	// Now stamps DateTime; time.Now when nil.
	Now func() time.Time

	Messages      chan Received
	Notifications chan imdn.Notification
	Reports       chan msrp.Report

	// Dropped counts what arrived when a channel was full, and Malformed
	// what could not be read; a scenario fails on either.
	Dropped, Malformed atomic.Int64

	pending sync.WaitGroup
}

// NewEndpoint returns an Endpoint for self.
func NewEndpoint(self cpim.Address) *Endpoint {
	return &Endpoint{
		Self:          self,
		Messages:      make(chan Received, queueLength),
		Notifications: make(chan imdn.Notification, queueLength),
		Reports:       make(chan msrp.Report, queueLength),
	}
}

func (e *Endpoint) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Endpoint) random() io.Reader {
	if e.Rand != nil {
		return e.Rand
	}
	return rand.Reader
}

// HandleMessage implements msrp.Handler.
func (e *Endpoint) HandleMessage(s *msrp.Session, m *msrp.Message) error {
	if m.MediaType() != cpim.ContentType {
		// RCS chat content is always CPIM (RCC.07); anything else is a
		// fault of the peer this simulator exists to find.
		e.Malformed.Add(1)
		return &msrp.StatusError{Code: msrp.StatusUnsupportedMediaType}
	}
	c, err := cpim.Parse(m.Body.Bytes())
	if err != nil {
		e.Malformed.Add(1)
		return &msrp.StatusError{Code: msrp.StatusBadRequest}
	}
	if imdn.IsNotification(c) {
		n, err := imdn.ParseNotificationMessage(c)
		if err != nil {
			e.Malformed.Add(1)
			return nil
		}
		e.offer(func() bool {
			select {
			case e.Notifications <- n:
				return true
			default:
				return false
			}
		})
		return nil
	}
	req, err := imdn.ParseRequest(c)
	if err != nil {
		e.Malformed.Add(1)
		return nil
	}
	from, _ := c.From()
	r := Received{From: from, ContentType: c.ContentType(), Body: c.Body.Bytes(), Request: req}
	// Counted before the message is handed over, so that whoever has the
	// message and calls Wait waits for its notifications too.
	e.pending.Add(1)
	e.offer(func() bool {
		select {
		case e.Messages <- r:
			return true
		default:
			return false
		}
	})
	// The answers go out on a goroutine of their own: Send waits for its
	// window, and the handler must not hold up the session's reports.
	go func() {
		defer e.pending.Done()
		ctx, cancel := context.WithTimeout(context.Background(), msrp.DefaultTransactionTimeout)
		defer cancel()
		if req.Dispositions.Wants(imdn.DeliveryNotification, imdn.Delivered) {
			_ = e.notify(ctx, s, r, imdn.DeliveryNotification, imdn.Delivered)
		}
		if e.AutoDisplay && req.Dispositions.Wants(imdn.DisplayNotification, imdn.Displayed) {
			_ = e.notify(ctx, s, r, imdn.DisplayNotification, imdn.Displayed)
		}
	}()
	return nil
}

func (e *Endpoint) offer(send func() bool) {
	if !send() {
		e.Dropped.Add(1)
	}
}

// HandleReport implements msrp.Handler.
func (e *Endpoint) HandleReport(_ *msrp.Session, r msrp.Report) {
	select {
	case e.Reports <- r:
	default:
		e.Dropped.Add(1)
	}
}

// Wait waits for the notifications the handler is still sending.
func (e *Endpoint) Wait() { e.pending.Wait() }

// Sent names a message Send sent: its IMDN Message-ID, which notifications
// quote, and its MSRP Message-ID, which REPORTs quote.
type Sent struct {
	IMDN, MSRP string
}

// Send sends text to to on s as a CPIM message asking for the
// notifications in d (none when zero).
func (e *Endpoint) Send(ctx context.Context, s *msrp.Session, to cpim.Address, contentType string, text []byte, d imdn.Disposition) (Sent, error) {
	m := &cpim.Message{}
	var err error
	add := func(name, value string) {
		if err == nil {
			err = m.Add(cpim.CoreNamespace, name, value)
		}
	}
	add(cpim.HeaderFrom, e.Self.String())
	add(cpim.HeaderTo, to.String())
	add(cpim.HeaderDateTime, cpim.FormatDateTime(e.now()))
	if err != nil {
		return Sent{}, err
	}
	id, err := imdn.NewMessageID(e.random())
	if err != nil {
		return Sent{}, err
	}
	if d != 0 {
		if err := imdn.AddRequest(m, id, d); err != nil {
			return Sent{}, err
		}
	}
	m.ContentHeaders = []cpim.Field{{Name: "Content-Type", Value: contentType}}
	m.Body = content.BodyOf(text)
	body, err := m.Marshal()
	if err != nil {
		return Sent{}, err
	}
	msrpID, err := s.Send(ctx, msrp.Outgoing{ContentType: cpim.ContentType, Body: msrp.BodyOf(body), SuccessReport: true})
	if err != nil {
		return Sent{}, fmt.Errorf("chat: send: %w", safeerr.Reason(err))
	}
	return Sent{IMDN: id, MSRP: msrpID}, nil
}

// Display sends the display notification r asked for, as a user reading the
// message would (RFC 5438 §7.2.1).
func (e *Endpoint) Display(ctx context.Context, s *msrp.Session, r Received) error {
	return e.notify(ctx, s, r, imdn.DisplayNotification, imdn.Displayed)
}

func (e *Endpoint) notify(ctx context.Context, s *msrp.Session, r Received, k imdn.Kind, st imdn.Status) error {
	n, err := r.Request.Notification(k, st, e.Self.URI)
	if err != nil {
		return err
	}
	id, err := imdn.NewMessageID(e.random())
	if err != nil {
		return err
	}
	m, err := n.Message(imdn.Envelope{From: e.Self, To: r.From, Route: r.Request.RecordRoute, MessageID: id, DateTime: e.now()})
	if err != nil {
		return err
	}
	body, err := m.Marshal()
	if err != nil {
		return err
	}
	// Notifications are not reported on themselves (RFC 5438 §7.2.1), and
	// a failure costs only the receipt.
	_, err = s.Send(ctx, msrp.Outgoing{ContentType: cpim.ContentType, Body: msrp.BodyOf(body), FailureReport: msrp.ReportNo})
	return err
}

// LocalURI returns a fresh URI for this simulator's end of a session. The
// host is never connected to (the client is the active side, behind NAT),
// so it is a name that cannot resolve.
func LocalURI(r io.Reader) (msrp.URI, error) {
	if r == nil {
		r = rand.Reader
	}
	sid, err := msrp.NewSessionID(r)
	if err != nil {
		return msrp.URI{}, err
	}
	return msrp.URI{Host: "rcs-sim.invalid", Port: 9, SessionID: sid, Transport: "tcp"}, nil
}

// Client is the simulated device's end: one connection to the relay, as a
// client opens one per session, and the session on it.
type Client struct {
	Conn    *msrp.Conn
	Session *msrp.Session
}

// Dial connects to relayPath as a client behind NAT does: actively, over TLS
// for msrps, and binds the session with the bodiless SEND RFC 4975 §5.4
// asks of the active side. tlsConfig may be nil for the system defaults.
// wrap, when set, wraps the connection, so a scenario can watch what crosses
// it (that keep-alives go out, say). It wraps the MSRP stream, inside TLS
// for an msrps: path, so what it sees is MSRP and not ciphertext.
func Dial(ctx context.Context, relayPath, local msrp.URI, h msrp.Handler, cfg msrp.Config, tlsConfig *tls.Config, wrap func(net.Conn) net.Conn) (*Client, error) {
	addr, err := relayPath.Addr()
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("chat: connecting to the relay: %w", safeerr.Reason(err))
	}
	if relayPath.Secure {
		tc := &tls.Config{MinVersion: tls.VersionTLS12}
		if tlsConfig != nil {
			tc = tlsConfig.Clone()
		}
		if tc.ServerName == "" {
			tc.ServerName = relayPath.Host
		}
		conn := tls.Client(nc, tc)
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = nc.Close()
			return nil, fmt.Errorf("chat: TLS to the relay: %w", safeerr.Reason(err))
		}
		nc = conn
	}
	if wrap != nil {
		nc = wrap(nc)
	}
	c, err := msrp.NewActiveConn(nc, cfg)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	s, err := msrp.NewSession(msrp.SessionConfig{Local: local, Remote: []msrp.URI{relayPath}, Handler: h})
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if err := c.Open(ctx, s); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("chat: binding the session: %w", safeerr.Reason(err))
	}
	return &Client{Conn: c, Session: s}, nil
}

// Close ends the session and its connection.
func (c *Client) Close() error {
	_ = c.Session.Close()
	return c.Conn.Close()
}

// Core stands in for rcs-as: a passive MSRP listener the relay connects to,
// with the sessions the test registered, the way rcs-as registers one when it
// answers an INVITE.
type Core struct {
	ln   net.Listener
	host string
	port int
	cfg  msrp.Config
	reg  msrp.Registry

	mu     sync.Mutex
	conns  []*msrp.Conn
	closed bool
	done   chan struct{}
}

// ListenCore listens on addr. advertise is the host put in session URIs,
// the address the relay connects to; empty means the listener's own.
func ListenCore(addr, advertise string, cfg msrp.Config) (*Core, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return ServeCore(ln, advertise, cfg), nil
}

// ServeCore is ListenCore on a listener the caller made; Close closes it.
func ServeCore(ln net.Listener, advertise string, cfg msrp.Config) *Core {
	tcp := ln.Addr().(*net.TCPAddr)
	if advertise == "" {
		advertise = tcp.IP.String()
	}
	c := &Core{ln: ln, host: advertise, port: tcp.Port, cfg: cfg, done: make(chan struct{})}
	go c.accept()
	return c
}

func (c *Core) accept() {
	defer close(c.done)
	for {
		nc, err := c.ln.Accept()
		if err != nil {
			return
		}
		mc, err := msrp.NewPassiveConn(nc, &c.reg, c.cfg)
		if err != nil {
			_ = nc.Close()
			continue
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			_ = mc.Close()
			continue
		}
		c.conns = append(c.conns, mc)
		c.mu.Unlock()
	}
}

// Port is the port the stand-in listens on.
func (c *Core) Port() int { return c.port }

// NewURI returns a fresh session URI on the stand-in.
func (c *Core) NewURI(r io.Reader) (msrp.URI, error) {
	if r == nil {
		r = rand.Reader
	}
	sid, err := msrp.NewSessionID(r)
	if err != nil {
		return msrp.URI{}, err
	}
	return msrp.URI{Host: c.host, Port: c.port, SessionID: sid, Transport: "tcp"}, nil
}

// Expect registers a session at local whose peer is remote, the relay's
// core_path_local, so that the relay's connection binds to it.
func (c *Core) Expect(local, remote msrp.URI, h msrp.Handler) (*msrp.Session, error) {
	s, err := msrp.NewSession(msrp.SessionConfig{Local: local, Remote: []msrp.URI{remote}, Handler: h})
	if err != nil {
		return nil, err
	}
	if err := c.reg.Add(s); err != nil {
		return nil, err
	}
	return s, nil
}

// Close stops listening and closes every connection the relay opened.
func (c *Core) Close() error {
	err := c.ln.Close()
	<-c.done
	c.mu.Lock()
	c.closed = true
	conns := c.conns
	c.mu.Unlock()
	for _, mc := range conns {
		_ = mc.Close()
	}
	return err
}

// String names the stand-in without any session.
func (c *Core) String() string { return "rcs-as stand-in on port " + strconv.Itoa(c.port) }
