package sipua

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// waitFor bounds how long a test waits for something the network or another
// goroutine does. It is a failure deadline, never a delay.
const waitFor = 5 * time.Second

// Test identities: on .github/allowed-test-identifiers.txt, in a domain that
// is not anyone's.
const (
	testDomain   = "ims.example.com"
	testIMPU     = "sip:+15550100001@ims.example.com"
	testTel      = "tel:+15550100001"
	testInstance = "urn:uuid:00000000-0000-4000-8000-000000000001"
	// The stand-in's Service-Route: the S-CSCF's originating URI, then one
	// more hop, so the order is seen.
	testRoute1 = "<sip:orig@scscf.example.com;lr>"
	testRoute2 = "<sip:as.example.com;lr>"
)

// standIn plays the P-CSCF and the registrar behind it on one transport, as
// far as a UA can tell: it answers REGISTER as RFC 3261 §10.3 and RFC 5626 §6
// do, answers other requests 200, and sends requests back over a client's
// flow. Its fields are set before the UA dials.
type standIn struct {
	t     *testing.T
	tr    *transport.Transport
	layer *transaction.Layer
	ids   sip.IDGenerator
	addr  netip.AddrPort
	// roots verify the TLS listener's certificate, for "example.com".
	roots *tls.Config

	// refuse, when set, is the status REGISTER is answered with.
	refuse int
	// flowTimer, when set, goes in the 2xx to REGISTER.
	flowTimer int
	// grant caps the expiry granted; zero is 3600.
	grant uint32
	// rewrite, when set, changes each contact the 2xx to REGISTER lists.
	rewrite func(*sip.Contact)
	// auth, when set, authenticates every REGISTER as the S-CSCF does, and
	// proxyAuth, before it, as a proxy on the way would.
	auth, proxyAuth *authRegistrar
	// hook, when set, answers REGISTERs in their place: a response, or nil
	// for the stand-in's own 200.
	hook func(req *sip.Request, tag string) *sip.Response
	// noOutbound leaves Require: outbound out of the 2xx to REGISTER, as a
	// registrar that did not use the reg-id does (RFC 5626 §6).
	noOutbound bool
	// delay, when set, is how long the n-th REGISTER (from 1) waits for
	// its answer, which then comes from another goroutine.
	delay func(n int) time.Duration

	mu sync.Mutex
	// registers counts REGISTERs; open is how many have no answer yet, and
	// overlaps how many arrived while another had none.
	registers, open, overlaps int
	// lastExpires is the Expires of the last REGISTER received.
	lastExpires uint32
	// holdBye, when set, keeps BYEs unanswered until it is closed.
	holdBye chan struct{}

	got chan received
	// onInvite, when set, answers each INVITE, as the far end would; the
	// stand-in answers CANCEL itself, with 487 to the INVITE (RFC 3261
	// §9.2). acks hears the ACKs to 2xx, which reach the TU as strays.
	onInvite func(tx *transaction.ServerTransaction)
	// onCancel, when set, answers the INVITE a CANCEL names instead of
	// the stand-in's 487.
	onCancel func(inv *transaction.ServerTransaction)
	acks     chan *sip.Request
	// closing is set as the test ends: a request it has already read may
	// still be answered then, and fail to be, which is no fault.
	closing atomic.Bool
}

type received struct {
	req *sip.Request
	src transport.Source
}

func newStandIn(t *testing.T, network transport.Network) *standIn {
	t.Helper()
	s := &standIn{t: t, got: make(chan received, 64), acks: make(chan *sip.Request, 16)}
	var cfg transport.Config
	if network == transport.TLS {
		ts := httptest.NewTLSServer(http.NotFoundHandler()) // only for its certificate
		t.Cleanup(ts.Close)
		cfg.TLS = ts.TLS.Clone()
		s.roots = ts.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	}
	tr, err := transport.New(cfg, func(in transport.Inbound) { s.layer.Receive(in) })
	if err != nil {
		t.Fatal(err)
	}
	s.tr = tr
	s.layer = transaction.New(tr, s, transaction.Config{})
	t.Cleanup(func() { s.closing.Store(true); s.layer.Close(); tr.Close() })
	s.addr, err = tr.Listen(transport.ListenerConfig{
		Network: network, Addr: "127.0.0.1:0", ClientFacing: true,
		AdvertisedHost: "pcscf.example.com", AdvertisedPort: 5060,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// config is a UA configuration for this stand-in.
func (s *standIn) config() Config {
	cfg := Config{
		Network:    transport.TCP,
		Proxy:      s.addr,
		Domain:     testDomain,
		IMPU:       mustURI(s.t, testIMPU),
		InstanceID: testInstance,
	}
	if s.roots != nil {
		cfg.Network, cfg.ServerName, cfg.TLS = transport.TLS, "example.com", s.roots
	}
	return cfg
}

func (s *standIn) Request(tx *transaction.ServerTransaction) {
	req := tx.Request()
	s.got <- received{req.Clone(), tx.Source()}
	switch {
	case req.Method == "INVITE" && s.onInvite != nil:
		s.onInvite(tx)
		return
	case req.Method == "CANCEL":
		if res, err := sip.NewResponse(req, 200, "", "c1"); err == nil {
			tx.Respond(res)
		}
		if inv, ok := s.layer.InviteFor(req); ok && s.onCancel != nil {
			s.onCancel(inv)
		} else if ok {
			if res, err := sip.NewResponse(inv.Request(), 487, "", "callee"); err == nil {
				// Refused once the INVITE has its final response.
				_ = inv.Respond(res)
			}
		}
		return
	}
	var wait time.Duration
	s.mu.Lock()
	hold := s.holdBye
	s.mu.Unlock()
	if req.Method == "BYE" && hold != nil {
		go func() {
			<-hold
			if res := s.response(req); res != nil {
				_ = tx.Respond(res)
			}
		}()
		return
	}
	if req.Method == "REGISTER" {
		s.mu.Lock()
		s.registers++
		if s.open > 0 {
			s.overlaps++
		}
		s.open++
		s.lastExpires, _ = req.Header.Expires()
		if s.delay != nil {
			wait = s.delay(s.registers)
		}
		s.mu.Unlock()
	}
	answer := func() {
		res := s.response(req)
		if res == nil {
			return
		}
		if req.Method == "REGISTER" {
			s.mu.Lock()
			s.open--
			s.mu.Unlock()
		}
		if err := tx.Respond(res); err != nil && !s.closing.Load() {
			s.t.Errorf("stand-in: answering %s: %v", req.Method, err)
		}
	}
	if wait == 0 {
		answer()
		return
	}
	go func() {
		time.Sleep(wait)
		answer()
	}()
}

func (s *standIn) response(req *sip.Request) *sip.Response {
	tag, _ := s.ids.Tag()
	code := 200
	if req.Method == "REGISTER" && s.refuse != 0 {
		code = s.refuse
	}
	if req.Method == "REGISTER" && code == 200 && s.hook != nil {
		if res := s.hook(req, tag); res != nil {
			return res
		}
	}
	for _, a := range []*authRegistrar{s.proxyAuth, s.auth} {
		if req.Method == "REGISTER" && code == 200 && a != nil {
			if res := a.check(s.t, req, tag); res != nil {
				return res
			}
		}
	}
	res, err := sip.NewResponse(req, code, "", tag)
	if err != nil {
		// Errorf, not Fatalf: a delayed answer runs off the test's goroutine.
		s.t.Errorf("stand-in: %v", err)
		return nil
	}
	if req.Method != "REGISTER" || code != 200 {
		return res
	}
	grant := s.grant
	if grant == 0 {
		grant = 3600
	}
	expires, err := req.Header.Expires()
	if err != nil {
		s.t.Errorf("stand-in: Expires: %v", err)
	}
	contacts, err := req.Header.Contact()
	if err != nil {
		s.t.Errorf("stand-in: Contact: %v", err)
	}
	for _, c := range contacts {
		if e := min(expires, grant); e > 0 {
			c.Params.Set("expires", strconv.FormatUint(uint64(e), 10))
			if s.rewrite != nil {
				s.rewrite(&c)
			}
			res.Header.Add("Contact", c.String())
		}
	}
	if !s.noOutbound {
		res.Header.Add("Require", "outbound")
	}
	res.Header.Add("Path", "<sip:flowtoken@pcscf.example.com;lr;ob>")
	res.Header.Add("Service-Route", testRoute1)
	res.Header.Add("Service-Route", testRoute2)
	res.Header.Add("P-Associated-URI", "<"+testIMPU+">, <"+testTel+">")
	if s.flowTimer != 0 {
		res.Header.Add("Flow-Timer", strconv.Itoa(s.flowTimer))
	}
	return res
}

// registerCount is how many REGISTERs the stand-in has received.
func (s *standIn) registerCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.registers
}

func (s *standIn) Stray(in transport.Inbound) {
	if req, ok := in.Message.(*sip.Request); ok && req.Method == "ACK" {
		s.acks <- req
	}
}

func (s *standIn) ServerFailed(*transaction.ServerTransaction, error) {}

// next returns the next request the stand-in answered.
func (s *standIn) next(t *testing.T) received {
	t.Helper()
	select {
	case r := <-s.got:
		return r
	case <-time.After(waitFor):
		t.Fatal("the stand-in received no request")
		return received{}
	}
}

// send sends a request to the client over flow, as a terminating request
// reaches it, and returns the final response.
func (s *standIn) send(t *testing.T, method string, flow transport.FlowID) *sip.Response {
	t.Helper()
	branch, _ := s.ids.Branch()
	tag, _ := s.ids.Tag()
	callID, _ := s.ids.CallID("")
	req := &sip.Request{Method: method, URI: mustURI(t, testIMPU)}
	for _, f := range [][2]string{
		{"Via", "SIP/2.0/TCP standin.invalid;branch=" + branch},
		{"Max-Forwards", "70"},
		{"From", "<sip:+15550100002@ims.example.com>;tag=" + tag},
		{"To", "<" + testIMPU + ">"},
		{"Call-ID", callID},
		{"CSeq", "1 " + method},
	} {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			t.Fatal(err)
		}
	}
	return s.sendRequest(t, req, flow)
}

// sendRequest sends req over flow and returns its final response.
func (s *standIn) sendRequest(t *testing.T, req *sip.Request, flow transport.FlowID) *sip.Response {
	t.Helper()
	method := req.Method
	final := make(chan *sip.Response, 1)
	_, err := s.layer.Request(req, transport.Destination{Flow: flow}, func(res *sip.Response, err error) {
		if err != nil {
			t.Errorf("stand-in %s: %v", method, err)
			final <- nil
		} else if res.StatusCode >= 200 {
			final <- res
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case res := <-final:
		if res == nil {
			t.FailNow()
		}
		return res
	case <-time.After(waitFor):
		t.Fatalf("no final response to the stand-in's %s", method)
		return nil
	}
}

// rawRegistrar is a registrar on a bare TCP socket, for what a transport
// would not do: it answers one REGISTER and then leaves pings unanswered.
type rawRegistrar struct {
	ln   net.Listener
	conn net.Conn
	br   *bufio.Reader
}

func newRawRegistrar(t *testing.T) *rawRegistrar {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return &rawRegistrar{ln: ln}
}

func (r *rawRegistrar) addr() netip.AddrPort { return netip.MustParseAddrPort(r.ln.Addr().String()) }

// register runs Register on ua while it accepts the connection and answers
// with a 200 that binds the contact for an hour.
func (r *rawRegistrar) register(t *testing.T, ua *UA) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := ua.Register(context.Background())
		done <- err
	}()
	c, err := r.ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(waitFor))
	r.conn, r.br = c, bufio.NewReader(c)
	m, err := sip.NewReader(r.br, sip.Limits{}).ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	req := m.(*sip.Request)
	res, err := sip.NewResponse(req, 200, "", "r1")
	if err != nil {
		t.Fatal(err)
	}
	contacts, _ := req.Header.Contact()
	contacts[0].Params.Set("expires", "3600")
	res.Header.Add("Contact", contacts[0].String())
	res.Header.Add("Require", "outbound")
	b, _ := res.Bytes()
	c.Write(b)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
	case <-time.After(waitFor):
		t.Fatal("Register did not return")
	}
}

// readPing reads one ping from the client.
func (r *rawRegistrar) readPing(t *testing.T) {
	t.Helper()
	b := make([]byte, 4)
	if _, err := io.ReadFull(r.br, b); err != nil || string(b) != "\r\n\r\n" {
		t.Fatalf("ping = %q, %v", b, err)
	}
}

// fakeClock runs timers only when a test fires them, in due order, on the
// test's goroutine.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Duration
	timers []*fakeTimer
	// armed hears the duration of every timer armed, so a test can wait
	// until the code under test is waiting.
	armed chan time.Duration
}

type fakeTimer struct {
	c    *fakeClock
	at   time.Duration
	f    func()
	done bool
}

func newFakeClock() *fakeClock { return &fakeClock{armed: make(chan time.Duration, 1024)} }

func (c *fakeClock) AfterFunc(d time.Duration, f func()) transaction.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{c: c, at: c.now + d, f: f}
	c.timers = append(c.timers, t)
	select {
	case c.armed <- d:
	default:
	}
	return t
}

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := !t.done
	t.done = true
	return was
}

// waitArmed waits until a timer whose duration satisfies ok is armed, and
// returns that duration.
func (c *fakeClock) waitArmed(t *testing.T, what string, ok func(time.Duration) bool) time.Duration {
	t.Helper()
	deadline := time.After(waitFor)
	for {
		select {
		case d := <-c.armed:
			if ok(d) {
				return d
			}
		case <-deadline:
			t.Fatalf("no %s timer was armed", what)
			return 0
		}
	}
}

// armedFor is waitArmed for one exact duration.
func (c *fakeClock) armedFor(t *testing.T, d time.Duration) {
	t.Helper()
	c.waitArmed(t, d.String(), func(got time.Duration) bool { return got == d })
}

// advance moves the clock forward by d, firing every timer that falls due.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	end := c.now + d
	for {
		var next *fakeTimer
		for _, t := range c.timers {
			if !t.done && t.at <= end && (next == nil || t.at < next.at) {
				next = t
			}
		}
		if next == nil {
			break
		}
		next.done = true
		c.now = next.at
		c.mu.Unlock()
		next.f()
		c.mu.Lock()
	}
	c.now = end
	c.timers = slices.DeleteFunc(c.timers, func(t *fakeTimer) bool { return t.done })
	c.mu.Unlock()
}

func mustURI(t *testing.T, s string) sip.URI {
	t.Helper()
	u, err := sip.ParseURI(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// dial is Dial for a test: it fails the test on an error and closes the UA
// when the test ends.
func dial(t *testing.T, cfg Config) *UA {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	ua, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ua.Close() })
	return ua
}

func register(t *testing.T, ua *UA) *Registration {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	reg, err := ua.Register(ctx)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return reg
}
