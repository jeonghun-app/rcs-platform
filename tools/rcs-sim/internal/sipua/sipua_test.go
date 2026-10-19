package sipua

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

func TestRegisterAsksForOutboundOverOneConnection(t *testing.T) {
	for _, network := range []transport.Network{transport.TCP, transport.TLS} {
		t.Run(string(network), func(t *testing.T) {
			s := newStandIn(t, network)
			s.flowTimer = 100
			ua := dial(t, s.config())
			reg := register(t, ua)
			got := s.next(t)
			req := got.req

			if req.URI.String() != "sip:"+testDomain {
				t.Errorf("Request-URI = %s, want the home domain", req.URI)
			}
			from, _ := req.Header.From()
			to, _ := req.Header.To()
			if from.URI.String() != testIMPU || to.URI.String() != testIMPU || from.Tag() == "" {
				t.Errorf("From = %s, To = %s, want the IMPU with a From tag", from, to)
			}
			contacts, err := req.Header.Contact()
			if err != nil || len(contacts) != 1 {
				t.Fatalf("Contact = %v, %v", contacts, err)
			}
			c := contacts[0]
			inst, _ := c.Instance()
			id, _, _ := c.RegID()
			tp, _ := c.URI.Param("transport")
			if inst != "<"+testInstance+">" || id != 1 || tp != strings.ToLower(string(network)) || c.URI.User != "" {
				t.Errorf("Contact = %s, want +sip.instance, reg-id=1 and the transport, and no user part", c)
			}
			if !strings.Contains(req.Header.Get("Contact"), `+sip.instance="<`+testInstance+`>"`) {
				t.Errorf("Contact = %s, want the instance quoted (RFC 5626 §4.1)", req.Header.Get("Contact"))
			}
			if sup, _ := req.Header.Supported(); !hasTag(sup, "outbound") || !hasTag(sup, "path") {
				t.Errorf("Supported = %v, want outbound and path", sup)
			}
			if exp, _ := req.Header.Expires(); exp != 600000 {
				t.Errorf("Expires = %d, want 600000 (TS 24.229 §5.1.1.2.1)", exp)
			}
			routes, _ := req.Header.Route()
			if len(routes) != 1 || routes[0].URI.Host != s.config().proxyHost() || !routes[0].URI.Params.Has("lr") {
				t.Errorf("Route = %v, want the P-CSCF alone, loose-routing", routes)
			}

			if reg.Expires != time.Hour || !reg.Outbound || reg.FlowTimer != 100*time.Second {
				t.Errorf("registration = %+v", reg)
			}
			if len(reg.ServiceRoute) != 2 || len(reg.AssociatedURIs) != 2 || reg.Response.StatusCode != 200 {
				t.Errorf("registration = %+v", reg)
			}

			// A refresh is the same registration: Call-ID and From tag kept,
			// CSeq one higher (RFC 3261 §10.2.4), over the same flow.
			register(t, ua)
			again := s.next(t)
			callID, _ := req.Header.CallID()
			callID2, _ := again.req.Header.CallID()
			from2, _ := again.req.Header.From()
			cseq, _ := again.req.Header.CSeq()
			if callID2 != callID || from2.Tag() != from.Tag() || cseq.Seq != 2 || again.src.Flow != got.src.Flow {
				t.Errorf("refresh: Call-ID kept %v, tag kept %v, CSeq %d, same flow %v",
					callID2 == callID, from2.Tag() == from.Tag(), cseq.Seq, again.src.Flow == got.src.Flow)
			}
			if st := s.tr.Stats(); st.Accepted != 1 {
				t.Errorf("Accepted = %d, want one connection", st.Accepted)
			}
		})
	}
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

func (c Config) proxyHost() string {
	if c.ServerName != "" {
		return c.ServerName
	}
	return c.Proxy.Addr().String()
}

func TestRequestsAfterRegistrationCarryTheRouteSet(t *testing.T) {
	s := newStandIn(t, transport.TCP)
	ua := dial(t, s.config())
	target := mustURI(t, "sip:+15550100002@ims.example.com")
	if _, err := ua.NewRequest("MESSAGE", target); !errors.Is(err, ErrNotRegistered) {
		t.Fatalf("NewRequest before Register = %v, want ErrNotRegistered", err)
	}
	register(t, ua)
	reg := s.next(t)

	req, err := ua.NewRequest("MESSAGE", target)
	if err != nil {
		t.Fatal(err)
	}
	res, err := ua.Send(context.Background(), req)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("Send = %v, %v", res, err)
	}
	got := s.next(t)
	if got.src.Flow != reg.src.Flow {
		t.Error("MESSAGE came over another flow")
	}
	// TS 24.229 §5.1.2A.1.1: the P-CSCF, then the Service-Route in order.
	routes, _ := got.req.Header.Route()
	var hosts []string
	for _, r := range routes {
		hosts = append(hosts, r.URI.Host)
	}
	if strings.Join(hosts, " ") != "127.0.0.1 scscf.example.com as.example.com" {
		t.Errorf("Route hosts = %v", hosts)
	}
	to, _ := got.req.Header.To()
	from, _ := got.req.Header.From()
	if got.req.URI.String() != target.String() || to.URI.String() != target.String() || from.URI.String() != testIMPU {
		t.Errorf("Request-URI %s, To %s, From %s", got.req.URI, to, from)
	}
}

func TestRequestsFromTheNetworkArriveOverTheSameConnection(t *testing.T) {
	s := newStandIn(t, transport.TCP)
	cfg := s.config()
	answered := make(chan string, 1)
	cfg.OnRequest = func(tx *transaction.ServerTransaction) {
		answered <- tx.Request().Method
		res, _ := sip.NewResponse(tx.Request(), 200, "", "u1")
		tx.Respond(res)
	}
	ua := dial(t, cfg)
	register(t, ua)
	flow := s.next(t).src.Flow

	if res := s.send(t, "MESSAGE", flow); res.StatusCode != 200 {
		t.Fatalf("MESSAGE answered %d", res.StatusCode)
	}
	if m := <-answered; m != "MESSAGE" {
		t.Fatalf("OnRequest got %s", m)
	}
	if st := s.tr.Stats(); st.Accepted != 1 || st.Dialed != 0 {
		t.Fatalf("stats = %+v, want the client's one connection used both ways", st)
	}
}

func TestRequestWithoutAHandlerIsAnswered501(t *testing.T) {
	s := newStandIn(t, transport.TCP)
	ua := dial(t, s.config())
	register(t, ua)
	if res := s.send(t, "MESSAGE", s.next(t).src.Flow); res.StatusCode != 501 {
		t.Fatalf("MESSAGE answered %d, want 501", res.StatusCode)
	}
}

func TestKeepAlivePingsAndTheStandInsPongIsSeen(t *testing.T) {
	s := newStandIn(t, transport.TCP)
	clock := newFakeClock()
	cfg := s.config()
	cfg.Clock, cfg.KeepAlive = clock, 30*time.Second
	ua := dial(t, cfg)
	register(t, ua)

	for i := int64(1); i <= 2; i++ {
		clock.armedFor(t, 30*time.Second)
		clock.advance(30 * time.Second)
		clock.armedFor(t, DefaultPongTimeout)
		waitUntil(t, "the pong", func() bool { _, pongs := ua.KeepAlives(); return pongs == i })
	}
	// The pong stopped its timer: the flow outlives the pong timeout.
	clock.advance(DefaultPongTimeout)
	if err := ua.Err(); err != nil {
		t.Fatalf("Err = %v after pongs", err)
	}
	if pings, _ := ua.KeepAlives(); pings != 2 {
		t.Fatalf("pings = %d", pings)
	}
	if st := s.tr.Stats(); st.KeepAlives != 2 {
		t.Fatalf("the stand-in answered %d pings", st.KeepAlives)
	}
}

func TestUnansweredPingFailsTheFlow(t *testing.T) {
	r := newRawRegistrar(t)
	clock := newFakeClock()
	ua := dial(t, Config{
		Network: transport.TCP, Proxy: r.addr(), Domain: testDomain,
		IMPU: mustURI(t, testIMPU), InstanceID: testInstance,
		Clock: clock, KeepAlive: 30 * time.Second,
	})
	r.register(t, ua)

	clock.armedFor(t, 30*time.Second)
	clock.advance(30 * time.Second)
	r.readPing(t)
	select {
	case <-ua.Done():
		t.Fatal("the UA failed before the pong timeout")
	default:
	}
	clock.advance(DefaultPongTimeout)
	waitDone(t, ua)
	if err := ua.Err(); !errors.Is(err, ErrFlowFailed) {
		t.Fatalf("Err = %v, want ErrFlowFailed", err)
	}
	// RFC 5626 §4.4.1: the failed flow is closed.
	if _, err := r.br.ReadByte(); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read after the pong timeout = %v, want the connection closed", err)
	}
}

func TestKeepAliveIntervalComesFromTheFlowTimer(t *testing.T) {
	for _, tc := range []struct {
		flowTimer int
		base      time.Duration
	}{
		{100, 100 * time.Second},
		{0, DefaultFlowTimer},
	} {
		s := newStandIn(t, transport.TCP)
		s.flowTimer = tc.flowTimer
		clock := newFakeClock()
		cfg := s.config()
		cfg.Clock = clock
		ua := dial(t, cfg)
		register(t, ua)
		// RFC 5626 §4.4.1: between 80% and 100% of the interval.
		d := clock.waitArmed(t, "keep-alive", func(d time.Duration) bool {
			return d >= tc.base*8/10 && d <= tc.base
		})
		clock.advance(d)
		waitUntil(t, "the ping", func() bool { pings, _ := ua.KeepAlives(); return pings == 1 })
	}
}

func TestKeepAliveIntervalIsDrawnForEachPing(t *testing.T) {
	// RFC 5626 §4.4.1: "the random number will be different for each
	// keep-alive ping", so clients that drew the same first interval do
	// not ping together from then on.
	s := newStandIn(t, transport.TCP)
	s.flowTimer = 100
	clock := newFakeClock()
	cfg := s.config()
	cfg.Clock = clock
	ua := dial(t, cfg)
	register(t, ua)
	var intervals []time.Duration
	for i := int64(1); i <= 4; i++ {
		d := clock.waitArmed(t, "keep-alive", func(d time.Duration) bool { return d >= 80*time.Second && d <= 100*time.Second })
		intervals = append(intervals, d)
		clock.advance(d)
		// The pong before the next advance, which passes its timer.
		waitUntil(t, "the pong", func() bool { _, pongs := ua.KeepAlives(); return pongs == i })
	}
	if slices.Equal(intervals, []time.Duration{intervals[0], intervals[0], intervals[0], intervals[0]}) {
		t.Fatalf("intervals = %v, all the same", intervals)
	}
}

func TestNoKeepAliveWithoutRequireOutbound(t *testing.T) {
	// RFC 5626 §4.2.1: keep-alives start once Require: outbound shows the
	// outbound registration succeeded; a first hop that did not use it
	// need not answer them.
	s := newStandIn(t, transport.TCP)
	s.noOutbound = true
	clock := newFakeClock()
	cfg := s.config()
	cfg.Clock, cfg.KeepAlive = clock, 30*time.Second
	ua := dial(t, cfg)
	if reg := register(t, ua); reg.Outbound {
		t.Fatal("registration reports outbound without Require: outbound")
	}
	clock.advance(time.Hour)
	if pings, _ := ua.KeepAlives(); pings != 0 {
		t.Fatalf("%d pings without outbound", pings)
	}
	if err := ua.Err(); err != nil {
		t.Fatalf("Err = %v", err)
	}
}

func TestRefreshAndUnregisterNeverOverlap(t *testing.T) {
	// RFC 3261 §10.2: no REGISTER before the previous one has its final
	// response. Code review's case: a refresh and an Unregister at once,
	// with the first REGISTER to arrive answered last. Overlapping, the
	// UA would take the answers in the wrong order and stay registered
	// while the registrar removed the binding.
	s := newStandIn(t, transport.TCP)
	s.delay = func(n int) time.Duration {
		if n == 2 {
			return 200 * time.Millisecond
		}
		return 0
	}
	ua := dial(t, s.config())
	register(t, ua)
	errs := make(chan error, 2)
	go func() { _, err := ua.Register(context.Background()); errs <- err }()
	go func() { _, err := ua.Unregister(context.Background()); errs <- err }()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	s.mu.Lock()
	overlaps, last := s.overlaps, s.lastExpires
	s.mu.Unlock()
	if overlaps != 0 {
		t.Fatalf("%d REGISTERs sent before the previous one was answered", overlaps)
	}
	// The UA ends as the registrar does, after whichever came last.
	_, err := ua.NewRequest("MESSAGE", mustURI(t, testIMPU))
	if registered := err == nil; registered != (last != 0) {
		t.Fatalf("UA registered %v, but the last REGISTER had Expires %d", registered, last)
	}
}

func TestClosedConnectionFailsTheUAAndIsNotReplaced(t *testing.T) {
	s := newStandIn(t, transport.TCP)
	ua := dial(t, s.config())
	register(t, ua)
	s.tr.CloseFlow(s.next(t).src.Flow)
	waitDone(t, ua)
	if err := ua.Err(); !errors.Is(err, ErrFlowFailed) {
		t.Fatalf("Err = %v, want ErrFlowFailed", err)
	}
	if _, err := ua.Register(context.Background()); !errors.Is(err, ErrFlowFailed) {
		t.Fatalf("Register after the flow closed = %v, want ErrFlowFailed", err)
	}
	if st := s.tr.Stats(); st.Accepted != 1 {
		t.Fatalf("Accepted = %d: the UA opened another connection", st.Accepted)
	}
}

func TestRefusedRegistrationReportsTheStatusOnly(t *testing.T) {
	s := newStandIn(t, transport.TCP)
	s.refuse = 403
	ua := dial(t, s.config())
	_, err := ua.Register(context.Background())
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 403 || se.Method != "REGISTER" {
		t.Fatalf("Register = %v, want a 403 StatusError", err)
	}
	for _, leak := range []string{"15550100001", testDomain, "127.0.0.1", testInstance} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error %q names %q", err, leak)
		}
	}
}

func TestRegistrationNeedsABindingForThisInstanceAndRegID(t *testing.T) {
	for name, rewrite := range map[string]func(*sip.Contact){
		"another instance": func(c *sip.Contact) {
			c.Params.Set("+sip.instance", "<urn:uuid:00000000-0000-4000-8000-000000000002>")
		},
		"another reg-id": func(c *sip.Contact) { c.Params.Set("reg-id", "2") },
		"no reg-id":      func(c *sip.Contact) { c.Params.Del("reg-id") },
	} {
		s := newStandIn(t, transport.TCP)
		s.rewrite = rewrite
		ua := dial(t, s.config())
		if _, err := ua.Register(context.Background()); !errors.Is(err, ErrNoBinding) {
			t.Errorf("%s: Register = %v, want ErrNoBinding", name, err)
		}
	}
}

func TestUnregisterRemovesTheBindingAndStopsTheKeepAlive(t *testing.T) {
	s := newStandIn(t, transport.TCP)
	clock := newFakeClock()
	cfg := s.config()
	cfg.Clock, cfg.KeepAlive = clock, 30*time.Second
	ua := dial(t, cfg)
	register(t, ua)
	s.next(t)
	clock.armedFor(t, 30*time.Second)

	reg, err := ua.Unregister(context.Background())
	if err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	got := s.next(t)
	if exp, _ := got.req.Header.Expires(); exp != 0 || reg.Expires != 0 {
		t.Fatalf("Expires = %d, granted %v; want 0", exp, reg.Expires)
	}
	if c, _ := reg.Response.Header.Contact(); len(c) != 0 {
		t.Fatalf("the 200 still lists %d contacts", len(c))
	}
	clock.advance(time.Hour)
	if pings, _ := ua.KeepAlives(); pings != 0 {
		t.Fatalf("%d pings after Unregister", pings)
	}
	if _, err := ua.NewRequest("MESSAGE", mustURI(t, testIMPU)); !errors.Is(err, ErrNotRegistered) {
		t.Fatalf("NewRequest after Unregister = %v", err)
	}
}

func TestDialRefusesAnIncompleteConfig(t *testing.T) {
	good := Config{
		Network: transport.TCP, Proxy: newRawRegistrar(t).addr(), Domain: testDomain,
		IMPU: mustURI(t, testIMPU), InstanceID: testInstance,
	}
	for name, mutate := range map[string]func(*Config){
		"UDP":             func(c *Config) { c.Network = transport.UDP },
		"no proxy":        func(c *Config) { c.Proxy = netip.AddrPort{} },
		"no domain":       func(c *Config) { c.Domain = "" },
		"domain not host": func(c *Config) { c.Domain = "ims.example.com;x=1" },
		"IMPU not SIP":    func(c *Config) { c.IMPU = mustURI(t, "mailto:a@example.com") },
		"IMPU tel":        func(c *Config) { c.IMPU = mustURI(t, testTel) },
		"instance":        func(c *Config) { c.InstanceID = "00000000-0000-4000-8000-000000000001" },
		"reg-id":          func(c *Config) { c.RegID = 1 << 31 },
		"server name":     func(c *Config) { c.ServerName = "pcscf.example.com;lr" },
		"TLS, no name":    func(c *Config) { c.Network = transport.TLS },
	} {
		cfg := good
		mutate(&cfg)
		if ua, err := Dial(context.Background(), cfg); err == nil {
			ua.Close()
			t.Errorf("%s: Dial accepted the config", name)
		}
	}
}

func TestSendAfterCloseFails(t *testing.T) {
	s := newStandIn(t, transport.TCP)
	ua := dial(t, s.config())
	register(t, ua)
	req, err := ua.NewRequest("MESSAGE", mustURI(t, testIMPU))
	if err != nil {
		t.Fatal(err)
	}
	ua.Close()
	if _, err := ua.Send(context.Background(), req); !errors.Is(err, ErrClosed) {
		t.Fatalf("Send after Close = %v, want ErrClosed", err)
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitDone(t *testing.T, ua *UA) {
	t.Helper()
	select {
	case <-ua.Done():
	case <-time.After(waitFor):
		t.Fatal("the UA did not finish")
	}
}
