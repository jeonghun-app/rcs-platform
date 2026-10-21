package icscf

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// These tests run icscf as runtime.Main would, against a Diameter HSS and a
// SIP S-CSCF on loopback: the in-process scenario of #15 PR B.

// diameterHSS is an HSS task: a Diameter node on loopback that answers UAR
// and LIR with answer.
type diameterHSS struct {
	node *diameter.Node
	addr string
	ln   *countingListener
	mu   sync.Mutex
	// answer decides the result and Server-Name of each answer.
	answer func(code uint32) (cx.Result, string)
	got    []uint32
}

func startHSS(t *testing.T) *diameterHSS { return startHSSAs(t, "hss-0a1b2c.rcs.local") }

// startHSSAs starts an HSS task whose Origin-Host is host.
func startHSSAs(t *testing.T, host string) *diameterHSS {
	t.Helper()
	return startHSSAt(t, host, "127.0.0.1:0")
}

// startHSSAt starts an HSS task listening on addr, such as the address of
// one that stopped.
func startHSSAt(t *testing.T, host, addr string) *diameterHSS {
	t.Helper()
	dict, err := diameter.NewDictionary(cx.AVPs...)
	if err != nil {
		t.Fatal(err)
	}
	n, err := diameter.NewNode(diameter.Config{
		OriginHost: host, OriginRealm: home,
		HostIPAddresses:    []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		Applications:       []diameter.Application{cx.Application},
		SupportedVendorIDs: []uint32{cx.Vendor3GPP, cx.VendorETSI},
		Dictionary:         dict,
		Accept:             []diameter.PeerRule{{HostPattern: "icscf-*.rcs.local"}},
		Logger:             slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	n.SetErrorAVPs(cx.ApplicationID, cx.ErrorAVPs)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ln := &countingListener{Listener: l}
	h := &diameterHSS{node: n, addr: ln.Addr().String(), ln: ln}
	for _, code := range []uint32{cx.CodeUserAuthorization, cx.CodeLocationInfo} {
		n.HandleFunc(cx.ApplicationID, code, func(_ context.Context, _ *diameter.Peer, req *diameter.Message) (*diameter.Message, error) {
			h.mu.Lock()
			h.got = append(h.got, code)
			answer := h.answer
			h.mu.Unlock()
			res, name := answer(code)
			a := cx.Answer{Result: res}
			if code == cx.CodeUserAuthorization {
				return (&cx.UAA{Answer: a, ServerName: name}).Message(n, req)
			}
			return (&cx.LIA{Answer: a, ServerName: name}).Message(n, req)
		})
	}
	go func() { _ = n.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), realWait)
		defer cancel()
		_ = n.Shutdown(ctx)
	})
	return h
}

// countingListener counts the connections it accepts.
type countingListener struct {
	net.Listener
	accepted atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return c, err
}

func (h *diameterHSS) commands() []uint32 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]uint32(nil), h.got...)
}

// sipPeer is a SIP endpoint on loopback TCP: the S-CSCF, which answers
// every request 200 and records it, or the pcscf side of a connection.
type sipPeer struct {
	ln  net.Listener
	got chan *sip.Request
}

func startSCSCF(t *testing.T) *sipPeer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &sipPeer{ln: ln, got: make(chan *sip.Request, 16)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(t, c)
		}
	}()
	return s
}

func (s *sipPeer) serve(t *testing.T, c net.Conn) {
	defer c.Close()
	r := sip.NewReader(bufio.NewReader(c), sip.Limits{})
	for {
		m, err := r.ReadMessage()
		if err != nil {
			return
		}
		req, ok := m.(*sip.Request)
		if !ok || req.Method == "ACK" {
			continue
		}
		s.got <- req
		res, err := sip.NewResponse(req, 200, "", "scscf1")
		if err != nil {
			return
		}
		b, err := res.Bytes()
		if err != nil {
			return
		}
		_, _ = c.Write(b)
	}
}

func (s *sipPeer) uri() string {
	return "sip:" + s.ln.Addr().String() + ";transport=tcp"
}

func (s *sipPeer) next(t *testing.T) *sip.Request {
	t.Helper()
	select {
	case req := <-s.got:
		return req
	case <-time.After(realWait):
		t.Fatal("the S-CSCF got nothing")
		return nil
	}
}

// running is icscf started by startICSCF.
type running struct {
	core netip.AddrPort
	h    *runtimetest.Harness
	// stop does what runtime.Run does on SIGTERM and waits for Run to
	// return.
	stop func()
	// stopWithin is stop, failing the test if Run has not returned within d.
	stopWithin func(d time.Duration)
}

// startICSCF runs icscf until the test ends, with its HSS at hss and the
// S-CSCF list scscfs.
func startICSCF(t *testing.T, hss *diameterHSS, scscfs []SCSCF, opts ...func(*ServiceConfig, *deps)) *running {
	t.Helper()
	h := runtimetest.New(t, "icscf")
	cfg := ServiceConfig{
		HomeDomain: home, Namespace: "rcs.local",
		// Not the bound address, so a test sees the advertised one in Via.
		CoreAddr: "127.0.0.1:0", CoreHost: netip.MustParseAddr("127.0.0.2"),
		SCSCFs: scscfs, RetryAfter: DefaultRetryAfter, RegisterTimeout: DefaultRegisterTimeout,
		OriginRealm: home, HSSRealm: home, HSSDiscovery: DiscoveryDNS,
		HSSHostPattern: "hss-*.rcs.local", CxTimeout: 2 * time.Second,
	}
	listening := make(chan netip.AddrPort, 1)
	d := deps{
		rand:      constantBytes(0x0c),
		discovery: staticDiscovery{netip.MustParseAddr("127.0.0.1")},
		// Every HSS address is the loopback HSS, on whatever port it got.
		dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dl net.Dialer
			return dl.DialContext(ctx, network, hss.addr)
		},
		listening: func(a netip.AddrPort) { listening <- a },
		// The S-CSCFs of these tests listen on loopback, which production
		// does not resolve to.
		allow: func(a netip.Addr) bool { return a.IsLoopback() },
	}
	for _, o := range opts {
		o(&cfg, &d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, h.Runtime, cfg, d) }()
	r := &running{h: h}
	select {
	case r.core = <-listening:
	case err := <-done:
		cancel()
		t.Fatalf("run ended: %v", err)
	case <-time.After(realWait):
		cancel()
		t.Fatal("icscf did not start")
	}
	var once sync.Once
	r.stopWithin = func(d time.Duration) {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("run: %v", err)
				}
			case <-time.After(d):
				t.Errorf("icscf did not stop within %v", d)
			}
		})
	}
	r.stop = func() { r.stopWithin(realWait) }
	t.Cleanup(r.stop)
	return r
}

type staticDiscovery []netip.Addr

func (s staticDiscovery) HSSAddresses(context.Context) ([]netip.Addr, error) { return s, nil }

// sends numbers the requests of these tests, so no two share a branch.
var sends atomic.Int64

// send writes a request from the pcscf side on a new connection and returns
// the response.
func (r *running) send(t *testing.T, method, uri string, fields ...string) *sip.Response {
	t.Helper()
	nc, err := net.Dial("tcp", r.core.String())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	n := sends.Add(1)
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s SIP/2.0\r\n", method, uri)
	fmt.Fprintf(&b, "Via: SIP/2.0/TCP 127.0.0.1:%d;branch=z9hG4bK-icscf-%d\r\n", nc.LocalAddr().(*net.TCPAddr).Port, n)
	b.WriteString("Max-Forwards: 70\r\n")
	fmt.Fprintf(&b, "Call-ID: icscf-run-%d\r\nCSeq: 1 %s\r\n", n, method)
	for _, f := range fields {
		b.WriteString(f + "\r\n")
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	_ = nc.SetDeadline(time.Now().Add(realWait))
	if _, err := io.WriteString(nc, b.String()); err != nil {
		t.Fatal(err)
	}
	rd := sip.NewReader(bufio.NewReader(nc), sip.Limits{})
	for {
		m, err := rd.ReadMessage()
		if err != nil {
			t.Fatalf("no final response: %v", err)
		}
		if res, ok := m.(*sip.Response); ok && res.StatusCode >= 200 {
			return res
		}
	}
}

// waitReady waits until /readyz says icscf can take work, which needs an
// HSS task connected. The harness clock is advanced past the readiness cache
// at every look.
func (r *running) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(realWait)
	for {
		r.h.Advance(2 * time.Second)
		if code, _ := r.h.Get("/readyz"); code == 200 {
			return
		}
		if time.Now().After(deadline) {
			_, body := r.h.Get("/readyz")
			t.Fatalf("icscf did not become ready: %s", body)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestARegisterGoesToTheSCSCFTheHSSNames(t *testing.T) {
	hss := startHSS(t)
	scscf := startSCSCF(t)
	hss.answer = func(uint32) (cx.Result, string) {
		return cx.ExperimentalResult(cx.SubsequentRegistration), scscf.uri()
	}
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI(scscf.uri())}})
	r.waitReady(t)
	res := r.send(t, "REGISTER", "sip:"+home,
		"From: <"+impu1+">;tag=f1", "To: <"+impu1+">",
		"Contact: <sip:127.0.0.1:5070;transport=tcp>;expires=600")
	if res.StatusCode != 200 {
		t.Fatalf("REGISTER answered %d", res.StatusCode)
	}
	if got := scscf.next(t); got.Method != "REGISTER" || got.URI.String() != scscf.uri() {
		t.Errorf("the S-CSCF got %s %s, want REGISTER %s", got.Method, got.URI.String(), scscf.uri())
	}
	if got := hss.commands(); len(got) != 1 || got[0] != cx.CodeUserAuthorization {
		t.Errorf("the HSS got %v, want one UAR", got)
	}
}

func TestATerminatingRequestGoesToTheSCSCFAsItsRoute(t *testing.T) {
	hss := startHSS(t)
	scscf := startSCSCF(t)
	hss.answer = func(uint32) (cx.Result, string) { return cx.ResultCode(diameter.ResultSuccess), scscf.uri() }
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI(scscf.uri())}})
	r.waitReady(t)
	res := r.send(t, "MESSAGE", tel1,
		"From: <sip:+15550100002@"+home+">;tag=f1", "To: <"+tel1+">")
	if res.StatusCode != 200 {
		t.Fatalf("MESSAGE answered %d", res.StatusCode)
	}
	got := scscf.next(t)
	routes, err := got.Header.Route()
	if err != nil || len(routes) != 1 || got.URI.String() != tel1 {
		t.Fatalf("the S-CSCF got %s with Route %v (%v)", got.URI.String(), routes, err)
	}
	if !strings.HasPrefix(routes[0].URI.String(), scscf.uri()) {
		t.Errorf("Route = %s, want the S-CSCF's", routes[0].URI.String())
	}
}

func TestAnUnknownUserIsNotFoundAndAnUnregisteredOneUnavailable(t *testing.T) {
	hss := startHSS(t)
	var result atomic.Uint32
	hss.answer = func(uint32) (cx.Result, string) { return cx.ExperimentalResult(result.Load()), "" }
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI("sip:scscf.rcs.local;transport=tcp")}})
	r.waitReady(t)
	for _, tc := range []struct {
		result uint32
		want   int
	}{{cx.ErrorUserUnknown, 404}, {cx.ErrorIdentityNotRegistered, 480}} {
		result.Store(tc.result)
		if res := r.send(t, "MESSAGE", tel1, "From: <sip:+15550100002@"+home+">;tag=f1", "To: <"+tel1+">"); res.StatusCode != tc.want {
			t.Errorf("result %d: answered %d, want %d", tc.result, res.StatusCode, tc.want)
		}
	}
	result.Store(cx.ErrorUserUnknown)
	if res := r.send(t, "REGISTER", "sip:"+home, "From: <"+impu1+">;tag=f1", "To: <"+impu1+">"); res.StatusCode != 403 {
		t.Errorf("REGISTER for an unknown user answered %d, want 403", res.StatusCode)
	}
}

// Before any HSS task is connected, a request is answered 480 with
// Retry-After, and the readiness check names the HSS.
func TestWithoutAnHSSRequestsGet480WithRetryAfter(t *testing.T) {
	hss := startHSS(t)
	hss.answer = func(uint32) (cx.Result, string) { return cx.ResultCode(diameter.ResultSuccess), "" }
	_ = hss.node.Shutdown(context.Background())
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI("sip:scscf.rcs.local;transport=tcp")}})
	res := r.send(t, "MESSAGE", tel1, "From: <sip:+15550100002@"+home+">;tag=f1", "To: <"+tel1+">")
	if res.StatusCode != 480 || res.Header.Get("Retry-After") != "10" {
		t.Fatalf("answered %d with Retry-After %q, want 480 and 10", res.StatusCode, res.Header.Get("Retry-After"))
	}
	r.h.Advance(2 * time.Second)
	if code, body := r.h.Get("/readyz"); code != 503 || !strings.Contains(body, "hss") {
		t.Errorf("/readyz = %d %s, want 503 naming hss", code, body)
	}
}

func TestTheOriginHostIsDrawnAtStartOrConfigured(t *testing.T) {
	rt := runtimetest.New(t, "icscf").Runtime
	cfg := ServiceConfig{Namespace: "rcs.local", OriginRealm: home, HSSRealm: home, HSSDiscovery: DiscoveryDNS, CxTimeout: time.Second}
	c, host, err := newCxClient(context.Background(), rt, cfg, deps{rand: constantBytes(0x0c), discovery: staticDiscovery{}})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close(context.Background())
	if host != "icscf-0c0c0c0c0c0c.rcs.local" {
		t.Errorf("Origin-Host = %q", host)
	}
	cfg.OriginHost = "icscf-fixed.rcs.local"
	c, host, err = newCxClient(context.Background(), rt, cfg, deps{rand: constantBytes(0x0c), discovery: staticDiscovery{}})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close(context.Background())
	if host != "icscf-fixed.rcs.local" {
		t.Errorf("Origin-Host = %q, want the configured one", host)
	}
	if _, _, err := newCxClient(context.Background(), rt, ServiceConfig{Namespace: "rcs.local", HSSRealm: home}, deps{rand: failingReader{}}); err == nil {
		t.Error("no error without randomness for the Origin-Host")
	}
}

// Threat model T1: a Diameter peer on the HSS's address whose Origin-Host is
// not hss-*.<namespace> gets no request, so icscf does not become ready and
// answers as without an HSS.
func TestAPeerThatIsNotAnHSSTaskIsNotAsked(t *testing.T) {
	impostor := startHSSAs(t, "impostor.rcs.local")
	impostor.answer = func(uint32) (cx.Result, string) { return cx.ResultCode(diameter.ResultSuccess), "sip:192.0.2.66" }
	r := startICSCF(t, impostor, []SCSCF{{URI: mustURI("sip:scscf.rcs.local;transport=tcp")}})
	// icscf must have connected and seen the CEA, or the test would pass
	// for a peer it never reached (review of #276).
	deadline := time.Now().Add(realWait)
	for impostor.ln.accepted.Load() == 0 || len(impostor.node.Peers()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("icscf never connected to the peer")
		}
		time.Sleep(10 * time.Millisecond)
	}
	res := r.send(t, "MESSAGE", tel1, "From: <sip:+15550100002@"+home+">;tag=f1", "To: <"+tel1+">")
	if res.StatusCode != 480 {
		t.Fatalf("answered %d, want 480", res.StatusCode)
	}
	if got := impostor.commands(); len(got) != 0 {
		t.Errorf("the impostor got %v", got)
	}
	r.h.Advance(2 * time.Second)
	if code, _ := r.h.Get("/readyz"); code != 503 {
		t.Errorf("/readyz = %d with only an impostor, want 503", code)
	}
}

// Review of #274, for this PR: a Route naming icscf by its Cloud Map name,
// as pcscf (PCSCF_ICSCF_URI, sip:icscf.<namespace>;transport=tcp;lr) and
// scscf put it, is icscf's own, so it is consumed and the request looked up,
// not forwarded back to icscf itself (482 Loop Detected).
func TestARouteNamingIcscfByItsServiceNameIsItsOwn(t *testing.T) {
	hss := startHSS(t)
	scscf := startSCSCF(t)
	hss.answer = func(uint32) (cx.Result, string) { return cx.ResultCode(diameter.ResultSuccess), scscf.uri() }
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI(scscf.uri())}})
	r.waitReady(t)
	route := fmt.Sprintf("Route: <sip:icscf.rcs.local:%d;transport=tcp;lr>", r.core.Port())
	res := r.send(t, "MESSAGE", tel1, "From: <sip:+15550100002@"+home+">;tag=f1", "To: <"+tel1+">", route)
	if res.StatusCode != 200 {
		t.Fatalf("answered %d", res.StatusCode)
	}
	got := scscf.next(t)
	routes, err := got.Header.Route()
	if err != nil || len(routes) != 1 || !strings.HasPrefix(routes[0].URI.String(), scscf.uri()) {
		t.Fatalf("the S-CSCF got Route %v (%v), want only its own", routes, err)
	}
	if cmds := hss.commands(); len(cmds) != 1 || cmds[0] != cx.CodeLocationInfo {
		t.Errorf("the HSS got %v, want one LIR", cmds)
	}
}

// selfURIs names icscf by its address and its Cloud Map name, on its port.
func TestIcscfKnowsItselfByItsAddressAndItsServiceName(t *testing.T) {
	cfg := ServiceConfig{Namespace: "rcs.local", CoreHost: netip.MustParseAddr("10.0.3.9")}
	var got []string
	for _, u := range selfURIs(cfg, 5060) {
		got = append(got, u.String())
	}
	if want := []string{"sip:10.0.3.9:5060;lr", "sip:icscf.rcs.local:5060;lr"}; strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("Self = %v, want %v", got, want)
	}
}

// Review of #274: the HSS names the S-CSCF without the transport and port
// ICSCF_SCSCF gives (sip:scscf.<namespace> in production); the request
// still reaches it on the configured TCP port.
func TestANameWithoutTransportOrPortReachesTheConfiguredSCSCF(t *testing.T) {
	hss := startHSS(t)
	scscf := startSCSCF(t)
	hss.answer = func(uint32) (cx.Result, string) {
		return cx.ExperimentalResult(cx.SubsequentRegistration), "sip:127.0.0.1"
	}
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI(scscf.uri())}})
	r.waitReady(t)
	res := r.send(t, "REGISTER", "sip:"+home, "From: <"+impu1+">;tag=f1", "To: <"+impu1+">")
	if res.StatusCode != 200 {
		t.Fatalf("REGISTER answered %d", res.StatusCode)
	}
	if got := scscf.next(t); got.URI.String() != scscf.uri() {
		t.Errorf("the S-CSCF got %s, want the configured %s", got.URI.String(), scscf.uri())
	}
}
