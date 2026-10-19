package pcscf

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

const (
	aliceIMPU = "sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org"
	homeURI   = "sip:ims.mnc001.mcc001.3gppnetwork.org"
	aliceTel  = "tel:+15550100001"
)

// registerText is a REGISTER from a client; contact and extra are written as
// they are.
func registerText(contact string, extra ...string) string {
	var b strings.Builder
	b.WriteString("REGISTER " + homeURI + " SIP/2.0\r\n")
	b.WriteString("Via: SIP/2.0/TCP 192.0.2.10:40000;branch=z9hG4bK-reg-1\r\n")
	b.WriteString("Max-Forwards: 70\r\n")
	b.WriteString("From: <" + aliceIMPU + ">;tag=r1\r\n")
	b.WriteString("To: <" + aliceIMPU + ">\r\n")
	b.WriteString("Call-ID: reg-1\r\nCSeq: 1 REGISTER\r\n")
	if contact != "" {
		b.WriteString("Contact: " + contact + "\r\n")
	}
	for _, e := range extra {
		b.WriteString(e + "\r\n")
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	return b.String()
}

func parseRequest(t *testing.T, text string) *sip.Request {
	t.Helper()
	m, err := sip.ParseMessage([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return m.(*sip.Request)
}

func parseResponse(t *testing.T, text string) *sip.Response {
	t.Helper()
	m, err := sip.ParseMessage([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return m.(*sip.Response)
}

// okText is a 200 to registerText with the given Contact and extra fields.
func okText(contact string, extra ...string) string {
	var b strings.Builder
	b.WriteString("SIP/2.0 200 OK\r\n")
	b.WriteString("Via: SIP/2.0/TCP 192.0.2.10:40000;branch=z9hG4bK-reg-1\r\n")
	b.WriteString("From: <" + aliceIMPU + ">;tag=r1\r\n")
	b.WriteString("To: <" + aliceIMPU + ">;tag=s1\r\n")
	b.WriteString("Call-ID: reg-1\r\nCSeq: 1 REGISTER\r\n")
	if contact != "" {
		b.WriteString("Contact: " + contact + "\r\n")
	}
	for _, e := range extra {
		b.WriteString(e + "\r\n")
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	return b.String()
}

// idleSet records the idle timeouts set on flows.
type idleSet map[transport.FlowID]time.Duration

func (s idleSet) SetFlowIdleTimeout(id transport.FlowID, d time.Duration) bool {
	s[id] = d
	return true
}

type testClock struct{ t time.Time }

func (c *testClock) now() time.Time { return c.t }

func newTestPcscf(clock *testClock) (*pcscf, idleSet) {
	idle := idleSet{}
	cfg := testConfig()
	cfg.CoreHost = netip.MustParseAddr("10.0.2.9")
	return &pcscf{
		cfg: cfg, corePort: 5070,
		registry:  newRegistry(cfg.MaxRegistrations, clock.now),
		registers: newLimiter(cfg.RegisterRate, cfg.RegisterBurst, clock.now),
		flows:     idle, now: clock.now, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, idle
}

const outboundContact = `<sip:alice@192.0.2.10:40000;transport=tcp>;+sip.instance="<urn:uuid:00000000-0000-1000-8000-000000000001>";reg-id=1`

func clientRequest(t *testing.T, text string, flow transport.FlowID) *proxy.Request {
	return &proxy.Request{Message: parseRequest(t, text), Source: transport.Source{
		Flow: flow, Network: transport.TCP, Addr: netip.MustParseAddrPort("192.0.2.10:40000"), Listener: clientListener}}
}

// A REGISTER goes to icscf with Path naming this task's core listener and the
// flow, ob for outbound, Supported: path, and no network-only header (TS
// 24.229 §5.2.2.1, RFC 5626 §5.1).
func TestARegisterGoesToICSCFWithAPathNamingTheFlow(t *testing.T) {
	p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
	r := clientRequest(t, registerText(outboundContact, "Supported: outbound", "P-Asserted-Identity: <"+aliceIMPU+">"), "FLOWTOKEN1")
	d := p.Route(context.Background(), r)
	if len(d.Targets) != 1 || d.Targets[0].URI.String() != homeURI || len(d.Targets[0].Routes) != 1 || d.Targets[0].Routes[0].URI.String() != p.cfg.ICSCF.String() {
		t.Fatalf("decision %+v", d)
	}
	req := r.Message.Clone()
	if err := d.Prepare(context.Background(), d.Targets[0], req); err != nil {
		t.Fatal(err)
	}
	if got, want := req.Header.Get("Path"), "<sip:FLOWTOKEN1@10.0.2.9:5070;transport=tcp;lr;ob>"; got != want {
		t.Errorf("Path %q, want %q", got, want)
	}
	if !hasOption(req.Header.Supported, "path") || !hasOption(req.Header.Supported, "outbound") {
		t.Errorf("Supported %q", req.Header.Values("Supported"))
	}
	if req.Header.Has("P-Asserted-Identity") {
		t.Error("the client's P-Asserted-Identity was forwarded")
	}
	// Outbound keeps the flow alive, so the expiry is the client's.
	if c, _ := req.Header.Contact(); strings.Contains(c[0].String(), "expires") || req.Header.Has("Expires") {
		t.Errorf("an outbound client's expiry was changed: %q", req.Header.Get("Contact"))
	}
	if strings.Contains(r.Message.Header.Get("Path"), "FLOW") {
		t.Error("Prepare changed the shared request")
	}
}

// A client that keeps no keep-alive has its REGISTER capped before it goes
// to icscf; one with Via keep has not.
func TestPrepareCapsTheExpiryOfAClientWithoutKeepAlive(t *testing.T) {
	p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
	for _, tt := range []struct{ name, via, want string }{{"none", "", "600"}, {"Via keep", ";keep", "3600"}} {
		text := strings.Replace(registerText("<sip:alice@192.0.2.10:40000>", "Expires: 3600"), "branch=z9hG4bK-reg-1", "branch=z9hG4bK-reg-1"+tt.via, 1)
		r := clientRequest(t, text, "F")
		d := p.Route(context.Background(), r)
		req := r.Message.Clone()
		if err := d.Prepare(context.Background(), d.Targets[0], req); err != nil {
			t.Fatal(err)
		}
		if got := req.Header.Get("Expires"); got != tt.want {
			t.Errorf("%s: Expires %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestAClientWithoutOutboundGetsAPathWithoutOb(t *testing.T) {
	p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
	for _, tt := range []struct{ name, contact, extra string }{
		{"no Supported", outboundContact, ""},
		{"no reg-id", `<sip:alice@192.0.2.10:40000;transport=tcp>;+sip.instance="<urn:uuid:00000000-0000-1000-8000-000000000001>"`, "Supported: outbound"},
		{"no instance", `<sip:alice@192.0.2.10:40000;transport=tcp>;reg-id=1`, "Supported: outbound"},
		{"wildcard", "*", "Supported: outbound"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			extra := []string{"Expires: 0"}
			if tt.extra != "" {
				extra = append(extra, tt.extra)
			}
			r := clientRequest(t, registerText(tt.contact, extra...), "F")
			d := p.Route(context.Background(), r)
			req := r.Message.Clone()
			if err := d.Prepare(context.Background(), d.Targets[0], req); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(req.Header.Get("Path"), ";ob") {
				t.Errorf("Path %q has ob", req.Header.Get("Path"))
			}
		})
	}
}

// A client that keeps no keep-alive registers for at most 600 s, in the
// REGISTER and in the 200 (ADR 0003).
func TestExpiriesAreCappedWithoutKeepAlive(t *testing.T) {
	for _, tt := range []struct {
		name, contact string
		extra         []string
		wantContact   string
		wantExpires   string
	}{
		{"default", "<sip:alice@192.0.2.10:40000>", nil, "<sip:alice@192.0.2.10:40000>;expires=600", ""},
		{"header", "<sip:alice@192.0.2.10:40000>", []string{"Expires: 7200"}, "<sip:alice@192.0.2.10:40000>;expires=600", "600"},
		{"short header", "<sip:alice@192.0.2.10:40000>", []string{"Expires: 300"}, "<sip:alice@192.0.2.10:40000>", "300"},
		{"parameter", "<sip:alice@192.0.2.10:40000>;expires=3600", nil, "<sip:alice@192.0.2.10:40000>;expires=600", ""},
		{"short parameter", "<sip:alice@192.0.2.10:40000>;expires=120", []string{"Expires: 3600"}, "<sip:alice@192.0.2.10:40000>;expires=120", "600"},
		{"just over", "<sip:alice@192.0.2.10:40000>;expires=601", nil, "<sip:alice@192.0.2.10:40000>;expires=600", ""},
		{"at the cap", "<sip:alice@192.0.2.10:40000>;expires=600", nil, "<sip:alice@192.0.2.10:40000>;expires=600", ""},
		{"removal", "<sip:alice@192.0.2.10:40000>;expires=0", nil, "<sip:alice@192.0.2.10:40000>;expires=0", ""},
		{"wildcard", "*", []string{"Expires: 0"}, "*", "0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := parseRequest(t, registerText(tt.contact, tt.extra...))
			if err := capExpires(&req.Header, 600); err != nil {
				t.Fatal(err)
			}
			if got := req.Header.Get("Contact"); got != tt.wantContact {
				t.Errorf("Contact %q, want %q", got, tt.wantContact)
			}
			if got := req.Header.Get("Expires"); got != tt.wantExpires {
				t.Errorf("Expires %q, want %q", got, tt.wantExpires)
			}
		})
	}
	req := parseRequest(t, registerText("<sip:alice@192.0.2.10:40000>", "Expires: soon"))
	if err := capExpires(&req.Header, 600); err == nil {
		t.Error("a malformed Expires was accepted")
	}
}

// The 200 is remembered for the flow: the client's contacts, Service-Route,
// P-Associated-URI and the expiry; an outbound client is told the
// Flow-Timer, and its flow's idle timeout is set to match (RFC 5626 §4.4).
func TestThe200IsRememberedAndTellsAnOutboundClientItsFlowTimer(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	p, idle := newTestPcscf(clock)
	r := clientRequest(t, registerText(outboundContact, "Supported: outbound"), "FLOW-A")
	d := p.Route(context.Background(), r)
	res := parseResponse(t, okText(outboundContact+";expires=3600, <sip:other@198.51.100.4>;expires=3600",
		"Service-Route: <sip:orig@scscf.rcs.internal;lr>",
		"P-Associated-URI: <"+aliceIMPU+">, <"+aliceTel+">"))
	d.OnResponse(context.Background(), res)
	reg, ok := p.registry.lookup("FLOW-A", aorKey(mustURI(t, aliceIMPU)))
	if !ok {
		t.Fatal("no registration kept")
	}
	if len(reg.contacts) != 1 || reg.contacts[0].URI.User != "alice" || !reg.outbound || !reg.keepAlive {
		t.Errorf("contacts %v outbound %v keep-alive %v", reg.contacts, reg.outbound, reg.keepAlive)
	}
	if len(reg.serviceRoute) != 1 || reg.serviceRoute[0].URI.Host != "scscf.rcs.internal" || len(reg.associated) != 2 || reg.associated[1].URI.String() != aliceTel {
		t.Errorf("Service-Route %v, P-Associated-URI %v", reg.serviceRoute, reg.associated)
	}
	if !reg.expires.Equal(clock.t.Add(time.Hour)) {
		t.Errorf("expires %v", reg.expires)
	}
	if res.Header.Get("Flow-Timer") != "120" || !hasOption(res.Header.Require, "outbound") {
		t.Errorf("Flow-Timer %q, Require %q", res.Header.Get("Flow-Timer"), res.Header.Values("Require"))
	}
	if idle["FLOW-A"] != keepAliveIdleTCP {
		t.Errorf("idle timeout %v, want %v on TCP", idle["FLOW-A"], keepAliveIdleTCP)
	}
	// The registration lapses at its expiry.
	clock.t = clock.t.Add(time.Hour)
	if _, ok := p.registry.lookup("FLOW-A", aorKey(mustURI(t, aliceIMPU))); ok {
		t.Error("an expired registration was found")
	}
}

func TestKeepAliveDecidesTheIdleTimeoutAndTheViaKeep(t *testing.T) {
	for _, tt := range []struct {
		name      string
		transport string
		via       string
		contact   string
		extra     []string
		wantIdle  time.Duration
		wantVia   string
		wantTimer bool
	}{
		{"outbound over NLB TLS", ClientNLBTLS, "", outboundContact, []string{"Supported: outbound"}, keepAliveIdleTLS, "", true},
		{"Via keep over TLS", ClientTLS, ";keep", "<sip:alice@192.0.2.10:40000>", nil, keepAliveIdleTLS, "keep=120", false},
		{"no keep-alive", ClientNLBTLS, "", "<sip:alice@192.0.2.10:40000>", nil, DefaultClientIdleTimeout, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, idle := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
			p.cfg.ClientTransport = tt.transport
			text := strings.Replace(registerText(tt.contact, tt.extra...), "branch=z9hG4bK-reg-1", "branch=z9hG4bK-reg-1"+tt.via, 1)
			d := p.Route(context.Background(), clientRequest(t, text, "F"))
			res := strings.Replace(okText(tt.contact+";expires=3600"), "branch=z9hG4bK-reg-1", "branch=z9hG4bK-reg-1"+tt.via, 1)
			ok := parseResponse(t, res)
			d.OnResponse(context.Background(), ok)
			if idle["F"] != tt.wantIdle {
				t.Errorf("idle %v, want %v", idle["F"], tt.wantIdle)
			}
			if v := ok.Header.Get("Via"); tt.wantVia != "" && !strings.Contains(v, tt.wantVia) || tt.wantVia == "" && strings.Contains(v, "keep=") {
				t.Errorf("Via %q, want %q", v, tt.wantVia)
			}
			if ok.Header.Has("Flow-Timer") != tt.wantTimer {
				t.Errorf("Flow-Timer %q", ok.Header.Get("Flow-Timer"))
			}
			if tt.wantIdle == DefaultClientIdleTimeout && !strings.Contains(ok.Header.Get("Contact"), "expires=600") {
				t.Errorf("Contact %q, want the expiry capped to 600", ok.Header.Get("Contact"))
			}
		})
	}
}

// A 200 that lists none of the client's contacts on this flow, after a
// removal, forgets the registration; a provisional or failure response
// changes nothing.
func TestARemovalForgetsTheRegistration(t *testing.T) {
	p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
	key := aorKey(mustURI(t, aliceIMPU))
	d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact, "Supported: outbound"), "F"))
	d.OnResponse(context.Background(), parseResponse(t, okText(outboundContact+";expires=3600")))
	if p.registry.size() != 1 {
		t.Fatal("not registered")
	}
	d = p.Route(context.Background(), clientRequest(t, registerText(outboundContact+";expires=0", "Supported: outbound"), "F"))
	d.OnResponse(context.Background(), parseResponse(t, strings.Replace(okText(outboundContact+";expires=3600"), "200 OK", "401 Unauthorized", 1)))
	if _, ok := p.registry.lookup("F", key); !ok {
		t.Fatal("a 401 removed the registration")
	}
	d.OnResponse(context.Background(), parseResponse(t, okText("")))
	if _, ok := p.registry.lookup("F", key); ok || p.registry.size() != 0 {
		t.Fatal("the removal was not applied")
	}
}

// Only a 2xx registers: a challenge listing the contacts does not.
func TestAChallengeRegistersNothing(t *testing.T) {
	p, idle := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
	d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact, "Supported: outbound"), "F"))
	res := parseResponse(t, strings.Replace(okText(outboundContact+";expires=3600"), "200 OK", "401 Unauthorized", 1))
	d.OnResponse(context.Background(), res)
	if p.registry.size() != 0 || len(idle) != 0 || res.Header.Has("Flow-Timer") {
		t.Fatalf("a 401 registered: size %d, idle %v, Flow-Timer %q", p.registry.size(), idle, res.Header.Get("Flow-Timer"))
	}
}

// REGISTERs of one client address beyond the rate are answered 503 with
// Retry-After, and so is a new registration once the registry is full.
func TestRegistersAreRefusedPastTheRateAndTheRegistrySize(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	p, _ := newTestPcscf(clock)
	p.registers = newLimiter(1, 2, clock.now)
	for i := range 3 {
		d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact), "F"))
		if refused := d.Response != nil; refused != (i == 2) {
			t.Fatalf("REGISTER %d refused %v", i, refused)
		}
		if d.Response != nil && (d.Response.StatusCode != 503 || d.Response.Header.Get("Retry-After") != "1") {
			t.Fatalf("refusal %d %q", d.Response.StatusCode, d.Response.Header.Get("Retry-After"))
		}
	}
	clock.t = clock.t.Add(time.Second)
	if d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact), "F")); d.Response != nil {
		t.Fatal("the bucket did not refill")
	}

	p, _ = newTestPcscf(clock)
	p.registry = newRegistry(1, clock.now)
	d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact), "F1"))
	d.OnResponse(context.Background(), parseResponse(t, okText(outboundContact+";expires=3600")))
	if d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact), "F2")); d.Response == nil || d.Response.StatusCode != 503 {
		t.Fatalf("a registration past the size was routed: %+v", d)
	}
	// The registration already kept may still refresh.
	if d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact), "F1")); d.Response != nil {
		t.Fatal("a refresh was refused")
	}
}

func TestMalformedRegistersAreAnswered400(t *testing.T) {
	p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
	bad := registerText("<sip:alice@192.0.2.10>")
	for name, text := range map[string]string{
		"To":      strings.Replace(bad, "To: <"+aliceIMPU+">", "To: <<", 1),
		"Contact": strings.Replace(bad, "Contact: <sip:alice@192.0.2.10>", "Contact: <sip:a>,,<", 1),
	} {
		r := &proxy.Request{Message: parseRequest(t, text), Source: transport.Source{Flow: "F", Listener: clientListener, Addr: netip.MustParseAddrPort("192.0.2.10:1")}}
		if d := p.Route(context.Background(), r); d.Status != 400 {
			t.Errorf("%s: decision %+v", name, d)
		}
	}
}
