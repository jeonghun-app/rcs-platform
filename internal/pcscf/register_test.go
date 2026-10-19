package pcscf

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand/v2"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
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

// icscfAt is an allResolver that finds icscf at the given addresses, in
// that order, through the core listener; none is a failed lookup.
type icscfAt []string

func (a icscfAt) ResolveAll(context.Context, sip.URI) ([]transport.Destination, error) {
	if len(a) == 0 {
		return nil, proxy.ErrUnresolvable
	}
	var out []transport.Destination
	for _, addr := range a {
		out = append(out, transport.Destination{Network: transport.TCP, Addr: netip.MustParseAddrPort(addr), Listener: coreListener})
	}
	return out, nil
}

func newTestPcscf(clock *testClock) (*pcscf, idleSet) {
	idle := idleSet{}
	cfg := testConfig()
	cfg.CoreHost = netip.MustParseAddr("10.0.2.9")
	return &pcscf{
		cfg: cfg, corePort: 5070,
		registry:     newRegistry(cfg.MaxRegistrations, clock.now),
		registers:    newLimiter(cfg.RegisterRate, cfg.RegisterBurst, clock.now),
		allRegisters: newTaskLimit(cfg.MaxRegisterRate, cfg.MaxRegisterBurst, clock.now),
		icscfFirst:   icscfFirstTimeout, icscfTotal: icscfTotalTimeout,
		icscfs: icscfAt{"10.0.3.7:5060", "10.0.3.8:5060", "10.0.3.9:5060", "10.0.3.10:5060"}, rand: seededRand(),
		flows: idle, now: clock.now, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, idle
}

func seededRand() io.Reader { return mrand.NewChaCha8([32]byte{16}) }

// prepared is the request d forwards to its first target.
func prepared(t *testing.T, d proxy.Decision, r *proxy.Request) *sip.Request {
	t.Helper()
	if len(d.Targets) == 0 || d.Prepare == nil {
		t.Fatalf("decision %+v", d)
	}
	req := r.Message.Clone()
	if err := d.Prepare(context.Background(), d.Targets[0], req); err != nil {
		t.Fatal(err)
	}
	return req
}

// icidValue is pcscf's P-Charging-Vector: a new icid, and the home domain
// as the type 1 orig-ioi.
var icidValue = regexp.MustCompile(`^icid-value=[0-9a-f]{32};orig-ioi=ims\.mnc001\.mcc001\.3gppnetwork\.org$`)

const outboundContact = `<sip:alice@192.0.2.10:40000;transport=tcp>;+sip.instance="<urn:uuid:00000000-0000-1000-8000-000000000001>";reg-id=1`

func clientRequest(t *testing.T, text string, flow transport.FlowID) *proxy.Request {
	return &proxy.Request{Message: parseRequest(t, text), Source: transport.Source{
		Flow: flow, Network: transport.TCP, Addr: netip.MustParseAddrPort("192.0.2.10:40000"), Listener: clientListener}}
}

// A REGISTER goes to the first icscf address with icscf as its only Route,
// Path naming this task's core listener and the flow, ob for outbound,
// Require: path, the visited network and a new charging identifier (TS
// 24.229 §5.2.2.1, RFC 5626 §5.1).
func TestARegisterGoesToICSCFWithAPathNamingTheFlow(t *testing.T) {
	p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
	r := clientRequest(t, registerText(outboundContact, "Supported: outbound", "Route: <sip:10.0.9.9;lr>"), "FLOWTOKEN1")
	d := p.Route(context.Background(), r)
	if len(d.Targets) != 1 || d.Targets[0].URI.String() != homeURI || d.Targets[0].Destination == nil ||
		d.Targets[0].Destination.Addr.String() != "10.0.3.7:5060" || d.Targets[0].Destination.Listener != coreListener || d.Targets[0].Timeout != icscfFirstTimeout {
		t.Fatalf("decision %+v", d)
	}
	req := prepared(t, d, r)
	if got := req.Header.Values("Route"); !slices.Equal(got, []string{"<" + p.cfg.ICSCF.String() + ">"}) {
		t.Errorf("Route %q, want icscf alone", got)
	}
	if got, want := req.Header.Get("Path"), "<sip:FLOWTOKEN1@10.0.2.9:5070;transport=tcp;lr;ob>"; got != want {
		t.Errorf("Path %q, want %q", got, want)
	}
	// Supported: path is the client's to say (RFC 3327 §5.2).
	if !hasOption(req.Header.Require, "path") || hasOption(req.Header.Supported, "path") || !hasOption(req.Header.Supported, "outbound") {
		t.Errorf("Require %q, Supported %q", req.Header.Values("Require"), req.Header.Values("Supported"))
	}
	if got := req.Header.Get("P-Visited-Network-ID"); got != p.cfg.VisitedNetworkID {
		t.Errorf("P-Visited-Network-ID %q", got)
	}
	// The configured visited network, not the home domain (QA of #198).
	p.cfg.VisitedNetworkID = "visited.example.net"
	if got := prepared(t, p.Route(context.Background(), r), r).Header.Get("P-Visited-Network-ID"); got != "visited.example.net" {
		t.Errorf("P-Visited-Network-ID %q, want PCSCF_VISITED_NETWORK_ID", got)
	}
	first := req.Header.Get("P-Charging-Vector")
	if !icidValue.MatchString(first) {
		t.Errorf("P-Charging-Vector %q", first)
	}
	if again := prepared(t, p.Route(context.Background(), r), r).Header.Get("P-Charging-Vector"); again == first || !icidValue.MatchString(again) {
		t.Errorf("second P-Charging-Vector %q after %q", again, first)
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
		{"Via keep only", "<sip:alice@192.0.2.10:40000;transport=tcp>", "Via keep"},
		{"no Contact", "", "Supported: outbound"},
		{"no reg-id", `<sip:alice@192.0.2.10:40000;transport=tcp>;+sip.instance="<urn:uuid:00000000-0000-1000-8000-000000000001>"`, "Supported: outbound"},
		{"no instance", `<sip:alice@192.0.2.10:40000;transport=tcp>;reg-id=1`, "Supported: outbound"},
		{"wildcard", "*", "Supported: outbound"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			extra := []string{"Expires: 0"}
			if tt.extra != "" && tt.extra != "Via keep" {
				extra = append(extra, tt.extra)
			}
			text := registerText(tt.contact, extra...)
			if tt.extra == "Via keep" {
				text = strings.Replace(text, "branch=z9hG4bK-reg-1", "branch=z9hG4bK-reg-1;keep", 1)
			}
			r := clientRequest(t, text, "F")
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
		{"header just over", "<sip:alice@192.0.2.10:40000>", []string{"Expires: 601"}, "<sip:alice@192.0.2.10:40000>;expires=600", "600"},
		{"header at the cap", "<sip:alice@192.0.2.10:40000>", []string{"Expires: 600"}, "<sip:alice@192.0.2.10:40000>", "600"},
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
	res := parseResponse(t, okText(outboundContact+";expires=3600, <sip:other@198.51.100.4>;expires=3600", "Require: outbound",
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
	if res.Header.Get("Flow-Timer") != "120" || !slices.Equal(res.Header.Values("Require"), []string{"outbound"}) {
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
		{"outbound by Require", ClientNLBTLS, "", outboundContact, []string{"Require: outbound"}, keepAliveIdleTLS, "", true},
		{"Via keep over TLS", ClientTLS, ";keep", "<sip:alice@192.0.2.10:40000>", nil, keepAliveIdleTLS, "keep=120", false},
		{"no keep-alive", ClientNLBTLS, "", "<sip:alice@192.0.2.10:40000>", nil, DefaultClientIdleTimeout, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, idle := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
			p.cfg.ClientTransport = tt.transport
			text := strings.Replace(registerText(tt.contact, tt.extra...), "branch=z9hG4bK-reg-1", "branch=z9hG4bK-reg-1"+tt.via, 1)
			d := p.Route(context.Background(), clientRequest(t, text, "F"))
			var require []string
			if tt.wantTimer {
				// The registrar applied outbound (RFC 5626 §5.4).
				require = []string{"Require: outbound"}
			}
			res := strings.Replace(okText(tt.contact+";expires=3600", require...), "branch=z9hG4bK-reg-1", "branch=z9hG4bK-reg-1"+tt.via, 1)
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

// A registrar that does not apply outbound leaves Require: outbound out of
// its 200 (RFC 5626 §5.4): the client then has no keep-alive, gets no
// Flow-Timer and is capped like any client without one, and pcscf does not
// claim outbound for the registrar.
func TestOutboundIsWhatTheRegistrarApplied(t *testing.T) {
	p, idle := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
	d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact, "Supported: outbound"), "F"))
	res := parseResponse(t, okText(outboundContact+";expires=3600"))
	d.OnResponse(context.Background(), res)
	if res.Header.Has("Flow-Timer") || hasOption(res.Header.Require, "outbound") || !strings.Contains(res.Header.Get("Contact"), "expires=600") {
		t.Errorf("Flow-Timer %q, Require %q, Contact %q", res.Header.Get("Flow-Timer"), res.Header.Values("Require"), res.Header.Get("Contact"))
	}
	reg, ok := p.registry.lookup("F", aorKey(mustURI(t, aliceIMPU)))
	if !ok || reg.outbound || reg.keepAlive || idle["F"] != DefaultClientIdleTimeout {
		t.Errorf("registration %+v, idle %v", reg, idle["F"])
	}
}

// A REGISTER without Contact fetches the bindings (RFC 3261 §10.2.3, TS
// 24.229 §5.2.2.1): the registration stays as it is (reviews of #198).
func TestABindingFetchKeepsTheRegistration(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	p, _ := newTestPcscf(clock)
	key := aorKey(mustURI(t, aliceIMPU))
	d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact, "Supported: outbound"), "F"))
	d.OnResponse(context.Background(), parseResponse(t, okText(outboundContact+";expires=3600", "Require: outbound")))
	d = p.Route(context.Background(), clientRequest(t, registerText(""), "F"))
	if d.Response != nil || d.Status != 0 {
		t.Fatalf("the fetch was refused: %+v", d)
	}
	d.OnResponse(context.Background(), parseResponse(t, okText(outboundContact+";expires=1800")))
	reg, ok := p.registry.lookup("F", key)
	if !ok || !reg.expires.Equal(clock.t.Add(time.Hour)) || p.registry.size() != 1 {
		t.Fatalf("after a fetch: %+v, %v, size %d", reg, ok, p.registry.size())
	}
}

// closedFlows is a flowSetter whose flows have all closed.
type closedFlows struct{}

func (closedFlows) SetFlowIdleTimeout(transport.FlowID, time.Duration) bool { return false }

// A 200 that comes back after its client's flow closed keeps nothing:
// OnFlowClosed ran before there was a registration to remove (QA of #198).
func TestA200AfterItsFlowClosedKeepsNothing(t *testing.T) {
	p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
	p.flows = closedFlows{}
	d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact, "Supported: outbound"), "GONE"))
	d.OnResponse(context.Background(), parseResponse(t, okText(outboundContact+";expires=600000", "Require: outbound")))
	if _, ok := p.registry.lookup("GONE", aorKey(mustURI(t, aliceIMPU))); ok || p.registry.size() != 0 {
		t.Fatalf("a closed flow's registration was kept: size %d", p.registry.size())
	}
}

// The last registry slot goes to the first REGISTER for it, before either is
// forwarded, so no client gets a 200 that pcscf keeps nothing for; it is
// free again once that REGISTER ends without registering (QA of #198).
func TestTheLastSlotGoesToTheFirstRegister(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	p, _ := newTestPcscf(clock)
	p.registry = newRegistry(1, clock.now)
	d1 := p.Route(context.Background(), clientRequest(t, registerText(outboundContact), "F1"))
	d2 := p.Route(context.Background(), clientRequest(t, registerText(outboundContact), "F2"))
	if d1.Response != nil || d2.Response == nil || d2.Response.StatusCode != 503 || d2.Response.Header.Get("Retry-After") != "1" {
		t.Fatalf("first %+v, second %+v", d1, d2)
	}
	d1.OnResponse(context.Background(), parseResponse(t, strings.Replace(okText(outboundContact), "200 OK", "401 Unauthorized", 1)))
	if d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact), "F2")); d.Response != nil {
		t.Fatal("the slot was not freed by the 401")
	}
}

// The REGISTER limit counts an IPv6 client by its /64, as the flow limit
// does (QA of #198).
func TestTheRegisterLimitCountsAnIPv6ClientByItsSlash64(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	p, _ := newTestPcscf(clock)
	p.registers = newLimiter(1, 1, clock.now)
	allowed := func(addr string) bool {
		r := clientRequest(t, registerText(outboundContact), "F")
		r.Source.Addr = netip.MustParseAddrPort(addr)
		return p.Route(context.Background(), r).Response == nil
	}
	if !allowed("[2001:db8:1:2::1]:1") || allowed("[2001:db8:1:2::99]:1") || !allowed("[2001:db8:1:3::1]:1") {
		t.Fatal("the bucket is not per /64")
	}
}

// The registration lasts as long as the shortest of its contacts, and a
// contact the 200 lists with expires=0 is not one of them.
func TestTheRegistrationLastsAsLongAsItsShortestContact(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	p, _ := newTestPcscf(clock)
	second := `<sip:alice2@192.0.2.10:40000;transport=tcp>;+sip.instance="<urn:uuid:00000000-0000-1000-8000-000000000001>";reg-id=2`
	d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact+", "+second, "Supported: outbound"), "F"))
	d.OnResponse(context.Background(), parseResponse(t, okText(outboundContact+";expires=3600, "+second+";expires=1200", "Require: outbound")))
	reg, ok := p.registry.lookup("F", aorKey(mustURI(t, aliceIMPU)))
	if !ok || !reg.expires.Equal(clock.t.Add(1200*time.Second)) || len(reg.contacts) != 2 {
		t.Fatalf("registration %+v, %v", reg, ok)
	}
	d = p.Route(context.Background(), clientRequest(t, registerText(outboundContact, "Supported: outbound"), "F"))
	d.OnResponse(context.Background(), parseResponse(t, okText(outboundContact+";expires=0", "Require: outbound")))
	if p.registry.size() != 0 {
		t.Fatalf("a contact with expires=0 was kept: size %d", p.registry.size())
	}
}

// Only a 2xx registers, not a redirection either.
func TestARedirectionRegistersNothing(t *testing.T) {
	p, idle := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
	d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact, "Supported: outbound"), "F"))
	d.OnResponse(context.Background(), parseResponse(t, strings.Replace(okText(outboundContact+";expires=3600"), "200 OK", "302 Moved Temporarily", 1)))
	if p.registry.size() != 0 || len(idle) != 0 {
		t.Fatalf("a 302 registered: size %d", p.registry.size())
	}
}

// An icscf address that does not answer, fails or answers 3xx, 480 or 503
// gives way to the next, up to maxICSCFAttempts; after the last the client
// gets 504, and a failed lookup is 504 at once (TS 24.229 §5.2.2.1 7),
// review of #198).
func TestARegisterTriesTheNextICSCFAndEndsIn504(t *testing.T) {
	failure := func(t *testing.T, code int) proxy.BranchFailure {
		res := parseResponse(t, strings.Replace(okText(""), "200 OK", strconv.Itoa(code)+" "+sip.DefaultReason(code), 1))
		return proxy.BranchFailure{Response: res}
	}
	for _, code := range []int{408, 503, 480, 302} {
		p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
		d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact), "F"))
		var tried []string
		for range maxICSCFAttempts {
			next := d.OnBranchFailure(context.Background(), failure(t, code))
			if len(next) == 1 {
				tried = append(tried, next[0].Destination.Addr.String())
				// Failing at once, the next attempt has all the time left.
				if next[0].Timeout != icscfTotalTimeout || next[0].Destination.Listener != coreListener || next[0].URI.String() != homeURI {
					t.Errorf("%d: next target %+v", code, next[0])
				}
			}
		}
		if !slices.Equal(tried, []string{"10.0.3.8:5060", "10.0.3.9:5060"}) {
			t.Errorf("%d: tried %v after the first, want two more", code, tried)
		}
		res := failure(t, code).Response
		d.OnFinal(context.Background(), res)
		if res.StatusCode != 504 {
			t.Errorf("%d: the client got %d after every icscf", code, res.StatusCode)
		}
	}
	// An answer that is icscf's to give is passed on.
	p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
	d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact), "F"))
	if next := d.OnBranchFailure(context.Background(), failure(t, 403)); next != nil {
		t.Errorf("a 403 was retried: %+v", next)
	}
	res := failure(t, 403).Response
	if d.OnFinal(context.Background(), res); res.StatusCode != 403 {
		t.Errorf("a 403 became %d", res.StatusCode)
	}
	res = failure(t, 430).Response
	if d.OnFinal(context.Background(), res); res.StatusCode != 480 {
		t.Errorf("a 430 reached the client as %d", res.StatusCode)
	}
	p, _ = newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
	p.icscfs = icscfAt{}
	if d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact), "F")); d.Status != 504 || p.registry.size() != 0 {
		t.Errorf("a failed lookup: %+v, size %d", d, p.registry.size())
	}
}

// Production reaches private core addresses only, not loopback or the task
// metadata address (ADR 0007 §5).
func TestProductionCoreHopsArePrivateOnly(t *testing.T) {
	cfg := testConfig()
	cfg.AllowLoopback = false
	allow := allowCore(cfg)
	for addr, want := range map[string]bool{"10.0.3.7": true, "fd00::7": true, "127.0.0.1": false, "::1": false, "169.254.170.2": false, "198.51.100.7": false} {
		if allow(netip.MustParseAddr(addr)) != want {
			t.Errorf("%s allowed %v", addr, !want)
		}
	}
	cfg.AllowLoopback = true
	if !allowCore(cfg)(netip.MustParseAddr("127.0.0.1")) {
		t.Error("dev refuses loopback")
	}
}

// The first attempt at icscf may take 12 s, longer than the core's own
// retry of an HSS, and the next only what is left of 30 s, so the client's
// 504 comes before its Timer F (review of #198); a registry slot is held
// for longer than all of that.
func TestTheICSCFAttemptsShareThirtySeconds(t *testing.T) {
	if icscfFirstTimeout != 12*time.Second || icscfTotalTimeout != 30*time.Second || icscfTotalTimeout >= 32*time.Second {
		t.Fatalf("first %v, total %v", icscfFirstTimeout, icscfTotalTimeout)
	}
	if reservationHold < icscfTotalTimeout || reservationHold < maxICSCFAttempts*icscfFirstTimeout {
		t.Fatalf("reservationHold %v is shorter than the attempts", reservationHold)
	}
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	p, _ := newTestPcscf(clock)
	d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact), "F"))
	timeout := parseResponse(t, strings.Replace(okText(""), "200 OK", "408 Request Timeout", 1))
	clock.t = clock.t.Add(icscfFirstTimeout)
	next := d.OnBranchFailure(context.Background(), proxy.BranchFailure{Response: timeout})
	if len(next) != 1 || next[0].Timeout != 18*time.Second {
		t.Fatalf("second attempt %+v, want 18 s", next)
	}
	clock.t = clock.t.Add(18 * time.Second)
	if next := d.OnBranchFailure(context.Background(), proxy.BranchFailure{Response: timeout}); next != nil {
		t.Fatalf("a third attempt with no time left: %+v", next)
	}
	res := parseResponse(t, strings.Replace(okText(""), "200 OK", "408 Request Timeout", 1))
	if d.OnFinal(context.Background(), res); res.StatusCode != 504 {
		t.Fatalf("the client got %d", res.StatusCode)
	}
}

// registerAs is a REGISTER from 192.0.2.10 for identity n, over flow.
func registerAs(t *testing.T, n int, flow transport.FlowID) *proxy.Request {
	text := strings.ReplaceAll(registerText("<sip:x@192.0.2.10:40000>"), aliceIMPU, fmt.Sprintf("sip:user%d@ims.mnc001.mcc001.3gppnetwork.org", n))
	return clientRequest(t, text, flow)
}

// A flow may have REGISTERs under way for at most eight identities, and a
// client address, an IPv4 address or IPv6 /64, for at most
// PCSCF_MAX_PENDING_REGISTERS_PER_IP over all its flows: one writing new To
// values while the core is slow holds no more slots, and another client
// still registers (QA of #198).
func TestAClientHoldsAFewSlotsForUnansweredRegisters(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	p, _ := newTestPcscf(clock)
	p.registry = newRegistry(1000, clock.now)
	refused := func(d proxy.Decision) bool {
		if d.Response == nil {
			return false
		}
		if d.Response.StatusCode != 503 || d.Response.Header.Get("Retry-After") != "1" {
			t.Fatalf("refusal %d %q", d.Response.StatusCode, d.Response.Header.Get("Retry-After"))
		}
		return true
	}
	n := 0
	// The ninth identity of one flow is refused.
	for i := range maxPendingPerFlow + 1 {
		if refused(p.Route(context.Background(), registerAs(t, n, "BUSY-0"))) != (i == maxPendingPerFlow) {
			t.Fatalf("identity %d on one flow", i)
		}
		n++
	}
	// Nine flows from the address, eight identities each: the first 64 are
	// held, and from the 65th on they are refused.
	held := maxPendingPerFlow
	for f := 1; f < 9; f++ {
		for range maxPendingPerFlow {
			if refused(p.Route(context.Background(), registerAs(t, n, transport.FlowID(fmt.Sprint("BUSY-", f))))) != (held >= DefaultMaxPendingRegistersPerIP) {
				t.Fatalf("identity %d on flow %d, with %d held", n, f, held)
			}
			held = min(held+1, DefaultMaxPendingRegistersPerIP)
			n++
		}
	}
	if size := p.registry.size(); size != DefaultMaxPendingRegistersPerIP {
		t.Fatalf("%d slots held, want %d", size, DefaultMaxPendingRegistersPerIP)
	}
	// One already under way is not a new identity.
	if refused(p.Route(context.Background(), registerAs(t, 0, "BUSY-0"))) {
		t.Fatal("a retransmitted identity was refused")
	}
	// The same /64 is the same client.
	p.registry.perClient = 2
	for i := range 2 {
		r := registerAs(t, 1000+i, transport.FlowID(fmt.Sprint("V6-", i)))
		r.Source.Addr = netip.MustParseAddrPort("[2001:db8:1:2::1]:1")
		_ = p.Route(context.Background(), r)
	}
	r := registerAs(t, 1002, "V6-2")
	r.Source.Addr = netip.MustParseAddrPort("[2001:db8:1:2::99]:1")
	if !refused(p.Route(context.Background(), r)) {
		t.Fatal("another address of the same /64 got slots of its own")
	}
	other := clientRequest(t, registerText(outboundContact, "Supported: outbound"), "OTHER")
	other.Source.Addr = netip.MustParseAddrPort("192.0.2.11:40000")
	d := p.Route(context.Background(), other)
	if d.Response != nil {
		t.Fatalf("another client was refused: %+v", d.Response)
	}
	d.OnResponse(context.Background(), parseResponse(t, okText(outboundContact+";expires=3600", "Require: outbound")))
	if _, ok := p.registry.lookup("OTHER", aorKey(mustURI(t, aliceIMPU))); !ok {
		t.Fatal("not registered")
	}
}

// The REGISTERs of all clients together are bounded, and a refusal is
// counted (security review of #198). A REGISTER refused as malformed costs
// nothing, and a share is kept for refreshes of registrations the task
// holds, so new ones cannot use it all up.
func TestTheTaskBoundsTheRegistersOfAllClients(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	p, _ := newTestPcscf(clock)
	var out strings.Builder
	p.metrics = runtime.NewMetrics(&out, "RCS", "pcscf", clock.now, p.log)
	p.allRegisters = newTaskLimit(4, 4, clock.now) // 3 for anyone, 1 kept for refreshes
	client := func(i int) *proxy.Request {
		r := clientRequest(t, registerText(outboundContact), transport.FlowID(fmt.Sprint("F", i)))
		r.Source.Addr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(20 + i)}), 40000)
		return r
	}
	malformed := client(9)
	malformed.Message.Header.Set("To", "<<")
	if d := p.Route(context.Background(), malformed); d.Status != 400 {
		t.Fatalf("malformed: %+v", d)
	}
	for i := range 3 {
		d := p.Route(context.Background(), client(i))
		if d.Response != nil {
			t.Fatalf("REGISTER %d refused", i)
		}
		if i == 0 {
			d.OnResponse(context.Background(), parseResponse(t, okText(outboundContact+";expires=3600")))
		}
	}
	d := p.Route(context.Background(), client(3))
	if d.Response == nil || d.Response.StatusCode != 503 || d.Response.Header.Get("Retry-After") != "1" {
		t.Fatalf("a new registration past the shared rate: %+v", d)
	}
	// The registration of F0 refreshes from the share kept for it.
	if d := p.Route(context.Background(), client(0)); d.Response != nil {
		t.Fatalf("a refresh was refused: %d", d.Response.StatusCode)
	}
	if d := p.Route(context.Background(), client(0)); d.Response == nil {
		t.Fatal("a refresh past the whole rate was routed")
	}
	p.metrics.Flush()
	if !strings.Contains(out.String(), `"`+metricRegisterTaskLimit+`":2`) {
		t.Errorf("metrics %s", out.String())
	}
}

// pcscf sets no integrity-protected: whatever a client says of it is
// dropped, the rest of its credentials kept.
func TestPcscfOwnsIntegrityProtected(t *testing.T) {
	p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
	auth := `Digest username="001010000000001@ims.mnc001.mcc001.3gppnetwork.org", realm="ims.mnc001.mcc001.3gppnetwork.org", nonce="", uri="sip:ims.mnc001.mcc001.3gppnetwork.org", response="", integrity-protected="yes"`
	r := clientRequest(t, registerText(outboundContact, "Authorization: "+auth, `Authorization: Digest username="u", realm="r", nonce="n", uri="sip:x", response="y", Integrity-Protected=tls-yes`), "F")
	req := prepared(t, p.Route(context.Background(), r), r)
	creds, err := req.Header.Authorization()
	if err != nil || len(creds) != 2 {
		t.Fatalf("credentials %v, %v", creds, err)
	}
	for _, c := range creds {
		if _, ok := c.Param("integrity-protected"); ok {
			t.Errorf("integrity-protected kept: %s", c)
		}
		if v, _ := c.Param("username"); v == "" {
			t.Errorf("credentials lost: %s", c)
		}
	}
	bad := clientRequest(t, registerText(outboundContact, "Authorization: Digest ,,"), "F")
	if d := p.Route(context.Background(), bad); d.Status != 400 {
		t.Errorf("malformed credentials: %+v", d)
	}
}
