package pcscf

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// fakeCoreNode is icscf or scscf: it accepts pcscf's core connections and
// answers each request with what answer returns, nothing if that is empty,
// after passing it to got, or a SUBSCRIBE, which pcscf sends of its own
// accord after a registration, to subscribes. Each answer is written once
// it is ready, so one that waits holds up no other. As a UAS it answers an
// INVITE 100 Trying at once, and a CANCEL 200 and its INVITE 487, unless a
// final response went before (RFC 3261 §9.2, §17.2.1): a CANCEL pcscf sends
// once it has the 100 then ends the INVITE at once, not at Timer B.
type fakeCoreNode struct {
	ln         net.Listener
	got        chan *sip.Request
	subscribes chan *sip.Request
	answer     func(req *sip.Request) string
}

func startCoreNode(t *testing.T, answer func(*sip.Request) string) *fakeCoreNode {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	f := &fakeCoreNode{ln: ln, got: make(chan *sip.Request, 16), subscribes: make(chan *sip.Request, 16), answer: answer}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(t, nc)
		}
	}()
	return f
}

func (f *fakeCoreNode) serve(t *testing.T, nc net.Conn) {
	defer nc.Close()
	var mu sync.Mutex
	// invites holds whether each INVITE, by its top Via branch, has had a
	// final response; mu guards it and the writes.
	invites := map[string]*sip.Request{}
	finished := map[string]bool{}
	write := func(text string) {
		_, _ = io.WriteString(nc, text)
	}
	r := sip.NewReader(bufio.NewReader(nc), sip.Limits{})
	for {
		m, err := r.ReadMessage()
		if err != nil {
			return
		}
		req, ok := m.(*sip.Request)
		if !ok {
			continue
		}
		branch := topBranch(req)
		switch req.Method {
		case "INVITE":
			mu.Lock()
			invites[branch] = req
			write(respondTo(req, 100, "s1"))
			mu.Unlock()
		case "CANCEL":
			mu.Lock()
			write(respondTo(req, 200, "s1"))
			if inv := invites[branch]; inv != nil && !finished[branch] {
				finished[branch] = true
				write(respondTo(inv, 487, "s1"))
			}
			mu.Unlock()
		}
		if req.Method == "SUBSCRIBE" {
			select {
			case f.subscribes <- req:
			default:
			}
		} else {
			f.got <- req
		}
		if req.Method == "CANCEL" {
			continue
		}
		go func() {
			a := f.answer(req)
			if a == "" {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if req.Method == "INVITE" && finalText(a) {
				if finished[branch] {
					return // cancelled: its 487 went
				}
				finished[branch] = true
			}
			write(a)
		}()
	}
}

// topBranch is the branch of req's top Via, which a CANCEL shares with its
// INVITE (RFC 3261 §9.1).
func topBranch(req *sip.Request) string {
	vias, err := req.Header.Via()
	if err != nil || len(vias) == 0 {
		return ""
	}
	return vias[0].Branch()
}

// finalText reports whether a, a response's text, has a final status:
// "SIP/2.0 " and a code not of the 1xx class.
func finalText(a string) bool {
	const start = "SIP/2.0 "
	return strings.HasPrefix(a, start) && len(a) > len(start) && a[len(start)] != '1'
}

// receive waits for the next request at f.
func (f *fakeCoreNode) receive(t *testing.T) *sip.Request {
	t.Helper()
	select {
	case req := <-f.got:
		return req
	case <-time.After(waitFor):
		t.Fatal("no request reached the core")
		return nil
	}
}

// echo200 answers a REGISTER with 200, echoing its Via, Path and contacts
// with expires=3600, as a registrar does, and Require: outbound when the
// Path has ob (RFC 5626 §6).
func echo200(req *sip.Request) string {
	var b strings.Builder
	b.WriteString("SIP/2.0 200 OK\r\n")
	for _, v := range req.Header.Values("Via") {
		b.WriteString("Via: " + v + "\r\n")
	}
	for _, name := range []string{"From", "Call-ID", "CSeq"} {
		b.WriteString(name + ": " + req.Header.Get(name) + "\r\n")
	}
	b.WriteString("To: " + req.Header.Get("To") + ";tag=s1\r\n")
	if p := req.Header.Get("Path"); p != "" {
		b.WriteString("Path: " + p + "\r\n")
		if strings.Contains(p, ";ob") {
			b.WriteString("Require: outbound\r\n")
		}
	}
	if cs, err := req.Header.Contact(); err == nil {
		for _, c := range cs {
			if !c.Star {
				if _, ok, _ := c.Expires(); !ok {
					c.Params.Set("expires", "3600")
				}
				b.WriteString("Contact: " + c.String() + "\r\n")
			}
		}
	}
	b.WriteString("Service-Route: <sip:orig@10.0.4.4;lr>\r\n")
	b.WriteString("P-Associated-URI: <" + aliceIMPU + ">\r\n")
	b.WriteString("Content-Length: 0\r\n\r\n")
	return b.String()
}

// The REGISTER crosses pcscf to icscf and back; its Path names a flow the
// transport knows, the client gets the Flow-Timer, and when the client's
// connection closes its registration goes (RFC 5626 §5.3).
func TestARegisterCrossesPcscfAndItsFlowsClosureEndsIt(t *testing.T) {
	icscf := startCoreNode(t, echo200)
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	var pc *pcscf
	s := start(t, cfg, deps{started: func(p *pcscf) { pc = p }})
	c := dial(t, s.client, nil)
	// Headers only the network may set do not reach icscf as the client
	// wrote them (#16 plan, review of #188), nor does a Path or a Route
	// below pcscf's own (reviews of #198 and #196).
	text := registerText(outboundContact, "Supported: outbound", "P-Asserted-Identity: <"+aliceIMPU+">",
		"P-Charging-Vector: icid-value=1", "P-Visited-Network-ID: forged.example.net",
		"P-Access-Network-Info: 3GPP-E-UTRAN-FDD; network-provided",
		"P-Access-Network-Info: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=001010000000001",
		"Path: <sip:forged@10.0.9.9;lr>", "Route: <sip:"+publicHost+";lr>, <sip:10.0.9.9:5060;transport=tcp;lr>")
	_ = c.nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := io.WriteString(c.nc, text); err != nil {
		t.Fatal(err)
	}
	m, err := c.r.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	res := m.(*sip.Response)
	if res.StatusCode != 200 || res.Header.Get("Flow-Timer") != "120" {
		t.Fatalf("%d, Flow-Timer %q", res.StatusCode, res.Header.Get("Flow-Timer"))
	}
	got := <-icscf.got
	for _, name := range networkOnlyHeaders {
		switch name {
		case "P-Charging-Vector":
			if v := got.Header.Values(name); len(v) != 1 || !icidValue.MatchString(v[0]) {
				t.Errorf("P-Charging-Vector at icscf %q, want pcscf's", v)
			}
		case "P-Visited-Network-ID":
			if v := got.Header.Values(name); len(v) != 1 || v[0] != cfg.VisitedNetworkID {
				t.Errorf("P-Visited-Network-ID at icscf %q, want pcscf's", v)
			}
		case "Path":
			// Checked below: pcscf's own alone.
		default:
			if got.Header.Has(name) {
				t.Errorf("%s reached icscf: %q", name, got.Header.Get(name))
			}
		}
	}
	if pani := got.Header.Values("P-Access-Network-Info"); len(pani) != 1 || strings.Contains(pani[0], "network-provided") {
		t.Errorf("P-Access-Network-Info at icscf %q, want the client's own only", pani)
	}
	paths, err := got.Header.Path()
	if err != nil || len(paths) != 1 {
		t.Fatalf("Path %q, %v", got.Header.Get("Path"), err)
	}
	if want := fmt.Sprintf("127.0.0.2:%d", s.core.Port()); fmt.Sprintf("%s:%d", paths[0].URI.Host, paths[0].URI.Port) != want {
		t.Errorf("Path %q names %s:%d, want the core listener %s", got.Header.Get("Path"), paths[0].URI.Host, paths[0].URI.Port, want)
	}
	if vias, _ := got.Header.Via(); len(vias) == 0 || vias[0].Port != int(s.core.Port()) {
		t.Errorf("Via %q does not name the core listener", got.Header.Get("Via"))
	}
	if routes, _ := got.Header.Route(); len(routes) != 1 || routes[0].URI.String() != cfg.ICSCF.String() {
		t.Errorf("Route %q", got.Header.Get("Route"))
	}
	token := paths[0].URI.User
	key := aorKey(mustURI(t, aliceIMPU))
	if _, ok := pc.registry.lookup(transportFlow(token), key); !ok {
		t.Fatalf("no registration under the Path's flow token")
	}
	_ = c.nc.Close()
	deadline := time.Now().Add(waitFor)
	for pc.registry.size() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the closed flow's registration stayed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func transportFlow(s string) transport.FlowID { return transport.FlowID(s) }

// registerOver sends a REGISTER over c, with a branch and Call-ID of its
// own, and returns the final response.
func registerOver(t *testing.T, c *peer) *sip.Response {
	t.Helper()
	n := strconv.FormatInt(requests.Add(1), 10)
	text := strings.ReplaceAll(registerText(outboundContact, "Supported: outbound"), "reg-1", "reg-e2e-"+n)
	_ = c.nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := io.WriteString(c.nc, text); err != nil {
		t.Fatal(err)
	}
	for {
		m, err := c.r.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		if res, ok := m.(*sip.Response); ok && res.StatusCode >= 200 {
			return res
		}
	}
}

// icscfLookup answers every name with addrs.
func icscfLookup(addrs ...string) func(context.Context, string, string) ([]netip.Addr, error) {
	return func(context.Context, string, string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
}

// With one of icscf's two addresses dead, every REGISTER still registers,
// through the other; with both dead, or no answer to the lookup, the client
// gets 504 (TS 24.229 §5.2.2.1 7), review of #198).
func TestARegisterFailsOverToAnotherICSCF(t *testing.T) {
	icscf := startCoreNode(t, echo200)
	port := icscf.ln.Addr().(*net.TCPAddr).Port
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, fmt.Sprintf("sip:icscf.rcs.internal:%d;transport=tcp;lr", port))
	// Nothing listens on 127.0.0.3 at icscf's port: connecting is refused.
	s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.3", "127.0.0.1")})
	c := dial(t, s.client, nil)
	for i := range 20 {
		if res := registerOver(t, c); res.StatusCode != 200 {
			t.Fatalf("REGISTER %d: %d", i, res.StatusCode)
		}
		<-icscf.got
	}

	dead := start(t, cfg, deps{lookup: icscfLookup("127.0.0.3", "127.0.0.4")})
	if res := registerOver(t, dial(t, dead.client, nil)); res.StatusCode != 504 {
		t.Errorf("every icscf dead: %d, want 504", res.StatusCode)
	}
	none := start(t, cfg, deps{lookup: func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "icscf.rcs.internal", IsNotFound: true}
	}})
	if res := registerOver(t, dial(t, none.client, nil)); res.StatusCode != 504 {
		t.Errorf("failed lookup: %d, want 504", res.StatusCode)
	}
}

// A client whose flow closes while its REGISTER is at icscf leaves no
// registration behind when the 200 comes back, however many do so (QA of
// #198).
func TestRegistrationsOfFlowsThatClosedBeforeThe200AreNotKept(t *testing.T) {
	release := make(chan struct{})
	icscf := startCoreNode(t, func(req *sip.Request) string { <-release; return echo200(req) })
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	var pc *pcscf
	s := start(t, cfg, deps{started: func(p *pcscf) { pc = p }})
	const n = 20
	var tokens []transport.FlowID
	for range n {
		c := dial(t, s.client, nil)
		text := strings.ReplaceAll(registerText(outboundContact, "Supported: outbound"), "reg-1", fmt.Sprintf("reg-closed-%d", requests.Add(1)))
		if _, err := io.WriteString(c.nc, text); err != nil {
			t.Fatal(err)
		}
		paths, err := icscf.receive(t).Header.Path()
		if err != nil || len(paths) != 1 {
			t.Fatal("no Path")
		}
		tokens = append(tokens, transport.FlowID(paths[0].URI.User))
		_ = c.nc.Close()
	}
	// Every 200 comes after its flow has closed.
	deadline := time.Now().Add(waitFor)
	for _, id := range tokens {
		for pc.flows.SetFlowIdleTimeout(id, time.Minute) {
			if time.Now().After(deadline) {
				t.Fatal("a closed client connection's flow stayed")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	close(release)
	for pc.registry.size() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d closed flows left a registration", pc.registry.size(), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// syncClock is a clock tests move while the service runs.
type syncClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *syncClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *syncClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// Expired registrations are dropped by the sweep, without a lookup, so the
// registry's memory and slots are bounded by live registrations.
func TestTheSweepDropsExpiredRegistrations(t *testing.T) {
	icscf := startCoreNode(t, echo200)
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	clock := &syncClock{t: time.Unix(1_800_000_000, 0)}
	var pc *pcscf
	s := start(t, cfg, deps{started: func(p *pcscf) { pc = p }, now: clock.now, sweep: 5 * time.Millisecond})
	if res := registerOver(t, dial(t, s.client, nil)); res.StatusCode != 200 || pc.registry.size() != 1 {
		t.Fatalf("%d, size %d", res.StatusCode, pc.registry.size())
	}
	clock.add(time.Hour)
	deadline := time.Now().Add(waitFor)
	for pc.registry.size() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the expired registration was not swept")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Whatever integrity-protected a client writes in its credentials does not
// reach icscf: pcscf owns that parameter (security review of #198).
func TestAClientsIntegrityProtectedDoesNotReachICSCF(t *testing.T) {
	icscf := startCoreNode(t, echo200)
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	s := start(t, cfg, deps{})
	c := dial(t, s.client, nil)
	for _, v := range []string{`"yes"`, "tls-yes", `"ip-assoc-yes"`} {
		text := strings.ReplaceAll(registerText(outboundContact, "Supported: outbound",
			`Authorization: Digest username="001010000000001@ims.mnc001.mcc001.3gppnetwork.org", realm="ims.mnc001.mcc001.3gppnetwork.org", nonce="", uri="sip:ims.mnc001.mcc001.3gppnetwork.org", response="", integrity-protected=`+v),
			"reg-1", fmt.Sprintf("reg-ip-%d", requests.Add(1)))
		_ = c.nc.SetDeadline(time.Now().Add(waitFor))
		if _, err := io.WriteString(c.nc, text); err != nil {
			t.Fatal(err)
		}
		got := icscf.receive(t)
		if a := got.Header.Get("Authorization"); strings.Contains(strings.ToLower(a), "integrity-protected") || !strings.Contains(a, "username=") {
			t.Errorf("icscf got Authorization %q", a)
		}
		if res := c.final(); res.StatusCode != 200 {
			t.Fatalf("REGISTER: %d", res.StatusCode)
		}
	}
}

// A core that answers the first copy of a REGISTER slowly, as when its HSS
// stalls and it retries another, still registers the client: the first
// attempt outlasts that retry, and a second copy elsewhere, which a
// registrar refuses as out of order, is never sent (review of #198). The
// timeouts are scaled down for the test.
func TestASlowCoreStillRegistersTheClient(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	node := &fakeCoreNode{ln: ln, got: make(chan *sip.Request, 16), answer: func(req *sip.Request) string {
		key := req.Header.Get("Call-ID") + " " + req.Header.Get("CSeq")
		mu.Lock()
		again := seen[key]
		seen[key] = true
		mu.Unlock()
		if again {
			return strings.Replace(echo200(req), "200 OK", "500 Out of Order REGISTER", 1)
		}
		time.Sleep(time.Second) // 9 s of 12, scaled
		return echo200(req)
	}}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go node.serve(t, nc)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, fmt.Sprintf("sip:icscf.rcs.internal:%d;transport=tcp;lr", port))
	s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1", "127.0.0.6"), icscfFirst: 2 * time.Second, icscfTotal: 4 * time.Second})
	if res := registerOver(t, dial(t, s.client, nil)); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d, want the slow 200", res.StatusCode)
	}
}

// final reads responses until a final one.
func (p *peer) final() *sip.Response {
	p.t.Helper()
	for {
		m, err := p.r.ReadMessage()
		if err != nil {
			p.t.Fatal(err)
		}
		res, ok := m.(*sip.Response)
		if !ok {
			p.t.Fatalf("got a request: %v", m)
		}
		if res.StatusCode >= 200 {
			return res
		}
	}
}

// PCSCF_MAX_PENDING_REGISTERS_PER_IP reaches the registry.
func TestTheRegistryTakesThePendingRegistersPerIP(t *testing.T) {
	cfg := testConfig()
	cfg.MaxPendingRegistersPerIP = 3
	var pc *pcscf
	start(t, cfg, deps{started: func(p *pcscf) { pc = p }})
	if pc.registry.perClient != 3 {
		t.Fatalf("per-client bound %d", pc.registry.perClient)
	}
}
