package pcscf

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/proxyproto"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/reginfo"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// proxyHeaderFrom is the NLB's PROXY header for a client at src.
func proxyHeaderFrom(src string) []byte {
	return proxyproto.Header{Command: proxyproto.Proxy, Source: netip.MustParseAddrPort(src), Destination: netip.MustParseAddrPort("10.0.2.9:5061")}.Marshal()
}

// One client goes through every rule of #16 in turn, against pcscf as run
// starts it, behind a PROXY header, with icscf and scscf fakes on
// loopback (#16 AC 7). Each step waits for what it checks to happen, never
// for a time:
//  1. the client's flow is admitted for the address in the PROXY header
//     (AC 1), and one more than PCSCF_MAX_FLOWS_PER_IP of that address is
//     refused (AC 6);
//  2. its REGISTER reaches icscf with Path, the flow token and ob, icscf
//     alone as Route, and nothing the client forged, and its 200 gives a
//     Flow-Timer (AC 2, AC 5); a CRLF keep-alive is answered (AC 5);
//  3. pcscf subscribes to the user's reg event at scscf (AC 2);
//  4. a MESSAGE goes along the Service-Route, as the identity the
//     registration allows, with an icid and nothing forged (AC 3);
//  5. a request of the core reaches the client over the flow its Path
//     names, without P-Asserted-Identity when it asks for privacy (AC 4);
//  6. a NOTIFY that ends the binding deregisters the client (AC 2);
//  7. a request to a flow that closed is 430 (AC 4);
//
// and the metrics count what happened (AC 6). How a stop closes the flows
// left, one by one over the drain (AC 5), is
// TestAStopClosesTheClientFlowsOneByOne's: here run's own close of the
// transport would close them all the same (#345 code review 2).
func TestAClientGoesThroughEveryRule(t *testing.T) {
	scscf := startCoreNode(t, answerSubscribe)
	scscfPort := scscf.ln.Addr().(*net.TCPAddr).Port
	icscf := startCoreNode(t, func(req *sip.Request) string {
		return strings.Replace(registrarAt(scscfPort)(req), "P-Associated-URI: <"+aliceIMPU+">", "P-Associated-URI: <"+aliceIMPU+">, <"+aliceTel+">", 1)
	})
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	cfg.SCSCFPort = scscfPort
	cfg.ProxyProtocol = true
	cfg.MaxFlowsPerIP = 2
	h := runtimetest.New(t, "pcscf")
	var pc *pcscf
	s := startWith(t, h, cfg, deps{lookup: icscfLookup("127.0.0.1"), started: func(p *pcscf) { pc = p }, sweep: 5 * time.Millisecond})

	// 1. Flows, by the address in the PROXY header.
	c := dial(t, s.client, proxyHeaderFrom("192.0.2.10:40000"))
	// The spare flow stays open to the end.
	_ = dial(t, s.client, proxyHeaderFrom("192.0.2.10:40001"))
	// The flows are admitted once their headers are read, in their own
	// order: the third comes once the first two are in.
	tr := pc.flows.(*transport.Transport)
	for deadline := time.Now().Add(waitFor); tr.Stats().OpenInbound < 2; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the first two flows were not admitted")
		}
	}
	if !dial(t, s.client, proxyHeaderFrom("192.0.2.10:40002")).closed() {
		t.Fatal("a third flow of one address was admitted")
	}

	// 2. Registration.
	text := strings.ReplaceAll(registerText(outboundContact, append([]string{"Supported: outbound"}, forged...)...), "reg-1", "reg-scenario")
	_ = c.nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := io.WriteString(c.nc, text); err != nil {
		t.Fatal(err)
	}
	ok := c.final()
	if ok.StatusCode != 200 || ok.Header.Get("Flow-Timer") == "" {
		t.Fatalf("REGISTER: %d, Flow-Timer %q", ok.StatusCode, ok.Header.Get("Flow-Timer"))
	}
	reg := icscf.receive(t)
	noForged(t, reg)
	paths, err := reg.Header.Path()
	if err != nil || len(paths) != 1 || !paths[0].URI.Params.Has("ob") || paths[0].URI.User == "" ||
		!slices.Equal(reg.Header.Values("Route"), []string{"<" + cfg.ICSCF.String() + ">"}) {
		t.Fatalf("REGISTER at icscf: Path %q, Route %q", reg.Header.Values("Path"), reg.Header.Values("Route"))
	}
	path := paths[0].URI.String()
	flow := transportFlow(paths[0].URI.User)
	_ = c.nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := io.WriteString(c.nc, "\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	pong := make([]byte, 2)
	if _, err := io.ReadFull(c.nc, pong); err != nil || string(pong) != "\r\n" {
		t.Fatalf("keep-alive answered %q, %v", pong, err)
	}

	// 3. The reg event subscription.
	var sub *sip.Request
	select {
	case sub = <-scscf.subscribes:
	case <-time.After(waitFor):
		t.Fatal("no SUBSCRIBE reached scscf")
	}
	if sub.URI.String() != aliceIMPU || sub.Header.Get("Event") != "reg" {
		t.Fatalf("SUBSCRIBE %s, Event %q", sub.URI, sub.Header.Get("Event"))
	}

	// 4. An originating request.
	c.send("scenario-msg-1", "MESSAGE "+bobIMPU+" SIP/2.0", "", 1, "MESSAGE", forged...)
	msg := scscf.receive(t)
	noForged(t, msg)
	if got := msg.Header.Values("P-Asserted-Identity"); !slices.Equal(got, []string{"<" + aliceIMPU + ">", "<" + aliceTel + ">"}) ||
		len(msg.Header.Values("Route")) != 1 || !strings.Contains(msg.Header.Get("Route"), fmt.Sprintf("scscf.rcs.internal:%d", scscfPort)) ||
		!icidValue.MatchString(msg.Header.Get("P-Charging-Vector")) || msg.Header.Has("Record-Route") {
		t.Errorf("MESSAGE at scscf: P-Asserted-Identity %q, Route %q, P-Charging-Vector %q, Record-Route %q",
			got, msg.Header.Values("Route"), msg.Header.Get("P-Charging-Vector"), msg.Header.Values("Record-Route"))
	}
	if res := c.final(); res.StatusCode != 200 {
		t.Fatalf("MESSAGE: %d", res.StatusCode)
	}

	// 5. A terminating request, asking for privacy.
	core := dial(t, s.core, nil)
	contact := "sip:alice@192.0.2.10:40000;transport=tcp"
	core.write(coreRequest("MESSAGE", contact, "scenario-term-1", "", 1, "Route: <"+path+">", "P-Asserted-Identity: <"+bobIMPU+">", "Privacy: id"))
	in := c.nextRequest()
	if in.Method != "MESSAGE" || in.Header.Has("P-Asserted-Identity") {
		t.Fatalf("the client got %s with P-Asserted-Identity %q", in.Method, in.Header.Get("P-Asserted-Identity"))
	}
	c.write(respondTo(in, 200, "a1"))
	if res := core.final(); res.StatusCode != 200 {
		t.Fatalf("terminating MESSAGE: %d", res.StatusCode)
	}

	// 6. The network ends the registration.
	notifier := dial(t, s.core, nil)
	notifier.write(notifyText(t, sub, 1, "active;expires=1200", aliceDoc(0, reginfo.Full, reginfo.ContactActive, reginfo.Registered)))
	if res := notifier.final(); res.StatusCode != 200 || !aliceRegistered(t, pc, flow) {
		t.Fatalf("first NOTIFY: %d, registered %v", res.StatusCode, aliceRegistered(t, pc, flow))
	}
	notifier.write(notifyText(t, sub, 2, "active;expires=1100", aliceDoc(1, reginfo.Full, reginfo.ContactTerminated, reginfo.Deactivated)))
	if res := notifier.final(); res.StatusCode != 200 || aliceRegistered(t, pc, flow) {
		t.Fatalf("NOTIFY ending the binding: %d, registered %v", res.StatusCode, aliceRegistered(t, pc, flow))
	}

	// 7. The client goes; its flow is not reused. The request goes once the
	// client listener holds the spare connection alone, so that it meets a
	// flow known to be gone and gets terminate's own 430, not the proxy's
	// for a flow that closes under it (#293), which other tests count.
	_ = c.nc.Close()
	for deadline := time.Now().Add(waitFor); tr.Stats().ListenerConnections[clientListener] != 1; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the closed flow is still open")
		}
	}
	core.write(coreRequest("MESSAGE", contact, "scenario-term-2", "", 1, "Route: <"+path+">"))
	if res := core.final(); res.StatusCode != statusFlowFailed {
		t.Fatalf("a request to the closed flow: %d", res.StatusCode)
	}

	// The metrics, from the sweep and from the refusals.
	waitMetric(t, h, metricFlows, 1) // the spare flow alone
	for _, name := range []string{metricFlowsRefusedPerAddr, metricTerminatingFlow, metricDeregistered} {
		if n, ok := h.Metric(name); !ok || n < 1 {
			t.Errorf("%s: %v, %v", name, n, ok)
		}
	}
}
