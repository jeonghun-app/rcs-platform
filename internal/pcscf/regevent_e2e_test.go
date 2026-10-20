package pcscf

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/reginfo"
)

// answerSubscribe answers a SUBSCRIBE with 200 for its Expires, as a
// notifier does (RFC 6665 §4.2.1.1), and any other request as answerAsUAS.
func answerSubscribe(req *sip.Request) string {
	if req.Method != "SUBSCRIBE" {
		return answerAsUAS(req)
	}
	return strings.Replace(answerAsUAS(req), "Content-Length: 0", "Expires: "+req.Header.Get("Expires")+"\r\nContent-Length: 0", 1)
}

// registrarAt answers a REGISTER as echo200 does, with a Service-Route to
// scscf on port.
func registrarAt(port int) func(*sip.Request) string {
	return func(req *sip.Request) string {
		return strings.Replace(echo200(req), "Service-Route: <sip:orig@10.0.4.4;lr>",
			fmt.Sprintf("Service-Route: <sip:scscf.rcs.internal:%d;transport=tcp;lr;orig>", port), 1)
	}
}

// notifyText is scscf's NOTIFY in the subscription sub set up, over the
// core listener.
func notifyText(t *testing.T, sub *sip.Request, cseq int, state string, doc *reginfo.Info) string {
	t.Helper()
	r := notifyFor(t, sub, cseq, state, doc)
	b, err := r.Message.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A registration over pcscf subscribes to the user's reg event at the
// scscf of its Service-Route; scscf's NOTIFY, on a connection of its own
// to the core listener, is answered 200 with pcscf's charging, and one
// that ends the client's contact ends its registration but not its flow,
// over which the client registers again (TS 24.229 §5.2.3, §5.2.5.2, #16
// plan E).
func TestTheNetworkEndsARegistrationThroughTheRegEvent(t *testing.T) {
	scscf := startCoreNode(t, answerSubscribe)
	icscf := startCoreNode(t, registrarAt(scscf.ln.Addr().(*net.TCPAddr).Port))
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	var pc *pcscf
	s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1"), started: func(p *pcscf) { pc = p }})
	c, path := registered(t, s, icscf)
	var sub *sip.Request
	select {
	case sub = <-scscf.subscribes:
	case <-time.After(waitFor):
		t.Fatal("no SUBSCRIBE reached scscf")
	}
	if sub.URI.String() != aliceIMPU || sub.Header.Get("Event") != "reg" || sub.Header.Get("P-Asserted-Identity") != "<"+path+">" {
		t.Errorf("SUBSCRIBE %s, Event %q, P-Asserted-Identity %q, Path %q", sub.URI, sub.Header.Get("Event"), sub.Header.Get("P-Asserted-Identity"), path)
	}
	flow := transportFlow(mustURI(t, path).User)

	core := dial(t, s.core, nil)
	core.write(notifyText(t, sub, 1, "active;expires=1200", aliceDoc(0, reginfo.Full, reginfo.ContactActive, reginfo.Registered)))
	res := core.final()
	if res.StatusCode != 200 || !strings.HasSuffix(res.Header.Get("P-Charging-Vector"), ";term-ioi=ims.mnc001.mcc001.3gppnetwork.org") {
		t.Fatalf("first NOTIFY: %d, P-Charging-Vector %q", res.StatusCode, res.Header.Get("P-Charging-Vector"))
	}
	if !aliceRegistered(t, pc, flow) {
		t.Fatal("not registered")
	}
	core.write(notifyText(t, sub, 2, "active;expires=1100", aliceDoc(1, reginfo.Full, reginfo.ContactTerminated, reginfo.Deactivated)))
	if res := core.final(); res.StatusCode != 200 {
		t.Fatalf("NOTIFY: %d", res.StatusCode)
	}
	if aliceRegistered(t, pc, flow) {
		t.Error("the network's deregistration left the registration")
	}
	if res := registerOver(t, c); res.StatusCode != 200 {
		t.Errorf("REGISTER over the same flow: %d", res.StatusCode)
	}
	if !aliceRegistered(t, pc, flow) {
		t.Error("registering again over the flow did not register")
	}
	// A NOTIFY to a subscription this task never had is 481.
	other := sub.Clone()
	_ = other.Header.Set("Contact", "<sip:"+subscriptionPrefix+"unknown@127.0.0.2:"+fmt.Sprint(s.core.Port())+";transport=tcp>")
	core.write(notifyText(t, other, 1, "active", nil))
	if res := core.final(); res.StatusCode != 481 {
		t.Errorf("unknown subscription: %d", res.StatusCode)
	}
	// Only NOTIFY is taken there.
	options := strings.Replace(strings.Replace(notifyText(t, sub, 3, "active", nil), "NOTIFY ", "OPTIONS ", 1), "3 NOTIFY", "3 OPTIONS", 1)
	core.write(options)
	if res := core.final(); res.StatusCode != 405 || res.Header.Get("Allow") != "NOTIFY" {
		t.Errorf("OPTIONS: %d, Allow %q", res.StatusCode, res.Header.Get("Allow"))
	}
}
