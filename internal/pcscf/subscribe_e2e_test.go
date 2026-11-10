package pcscf

import (
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// subscriberRequest is a request alice's client sends in her reg event
// subscription: to target, with the To tag of the notifier, if any, and
// the routes, then extra fields.
func subscriberRequest(method, target, call, toTag string, cseq int, routes []string, extra ...string) string {
	n := requests.Add(1)
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s SIP/2.0\r\n", method, target)
	fmt.Fprintf(&b, "Via: SIP/2.0/TCP 192.0.2.10:40000;branch=z9hG4bK-sub-e2e-%d\r\n", n)
	b.WriteString("Max-Forwards: 70\r\n")
	b.WriteString("From: <" + aliceIMPU + ">;tag=a1\r\n")
	to := "To: <" + aliceIMPU + ">"
	if toTag != "" {
		to += ";tag=" + toTag
	}
	b.WriteString(to + "\r\n")
	fmt.Fprintf(&b, "Call-ID: %s\r\nCSeq: %d %s\r\n", call, cseq, method)
	for _, r := range routes {
		b.WriteString("Route: " + r + "\r\n")
	}
	for _, e := range extra {
		b.WriteString(e + "\r\n")
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	return b.String()
}

// subscribe waits for the next SUBSCRIBE at f in call: pcscf's own
// SUBSCRIBEs to the reg event of the users it serves reach f too.
func (f *fakeCoreNode) subscribe(t *testing.T, call string) *sip.Request {
	t.Helper()
	timeout := time.After(waitFor)
	for {
		select {
		case req := <-f.subscribes:
			if req.Header.Get("Call-ID") == call {
				return req
			}
		case <-timeout:
			t.Fatalf("no SUBSCRIBE in %s reached the core", call)
			return nil
		}
	}
}

// A subscriber that follows RFC 6665 takes its route set from the first
// NOTIFY, not from the 2xx to its SUBSCRIBE (§4.4.1): pcscf record-routes
// that NOTIFY as it did the SUBSCRIBE (§4.3), so the client's refresh and
// its unsubscribe, along that route set, reach scscf (#550). Before, the
// NOTIFY carried no Record-Route, the route set was empty, and pcscf
// refused both 403.
func TestASubscriptionsRouteSetComesFromItsFirstNOTIFY(t *testing.T) {
	scscf := startCoreNode(t, answerAsUAS)
	scscfPort := scscf.ln.Addr().(*net.TCPAddr).Port
	scscfURI := fmt.Sprintf("sip:orig@scscf.rcs.internal:%d;transport=tcp;lr", scscfPort)
	icscf := startCoreNode(t, func(req *sip.Request) string {
		return strings.Replace(echo200(req), "<sip:orig@10.0.4.4;lr>", "<"+scscfURI+">", 1)
	})
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	cfg.SCSCFPort = scscfPort
	s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1")})
	c := dial(t, s.client, nil)
	_ = c.nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := io.WriteString(c.nc, registerText(outboundContact, "Supported: outbound")); err != nil {
		t.Fatal(err)
	}
	if res := c.final(); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	icscf.receive(t)

	call := fmt.Sprintf("sub-e2e-%d", requests.Add(1))
	contact := "sip:alice@192.0.2.10:40000;transport=tcp;ob"
	subscribe := []string{"Contact: <" + contact + ">", "Event: reg", "Accept: application/reginfo+xml"}
	c.write(subscriberRequest("SUBSCRIBE", aliceIMPU, call, "", 1, []string{fmt.Sprintf("<sip:%s:5060;transport=tcp;lr>", publicHost)},
		append(slices.Clone(subscribe), "Expires: 600")...))
	sub := scscf.subscribe(t, call)
	if res := c.final(); res.StatusCode != 200 {
		t.Fatalf("SUBSCRIBE: %d", res.StatusCode)
	}

	// scscf, the notifier, sends the first NOTIFY along the SUBSCRIBE's
	// Record-Route (RFC 3261 §12.1.1).
	notifierContact := fmt.Sprintf("sip:scscf.rcs.internal:%d;transport=tcp", scscfPort)
	var routes []string
	for _, v := range sub.Header.Values("Record-Route") {
		routes = append(routes, "Route: "+v)
	}
	core := dial(t, s.core, nil)
	core.write(strings.Replace(coreRequest("NOTIFY", contact, call, "a1", 1, append(routes,
		"Event: reg", "Subscription-State: active;expires=600", "Contact: <"+notifierContact+">")...),
		"From: <"+bobIMPU+">;tag=b1", "From: <"+aliceIMPU+">;tag=n1", 1))
	notify := c.nextRequest()
	if notify.Method != "NOTIFY" {
		t.Fatalf("the client got %s", notify.Method)
	}
	rr := notify.Header.Values("Record-Route")
	if want := sub.Header.Values("Record-Route"); !slices.Equal(rr, []string{want[1], want[0]}) {
		t.Fatalf("the NOTIFY's Record-Route %q, want pcscf's two from the SUBSCRIBE, %q", rr, []string{want[1], want[0]})
	}
	c.write(respondTo(notify, 200, "a1"))
	if res := core.final(); res.StatusCode != 200 {
		t.Fatalf("NOTIFY: %d", res.StatusCode)
	}

	// The route set is the NOTIFY's Record-Route, in order, as the
	// subscriber is its UAS (RFC 3261 §12.1.1), and the remote target its
	// Contact: the rules rcs-sim's sipua follows (Subscription.fromNotify).
	for i, expires := range []string{"600", "0"} {
		c.write(subscriberRequest("SUBSCRIBE", notifierContact, call, "n1", 2+i, rr, append(slices.Clone(subscribe), "Expires: "+expires)...))
		if res := c.final(); res.StatusCode != 200 {
			t.Fatalf("the SUBSCRIBE with Expires %s along the NOTIFY's route set: %d", expires, res.StatusCode)
		}
		if got := scscf.subscribe(t, call); got.Header.Get("Expires") != expires {
			t.Fatalf("scscf got a SUBSCRIBE with Expires %q, want %s", got.Header.Get("Expires"), expires)
		}
	}
}
