package pcscf

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/reginfo"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// sentRequest is a request pcscf started a client transaction for.
type sentRequest struct {
	req *sip.Request
	dst transport.Destination
	h   transaction.ResponseHandler
}

// fakeSender records the client transactions pcscf starts, or fails them
// with err.
type fakeSender struct {
	mu   sync.Mutex
	sent []sentRequest
	err  error
}

func (f *fakeSender) send(req *sip.Request, dst transport.Destination, h transaction.ResponseHandler) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, sentRequest{req, dst, h})
	return nil
}

// take waits for the SUBSCRIBEs under way and returns what was sent since
// the last take.
func (f *fakeSender) take(p *pcscf) []sentRequest {
	p.subs.wait()
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.sent
	f.sent = nil
	return out
}

// one is take that wants exactly one request.
func (f *fakeSender) one(t *testing.T, p *pcscf) sentRequest {
	t.Helper()
	got := f.take(p)
	if len(got) != 1 {
		t.Fatalf("%d requests sent, want 1", len(got))
	}
	return got[0]
}

// newSubscribingPcscf is newTestPcscf with reg event subscriptions, sent
// through the returned fakeSender.
func newSubscribingPcscf(t *testing.T) (*pcscf, *testClock, *fakeSender) {
	t.Helper()
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	p, _ := newTestPcscf(clock)
	f := &fakeSender{}
	p.subs = newSubscriptions(context.Background())
	p.send = f.send
	return p, clock, f
}

// registerKept registers alice over flow for an hour, as a client that
// keeps its flow alive with outbound, along scscfRoute, with
// aliceAssociated.
func registerKept(t *testing.T, p *pcscf, flow transport.FlowID) {
	t.Helper()
	registerAlice(t, p, flow, "Service-Route: "+scscfRoute, aliceAssociated, "Require: outbound")
}

// aliceAssociated is the P-Associated-URI of alice's registrations: her
// SIP identity, the default, and her number.
var aliceAssociated = "P-Associated-URI: <" + aliceIMPU + ">, <" + aliceTel + ">"

// respond answers s with code and extra fields.
func respond(t *testing.T, s sentRequest, code int, extra ...string) {
	t.Helper()
	res, err := sip.NewResponse(s.req, code, "", "n1")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range extra {
		name, value, _ := strings.Cut(e, ": ")
		if err := res.Header.Add(name, value); err != nil {
			t.Fatal(err)
		}
	}
	s.h(res, nil)
}

// A registration makes pcscf subscribe to its user's reg event (TS 24.229
// §5.2.3): to the default public identity, along the Service-Route, from
// this pcscf, with the registration's Path URI asserted, a new charging
// identifier and a Contact naming this task's core listener; for twice the
// registration's time. Another registration of the same user, over another
// flow, does not subscribe again.
func TestARegistrationSubscribesToItsUsersRegEvent(t *testing.T) {
	p, _, f := newSubscribingPcscf(t)
	registerKept(t, p, "FLOW-A")
	s := f.one(t, p)
	req := s.req
	if req.Method != "SUBSCRIBE" || req.URI.String() != aliceIMPU {
		t.Fatalf("%s %s", req.Method, req.URI)
	}
	to, _ := req.Header.To()
	from, _ := req.Header.From()
	if to.URI.String() != aliceIMPU || to.Tag() != "" || from.URI.String() != "sip:"+publicHost || from.Tag() == "" {
		t.Errorf("To %q, From %q", req.Header.Get("To"), req.Header.Get("From"))
	}
	for name, want := range map[string]string{
		"Event":               "reg",
		"Expires":             "7200",
		"Accept":              reginfo.ContentType,
		"Route":               scscfRoute,
		"P-Asserted-Identity": "<sip:FLOW-A@10.0.2.9:5070;transport=tcp;lr;ob>",
		"Max-Forwards":        "70",
	} {
		if got := req.Header.Get(name); got != want {
			t.Errorf("%s %q, want %q", name, got, want)
		}
	}
	cs, err := req.Header.Contact()
	if err != nil || len(cs) != 1 || !strings.HasPrefix(cs[0].URI.User, subscriptionPrefix) || !p.ownURI(cs[0].URI) ||
		cs[0].URI.String() != "sip:"+cs[0].URI.User+"@10.0.2.9:5070;transport=tcp" {
		t.Errorf("Contact %q", req.Header.Get("Contact"))
	}
	if icidOf(t, req.Header.Get("P-Charging-Vector")) == "" || !strings.HasSuffix(req.Header.Get("P-Charging-Vector"), ";orig-ioi=ims.mnc001.mcc001.3gppnetwork.org") {
		t.Errorf("P-Charging-Vector %q", req.Header.Get("P-Charging-Vector"))
	}
	if s.dst.Addr != netip.MustParseAddrPort("10.0.4.4:5060") || s.dst.Listener != coreListener {
		t.Errorf("sent to %+v", s.dst)
	}

	registerKept(t, p, "FLOW-B")
	registerKept(t, p, "FLOW-A")
	if got := f.take(p); len(got) != 0 {
		t.Errorf("%d more SUBSCRIBEs for one user", len(got))
	}
}

// A short registration still subscribes for minSubscriptionExpires, and
// one without a Service-Route, which has no way to scscf, not at all.
func TestASubscriptionLastsAtLeastTwentyMinutes(t *testing.T) {
	p, _, f := newSubscribingPcscf(t)
	d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact, "Supported: outbound"), "FLOW-A"))
	d.OnResponse(context.Background(), parseResponse(t, okText(outboundContact+";expires=300", "Service-Route: "+scscfRoute)))
	if got := f.one(t, p).req.Header.Get("Expires"); got != "1200" {
		t.Errorf("Expires %q", got)
	}
	p2, _, f2 := newSubscribingPcscf(t)
	registerAlice(t, p2, "FLOW-A")
	if got := f2.take(p2); len(got) != 0 {
		t.Errorf("%d SUBSCRIBEs without a Service-Route", len(got))
	}
}

// notifyFor is scscf's NOTIFY in the subscription sub set up, with CSeq
// cseq, the given Subscription-State and a document, if any, and extra
// fields.
func notifyFor(t *testing.T, sub *sip.Request, cseq int, state string, doc *reginfo.Info, extra ...string) *proxy.Request {
	t.Helper()
	cs, _ := sub.Header.Contact()
	var b strings.Builder
	fmt.Fprintf(&b, "NOTIFY %s SIP/2.0\r\n", cs[0].URI)
	fmt.Fprintf(&b, "Via: SIP/2.0/TCP 10.0.4.4:5060;branch=z9hG4bK-notify-%d\r\n", requests.Add(1))
	b.WriteString("Max-Forwards: 70\r\n")
	b.WriteString("From: " + sub.Header.Get("To") + ";tag=n1\r\n")
	b.WriteString("To: " + sub.Header.Get("From") + "\r\n")
	fmt.Fprintf(&b, "Call-ID: %s\r\nCSeq: %d NOTIFY\r\n", sub.Header.Get("Call-ID"), cseq)
	b.WriteString("Contact: <sip:scscf.rcs.internal:5060;transport=tcp>\r\n")
	b.WriteString("Event: reg\r\nSubscription-State: " + state + "\r\n")
	var body []byte
	if doc != nil {
		var err error
		if body, err = doc.Marshal(); err != nil {
			t.Fatal(err)
		}
		b.WriteString("Content-Type: " + reginfo.ContentType + "\r\n")
	}
	for _, e := range extra {
		b.WriteString(e + "\r\n")
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(body))
	b.Write(body)
	return &proxy.Request{Message: parseRequest(t, b.String()), Source: transport.Source{
		Flow: "CORE-1", Network: transport.TCP, Addr: netip.MustParseAddrPort("10.0.4.4:41000"), Listener: coreListener}}
}

// notify routes r as the proxy would and answers it as serveNotify does,
// returning the code.
func notify(t *testing.T, p *pcscf, r *proxy.Request) int {
	t.Helper()
	if d := p.Route(context.Background(), r); d.Serve == nil {
		t.Fatalf("a NOTIFY to the subscription was not served: %+v", d)
	}
	code, info := p.acceptNotify(r.Message)
	if info != nil {
		p.deregistered(info.key, info.doc)
	}
	return code
}

// aliceDoc is registration information for alice's two identities, with
// her contact over FLOW-A in the given state.
func aliceDoc(version uint32, state reginfo.State, contact reginfo.ContactState, event reginfo.Event) *reginfo.Info {
	c := []reginfo.Contact{{ID: "c1", State: contact, Event: event, URI: "sip:alice@192.0.2.10:40000;transport=tcp"}}
	regState := reginfo.Active
	if contact == reginfo.ContactTerminated {
		regState = reginfo.Terminated
	}
	return &reginfo.Info{Version: version, State: state, Registrations: []reginfo.Registration{
		{AOR: aliceIMPU, ID: "r1", State: regState, Contacts: c},
		{AOR: aliceTel, ID: "r2", State: regState, Contacts: c},
	}}
}

// subscribedAlice registers alice over FLOW-A, and answers the SUBSCRIBE
// with 200 and its first NOTIFY; it returns the SUBSCRIBE.
func subscribedAlice(t *testing.T, p *pcscf, f *fakeSender) *sip.Request {
	t.Helper()
	registerKept(t, p, "FLOW-A")
	s := f.one(t, p)
	respond(t, s, 200, "Expires: 7200")
	if code := notify(t, p, notifyFor(t, s.req, 1, "active;expires=7200", aliceDoc(0, reginfo.Full, reginfo.ContactActive, reginfo.Registered))); code != 200 {
		t.Fatalf("first NOTIFY: %d", code)
	}
	return s.req
}

func aliceRegistered(t *testing.T, p *pcscf, flow transport.FlowID) bool {
	t.Helper()
	_, ok := p.registry.lookup(flow, aorKey(mustURI(t, aliceIMPU)))
	return ok
}

// A NOTIFY that ends alice's contact over a flow ends that registration
// and nothing else (§5.2.5.2): the flow is not closed, and is counted.
func TestANotifyEndingAContactRemovesItsRegistration(t *testing.T) {
	p, _, f := newSubscribingPcscf(t)
	h := runtimeHarnessMetrics(t, p)
	sub := subscribedAlice(t, p, f)
	registerKept(t, p, "FLOW-B")
	if !aliceRegistered(t, p, "FLOW-A") {
		t.Fatal("an active contact ended the registration")
	}
	doc := aliceDoc(1, reginfo.Partial, reginfo.ContactTerminated, reginfo.Deactivated)
	doc.Registrations[0].State, doc.Registrations[1].State = reginfo.Active, reginfo.Active
	if code := notify(t, p, notifyFor(t, sub, 2, "active;expires=7000", doc)); code != 200 {
		t.Fatalf("NOTIFY: %d", code)
	}
	if aliceRegistered(t, p, "FLOW-A") {
		t.Error("the ended contact's registration stayed")
	}
	// FLOW-B's registration has the same contact URI in this test, so it
	// ends too: a contact URI is all reginfo names a binding by.
	if aliceRegistered(t, p, "FLOW-B") {
		t.Error("a registration with the ended contact stayed")
	}
	if !h.count(metricDeregistered, 2) {
		t.Errorf("metrics %s", h.out.String())
	}
}

// runtimeHarnessMetrics gives p metrics a test can read.
func runtimeHarnessMetrics(t *testing.T, p *pcscf) *metricReader {
	t.Helper()
	m := &metricReader{p: p}
	p.metrics = runtime.NewMetrics(&m.out, "RCS", "pcscf", p.now, p.log)
	return m
}

// A terminated registration ends every registration of that identity on
// this task, whatever its contacts say; one of the user's other
// identities only stops being one its registrations may assert.
func TestATerminatedIdentityEndsItsRegistrations(t *testing.T) {
	p, _, f := newSubscribingPcscf(t)
	sub := subscribedAlice(t, p, f)
	doc := &reginfo.Info{Version: 1, State: reginfo.Partial, Registrations: []reginfo.Registration{
		{AOR: aliceTel, ID: "r2", State: reginfo.Terminated},
	}}
	if code := notify(t, p, notifyFor(t, sub, 2, "active", doc)); code != 200 {
		t.Fatalf("NOTIFY: %d", code)
	}
	reg, ok := p.registry.lookup("FLOW-A", aorKey(mustURI(t, aliceIMPU)))
	if !ok || len(reg.associated) != 1 || reg.associated[0].URI.String() != aliceIMPU {
		t.Fatalf("after the number ended: %v, %+v", ok, reg)
	}
	// The same identity as scscf may write it: an escaped digit, the host
	// in another case, user=phone.
	doc = &reginfo.Info{Version: 2, State: reginfo.Partial, Registrations: []reginfo.Registration{
		{AOR: "sip:+%315550100001@IMS.mnc001.mcc001.3gppnetwork.org;user=phone", ID: "r1", State: reginfo.Terminated},
	}}
	if code := notify(t, p, notifyFor(t, sub, 3, "active", doc)); code != 200 {
		t.Fatalf("NOTIFY: %d", code)
	}
	if aliceRegistered(t, p, "FLOW-A") {
		t.Error("the terminated identity's registration stayed")
	}
}

// A NOTIFY is taken only in the subscription's dialog, in order, for the
// reg event, with a registration information document that parses;
// anything else is refused and changes nothing (RFC 6665 §4.1.3, RFC 3261
// §12.2.2).
func TestOnlyTheSubscriptionsNotifiesAreTaken(t *testing.T) {
	ended := aliceDoc(1, reginfo.Full, reginfo.ContactTerminated, reginfo.Deactivated)
	for _, tt := range []struct {
		name string
		edit func(r *proxy.Request)
		code int
	}{
		{"another subscription", func(r *proxy.Request) { r.Message.URI.User = subscriptionPrefix + "0" }, 481},
		{"another dialog's tag", func(r *proxy.Request) { replaceTag(t, r, "From", "n2") }, 481},
		{"another Call-ID", func(r *proxy.Request) { _ = r.Message.Header.Set("Call-ID", "other") }, 481},
		{"out of order", func(r *proxy.Request) { _ = r.Message.Header.Set("CSeq", "1 NOTIFY") }, 500},
		{"another event", func(r *proxy.Request) { _ = r.Message.Header.Set("Event", "presence") }, 489},
		{"an event id", func(r *proxy.Request) { _ = r.Message.Header.Set("Event", "reg;id=2") }, 489},
		{"no state", func(r *proxy.Request) { r.Message.Header.Del("Subscription-State") }, 400},
		{"another body", func(r *proxy.Request) { _ = r.Message.Header.Set("Content-Type", "application/xml") }, 415},
		{"a broken body", func(r *proxy.Request) { r.Message.Body = r.Message.Body[:len(r.Message.Body)-3] }, 400},
		{"not a NOTIFY", func(r *proxy.Request) { r.Message.Method = "OPTIONS" }, 405},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, _, f := newSubscribingPcscf(t)
			sub := subscribedAlice(t, p, f)
			r := notifyFor(t, sub, 2, "active", ended)
			tt.edit(r)
			if code := notify(t, p, r); code != tt.code {
				t.Errorf("code %d, want %d", code, tt.code)
			}
			if !aliceRegistered(t, p, "FLOW-A") {
				t.Error("a refused NOTIFY ended the registration")
			}
			// The dialog did not move: the NOTIFY that should have come
			// is still taken.
			if code := notify(t, p, notifyFor(t, sub, 2, "active", aliceDoc(1, reginfo.Full, reginfo.ContactActive, reginfo.Refreshed))); code != 200 {
				t.Errorf("the next NOTIFY: %d", code)
			}
		})
	}
}

// replaceTag gives the named field of r the tag.
func replaceTag(t *testing.T, r *proxy.Request, name, tag string) {
	t.Helper()
	a, err := r.Message.Header.From()
	if name == "To" {
		a, err = r.Message.Header.To()
	}
	if err != nil {
		t.Fatal(err)
	}
	a.Params.Set("tag", tag)
	if err := r.Message.Header.Set(name, a.String()); err != nil {
		t.Fatal(err)
	}
}

// The first NOTIFY sets up the dialog only if it answers the SUBSCRIBE:
// its Call-ID, compared exactly, and its To tag, the SUBSCRIBE's From tag,
// compared without case (RFC 6665 §4.4.1).
func TestTheFirstNotifyMustAnswerTheSubscribe(t *testing.T) {
	for _, tt := range []struct {
		name string
		edit func(t *testing.T, r *proxy.Request, sub *sip.Request)
		code int
	}{
		{"another Call-ID", func(_ *testing.T, r *proxy.Request, sub *sip.Request) {
			_ = r.Message.Header.Set("Call-ID", strings.ToUpper(sub.Header.Get("Call-ID")))
		}, 481},
		{"another To tag", func(t *testing.T, r *proxy.Request, _ *sip.Request) { replaceTag(t, r, "To", "x") }, 481},
		{"no To tag", func(t *testing.T, r *proxy.Request, _ *sip.Request) {
			to, _ := r.Message.Header.To()
			to.Params.Del("tag")
			_ = r.Message.Header.Set("To", to.String())
		}, 481},
		{"the To tag in upper case", func(t *testing.T, r *proxy.Request, sub *sip.Request) {
			from, _ := sub.Header.From()
			replaceTag(t, r, "To", strings.ToUpper(from.Tag()))
		}, 200},
		{"no From tag", func(t *testing.T, r *proxy.Request, _ *sip.Request) {
			from, _ := r.Message.Header.From()
			from.Params.Del("tag")
			_ = r.Message.Header.Set("From", from.String())
		}, 400},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, _, f := newSubscribingPcscf(t)
			registerKept(t, p, "FLOW-A")
			s := f.one(t, p)
			r := notifyFor(t, s.req, 1, "active", aliceDoc(0, reginfo.Full, reginfo.ContactActive, reginfo.Registered))
			tt.edit(t, r, s.req)
			if code := notify(t, p, r); code != tt.code {
				t.Errorf("code %d, want %d", code, tt.code)
			}
		})
	}
}

// A document no newer than the last one is not acted on (RFC 3680 §5.2).
func TestAStaleDocumentIsIgnored(t *testing.T) {
	p, _, f := newSubscribingPcscf(t)
	sub := subscribedAlice(t, p, f)
	if code := notify(t, p, notifyFor(t, sub, 2, "active", aliceDoc(0, reginfo.Full, reginfo.ContactTerminated, reginfo.Expired))); code != 200 {
		t.Fatalf("NOTIFY: %d", code)
	}
	if !aliceRegistered(t, p, "FLOW-A") {
		t.Error("a document of the same version ended the registration")
	}
}

// Only the core's NOTIFY reaches a subscription: a client's request to the
// subscription's Contact takes the client's path, and a core request to
// any other URI of this task goes to terminate.
func TestOnlyTheCoreReachesASubscription(t *testing.T) {
	p, _, f := newSubscribingPcscf(t)
	sub := subscribedAlice(t, p, f)
	r := notifyFor(t, sub, 2, "active", nil)
	r.Source = transport.Source{Flow: "FLOW-A", Network: transport.TCP, Addr: netip.MustParseAddrPort("192.0.2.10:40000"), Listener: clientListener}
	if d := p.Route(context.Background(), r); d.Serve != nil {
		t.Error("a client reached the subscription")
	}
	for _, uri := range []string{
		"sip:FLOW-A@10.0.2.9:5070;transport=tcp",
		"sip:" + subscriptionPrefix + "x@10.0.2.9:5071;transport=tcp",
		"sip:" + subscriptionPrefix + "x@10.0.2.8:5070;transport=tcp",
		"tel:+15550100001",
	} {
		r := notifyFor(t, sub, 2, "active", nil)
		r.Message.URI = mustURI(t, uri)
		if d := p.Route(context.Background(), r); d.Serve != nil {
			t.Errorf("%s was served as a subscription", uri)
		}
	}
}

// The subscription is refreshed refreshLead before it expires, or half way
// when granted for less than twice that, in its dialog, with the
// registration's Path asserted again (§5.2.3).
func TestTheSubscriptionIsRefreshedBeforeItExpires(t *testing.T) {
	p, clock, f := newSubscribingPcscf(t)
	registerKept(t, p, "FLOW-A")
	s := f.one(t, p)
	respond(t, s, 200, "Expires: 1800")
	sub := s.req
	if code := notify(t, p, notifyFor(t, sub, 1, "active;expires=1800", nil)); code != 200 {
		t.Fatalf("first NOTIFY: %d", code)
	}
	clock.t = clock.t.Add(1800*time.Second - refreshLead - time.Second)
	p.reconcileSubscriptions()
	if got := f.take(p); len(got) != 0 {
		t.Fatalf("refreshed early: %d", len(got))
	}
	clock.t = clock.t.Add(time.Second)
	p.reconcileSubscriptions()
	s = f.one(t, p)
	to, _ := s.req.Header.To()
	if s.req.Method != "SUBSCRIBE" || s.req.URI.String() != "sip:scscf.rcs.internal:5060;transport=tcp" ||
		s.req.Header.Get("CSeq") != "2 SUBSCRIBE" || to.Tag() != "n1" || s.req.Header.Get("Call-ID") != sub.Header.Get("Call-ID") ||
		s.req.Header.Get("P-Asserted-Identity") != "<sip:FLOW-A@10.0.2.9:5070;transport=tcp;lr;ob>" || s.req.Header.Get("Event") != "reg" {
		t.Errorf("refresh %s %s, CSeq %q, To %q, PAI %q", s.req.Method, s.req.URI, s.req.Header.Get("CSeq"), s.req.Header.Get("To"), s.req.Header.Get("P-Asserted-Identity"))
	}
	// While it is under way no other refresh goes.
	p.reconcileSubscriptions()
	if got := f.take(p); len(got) != 0 {
		t.Errorf("%d refreshes at once", len(got))
	}
	respond(t, s, 200, "Expires: 1000")
	clock.t = clock.t.Add(500*time.Second - time.Second)
	p.reconcileSubscriptions()
	if got := f.take(p); len(got) != 0 {
		t.Fatalf("refreshed before half of 1000 s: %d", len(got))
	}
	clock.t = clock.t.Add(time.Second)
	p.reconcileSubscriptions()
	if got := f.one(t, p).req.Header.Get("CSeq"); got != "3 SUBSCRIBE" {
		t.Errorf("second refresh CSeq %q", got)
	}
}

// Once the last registration of the user on this task ends, the
// subscription ends with Expires: 0 in its dialog, and is forgotten, so its
// last NOTIFY is answered 481 (decision 3).
func TestTheLastRegistrationsEndEndsTheSubscription(t *testing.T) {
	p, _, f := newSubscribingPcscf(t)
	sub := subscribedAlice(t, p, f)
	registerKept(t, p, "FLOW-B")
	p.registry.removeFlow("FLOW-A")
	p.reconcileSubscriptions()
	if got := f.take(p); len(got) != 0 {
		t.Fatalf("ended with a registration left: %d", len(got))
	}
	p.registry.removeFlow("FLOW-B")
	p.reconcileSubscriptions()
	s := f.one(t, p)
	if s.req.Header.Get("Expires") != "0" || s.req.Header.Get("CSeq") != "2 SUBSCRIBE" || s.req.Header.Has("P-Asserted-Identity") {
		t.Errorf("end: Expires %q, CSeq %q, PAI %q", s.req.Header.Get("Expires"), s.req.Header.Get("CSeq"), s.req.Header.Get("P-Asserted-Identity"))
	}
	if code := notify(t, p, notifyFor(t, sub, 2, "terminated;reason=timeout", nil)); code != 481 {
		t.Errorf("NOTIFY after the end: %d", code)
	}
}

// A subscription the notifier ends is forgotten, and set up again by the
// sweep while the user is registered, no sooner than its retry-after or
// resubscribeAfter, and after refusedResubscribeAfter when the notifier
// said a new one would fare no better (RFC 6665 §4.1.3).
func TestAnEndedSubscriptionIsSetUpAgainLater(t *testing.T) {
	for _, tt := range []struct {
		state string
		wait  time.Duration
	}{
		{"terminated;reason=deactivated", resubscribeAfter},
		{"terminated", resubscribeAfter},
		{"terminated;reason=probation;retry-after=90", 90 * time.Second},
		{"terminated;reason=giveup;retry-after=5", resubscribeAfter},
		{"terminated;reason=rejected", refusedResubscribeAfter},
		{"terminated;reason=NoResource", refusedResubscribeAfter},
		{"terminated;reason=invariant", refusedResubscribeAfter},
	} {
		t.Run(tt.state, func(t *testing.T) {
			p, clock, f := newSubscribingPcscf(t)
			sub := subscribedAlice(t, p, f)
			if code := notify(t, p, notifyFor(t, sub, 2, tt.state, nil)); code != 200 {
				t.Fatalf("NOTIFY: %d", code)
			}
			if code := notify(t, p, notifyFor(t, sub, 3, "active", nil)); code != 481 {
				t.Errorf("the ended subscription took a NOTIFY: %d", code)
			}
			clock.t = clock.t.Add(tt.wait - time.Second)
			p.reconcileSubscriptions()
			registerKept(t, p, "FLOW-A")
			if got := f.take(p); len(got) != 0 {
				t.Fatalf("set up again after %v", tt.wait-time.Second)
			}
			clock.t = clock.t.Add(time.Second)
			p.reconcileSubscriptions()
			if got := f.one(t, p).req; got.Method != "SUBSCRIBE" || got.Header.Get("Call-ID") == sub.Header.Get("Call-ID") {
				t.Errorf("not a new subscription: %s %q", got.Method, got.Header.Get("Call-ID"))
			}
		})
	}
}

// A SUBSCRIBE that fails or is refused leaves no subscription, and the
// sweep sets one up again after resubscribeAfter, or after
// refusedResubscribeAfter for a refusal other than 408; a 2xx without an
// Expires, which RFC 6665 §4.1.2.1 requires, counts as a failure.
func TestAFailedSubscribeIsTriedAgainLater(t *testing.T) {
	for _, tt := range []struct {
		name   string
		answer func(t *testing.T, s sentRequest)
		wait   time.Duration
	}{
		{"timeout", func(_ *testing.T, s sentRequest) { s.h(nil, transaction.ErrTimeout) }, resubscribeAfter},
		{"408", func(t *testing.T, s sentRequest) { respond(t, s, 408) }, resubscribeAfter},
		{"403", func(t *testing.T, s sentRequest) { respond(t, s, 403) }, refusedResubscribeAfter},
		{"489", func(t *testing.T, s sentRequest) { respond(t, s, 489) }, refusedResubscribeAfter},
		{"200 without Expires", func(t *testing.T, s sentRequest) { respond(t, s, 200) }, resubscribeAfter},
		{"200 with Expires: 0", func(t *testing.T, s sentRequest) { respond(t, s, 200, "Expires: 0") }, resubscribeAfter},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, clock, f := newSubscribingPcscf(t)
			registerKept(t, p, "FLOW-A")
			s := f.one(t, p)
			respond(t, s, 100)
			tt.answer(t, s)
			if code := notify(t, p, notifyFor(t, s.req, 1, "active", nil)); code != 481 {
				t.Errorf("the failed subscription took a NOTIFY: %d", code)
			}
			// The client keeps registering meanwhile.
			clock.t = clock.t.Add(tt.wait - time.Second)
			registerKept(t, p, "FLOW-A")
			p.reconcileSubscriptions()
			if got := f.take(p); len(got) != 0 {
				t.Fatalf("tried again after %v", tt.wait-time.Second)
			}
			clock.t = clock.t.Add(time.Second)
			p.reconcileSubscriptions()
			f.one(t, p)
		})
	}
}

// A SUBSCRIBE that cannot be sent, or whose next hop does not resolve,
// leaves no subscription; the sweep tries again after resubscribeAfter.
func TestASubscribeThatCannotBeSentIsTriedAgain(t *testing.T) {
	p, clock, f := newSubscribingPcscf(t)
	f.err = errors.New("no connection")
	registerKept(t, p, "FLOW-A")
	if got := f.take(p); len(got) != 0 {
		t.Fatal("sent")
	}
	f.err = nil
	clock.t = clock.t.Add(resubscribeAfter)
	p.reconcileSubscriptions()
	f.one(t, p)

	p, _, f = newSubscribingPcscf(t)
	registerAlice(t, p, "FLOW-A", "Service-Route: <sip:orig@unknown.rcs.internal;transport=tcp;lr>", aliceAssociated)
	if got := f.take(p); len(got) != 0 {
		t.Fatal("sent without a next hop")
	}
	p.subs.mu.Lock()
	n := len(p.subs.byKey) + len(p.subs.byID)
	p.subs.mu.Unlock()
	if n != 0 {
		t.Errorf("%d subscriptions kept", n)
	}
}

// A subscription whose dialog no NOTIFY set up is forgotten once it
// expires, and set up again.
func TestASubscriptionWithoutANotifyIsSetUpAgain(t *testing.T) {
	p, clock, f := newSubscribingPcscf(t)
	registerKept(t, p, "FLOW-A")
	respond(t, f.one(t, p), 200, "Expires: 1200")
	clock.t = clock.t.Add(1200*time.Second - time.Second)
	p.reconcileSubscriptions()
	if got := f.take(p); len(got) != 0 {
		t.Fatalf("%d sent before it expired", len(got))
	}
	clock.t = clock.t.Add(time.Second)
	p.reconcileSubscriptions()
	f.one(t, p)
}

// A refresh that the notifier answers 481 ends the subscription, which it
// lost; a new one is set up after resubscribeAfter, not the hour a
// refusal waits.
func TestAFailedRefreshEndsTheSubscription(t *testing.T) {
	p, clock, f := newSubscribingPcscf(t)
	registerKept(t, p, "FLOW-A")
	s := f.one(t, p)
	respond(t, s, 200, "Expires: 1800")
	if code := notify(t, p, notifyFor(t, s.req, 1, "active;expires=1800", nil)); code != 200 {
		t.Fatalf("first NOTIFY: %d", code)
	}
	clock.t = clock.t.Add(1800*time.Second - refreshLead)
	p.reconcileSubscriptions()
	refresh := f.one(t, p)
	if refresh.req.Header.Get("Expires") == "0" {
		t.Fatal("ended, not refreshed")
	}
	respond(t, refresh, 481)
	if code := notify(t, p, notifyFor(t, s.req, 2, "active", nil)); code != 481 {
		t.Errorf("the ended subscription took a NOTIFY: %d", code)
	}
	clock.t = clock.t.Add(resubscribeAfter)
	registerKept(t, p, "FLOW-A")
	if got := f.one(t, p).req; got.Header.Get("CSeq") != "1 SUBSCRIBE" {
		t.Errorf("CSeq %q", got.Header.Get("CSeq"))
	}
}

// A SUBSCRIBE that times out after its first NOTIFY has set up the dialog
// leaves the subscription standing (RFC 6665 §4.1.2.4).
func TestANotifyBeforeTheAnswerSetsUpTheSubscription(t *testing.T) {
	p, _, f := newSubscribingPcscf(t)
	registerKept(t, p, "FLOW-A")
	s := f.one(t, p)
	if code := notify(t, p, notifyFor(t, s.req, 1, "active;expires=7200", nil)); code != 200 {
		t.Fatalf("first NOTIFY: %d", code)
	}
	s.h(nil, transaction.ErrTimeout)
	if code := notify(t, p, notifyFor(t, s.req, 2, "active;expires=7100", nil)); code != 200 {
		t.Errorf("after the SUBSCRIBE timed out: %d", code)
	}
}

// The expiry a NOTIFY gives replaces the one the 2xx gave, so the refresh
// comes before the subscription ends (RFC 6665 §4.1.3).
func TestANotifysExpiryMovesTheRefresh(t *testing.T) {
	p, clock, f := newSubscribingPcscf(t)
	sub := subscribedAlice(t, p, f)
	if code := notify(t, p, notifyFor(t, sub, 2, "active;expires=1800", nil)); code != 200 {
		t.Fatalf("NOTIFY: %d", code)
	}
	clock.t = clock.t.Add(1800*time.Second - refreshLead)
	p.reconcileSubscriptions()
	if got := f.one(t, p).req; got.Header.Get("Expires") == "0" || got.Header.Get("CSeq") != "2 SUBSCRIBE" {
		t.Errorf("Expires %q, CSeq %q", got.Header.Get("Expires"), got.Header.Get("CSeq"))
	}
}

// A refresh asserts the Path of the user's registration that expires last,
// the one most likely to outlive the subscription.
func TestARefreshAssertsTheLatestRegistrationsPath(t *testing.T) {
	p, clock, f := newSubscribingPcscf(t)
	registerKept(t, p, "FLOW-A")
	s := f.one(t, p)
	respond(t, s, 200, "Expires: 1800")
	if code := notify(t, p, notifyFor(t, s.req, 1, "active;expires=1800", nil)); code != 200 {
		t.Fatalf("first NOTIFY: %d", code)
	}
	clock.t = clock.t.Add(time.Minute)
	registerKept(t, p, "FLOW-B")
	clock.t = clock.t.Add(1800*time.Second - refreshLead - time.Minute)
	p.reconcileSubscriptions()
	if got := f.one(t, p).req.Header.Get("P-Asserted-Identity"); got != "<sip:FLOW-B@10.0.2.9:5070;transport=tcp;lr;ob>" {
		t.Errorf("P-Asserted-Identity %q", got)
	}
}

// Identities compare as URIs without their parameters, whichever side has
// them; tel URIs keep theirs, which RFC 3966 §4 compares.
func TestIdentitiesCompareWithoutTheirParameters(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		same bool
	}{
		{aliceIMPU, aliceIMPU + ";user=phone", true},
		{aliceIMPU + ";user=phone", aliceIMPU, true},
		{aliceIMPU + "?subject=x", aliceIMPU, true},
		{aliceIMPU, "sip:+%315550100001@IMS.mnc001.mcc001.3gppnetwork.org", true},
		{aliceIMPU, bobIMPU, false},
		{aliceTel, "tel:+1-555-010-0001", true},
		{"tel:0100001;phone-context=ims.mnc001.mcc001.3gppnetwork.org", "tel:0100001;phone-context=example.net", false},
	} {
		if got := sameIdentity(mustURI(t, tt.a), mustURI(t, tt.b)); got != tt.same {
			t.Errorf("%s, %s: %v", tt.a, tt.b, got)
		}
	}
}

// A NOTIFY's change does not undo a registration saved since: replace
// puts its copy in place only of the registration it was made from.
func TestAChangeFromANotifyLeavesANewerRegistration(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	r := newRegistry(10, clock.now)
	u := mustURI(t, aliceIMPU)
	old := &registration{flow: "FLOW-A", uri: u, aor: aorKey(u), expires: clock.t.Add(time.Hour)}
	newer := &registration{flow: "FLOW-A", uri: u, aor: aorKey(u), expires: clock.t.Add(2 * time.Hour)}
	if r.save(old) != nil || r.save(newer) != nil {
		t.Fatal("save")
	}
	changed := *old
	r.replace(old, &changed)
	if got, _ := r.lookup("FLOW-A", aorKey(u)); got != newer {
		t.Errorf("the newer registration was replaced: %+v", got)
	}
	r.replace(newer, &changed)
	if got, _ := r.lookup("FLOW-A", aorKey(u)); got != &changed {
		t.Errorf("the current registration was not replaced: %+v", got)
	}
	if got := r.ofDefault(aorKey(u)); len(got) != 1 || got[0] != &changed {
		t.Errorf("index %+v", got)
	}
}

// One sweep sets up at most maxSubscribesPerSweep subscriptions, so that
// a task does not send one SUBSCRIBE per user at once; the next sweep goes
// on.
func TestASweepSetsUpABoundedNumberOfSubscriptions(t *testing.T) {
	p, clock, f := newSubscribingPcscf(t)
	for i := range maxSubscribesPerSweep + 10 {
		u := mustURI(t, fmt.Sprintf("sip:user%d@ims.mnc001.mcc001.3gppnetwork.org", i))
		reg := &registration{flow: "FLOW-A", uri: u, aor: aorKey(u), expires: clock.t.Add(time.Hour),
			serviceRoute: []sip.Address{{URI: mustURI(t, "sip:orig@scscf.rcs.internal;transport=tcp;lr")}}}
		if err := p.registry.save(reg); err != nil {
			t.Fatal(err)
		}
	}
	p.reconcileSubscriptions()
	if got := len(f.take(p)); got != maxSubscribesPerSweep {
		t.Errorf("first sweep: %d", got)
	}
	p.reconcileSubscriptions()
	if got := len(f.take(p)); got != 10 {
		t.Errorf("second sweep: %d", got)
	}
}

// metricReader keeps what a pcscf's metrics write.
type metricReader struct {
	p   *pcscf
	out strings.Builder
}

// count reports whether the metrics written so far count n of name.
func (m *metricReader) count(name string, n int) bool {
	m.p.metrics.Flush()
	return strings.Contains(m.out.String(), fmt.Sprintf(`"%s":%d`, name, n))
}
