package sipua

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

const (
	notifierContact = "<sip:scscf.example.com:5060;transport=tcp>"
	// The Record-Route of the 2xx to SUBSCRIBE, topmost first: the S-CSCF,
	// nearest the notifier.
	notifierRecordRoute = "<sip:scscf.example.com;lr>, <sip:pcscf.example.com;lr>"
)

// reginfo is a reg event body: the IMPU's registration with one contact.
func reginfo(version int, state, contactState, event string, uri string) string {
	return `<?xml version="1.0"?>` +
		`<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="` + strconv.Itoa(version) + `" state="` + state + `">` +
		`<registration aor="` + testIMPU + `" id="r1" state="active">` +
		`<contact id="c1" state="` + contactState + `" event="` + event + `" expires="3600"><uri>` + uri + `</uri></contact>` +
		`</registration></reginfo>`
}

// notifier is the stand-in as the S-CSCF's reg event notifier.
type notifier struct {
	s   *standIn
	tag string

	mu   sync.Mutex
	sub  *sip.Request
	flow transport.FlowID
	cseq uint32
	// before, when set, is sent as a NOTIFY before the 2xx to SUBSCRIBE.
	before string
	refuse int
}

func newNotifier(t *testing.T, s *standIn) *notifier {
	n := &notifier{s: s, tag: "notifier", cseq: 1}
	s.onSubscribe = func(tx *transaction.ServerTransaction) {
		req := tx.Request()
		n.mu.Lock()
		if n.sub == nil {
			n.sub, n.flow = req.Clone(), tx.Source().Flow
		}
		before, refuse := n.before, n.refuse
		n.mu.Unlock()
		answer := func() {
			code := 200
			if refuse != 0 {
				code = refuse
			}
			res := mustResponse(t, req, code, n.tag)
			if code == 200 {
				res.Header.Add("Contact", notifierContact)
				res.Header.Add("Record-Route", notifierRecordRoute)
				res.Header.Add("Expires", strconv.Itoa(RegEventExpires))
			}
			if err := tx.Respond(res); err != nil && !s.closing.Load() {
				t.Errorf("notifier: %v", err)
			}
		}
		if before == "" {
			answer()
			return
		}
		// The NOTIFY first, then the 2xx (RFC 6665 §4.1.2.4). Off the
		// reading goroutine, which must read the NOTIFY's answer.
		go func() {
			n.notifyNoWait(t, "active;expires=600000", before)
			answer()
		}()
	}
	return n
}

// notify sends a NOTIFY in the subscription's dialog and returns the final
// response.
func (n *notifier) notify(t *testing.T, state, body string) *sip.Response {
	t.Helper()
	return n.s.sendRequest(t, n.request(t, state, body, ""), n.flow)
}

func (n *notifier) notifyNoWait(t *testing.T, state, body string) {
	req := n.request(t, state, body, "")
	done := make(chan struct{})
	if _, err := n.s.layer.Request(req, transport.Destination{Flow: n.flow}, func(res *sip.Response, err error) {
		if err != nil || res.StatusCode >= 200 {
			close(done)
		}
	}); err != nil {
		t.Errorf("notifier: %v", err)
		return
	}
	<-done
}

// request builds a NOTIFY; event is the Event header, "reg" when empty.
func (n *notifier) request(t *testing.T, state, body, event string) *sip.Request {
	n.mu.Lock()
	sub := n.sub
	n.cseq++
	cseq := n.cseq
	n.mu.Unlock()
	contacts, _ := sub.Header.Contact()
	branch, _ := n.s.ids.Branch()
	if event == "" {
		event = "reg"
	}
	req := &sip.Request{Method: "NOTIFY", URI: contacts[0].URI}
	for _, f := range [][2]string{
		{"Via", "SIP/2.0/TCP standin.invalid;branch=" + branch},
		{"Max-Forwards", "70"},
		{"From", sub.Header.Get("To") + ";tag=" + n.tag},
		{"To", sub.Header.Get("From")},
		{"Call-ID", sub.Header.Get("Call-ID")},
		{"CSeq", fmt.Sprintf("%d NOTIFY", cseq)},
		{"Contact", notifierContact},
		{"Event", event},
		{"Subscription-State", state},
	} {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			t.Errorf("notifier: %v", err)
		}
	}
	if body != "" {
		req.Header.Add("Content-Type", "application/reginfo+xml")
		req.Body = []byte(body)
	}
	return req
}

func subscribed(t *testing.T) (*standIn, *notifier, *UA, *Subscription) {
	t.Helper()
	s := newStandIn(t, transport.TCP)
	n := newNotifier(t, s)
	ua := dial(t, s.config())
	register(t, ua)
	sub, res, err := ua.SubscribeRegEvent(context.Background())
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("SubscribeRegEvent = %v, %v", res, err)
	}
	return s, n, ua, sub
}

func nextNotification(t *testing.T, sub *Subscription) Notification {
	t.Helper()
	select {
	case n := <-sub.Notifications():
		return n
	case <-time.After(waitFor):
		t.Fatal("no notification")
		return Notification{}
	}
}

func TestSubscribeAsksForTheRegEventOfTheIMPU(t *testing.T) {
	s, _, _, _ := subscribed(t)
	req := s.nextMethod(t, "SUBSCRIBE").req
	to, _ := req.Header.To()
	contacts, _ := req.Header.Contact()
	switch {
	case req.URI.String() != testIMPU || to.URI.String() != testIMPU:
		t.Errorf("Request-URI %s, To %s: want the IMPU (TS 24.229 §5.1.1.3)", req.URI, to)
	case req.Header.Get("Event") != "reg" || req.Header.Get("Accept") != "application/reginfo+xml":
		t.Errorf("Event %q, Accept %q", req.Header.Get("Event"), req.Header.Get("Accept"))
	case req.Header.Get("Expires") != "600000":
		t.Errorf("Expires %q", req.Header.Get("Expires"))
	case req.Header.Get("P-Preferred-Identity") != "<"+testIMPU+">":
		t.Errorf("P-Preferred-Identity %q", req.Header.Get("P-Preferred-Identity"))
	case len(contacts) != 1 || !contacts[0].URI.Params.Has("ob"):
		t.Errorf("Contact %v", contacts)
	case routeHosts(t, req) != "127.0.0.1 scscf.example.com as.example.com":
		t.Errorf("Route %s", routeHosts(t, req))
	}
}

func TestNotificationsCarryTheRegistrationStateInOrder(t *testing.T) {
	s, n, ua, sub := subscribed(t)
	_ = s
	contact := ua.contact.URI.String()
	for v, body := range []string{
		reginfo(0, "full", "active", "registered", contact),
		reginfo(1, "full", "active", "refreshed", contact),
	} {
		if res := n.notify(t, "active;expires=600000", body); res.StatusCode != 200 {
			t.Fatalf("NOTIFY %d answered %d", v, res.StatusCode)
		}
		got := nextNotification(t, sub)
		c, ok := got.Info.Contact(testIMPU, contact)
		if got.Err != nil || got.State != "active" || got.Info.Version != uint64(v) || !ok || c.State != "active" {
			t.Fatalf("notification %d = %+v, contact %+v", v, got, c)
		}
	}
	// A network-initiated de-registration (RFC 3680 §5.3.2).
	n.notify(t, "terminated;reason=deactivated", reginfo(2, "full", "terminated", "deactivated", contact))
	got := nextNotification(t, sub)
	c, _ := got.Info.Contact(testIMPU, contact)
	if got.State != "terminated" || got.Reason != "deactivated" || c.State != "terminated" || c.Event != "deactivated" || got.Info.Version != 2 {
		t.Fatalf("final notification = %+v, contact %+v", got, c)
	}
	select {
	case <-sub.Done():
	case <-time.After(waitFor):
		t.Fatal("the subscription did not end")
	}
	// The dialog is gone: another NOTIFY gets 481 (RFC 6665 §4.1.3).
	if res := n.notify(t, "active", ""); res.StatusCode != 481 {
		t.Fatalf("NOTIFY after the end answered %d", res.StatusCode)
	}
}

func TestANotifyBeforeTheTwoHundredSetsUpTheSubscription(t *testing.T) {
	// RFC 6665 §4.1.2.4: the first NOTIFY may overtake the 2xx.
	s := newStandIn(t, transport.TCP)
	n := newNotifier(t, s)
	ua := dial(t, s.config())
	register(t, ua)
	n.before = reginfo(0, "full", "active", "registered", ua.contact.URI.String())
	sub, res, err := ua.SubscribeRegEvent(context.Background())
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("SubscribeRegEvent = %v, %v", res, err)
	}
	if got := nextNotification(t, sub); got.Err != nil || got.Info == nil || got.Info.Version != 0 {
		t.Fatalf("first notification = %+v", got)
	}
}

func TestUnsubscribeSendsExpiresZeroInTheDialog(t *testing.T) {
	s, n, _, sub := subscribed(t)
	first := s.nextMethod(t, "SUBSCRIBE").req
	n.notify(t, "active;expires=600000", "")
	nextNotification(t, sub)
	if res, err := sub.Unsubscribe(context.Background()); err != nil || res.StatusCode != 200 {
		t.Fatalf("Unsubscribe = %v, %v", res, err)
	}
	un := s.nextMethod(t, "SUBSCRIBE").req
	to, _ := un.Header.To()
	fc, _ := first.Header.CSeq()
	uc, _ := un.Header.CSeq()
	if un.Header.Get("Expires") != "0" || un.Header.Get("Event") != "reg" || to.Tag() != n.tag || uc.Seq != fc.Seq+1 ||
		un.URI.String() != mustURI(t, "sip:scscf.example.com:5060;transport=tcp").String() || routeHosts(t, un) != "pcscf.example.com scscf.example.com" {
		t.Fatalf("unsubscribe %s Expires %q To tag %q CSeq %v Route %s", un.URI, un.Header.Get("Expires"), to.Tag(), uc, routeHosts(t, un))
	}
	n.notify(t, "terminated;reason=timeout", "")
	select {
	case <-sub.Done():
	case <-time.After(waitFor):
		t.Fatal("the subscription did not end")
	}
	if _, err := sub.Unsubscribe(context.Background()); !errors.Is(err, ErrDialogEnded) {
		t.Fatalf("Unsubscribe after the end = %v", err)
	}
}

func TestNotifiesOutsideTheRulesAreRefusedOrFlagged(t *testing.T) {
	s, n, _, sub := subscribed(t)
	if res := s.sendRequest(t, n.request(t, "active", "", "presence"), n.flow); res.StatusCode != 489 {
		t.Errorf("NOTIFY for another event answered %d, want 489", res.StatusCode)
	}
	n.notify(t, "active", "")
	nextNotification(t, sub)
	// A CSeq not above the last one (RFC 3261 §12.2.2).
	stale := n.request(t, "active", "", "")
	stale.Header.Set("CSeq", "1 NOTIFY")
	if res := s.sendRequest(t, stale, n.flow); res.StatusCode != 500 {
		t.Errorf("NOTIFY with a lower CSeq answered %d, want 500", res.StatusCode)
	}
	if res := n.notify(t, "active", "<not-reginfo/>"); res.StatusCode != 200 {
		t.Errorf("NOTIFY with a bad body answered %d", res.StatusCode)
	}
	if got := nextNotification(t, sub); got.Err == nil {
		t.Error("a body that is not reginfo raised no error")
	}
	bad := n.request(t, "active", "", "")
	// Valid reginfo, under another type.
	bad.Header.Add("Content-Type", "text/plain")
	bad.Body = []byte(reginfo(2, "full", "active", "registered", "sip:x@192.0.2.9"))
	n.s.sendRequest(t, bad, n.flow)
	if got := nextNotification(t, sub); got.Err == nil {
		t.Error("a text/plain body raised no error")
	}
}

func TestARefusedSubscribeLeavesNoSubscription(t *testing.T) {
	s := newStandIn(t, transport.TCP)
	n := newNotifier(t, s)
	n.refuse = 403
	ua := dial(t, s.config())
	register(t, ua)
	sub, res, err := ua.SubscribeRegEvent(context.Background())
	var se *StatusError
	if sub != nil || res == nil || !errors.As(err, &se) || se.Code != 403 {
		t.Fatalf("SubscribeRegEvent = %v, %v, %v", sub, res, err)
	}
	if res := n.notify(t, "active", ""); res.StatusCode != 481 {
		t.Fatalf("NOTIFY for the refused subscription answered %d, want 481", res.StatusCode)
	}
}

func TestParseRegInfoReadsRFC3680sExample(t *testing.T) {
	// RFC 3680 §6, the example after a registration, shortened.
	body := `<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="partial">
  <registration aor="sip:user@example.com" id="as9" state="active">
    <contact id="76" state="active" event="registered" duration-registered="0" expires="3600">
      <uri>sip:user@pc887.example.com</uri>
    </contact>
  </registration>
</reginfo>`
	r, err := ParseRegInfo([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	c, ok := r.Contact("sip:user@example.com", "sip:user@pc887.example.com")
	if r.Version != 1 || r.State != "partial" || !ok || c.ID != "76" || c.Event != "registered" || c.Expires != 3600 {
		t.Fatalf("ParseRegInfo = %+v, contact %+v", r, c)
	}
	for _, bad := range []string{`<reginfo version="1" state="full"/>`, `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="whole"/>`, `not xml`} {
		if _, err := ParseRegInfo([]byte(bad)); err == nil {
			t.Errorf("ParseRegInfo(%q) accepted it", bad)
		}
	}
}
