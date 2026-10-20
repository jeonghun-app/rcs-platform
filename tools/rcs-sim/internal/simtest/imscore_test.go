package simtest_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/reginfo"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/simtest"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/sipua"
)

// Test subscribers on .github/allowed-test-identifiers.txt, with made-up
// passwords.
const (
	domain = "ims.mnc001.mcc001.3gppnetwork.org"
	impiA  = "001010000000001@" + domain
	impiB  = "001010000000002@" + domain
	impuA  = "sip:+15550100001@" + domain
	impuB  = "sip:+15550100002@" + domain
)

func registered(t *testing.T, ctx context.Context, core *simtest.IMSCore, impu, impi, password, instance string, onRequest func(*transaction.ServerTransaction)) *sipua.UA {
	t.Helper()
	u, err := sip.ParseURI(impu)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := sipua.DigestCredentials(impi, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	ua, err := sipua.Dial(ctx, sipua.Config{Network: transport.TCP, Proxy: core.Addr, Domain: domain, IMPU: u, InstanceID: instance, Credentials: creds, OnRequest: onRequest})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ua.Close() })
	if _, err := ua.Register(ctx); err != nil {
		t.Fatal(err)
	}
	return ua
}

func TestBindingsAndLookupsUseOneKey(t *testing.T) {
	// QA on #209: an IMPU registered with URI parameters is found without
	// them, and the other way round.
	core := simtest.StartIMSCore(t, domain, map[string]string{impiA: "a-password"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	registered(t, ctx, core, impuA+";user=phone", impiA, "a-password", "urn:uuid:00000000-0000-4000-8000-000000000001", nil)
	if !core.Registered(impuA) || !core.Registered(impuA+";user=phone") || !core.Registered("sip:+15550100001@IMS.mnc001.mcc001.3gppnetwork.org") {
		t.Fatal("the binding is not found by the IMPU's other forms")
	}
}

func TestARequestTheCalledPartyNeverAnswersGets408(t *testing.T) {
	// QA on #209: when the terminating transaction times out, the
	// originator hears it (RFC 3261 §16.7), not a step timeout. T1 is 10
	// ms here, so Timer F fires after 640 ms.
	core := simtest.StartIMSCore(t, domain, map[string]string{impiA: "a-password", impiB: "b-password"}, 10*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a := registered(t, ctx, core, impuA, impiA, "a-password", "urn:uuid:00000000-0000-4000-8000-000000000001", nil)
	// B takes every request and never answers it.
	registered(t, ctx, core, impuB, impiB, "b-password", "urn:uuid:00000000-0000-4000-8000-000000000002",
		func(*transaction.ServerTransaction) {})
	u, _ := sip.ParseURI(impuB)
	req, err := a.NewMessage(u, "text/plain", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if res, err := a.Send(ctx, req); err != nil || res.StatusCode != 408 {
		t.Fatalf("MESSAGE nobody answers = %v, %v; want 408", res, err)
	}
}

func TestAnExpiredBindingEndsItsRegEventSubscription(t *testing.T) {
	core := simtest.StartIMSCore(t, domain, map[string]string{impiA: "a-password"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ua := registered(t, ctx, core, impuA, impiA, "a-password", "urn:uuid:00000000-0000-4000-8000-000000000001", nil)
	sub, _, err := ua.SubscribeRegEvent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	next := func() sipua.Notification {
		select {
		case n := <-sub.Notifications():
			return n
		case <-ctx.Done():
			t.Fatal("no NOTIFY came")
		}
		return sipua.Notification{}
	}
	next()
	core.Expire(impuA)
	n := next()
	c, ok := ownContact(t, n.Info, impuA, ua.ContactURI())
	if n.State != "terminated" || !ok || c.Active() || c.Event != reginfo.Expired {
		t.Fatalf("notification %+v, contact %+v", n, c)
	}
	if core.Registered(impuA) {
		t.Fatal("the binding outlived its expiry")
	}
	select {
	case <-sub.Done():
	case <-ctx.Done():
		t.Fatal("the subscription did not end")
	}
}

// nextNotification is the subscription's next notification.
func nextNotification(t *testing.T, ctx context.Context, sub *sipua.Subscription) sipua.Notification {
	t.Helper()
	select {
	case n := <-sub.Notifications():
		return n
	case <-ctx.Done():
		t.Fatal("no NOTIFY came")
	}
	return sipua.Notification{}
}

func TestAUserPhoneIMPUIsNotifiedOfItsRefresh(t *testing.T) {
	// Code review on #216: REGISTER and SUBSCRIBE key the IMPU alike
	// (aorKey), so an IMPU with user=phone gets its contact in the first
	// NOTIFY and a NOTIFY at its refresh.
	core := simtest.StartIMSCore(t, domain, map[string]string{impiA: "a-password"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ua := registered(t, ctx, core, impuA+";user=phone", impiA, "a-password", "urn:uuid:00000000-0000-4000-8000-000000000001", nil)
	sub, _, err := ua.SubscribeRegEvent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n := nextNotification(t, ctx, sub); n.Info == nil {
		t.Fatalf("first notification %+v", n)
	} else if c, ok := ownContact(t, n.Info, impuA, ua.ContactURI()); !ok || !c.Active() {
		t.Fatalf("first notification %+v, contact %+v", n.Info, c)
	}
	if _, err := ua.Register(ctx); err != nil {
		t.Fatal(err)
	}
	if n := nextNotification(t, ctx, sub); n.Info == nil || n.Info.Version != 1 {
		t.Fatalf("notification after the refresh %+v", n)
	} else if c, ok := ownContact(t, n.Info, impuA, ua.ContactURI()); !ok || !c.Active() || c.Event != reginfo.Refreshed {
		t.Fatalf("contact after the refresh %+v", c)
	}
}

func TestAChangeIsToldOnlyToThoseSubscribedWhenItHappened(t *testing.T) {
	// #272: client A's de-registration was answered, and only then were
	// the subscribers it changed read. The reading goroutine of A's
	// connection, held up after the 200, could come to it after client B
	// on the same IMPU had registered and subscribed: B's subscription got
	// A's ending, a terminated NOTIFY without B's contact, and lost its
	// own. The hook holds A's goroutine just there.
	core := simtest.StartIMSCore(t, domain, map[string]string{impiA: "a-password"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a := registered(t, ctx, core, impuA, impiA, "a-password", "urn:uuid:00000000-0000-4000-8000-000000000001", nil)
	held, gate := make(chan struct{}), make(chan struct{})
	// Released on every way out, so that a failed check ends the test
	// rather than leaving A's goroutine, and the core's Close, waiting.
	release := sync.OnceFunc(func() { close(gate) })
	defer release()
	var once sync.Once
	simtest.SetAnswered(core, func(req *sip.Request) {
		if exp, err := req.Header.Expires(); err == nil && exp == 0 {
			once.Do(func() {
				close(held)
				<-gate
			})
		}
	})
	if _, err := a.Unregister(ctx); err != nil {
		t.Fatal(err)
	}
	<-held
	b := registered(t, ctx, core, impuA, impiA, "a-password", "urn:uuid:00000000-0000-4000-8000-000000000002", nil)
	sub, _, err := b.SubscribeRegEvent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n := nextNotification(t, ctx, sub); n.Info == nil {
		t.Fatalf("first notification %+v", n)
	} else if c, ok := ownContact(t, n.Info, impuA, b.ContactURI()); !ok || !c.Active() {
		t.Fatalf("first notification %+v, contact %+v", n.Info, c)
	}
	release()
	// B's own changes, and nothing of A's, in order.
	if _, err := b.Register(ctx); err != nil {
		t.Fatal(err)
	}
	n := nextNotification(t, ctx, sub)
	if c, ok := ownContact(t, n.Info, impuA, b.ContactURI()); n.State != "active" || !ok || !c.Active() || c.Event != reginfo.Refreshed {
		t.Fatalf("notification after B's refresh %+v, contact %+v", n, c)
	}
	if _, err := b.Unregister(ctx); err != nil {
		t.Fatal(err)
	}
	n = nextNotification(t, ctx, sub)
	if c, ok := ownContact(t, n.Info, impuA, b.ContactURI()); n.State != "terminated" || !ok || c.Active() || c.Event != reginfo.Unregistered {
		t.Fatalf("notification after B's de-registration %+v, contact %+v", n, c)
	}
}

func TestUnsubscribingWritesTheContactAsItStands(t *testing.T) {
	// Code review on #216 (RFC 3680 §4.7.1, TS 24.229 §5.4.2.1.2 NOTE 10):
	// the end of the subscription does not end the registration.
	core := simtest.StartIMSCore(t, domain, map[string]string{impiA: "a-password"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ua := registered(t, ctx, core, impuA, impiA, "a-password", "urn:uuid:00000000-0000-4000-8000-000000000001", nil)
	sub, _, err := ua.SubscribeRegEvent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nextNotification(t, ctx, sub)
	if _, err := sub.Unsubscribe(ctx); err != nil {
		t.Fatal(err)
	}
	n := nextNotification(t, ctx, sub)
	c, ok := ownContact(t, n.Info, impuA, ua.ContactURI())
	if n.State != "terminated" || n.Reason != "timeout" || !ok || !c.Active() || c.Event != reginfo.Registered {
		t.Fatalf("final notification %+v, contact %+v", n, c)
	}
}

// subscribeByHand sends ua's SUBSCRIBE for its reg event, with expires
// unless it is "", outside sipua's own subscriptions: the NOTIFYs go to
// ua's OnRequest.
func subscribeByHand(t *testing.T, ctx context.Context, ua *sipua.UA, impu, expires string) *sip.Response {
	t.Helper()
	u, _ := sip.ParseURI(impu)
	req, err := ua.NewRequest("SUBSCRIBE", u)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range [][2]string{{"Contact", "<" + ua.ContactURI().String() + ">"}, {"Event", "reg"}, {"Accept", "application/reginfo+xml"}} {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			t.Fatal(err)
		}
	}
	if expires != "" {
		_ = req.Header.Add("Expires", expires)
	}
	res, err := ua.Send(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// notifies records the NOTIFYs a UA's OnRequest gets, answering them
// unless hold is set, in which case the test answers them.
type notifies struct {
	got  chan *transaction.ServerTransaction
	hold bool
}

func (n *notifies) onRequest(tx *transaction.ServerTransaction) {
	if !n.hold {
		if res, err := sip.NewResponse(tx.Request(), 200, "", "ua"); err == nil {
			_ = tx.Respond(res)
		}
	}
	n.got <- tx
}

func (n *notifies) next(t *testing.T, ctx context.Context) *transaction.ServerTransaction {
	t.Helper()
	select {
	case tx := <-n.got:
		return tx
	case <-ctx.Done():
		t.Fatal("no NOTIFY came")
	}
	return nil
}

func TestARegEventSubscriptionIsNeverLengthened(t *testing.T) {
	// Code review and QA on #216: without Expires the subscription lasts
	// RFC 3680 §4.4's 3761 s, and a later NOTIFY says what is left of it,
	// never more (RFC 6665 §4.1.3).
	core := simtest.StartIMSCore(t, domain, map[string]string{impiA: "a-password"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	n := &notifies{got: make(chan *transaction.ServerTransaction, 8)}
	ua := registered(t, ctx, core, impuA, impiA, "a-password", "urn:uuid:00000000-0000-4000-8000-000000000001", n.onRequest)
	if res := subscribeByHand(t, ctx, ua, impuA, ""); res.StatusCode != 200 || res.Header.Get("Expires") != "3761" {
		t.Fatalf("SUBSCRIBE answered %d, Expires %q", res.StatusCode, res.Header.Get("Expires"))
	}
	if st := n.next(t, ctx).Request().Header.Get("Subscription-State"); st != "active;expires=3761" {
		t.Fatalf("first NOTIFY's Subscription-State %q", st)
	}
	if _, err := ua.Register(ctx); err != nil {
		t.Fatal(err)
	}
	ss, err := n.next(t, ctx).Request().Header.SubscriptionState()
	if left, ok := ss.Expires(); err != nil || ss.State != "active" || !ok || left > 3761 || left < 3700 {
		t.Fatalf("Subscription-State after the refresh %+v, %v", ss, err)
	}
}

func TestAnUnsubscribeForNoSubscriptionIs481(t *testing.T) {
	core := simtest.StartIMSCore(t, domain, map[string]string{impiA: "a-password"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ua := registered(t, ctx, core, impuA, impiA, "a-password", "urn:uuid:00000000-0000-4000-8000-000000000001", nil)
	if res := subscribeByHand(t, ctx, ua, impuA, "0"); res.StatusCode != 481 {
		t.Fatalf("SUBSCRIBE Expires: 0 for no subscription answered %d", res.StatusCode)
	}
}

func TestNotifiesGoOneAtATime(t *testing.T) {
	// QA on #216: the next NOTIFY waits for the last one's answer, so the
	// versions reach the subscriber in order.
	core := simtest.StartIMSCore(t, domain, map[string]string{impiA: "a-password"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	n := &notifies{got: make(chan *transaction.ServerTransaction, 8), hold: true}
	ua := registered(t, ctx, core, impuA, impiA, "a-password", "urn:uuid:00000000-0000-4000-8000-000000000001", n.onRequest)
	subscribeByHand(t, ctx, ua, impuA, "600")
	first := n.next(t, ctx)
	if _, err := ua.Register(ctx); err != nil {
		t.Fatal(err)
	}
	// A second NOTIFY sent without waiting would be here by now; this only
	// catches that.
	select {
	case <-n.got:
		t.Fatal("a NOTIFY went before the last one was answered")
	case <-time.After(300 * time.Millisecond):
	}
	if res, err := sip.NewResponse(first.Request(), 200, "", "ua"); err == nil {
		_ = first.Respond(res)
	}
	n.next(t, ctx)
}

// ownContact is the contact at uri of impu's registration in info.
func ownContact(t *testing.T, info *reginfo.Info, impu string, uri sip.URI) (reginfo.Contact, bool) {
	t.Helper()
	if info == nil {
		return reginfo.Contact{}, false
	}
	u, err := sip.ParseURI(impu)
	if err != nil {
		t.Fatal(err)
	}
	reg, ok := info.ByAOR(u)
	if !ok {
		return reginfo.Contact{}, false
	}
	if cs := reg.ByURI(uri); len(cs) > 0 {
		return cs[0], true
	}
	return reginfo.Contact{}, false
}
