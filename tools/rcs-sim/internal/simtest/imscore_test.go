package simtest_test

import (
	"context"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/reginfo"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/simtest"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/sipua"
)

func TestAnExpiredBindingEndsItsRegEventSubscription(t *testing.T) {
	// The test subscriber is on .github/allowed-test-identifiers.txt; its
	// password is made up.
	const (
		domain = "ims.mnc001.mcc001.3gppnetwork.org"
		impi   = "001010000000001@" + domain
		impu   = "sip:+15550100001@" + domain
	)
	core := simtest.StartIMSCore(t, domain, map[string]string{impi: "self-password"})
	u, _ := sip.ParseURI(impu)
	creds, err := sipua.DigestCredentials(impi, []byte("self-password"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ua, err := sipua.Dial(ctx, sipua.Config{Network: transport.TCP, Proxy: core.Addr, Domain: domain, IMPU: u,
		InstanceID: "urn:uuid:00000000-0000-4000-8000-000000000001", Credentials: creds})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ua.Close() })
	if _, err := ua.Register(ctx); err != nil {
		t.Fatal(err)
	}
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
	core.Expire(impu)
	n := next()
	var c reginfo.Contact
	ok := false
	for _, reg := range n.Info.ByAOR(u) {
		if cs := reg.ByURI(ua.ContactURI()); len(cs) == 1 {
			c, ok = cs[0], true
		}
	}
	if n.State != "terminated" || !ok || c.State != reginfo.ContactTerminated || c.Event != reginfo.Expired {
		t.Fatalf("notification %+v, contact %+v", n, c)
	}
	if core.Registered(impu) {
		t.Fatal("the binding outlived its expiry")
	}
	select {
	case <-sub.Done():
	case <-ctx.Done():
		t.Fatal("the subscription did not end")
	}
}
