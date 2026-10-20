package simtest_test

import (
	"context"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
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
