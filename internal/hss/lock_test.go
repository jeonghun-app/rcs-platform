package hss

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
)

// A request that holds a subscriber's lock for long, such as an API write
// whose store calls are slow, delays Cx for that stripe only as long as the
// Cx timeout: then the waiting request is answered DIAMETER_TOO_BUSY, which
// the S-CSCF may retry on another HSS task.
func TestABusySubscriptionAnswersTooBusyWithinTheCxTimeout(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	unlock, err := e.h.lock(context.Background(), impi1)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	c := connectCSCF(t, serveHSSWith(t, e.h, "hss-a.rcs.local", 200*time.Millisecond), "scscf-1.rcs.local")
	r := &cx.MAR{Request: cx.Request{DestinationRealm: domain}, UserName: impi1, PublicIdentity: impu1,
		AuthDataItem: cx.AuthDataItem{Scheme: cx.SchemeDigestAKAv1MD5}, NumberAuthItems: 1, ServerName: scscfName}
	start := time.Now()
	ans := c.send(r.Message(c.node))
	if rc, _ := ans.ResultCode(); rc != diameter.ResultTooBusy {
		t.Fatalf("Result-Code = %d, want DIAMETER_TOO_BUSY", rc)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("answered after %v; the wait must end at the Cx timeout", took)
	}
	if e.metrics.get("lock.busy") != 1 {
		t.Error("the busy lock was not counted")
	}
	// Reads need no lock: LIR is still answered.
	if lia := c.lir(impu1, false); lia.Result != exp(cx.UnregisteredService) {
		t.Errorf("LIA = %v", lia.Result)
	}
}

func TestABusySubscriptionAnswersTheAPIWith503(t *testing.T) {
	a := newAPIEnv(t, func(o *APIOptions) { o.StoreTimeout = 100 * time.Millisecond })
	a.create(impi1, true, impu1)
	unlock, err := a.h.lock(context.Background(), impi1)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	code, _, h := a.do("POST", subPath(impi1, "/digest-credential"), adminToken, "")
	if code != http.StatusServiceUnavailable || h.Get("Retry-After") == "" {
		t.Fatalf("busy = %d", code)
	}
}

func TestUnusableStoredSecretsAre500WithoutRetry(t *testing.T) {
	a := newAPIEnv(t)
	a.create(impi1, true, impu1)
	a.modify(impi1, func(s *store.Subscription) {
		s.Digest = []store.DigestCredential{{Realm: ftRealm, HA1MD5: store.Sealed("garbage"), HA1SHA256: store.Sealed("garbage")}}
	})
	code, _, h := a.do("GET", subPath(impi1, "/ft-credential?algorithm=MD5"), ftToken, "")
	if code != http.StatusInternalServerError || h.Get("Retry-After") != "" {
		t.Fatalf("corrupt HA1 = %d, Retry-After %q", code, h.Get("Retry-After"))
	}
	if a.metrics.get("api.data_error") != 1 || a.metrics.get("api.store_failure") != 0 {
		t.Error("a data error was counted as a store failure")
	}
}
