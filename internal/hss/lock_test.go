package hss

import (
	"context"
	"errors"
	"net/http"
	"sync"
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

// losingStore refuses the first n subscription writes as lost to
// another task, and counts every write.
type losingStore struct {
	store.Store
	mu      sync.Mutex
	n       int
	written int
}

func (c *losingStore) UpdateSubscription(ctx context.Context, old, s *store.Subscription) (*store.Subscription, error) {
	c.mu.Lock()
	c.written++
	lose := c.n > 0
	if lose {
		c.n--
	}
	c.mu.Unlock()
	if lose {
		return nil, store.ErrConflict
	}
	return c.Store.UpdateSubscription(ctx, old, s)
}

// A request that read the subscription and then waited for its lock reads
// it again: the request that held the lock wrote it, so the first read is
// stale for certain, and writing from it cost every queued MAR a lost write
// (#200).
func TestAnUpdateThatWaitedForTheLockReadsTheSubscriptionAgain(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	read, err := e.store.Subscription(context.Background(), impi1)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := e.h.lock(context.Background(), impi1)
	if err != nil {
		t.Fatal(err)
	}
	waiting := make(chan struct{})
	e.h.onLockWait = func() { close(waiting) }
	done := make(chan error, 1)
	go func() {
		_, err := e.h.updateFrom(context.Background(), impi1, read, func(s *store.Subscription) error {
			s.ServerName = "sip:scscf-2.rcs.local"
			return nil
		})
		done <- err
	}()
	<-waiting
	// What the lock's holder writes before it lets go.
	e.modify(impi1, func(s *store.Subscription) { s.ServerName = "sip:scscf-1.rcs.local" })
	unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := e.metrics.get("store.conflict"); got != 0 {
		t.Errorf("%d lost writes, want none: the stale read was written from", got)
	}
	if got := e.sub(impi1).ServerName; got != "sip:scscf-2.rcs.local" {
		t.Errorf("ServerName = %q", got)
	}
}

// A write that keeps losing to another task is retried for as long as the
// request has time, not a fixed handful of times: losing again is about as
// likely after any wait while that task keeps writing, so a count gave up
// MARs that had seconds left (#200). Without time, it stops at the deadline.
func TestAWriteLosingToAnotherTaskIsRetriedUntilItsDeadline(t *testing.T) {
	cs := &losingStore{Store: store.NewMemory(), n: 12}
	e := newEnvWith(t, cs)
	e.provision(impi1, impu1)
	set := func(s *store.Subscription) error {
		s.ServerName = "sip:scscf-1.rcs.local"
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), realWait)
	defer cancel()
	if _, err := e.h.update(ctx, impi1, set); err != nil {
		t.Fatalf("after 12 lost writes: %v", err)
	}
	if cs.written != 13 || e.sub(impi1).ServerName != "sip:scscf-1.rcs.local" {
		t.Errorf("%d writes, ServerName %q", cs.written, e.sub(impi1).ServerName)
	}

	cs.mu.Lock()
	cs.n = 1 << 30
	cs.mu.Unlock()
	short, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := e.h.update(short, impi1, set); err == nil {
		t.Fatal("a write that never wins succeeded")
	}
	if took := time.Since(start); took > realWait/2 {
		t.Errorf("gave up after %v; the deadline was 300ms", took)
	}

	// Without a deadline, nothing but the count stops it.
	cs.mu.Lock()
	cs.written = 0
	cs.mu.Unlock()
	if _, err := e.h.update(context.Background(), impi1, set); !errors.Is(err, errContention) {
		t.Fatalf("without a deadline: %v", err)
	}
	if cs.written != maxUpdateAttempts {
		t.Errorf("without a deadline: %d writes, want %d", cs.written, maxUpdateAttempts)
	}
}
