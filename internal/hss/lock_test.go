package hss

import (
	"context"
	"errors"
	"net/http"
	"strings"
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
	_, err := e.h.update(short, impi1, set)
	// Still contention, not a slow store (#244 review).
	if !errors.Is(err, errContention) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a write that never wins: %v, want contention at the deadline", err)
	}
	if took := time.Since(start); took > realWait/2 {
		t.Errorf("gave up after %v; the deadline was 300ms", took)
	}
}

// TestAnAPIWriteThatKeepsLosingIsAnsweredBusy: contention that runs to the
// store timeout is answered as contention, 503 "busy", not as a store
// failure: api.store_failure stays 0 and nothing is logged as an error
// (#244 review).
func TestAnAPIWriteThatKeepsLosingIsAnsweredBusy(t *testing.T) {
	a := newAPIEnv(t, func(o *APIOptions) { o.StoreTimeout = 300 * time.Millisecond })
	a.create(impi1, true, impu1)
	a.h.store = &losingStore{Store: a.h.store, n: 1 << 30}
	code, body, h := a.do("POST", subPath(impi1, "/digest-credential"), adminToken, "")
	if msg, _ := body["error"].(string); code != http.StatusServiceUnavailable || !strings.Contains(msg, "busy") || h.Get("Retry-After") == "" {
		t.Fatalf("%d %q", code, body)
	}
	if a.metrics.get("api.store_failure") != 0 {
		t.Error("contention was counted as a store failure")
	}
	if strings.Contains(a.logs.String(), `"level":"ERROR"`) {
		t.Errorf("contention was logged as an error: %s", a.logs.String())
	}
}

// slowWinStore lets the first write through only just before its context's
// deadline, as one that keeps losing to another task until then would.
type slowWinStore struct {
	store.Store
	margin time.Duration
}

func (s *slowWinStore) UpdateSubscription(ctx context.Context, old, n *store.Subscription) (*store.Subscription, error) {
	if d, ok := ctx.Deadline(); ok {
		time.Sleep(time.Until(d) - s.margin)
	}
	return s.Store.UpdateSubscription(ctx, old, n)
}

// deadlineNotifier records how much time each RTR had left.
type deadlineNotifier struct {
	recordingNotifier
	left []time.Duration
}

func (n *deadlineNotifier) Deregister(ctx context.Context, r *cx.RTR) error {
	if d, ok := ctx.Deadline(); ok {
		n.left = append(n.left, time.Until(d))
	}
	return n.recordingNotifier.Deregister(ctx, r)
}

// TestARefusedPPRsRTRKeepsTimeAfterALateUpdate: the S-CSCF refused new data,
// so the HSS marks the user not registered and deregisters it with
// SERVER_CHANGE. An update that wins only at its deadline, behind another
// task's writes, must not leave the RTR none (#244 review).
func TestARefusedPPRsRTRKeepsTimeAfterALateUpdate(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	e.modify(impi1, func(s *store.Subscription) {
		s.ServerName, s.PublicIdentities[0].State = scscfName, store.Registered
	})
	h := e.newHSS(func(o *Options) { o.Store = &slowWinStore{Store: e.store, margin: 20 * time.Millisecond} })
	n := &deadlineNotifier{recordingNotifier: *newRecorder()}
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	h.pprRejected(ctx, n, e.sub(impi1), exp(cx.ErrorNotSupportedUserData))
	if e.sub(impi1).Identity(impu1).State != store.NotRegistered {
		t.Fatal("the user was not marked not registered")
	}
	if len(n.left) != 1 || n.left[0] < 200*time.Millisecond {
		t.Errorf("RTRs with time left %v, want one with a good share of the push's", n.left)
	}
}
