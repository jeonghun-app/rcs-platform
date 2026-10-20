package hss

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
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
// it again: the request that held the lock most likely wrote it, and writing
// from the first read cost every queued MAR a lost write (#200).
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

// A provisioning write that keeps losing to another task is answered as a
// busy subscription, not as a store outage, also when its retries run into
// the request's deadline (#200 made them run until it): api.store_failure
// stays 0 and nothing is logged as an error. From QA and code review on
// #244.
func TestContentionUntilTheAPIDeadlineIsBusyNotAStoreFailure(t *testing.T) {
	cs := &losingStore{Store: store.NewMemory()}
	e := newEnvWith(t, cs)
	a := &apiEnv{env: e, api: e.h.NewAPI(APIOptions{
		Tokens:         Tokens{Admin: TokenPair{Current: adminToken}, ACS: TokenPair{Current: acsToken}},
		DefaultProfile: DefaultProfileID, StoreTimeout: 500 * time.Millisecond,
	})}
	a.create(impi1, true, impu1)
	cs.mu.Lock()
	cs.n = 1 << 30
	cs.mu.Unlock()
	code, body, _ := a.do("POST", subPath(impi1, "/digest-credential"), acsToken, "")
	if code != http.StatusServiceUnavailable || body["error"] != "the subscription is busy; retry" {
		t.Errorf("answer = %d %v", code, body)
	}
	if n := e.metrics.get("api.store_failure"); n != 0 {
		t.Errorf("api.store_failure = %d: contention was counted as a store outage", n)
	}
	if strings.Contains(e.logs.String(), `"level":"ERROR"`) {
		t.Errorf("contention was logged as an error: %s", e.logs.String())
	}
}

// losingFor loses every write of one subscription, and reports the first.
type losingFor struct {
	store.Store
	impi string
	once sync.Once
	lost chan struct{}
}

func (l *losingFor) UpdateSubscription(ctx context.Context, old, s *store.Subscription) (*store.Subscription, error) {
	if s.IMPI == l.impi {
		l.once.Do(func() { close(l.lost) })
		return nil, store.ErrConflict
	}
	return l.Store.UpdateSubscription(ctx, old, s)
}

// sameStripe is an IMPI whose lock is impi's.
func sameStripe(t *testing.T, impi string) string {
	stripe := func(s string) uint32 {
		f := fnv.New32a()
		_, _ = io.WriteString(f, s)
		return f.Sum32() % lockStripes
	}
	for i := range 100000 {
		if other := fmt.Sprintf("neighbour-%d@%s", i, domain); stripe(other) == stripe(impi) {
			return other
		}
	}
	t.Fatal("no IMPI shares the stripe")
	return ""
}

// TestAContendedSubscriberDoesNotHoldItsStripeThroughItsRetries: the lock is
// let go between attempts, so another subscriber of the same stripe gets it
// at once, not after the contended request's whole deadline (QA's minor 3 on
// #244).
func TestAContendedSubscriberDoesNotHoldItsStripeThroughItsRetries(t *testing.T) {
	lf := &losingFor{Store: store.NewMemory(), impi: impi1, lost: make(chan struct{})}
	e := newEnvWith(t, lf)
	e.provision(impi1, impu1)
	neighbour := sameStripe(t, impi1)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := e.h.update(ctx, impi1, func(s *store.Subscription) error { s.AuthPending = true; return nil })
		done <- err
	}()
	<-lf.lost
	start := time.Now()
	unlock, err := e.h.lock(ctx, neighbour)
	if err != nil {
		t.Fatalf("the neighbour did not get the lock: %v", err)
	}
	unlock()
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Errorf("the neighbour waited %v for the stripe", took)
	}
	if err := <-done; !errors.Is(err, errContention) {
		t.Errorf("the contended update: %v", err)
	}
}

// readCounting counts subscription reads.
type readCounting struct {
	store.Store
	mu    sync.Mutex
	reads int
}

func (r *readCounting) Subscription(ctx context.Context, impi string) (*store.Subscription, error) {
	r.mu.Lock()
	r.reads++
	r.mu.Unlock()
	return r.Store.Subscription(ctx, impi)
}

// TestAnUncontendedMARReadsTheSubscriptionOnce: the Cx path writes from the
// read it made before the lock when the lock was free, saving a read (QA's
// nit 4 on #244).
func TestAnUncontendedMARReadsTheSubscriptionOnce(t *testing.T) {
	rc := &readCounting{Store: store.NewMemory()}
	e := newEnvWith(t, rc)
	e.provision(impi1, impu1)
	c := connectCSCF(t, serveHSSWith(t, e.h, "hss-a.rcs.local", realWait), "scscf-1.rcs.local")
	rc.mu.Lock()
	rc.reads = 0
	rc.mu.Unlock()
	if maa := c.mar(impi1, impu1, cx.SchemeDigestAKAv1MD5, 1, scscfName, nil); maa.Result != resSuccess {
		t.Fatalf("MAA %v", maa.Result)
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.reads != 1 {
		t.Errorf("%d reads for one uncontended MAR, want 1", rc.reads)
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
