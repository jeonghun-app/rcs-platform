package hss

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
)

// A request that holds a subscriber's lock for long, such as an API write
// whose store calls are slow, delays Cx for that subscriber only as long as the
// Cx timeout: then the waiting request is answered DIAMETER_TOO_BUSY, which
// the S-CSCF may retry on another HSS task.
//
// The lock is held all along, so TOO_BUSY can only be the wait giving up;
// that it gives up at the Cx timeout is read from the deadline the wait
// runs to, not from the clock, which a loaded host stretches (#268). That
// the answer follows that deadline promptly is not checked: no wall-clock
// bound on it survives a loaded host, and a wait that sleeps on once its
// context has ended would need a clock seam to catch. A wait that ends on
// a timer of its own is caught by TestALockWaitEndsOnlyWithItsContext.
func TestABusySubscriptionAnswersTooBusyWithinTheCxTimeout(t *testing.T) {
	const timeout = 200 * time.Millisecond
	e := newEnv(t)
	e.provision(impi1, impu1)
	unlock, err := e.h.lock(context.Background(), impi1)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	type wait struct {
		at, deadline time.Time
		ok           bool
	}
	waits := make(chan wait, 1)
	e.h.onLockWait = func(ctx context.Context) {
		d, ok := ctx.Deadline()
		waits <- wait{time.Now(), d, ok}
	}
	c := connectCSCF(t, serveHSSWith(t, e.h, "hss-a.rcs.local", timeout), "scscf-1.rcs.local")
	r := &cx.MAR{Request: cx.Request{DestinationRealm: domain}, UserName: impi1, PublicIdentity: impu1,
		AuthDataItem: cx.AuthDataItem{Scheme: cx.SchemeDigestAKAv1MD5}, NumberAuthItems: 1, ServerName: scscfName}
	sent := time.Now()
	ans := c.send(r.Message(c.node))
	if rc, _ := ans.ResultCode(); rc != diameter.ResultTooBusy {
		t.Fatalf("Result-Code = %d, want DIAMETER_TOO_BUSY", rc)
	}
	// The handler started between the send and the wait, and its deadline
	// is the Cx timeout from then.
	// The hook sends before the handler answers, so the wait has been
	// recorded by now unless TOO_BUSY came without one.
	var w wait
	select {
	case w = <-waits:
	default:
		t.Fatal("answered DIAMETER_TOO_BUSY without waiting for the lock")
	}
	if !w.ok || w.deadline.Before(sent.Add(timeout)) || w.deadline.After(w.at.Add(timeout)) {
		t.Errorf("the wait ran to %v after the send (deadline set %v), want the Cx timeout %v", w.deadline.Sub(sent), w.ok, timeout)
	}
	if e.metrics.get("lock.busy") != 1 {
		t.Error("the busy lock was not counted")
	}
	// Reads need no lock: LIR is still answered.
	if lia := c.lir(impu1, false); lia.Result != exp(cx.UnregisteredService) {
		t.Errorf("LIA = %v", lia.Result)
	}
}

// A lock wait whose context has no deadline is given up by no other timer,
// such as one of DefaultCxTimeout: the lock is held for longer than that,
// and the wait still gets it (QA of #466). It is one-sided, so a loaded
// host cannot fail the correct code; the sleep is a lower bound only.
func TestALockWaitEndsOnlyWithItsContext(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	unlock, err := e.h.lock(context.Background(), impi1)
	if err != nil {
		t.Fatal(err)
	}
	waiting := make(chan struct{})
	e.h.onLockWait = func(context.Context) { close(waiting) }
	got := make(chan error, 1)
	go func() {
		u, err := e.h.lock(context.Background(), impi1)
		if err == nil {
			u()
		}
		got <- err
	}()
	// The lock's own result ends the wait too, so that a lock that never
	// waits fails here with a message rather than at the package's timeout
	// (#480).
	select {
	case <-waiting:
	case err := <-got:
		t.Fatalf("the lock returned %v without waiting for its holder", err)
	}
	time.Sleep(DefaultCxTimeout + 500*time.Millisecond)
	unlock()
	if err := <-got; err != nil {
		t.Fatalf("a wait with no deadline gave up: %v", err)
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
	e.h.onLockWait = func(context.Context) { close(waiting) }
	done := make(chan error, 1)
	go func() {
		_, err := e.h.updateFrom(context.Background(), impi1, read, func(s *store.Subscription) error {
			s.ServerName = "sip:scscf-2.rcs.local"
			return nil
		})
		done <- err
	}()
	select {
	case <-waiting:
	case err := <-done:
		t.Fatalf("the update returned %v without waiting for the lock", err)
	}
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

// TestTwoSubscriptionsNeverWaitOnEachOther: each subscription has a lock
// of its own, so a request that holds one, here through a store write that
// does not return, holds up no other subscription (QA's minor 3 on #244).
// The other update must finish while the first still holds its lock; how
// long it takes is not measured, so a loaded host cannot fail it (#321).
func TestTwoSubscriptionsNeverWaitOnEachOther(t *testing.T) {
	bf := &blockingFor{Store: store.NewMemory(), impi: impi1, entered: make(chan struct{}), release: make(chan struct{})}
	e := newEnvWith(t, bf)
	e.provision(impi1, impu1)
	e.provision(impi2, impu2)
	done := make(chan error, 1)
	go func() {
		_, err := e.h.update(context.Background(), impi1, func(s *store.Subscription) error { s.AuthPending = true; return nil })
		done <- err
	}()
	<-bf.entered // the first update holds impi1's lock, inside its write
	// Only a failure waits this long: an update that waits for the first
	// would never finish while the first is held.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := e.h.update(ctx, impi2, func(s *store.Subscription) error { s.AuthPending = true; return nil }); err != nil {
		t.Fatalf("the other subscription's update while the first held its lock: %v", err)
	}
	select {
	case err := <-done:
		t.Fatalf("the first update ended (%v) before it was released", err)
	default:
	}
	close(bf.release)
	if err := <-done; err != nil {
		t.Errorf("the first update: %v", err)
	}
}

// blockingFor holds the first write of one subscription until release.
type blockingFor struct {
	store.Store
	impi    string
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (b *blockingFor) UpdateSubscription(ctx context.Context, old, s *store.Subscription) (*store.Subscription, error) {
	if s.IMPI == b.impi {
		first := false
		b.once.Do(func() { first = true; close(b.entered) })
		if first {
			<-b.release
		}
	}
	return b.Store.UpdateSubscription(ctx, old, s)
}

// TestALockGoesWhenNoRequestHoldsIt: the locks of a task are as many as the
// subscriptions being written, not every subscription ever written.
func TestALockGoesWhenNoRequestHoldsIt(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	unlock, err := e.h.lock(context.Background(), impi1)
	if err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := e.h.lock(short, impi1); !errors.Is(err, errBusy) {
		t.Fatalf("a held lock: %v", err)
	}
	unlock()
	if _, err := e.h.update(context.Background(), impi1, func(s *store.Subscription) error { s.AuthPending = true; return nil }); err != nil {
		t.Fatal(err)
	}
	e.h.locksMu.Lock()
	defer e.h.locksMu.Unlock()
	if len(e.h.locks) != 0 {
		t.Errorf("%d locks left with no request", len(e.h.locks))
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

// deadlineStore records the deadline of each write's context.
type deadlineStore struct {
	store.Store
	mu        sync.Mutex
	deadlines []time.Time
}

func (s *deadlineStore) UpdateSubscription(ctx context.Context, old, n *store.Subscription) (*store.Subscription, error) {
	d, _ := ctx.Deadline()
	s.mu.Lock()
	s.deadlines = append(s.deadlines, d)
	s.mu.Unlock()
	return s.Store.UpdateSubscription(ctx, old, n)
}

// deadlineNotifier records the deadline of each RTR's context.
type deadlineNotifier struct {
	recordingNotifier
	deadlines []time.Time
}

func (n *deadlineNotifier) Deregister(ctx context.Context, r *cx.RTR) error {
	d, _ := ctx.Deadline()
	n.deadlines = append(n.deadlines, d)
	return n.recordingNotifier.Deregister(ctx, r)
}

// TestARefusedPPRsRTRKeepsTimeAfterALateUpdate: the S-CSCF refused new data,
// so the HSS marks the user not registered and deregisters it with
// SERVER_CHANGE. The update must leave the RTR time even if it wins only at
// its own deadline, behind another task's writes (#244 review): each gets
// the push timeout of its own, from when it starts (code review on #476).
// The deadlines are compared rather than the time left, which a loaded host
// eats into (#275).
func TestARefusedPPRsRTRKeepsTimeAfterALateUpdate(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	e.modify(impi1, func(s *store.Subscription) {
		s.ServerName, s.PublicIdentities[0].State = scscfName, store.Registered
	})
	ds := &deadlineStore{Store: e.store}
	h := e.newHSS(func(o *Options) { o.Store = ds })
	n := &deadlineNotifier{recordingNotifier: *newRecorder()}
	const each = time.Hour
	start := time.Now()
	h.pprRejected(context.Background(), n, e.sub(impi1), exp(cx.ErrorNotSupportedUserData), pushTimes{each: each, total: PushBudget, until: time.Now().Add(each * 2)})
	end := time.Now()
	if e.sub(impi1).Identity(impu1).State != store.NotRegistered {
		t.Fatal("the user was not marked not registered")
	}
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if len(ds.deadlines) != 1 || len(n.deadlines) != 1 {
		t.Fatalf("%d writes, %d RTRs", len(ds.deadlines), len(n.deadlines))
	}
	update, rtr := ds.deadlines[0], n.deadlines[0]
	within := func(d time.Time) bool { return !d.Before(start.Add(each)) && !d.After(end.Add(each)) }
	if !within(update) || !within(rtr) || rtr.Before(update) {
		t.Errorf("deadlines: update %v, RTR %v; want each %v from its own start, between %v and %v",
			update.Sub(start), rtr.Sub(start), each, time.Duration(0), end.Sub(start))
	}
}

// refusingLate refuses each PPR with TOO_MUCH_DATA after wait, as an S-CSCF
// answering close to the push timeout.
type refusingLate struct {
	deadlineNotifier
	wait time.Duration
	done time.Time
}

func (n *refusingLate) PushProfile(ctx context.Context, r *cx.PPR) error {
	time.Sleep(n.wait)
	n.done = time.Now()
	_ = n.recordingNotifier.PushProfile(ctx, r)
	return &RejectedError{Command: "PPR", Result: exp(cx.ErrorTooMuchData)}
}

// Code review on #476: a PPR refused near the end of its timeout leaves the
// RTR that follows a whole push timeout of its own, not what the PPR left.
func TestAnRTRAfterALateRefusalHasItsOwnTime(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	e.modify(impi1, func(s *store.Subscription) {
		s.ServerName, s.PublicIdentities[0].State = scscfName, store.Registered
	})
	const each = 400 * time.Millisecond
	n := &refusingLate{deadlineNotifier: deadlineNotifier{recordingNotifier: *newRecorder()}, wait: each * 9 / 10}
	p, err := e.store.Profile(t.Context(), DefaultProfileID)
	if err != nil {
		t.Fatal(err)
	}
	e.h.notify(t.Context(), n, e.sub(impi1), p, []push{{set: 0}}, pushTimes{each: each, total: PushBudget})
	if len(n.deadlines) != 1 {
		t.Fatalf("%d RTRs", len(n.deadlines))
	}
	if rtr := n.deadlines[0]; rtr.Before(n.done.Add(each)) {
		t.Errorf("the RTR's deadline is %v after the refusal, want at least %v", rtr.Sub(n.done), each)
	}
}

// stallingStore loses its first write and blocks the next one until the
// context ends, then fails as DynamoDB does, with the context's error
// wrapped.
type stallingStore struct {
	store.Store
	mu     sync.Mutex
	writes int
}

func (s *stallingStore) UpdateSubscription(ctx context.Context, old, n *store.Subscription) (*store.Subscription, error) {
	s.mu.Lock()
	s.writes++
	first := s.writes == 1
	s.mu.Unlock()
	if first {
		return nil, store.ErrConflict
	}
	<-ctx.Done()
	return nil, fmt.Errorf("update subscription: %w", ctx.Err())
}

// cancelStore loses its first write; the next one cancels the request's
// context, as a client that gives up does, and fails as DynamoDB does, with
// the context's error wrapped.
type cancelStore struct {
	store.Store
	cancel context.CancelFunc
	mu     sync.Mutex
	writes int
}

func (s *cancelStore) UpdateSubscription(ctx context.Context, old, n *store.Subscription) (*store.Subscription, error) {
	s.mu.Lock()
	s.writes++
	first := s.writes == 1
	s.mu.Unlock()
	if first {
		return nil, store.ErrConflict
	}
	s.cancel()
	<-ctx.Done()
	return nil, fmt.Errorf("update subscription: %w", ctx.Err())
}

// TestAWriteCanceledAfterALossIsContention: as at the deadline, a write the
// caller's cancellation cuts short after a lost one reports contention,
// not the store's failure (#244 review).
func TestAWriteCanceledAfterALossIsContention(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cs := &cancelStore{Store: store.NewMemory(), cancel: cancel}
	e := newEnvWith(t, cs)
	e.provision(impi1, impu1)
	_, err := e.h.update(ctx, impi1, func(s *store.Subscription) error { s.AuthPending = true; return nil })
	if !errors.Is(err, errContention) || !errors.Is(err, context.Canceled) {
		t.Fatalf("update = %v, want contention on the cancellation", err)
	}
}

// slowFirstStore is a slow store without contention: once armed, every
// write is still in flight at the deadline.
type slowFirstStore struct {
	store.Store
	arm atomic.Bool
}

func (q *slowFirstStore) UpdateSubscription(ctx context.Context, old, s *store.Subscription) (*store.Subscription, error) {
	if q.arm.Load() {
		<-ctx.Done()
		return nil, fmt.Errorf("awsstore: update subscription: %w", ctx.Err())
	}
	return q.Store.UpdateSubscription(ctx, old, s)
}

// TestASlowStoreWithoutALostWriteIsAStoreFailure: a context error on the
// first attempt, with no write lost, is the store's failure (503 "the
// subscriber store is unavailable"), not contention (QA on #244: the
// attempt > 0 guard).
func TestASlowStoreWithoutALostWriteIsAStoreFailure(t *testing.T) {
	q := &slowFirstStore{Store: store.NewMemory()}
	e := newEnvWith(t, q)
	a := &apiEnv{env: e, api: e.h.NewAPI(APIOptions{
		Tokens:         Tokens{Admin: TokenPair{Current: adminToken}, ACS: TokenPair{Current: acsToken}},
		DefaultProfile: DefaultProfileID, StoreTimeout: 300 * time.Millisecond,
	})}
	a.create(impi1, true, impu1)
	q.arm.Store(true)
	code, body, _ := a.do("POST", subPath(impi1, "/digest-credential"), acsToken, "")
	if code != http.StatusServiceUnavailable || body["error"] != "the subscriber store is unavailable; retry" || e.metrics.get("api.store_failure") != 1 {
		t.Errorf("answer = %d %v, api.store_failure = %d", code, body, e.metrics.get("api.store_failure"))
	}
}

// TestAWriteTheDeadlineCutsShortAfterALossIsContention: the DynamoDB path,
// where the deadline ends a store call in flight rather than the backoff
// (#244 review).
func TestAWriteTheDeadlineCutsShortAfterALossIsContention(t *testing.T) {
	ss := &stallingStore{Store: store.NewMemory()}
	e := newEnvWith(t, ss)
	e.provision(impi1, impu1)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := e.h.update(ctx, impi1, func(s *store.Subscription) error { s.AuthPending = true; return nil })
	if !errors.Is(err, errContention) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("update = %v, want contention at the deadline", err)
	}
}

// qaInflight loses the first write, then behaves like DynamoDB on a slow
// call: the next write is still in flight at the deadline and fails with the
// SDK's wrapped context error (mode "deadline"), or fails at once with a
// store error unrelated to the deadline (mode "outage"). From QA on #244.
type qaInflight struct {
	store.Store
	mode string
	mu   sync.Mutex
	arm  bool
	n    int
}

func (q *qaInflight) UpdateSubscription(ctx context.Context, old, s *store.Subscription) (*store.Subscription, error) {
	q.mu.Lock()
	arm := q.arm
	q.n++
	n := q.n
	q.mu.Unlock()
	if !arm {
		return q.Store.UpdateSubscription(ctx, old, s)
	}
	if n == 1 {
		return nil, store.ErrConflict
	}
	if q.mode == "outage" {
		return nil, errors.New("operation error DynamoDB: PutItem, https response error StatusCode: 500, InternalServerError")
	}
	<-ctx.Done()
	return nil, fmt.Errorf("operation error DynamoDB: PutItem, %w", ctx.Err())
}

func inflightAPI(t *testing.T, mode string) *apiEnv {
	q := &qaInflight{Store: store.NewMemory(), mode: mode}
	e := newEnvWith(t, q)
	a := &apiEnv{env: e, api: e.h.NewAPI(APIOptions{
		Tokens:         Tokens{Admin: TokenPair{Current: adminToken}, ACS: TokenPair{Current: acsToken}},
		DefaultProfile: DefaultProfileID, StoreTimeout: 500 * time.Millisecond,
	})}
	a.create(impi1, true, impu1)
	q.mu.Lock()
	q.arm, q.n = true, 0
	q.mu.Unlock()
	return a
}

// TestAWriteCutOffInFlightAfterALostOneIsBusy: contention, not a store
// failure (QA on #244).
func TestAWriteCutOffInFlightAfterALostOneIsBusy(t *testing.T) {
	a := inflightAPI(t, "deadline")
	code, body, _ := a.do("POST", subPath(impi1, "/digest-credential"), acsToken, "")
	if code != http.StatusServiceUnavailable || body["error"] != "the subscription is busy; retry" || a.metrics.get("api.store_failure") != 0 {
		t.Errorf("answer = %d %v, api.store_failure = %d", code, body, a.metrics.get("api.store_failure"))
	}
}

// TestAStoreOutageAfterALostWriteIsAStoreFailure: only a context error is
// contention; a store that fails is still one (QA on #244).
func TestAStoreOutageAfterALostWriteIsAStoreFailure(t *testing.T) {
	a := inflightAPI(t, "outage")
	code, body, _ := a.do("POST", subPath(impi1, "/digest-credential"), acsToken, "")
	if code != http.StatusServiceUnavailable || body["error"] != "the subscriber store is unavailable; retry" || a.metrics.get("api.store_failure") != 1 {
		t.Errorf("answer = %d %v, api.store_failure = %d", code, body, a.metrics.get("api.store_failure"))
	}
}
