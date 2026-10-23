package awsstore

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store/storetest"
)

// slowDynamo counts the reads and writes that reach the table and makes
// each take latency, so that requests in flight overlap.
type slowDynamo struct {
	*fakeDynamo
	latency time.Duration
	calls   atomic.Int64
}

func (d *slowDynamo) GetItem(ctx context.Context, in *dynamodb.GetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	d.calls.Add(1)
	time.Sleep(d.latency)
	return d.fakeDynamo.GetItem(ctx, in, opts...)
}

func (d *slowDynamo) UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	d.calls.Add(1)
	time.Sleep(d.latency)
	return d.fakeDynamo.UpdateItem(ctx, in, opts...)
}

// probe sends counts 1 to requests at once on one nonce, spread over the
// given tasks' stores, which back off as in production, and returns the
// table calls they made.
func probe(t *testing.T, tasks, requests int) int64 {
	t.Helper()
	_, _, ddb := fakeStores(t)
	slow := &slowDynamo{fakeDynamo: ddb, latency: 200 * time.Microsecond}
	stores := make([]*NonceCounts, tasks)
	for i := range stores {
		stores[i] = &NonceCounts{api: slow, table: "files", now: func() time.Time { return storetest.T0 }}
	}
	var wg sync.WaitGroup
	for nc := uint32(1); nc <= uint32(requests); nc++ {
		n := stores[int(nc)%tasks]
		wg.Go(func() {
			if ok, err := n.Advance(context.Background(), "alice", "n", nc, storetest.T0.Add(time.Minute)); !ok || err != nil {
				t.Errorf("Advance(%d) = %v, %v", nc, ok, err)
			}
		})
	}
	wg.Wait()
	for i, n := range stores {
		if l := n.locks.len(); l != 0 {
			t.Errorf("task %d still holds %d nonce locks", i, l)
		}
	}
	return slow.calls.Load()
}

func TestNonceCountsInFlightOnOneNonceCostOneReadAndWriteEach(t *testing.T) {
	// Security review on #610: 32 requests in flight on one nonce. In one
	// task they take turns, so none loses a write: one read and one write
	// each.
	if calls := probe(t, 1, 32); calls != 2*32 {
		t.Fatalf("%d table calls for 32 requests in one task, want 64", calls)
	}
	// Across two tasks a write is lost only to a write of the other task
	// that landed, and each landed write can make only the one request the
	// other task has in flight on the nonce lose: at most one lost write
	// per accepted count, so at most four calls a request. 15 a task, so
	// that no request can lose maxNonceCountAttempts writes.
	calls := probe(t, 2, 30)
	if calls > 4*30 {
		t.Fatalf("%d table calls for 30 requests on two tasks, want at most 120", calls)
	}
	t.Logf("two tasks: %.2f table calls a request", float64(calls)/30)
}

// heldDynamo holds the first GetItem until release is closed.
type heldDynamo struct {
	*fakeDynamo
	first   atomic.Bool
	reached chan struct{}
	release chan struct{}
}

func (d *heldDynamo) GetItem(ctx context.Context, in *dynamodb.GetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	if d.first.CompareAndSwap(false, true) {
		close(d.reached)
		<-d.release
	}
	return d.fakeDynamo.GetItem(ctx, in, opts...)
}

// users is how many Advances hold or wait for key.
func (l *nonceLocks) users(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.held[key]; e != nil {
		return e.users
	}
	return 0
}

func TestASecondAdvanceOnTheNonceWaitsAndIsCounted(t *testing.T) {
	_, _, ddb := fakeStores(t)
	held := &heldDynamo{fakeDynamo: ddb, reached: make(chan struct{}), release: make(chan struct{})}
	var contended atomic.Int32
	n := &NonceCounts{api: held, table: "files", now: func() time.Time { return storetest.T0 },
		contended: func() { contended.Add(1) }}
	exp := storetest.T0.Add(time.Minute)
	first := make(chan error, 1)
	go func() {
		_, err := n.Advance(context.Background(), "alice", "n", 1, exp)
		first <- err
	}()
	<-held.reached
	key := nonceKey("alice", "n")

	// One that gives up while it waits leaves nothing behind.
	ctx, cancel := context.WithCancel(context.Background())
	gaveUp := make(chan error, 1)
	go func() {
		_, err := n.Advance(ctx, "alice", "n", 2, exp)
		gaveUp <- err
	}()
	for n.locks.users(key) != 2 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-gaveUp; !errors.Is(err, context.Canceled) {
		t.Fatalf("Advance cancelled while waiting = %v", err)
	}
	if u := n.locks.users(key); u != 1 {
		t.Fatalf("%d users after the cancelled one left, want 1", u)
	}

	second := make(chan bool, 1)
	go func() {
		ok, _ := n.Advance(context.Background(), "alice", "n", 3, exp)
		second <- ok
	}()
	for n.locks.users(key) != 2 {
		time.Sleep(time.Millisecond)
	}
	select {
	case <-second:
		t.Fatal("the second Advance ran while the first held the nonce")
	default:
	}
	close(held.release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if !<-second {
		t.Fatal("the second Advance was refused")
	}
	if got := contended.Load(); got != 2 {
		t.Fatalf("contended = %d, want the two that waited", got)
	}
	if n.locks.len() != 0 {
		t.Fatal("a nonce lock outlived its users")
	}
	// Another nonce never waits for this one.
	if ok, err := n.Advance(context.Background(), "alice", "other", 1, exp); !ok || err != nil || contended.Load() != 2 {
		t.Fatalf("Advance on another nonce = %v, %v, contended %d", ok, err, contended.Load())
	}
}

func TestNonceLocksPastTheirBoundGoUnserialised(t *testing.T) {
	var l nonceLocks
	l.held = map[string]*nonceLock{}
	for i := range maxNonceLocks {
		l.held[string(rune(i))+"#busy"] = &nonceLock{token: make(chan struct{}, 1), users: 1}
	}
	unlock, waited, err := l.lock(context.Background(), "new")
	if err != nil || waited {
		t.Fatalf("lock past the bound = %v, %v", waited, err)
	}
	if l.len() != maxNonceLocks {
		t.Fatalf("%d keys held past the bound, want the bound", l.len())
	}
	unlock()
	if l.len() != maxNonceLocks {
		t.Fatalf("%d keys held, want the bound", l.len())
	}
}
