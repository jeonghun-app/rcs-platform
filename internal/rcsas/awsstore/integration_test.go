//go:build integration

package awsstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/jeonghun-app/rcs-platform/internal/content"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	groupstoretest "github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore/storetest"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store/storetest"
)

// The integration test runs the store contract against DynamoDB Local
// (make test-integration), which checks the condition expressions and error
// codes the unit tests fake. RCSAS_IT_DYNAMODB_ENDPOINT names the container.

func integrationStore(t *testing.T) store.Store {
	t.Helper()
	s, _ := integrationTable(t)
	return s
}

// integrationTable creates a table and returns the store over it, and the
// store itself for reaching the table behind its back.
func integrationTable(t *testing.T) (store.Store, *Store) {
	t.Helper()
	endpoint := os.Getenv("RCSAS_IT_DYNAMODB_ENDPOINT")
	if endpoint == "" {
		t.Fatal("RCSAS_IT_DYNAMODB_ENDPOINT must name the test container")
	}
	ctx := t.Context()
	table := "messages-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ddb := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(endpoint) })
	// The table as docs/rcs-as.md describes it for the infrastructure.
	if err := CreateMessagesTable(ctx, ddb, table); err != nil {
		t.Fatalf("creating the table: %v", err)
	}
	s, err := New(ctx, Config{Table: table, Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Ready(ctx); err != nil {
		t.Fatalf("Ready = %v", err)
	}
	return s, s
}

func TestIntegrationStoreMeetsTheContract(t *testing.T) {
	storetest.Run(t, integrationStore)
}

// pagerCount is a messaging.Deliverer that counts each body it delivers.
type pagerCount struct {
	online atomic.Bool
	mu     sync.Mutex
	got    map[string]int
}

func (p *pagerCount) Pager(_ context.Context, d messaging.Delivery) error {
	if !p.online.Load() {
		return messaging.ErrOffline
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.got[string(d.CPIM.Bytes())]++
	return nil
}

func (p *pagerCount) Invite(context.Context, messaging.Invitation) error { return messaging.ErrOffline }

type nopCounter struct{}

func (nopCounter) Count(string, int64) {}

// Two rcs-as tasks over one table: the conditional claim is what keeps a
// message from going out twice when both flush the same queue.
func TestIntegrationTwoEnginesShareTheQueueAndDeliverEachMessageOnce(t *testing.T) {
	s := integrationStore(t)
	p := &pagerCount{got: map[string]int{}}
	var engines []*messaging.Engine
	for i := range 2 {
		e, err := messaging.New(messaging.Config{InstanceID: fmt.Sprint("task-", i), MSRPHost: "127.0.0.1", MSRPPort: 2855}, s, p, nopCounter{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(e.Close)
		engines = append(engines, e)
	}
	const n = 20
	for i := range n {
		body := fmt.Sprintf("From: <tel:+15550100001>\r\nTo: <tel:+15550100002>\r\n\r\nContent-Type: text/plain\r\n\r\nmessage %d", i)
		o := messaging.Origin{Sender: "tel:+15550100001", Recipient: "tel:+15550100002", Mode: store.Standalone, Pager: true, CPIM: content.BodyOf([]byte(body))}
		if err := engines[i%2].Submit(t.Context(), o); err != nil {
			t.Fatal(err)
		}
	}
	p.online.Store(true)
	var wg sync.WaitGroup
	for _, e := range engines {
		wg.Add(1)
		go func() { defer wg.Done(); e.UserRegistered("tel:+15550100002", false) }()
	}
	wg.Wait()
	deadline := time.Now().Add(30 * time.Second)
	for {
		left, err := s.Pending(t.Context(), "tel:+15550100002", "", time.Now().Add(10*time.Minute), 100)
		if err != nil {
			t.Fatal(err)
		}
		p.mu.Lock()
		delivered := len(p.got)
		p.mu.Unlock()
		if len(left) == 0 && delivered == n {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d left queued, %d delivered", len(left), delivered)
		}
		time.Sleep(50 * time.Millisecond)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for body, c := range p.got {
		if c != 1 {
			t.Fatalf("%q delivered %d times", body, c)
		}
	}
}

// #605 over the table: task-0 finds bob unreachable and holds his queue
// for its retry timer, a minute; bob comes back through a registration
// task-1 takes. task-1's delivery marks him reached, and the next message
// task-0 takes goes out well within that minute.
func TestIntegrationAReachedMarkReleasesAnotherTasksHold(t *testing.T) {
	s := integrationStore(t)
	p := &pagerCount{got: map[string]int{}}
	var engines []*messaging.Engine
	for i := range 2 {
		e, err := messaging.New(messaging.Config{InstanceID: fmt.Sprint("task-", i), MSRPHost: "127.0.0.1", MSRPPort: 2855}, s, p, nopCounter{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(e.Close)
		engines = append(engines, e)
	}
	const bob = "tel:+15550100002"
	submit := func(e *messaging.Engine, text string) {
		t.Helper()
		body := "From: <tel:+15550100001>\r\nTo: <" + bob + ">\r\n\r\nContent-Type: text/plain\r\n\r\n" + text
		o := messaging.Origin{Sender: "tel:+15550100001", Recipient: bob, Mode: store.Standalone, Pager: true, CPIM: content.BodyOf([]byte(body))}
		if err := e.Submit(t.Context(), o); err != nil {
			t.Fatal(err)
		}
	}
	delivered := func() int {
		p.mu.Lock()
		defer p.mu.Unlock()
		return len(p.got)
	}
	start := time.Now()
	submit(engines[0], "one")
	// task-0's attempt fails and leaves m1 queued.
	for left := 0; left == 0; {
		ms, err := s.Pending(t.Context(), bob, "", time.Now(), 10)
		if err != nil {
			t.Fatal(err)
		}
		left = len(ms)
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // task-0's pass settles into its hold
	p.online.Store(true)
	engines[1].UserRegistered(bob, true)
	waitUntil(t, "m1 delivered by task-1", func() bool { return delivered() == 1 })
	submit(engines[0], "two")
	waitUntil(t, "m2 delivered", func() bool { return delivered() == 2 })
	if d := time.Since(start); d >= messaging.DefaultRetryInterval {
		t.Fatalf("m2 took %v, as long as task-0's retry timer", d)
	}
	marks, err := s.Reached(t.Context(), bob, time.Now())
	if err != nil || !slices.ContainsFunc(marks, func(m store.Mark) bool { return m.Task == "task-1" && m.Kind == store.Delivered }) {
		t.Fatalf("Reached = %v, %v; want task-1's mark of a delivery", marks, err)
	}
}

// waitUntil polls cond for up to 30 s.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The recount that corrects a drifted queue size, with its rate limit, as
// DynamoDB itself evaluates the expressions.
func TestIntegrationADriftedQueueSizeIsCorrectedOnce(t *testing.T) {
	_, s := integrationTable(t)
	ctx := t.Context()
	l := store.Limit{Count: 1, SenderCount: 1}
	at := func(id string, when time.Time) store.Message {
		return store.Message{Recipient: "sip:r@example.net", ID: id, Sender: "sip:s@example.net", Mode: store.Chat,
			CPIM: content.BodyOf([]byte("x")), Enqueued: when, Expires: when.Add(time.Hour)}
	}
	t1 := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	if err := s.Enqueue(ctx, at("1", t1), l); err != nil {
		t.Fatal(err)
	}
	// The queue item goes behind the store's back, as DynamoDB's TTL would.
	if _, err := s.api.(*dynamodb.Client).DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.table), Key: key(identityKey(queuePrefix, "sip:r@example.net"), "1"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(ctx, at("2", t1.Add(time.Second)), l); err != nil {
		t.Fatalf("Enqueue after drift = %v", err)
	}
	// Full now, really: refused, and not counted again within the interval.
	for i := range 3 {
		if err := s.Enqueue(ctx, at(fmt.Sprint("x", i), t1.Add(time.Duration(2+i)*time.Second)), l); !errors.Is(err, store.ErrQueueFull) {
			t.Fatalf("Enqueue to a full queue = %v", err)
		}
	}
}

// integrationGroups creates a groupchats table as docs/rcs-as.md
// describes it and returns the store over it, except that TTL is not
// turned on. The contract runs on a fixed clock (storetest's t0, in 2026),
// so every item's ttl is in the past by the wall clock, and DynamoDB
// Local's TTL would delete items in the middle of a test: the flake
// msrp-relay's tests saw on #52. TTL is only the backstop that keeps the
// table small; every read checks the expiry itself, which the contract
// covers.
func integrationGroups(t *testing.T) *Groups {
	t.Helper()
	endpoint := os.Getenv("RCSAS_IT_DYNAMODB_ENDPOINT")
	if endpoint == "" {
		t.Fatal("RCSAS_IT_DYNAMODB_ENDPOINT must name the test container")
	}
	ctx := t.Context()
	table := "groupchats-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ddb := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(endpoint) })
	if err := CreateGroupsTable(ctx, ddb, table); err != nil {
		t.Fatalf("creating the table: %v", err)
	}
	g, err := NewGroups(ctx, Config{Table: table, Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Ready(ctx); err != nil {
		t.Fatalf("Ready = %v", err)
	}
	return g
}

func TestIntegrationGroupsStoreMeetsTheContract(t *testing.T) {
	groups := integrationGroups(t)
	groupstoretest.Run(t, func(*testing.T) groupstore.Store { return groups }, disownIn(groups))
}

// Two tasks raising one group's roster version at once, each from what it
// read: every version is written once and none is lost.
// DynamoDB itself takes and returns the largest group rcs-as keeps.
func TestIntegrationTheLargestGroupIsStoredWhole(t *testing.T) {
	groups := integrationGroups(t)
	ctx := t.Context()
	t1 := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	g := largestGroup(t1)
	if err := groups.Create(ctx, g, testOwner, "c", t1); err != nil {
		t.Fatal(err)
	}
	got, err := groups.Get(ctx, g.URI, t1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Participants) != groupstore.MaxEntries {
		t.Fatalf("read back %d participants", len(got.Participants))
	}
	last, want := got.Participants[groupstore.MaxEntries-1], g.Participants[groupstore.MaxEntries-1]
	if last.Identity != want.Identity || last.DisplayName != want.DisplayName || last.AddedBy != want.AddedBy {
		t.Fatalf("last participant %+v", last)
	}
}

func TestIntegrationGroupVersionsCountAcrossWriters(t *testing.T) {
	groups := integrationGroups(t)
	ctx := t.Context()
	t1 := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	g := groupstore.Group{URI: "sip:chat-v@conf.example.net", Version: 1, Created: t1, Active: t1, Expires: t1.Add(time.Hour),
		Participants: []groupstore.Participant{{Identity: "sip:a@example.net", Role: groupstore.Chairman, State: groupstore.Joined, Since: t1}}}
	if err := groups.Create(ctx, g, testOwner, "c", t1); err != nil {
		t.Fatal(err)
	}
	const each = 15
	var mu sync.Mutex
	var written []uint32
	var wg sync.WaitGroup
	for w := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; {
				cur, err := groups.Get(ctx, g.URI, t1)
				if err != nil {
					t.Error(err)
					return
				}
				cur.Version++
				err = groups.Update(ctx, cur, testOwner, fmt.Sprintf("w%d-%d", w, i))
				if errors.Is(err, groupstore.ErrConflict) {
					continue
				}
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				written = append(written, cur.Version)
				mu.Unlock()
				i++
			}
		}()
	}
	wg.Wait()
	slices.Sort(written)
	for i, v := range written {
		if v != uint32(i+2) {
			t.Fatalf("versions written %v", written)
		}
	}
	final, err := groups.Get(ctx, g.URI, t1)
	if err != nil || final.Version != 1+2*each || final.Rev != 1+2*each {
		t.Fatalf("final %+v, %v", final, err)
	}
}

// #121 D2 against DynamoDB: the transaction of a fenced copy spans the
// messages and groupchats tables, and a stale owner queues nothing.
func TestIntegrationAFencedEnqueueSpansBothTables(t *testing.T) {
	_, queues := integrationTable(t)
	groups := integrationGroups(t)
	queues.SetGroupsTable(groups.table)
	ctx := t.Context()
	t1 := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	g := groupstore.Group{URI: "sip:chat-f@conf.example.net", Version: 1, Created: t1, Active: t1, Expires: t1.Add(time.Hour),
		Participants: []groupstore.Participant{{Identity: "sip:a@example.net", Role: groupstore.Chairman, State: groupstore.Joined, Since: t1}}}
	if err := groups.Create(ctx, g, testOwner, "c", t1); err != nil {
		t.Fatal(err)
	}
	copyOf := func(id string, owner groupstore.Owner) store.Message {
		return store.Message{Recipient: "tel:+15550100002", ID: id, Sender: g.URI, Mode: store.Group, CPIM: content.BodyOf([]byte("x")),
			Enqueued: t1, Expires: t1.Add(time.Hour), Fence: &store.Fence{Group: g.URI, Task: owner.Task, Epoch: owner.Epoch}}
	}
	if err := queues.Enqueue(ctx, copyOf("1", testOwner), store.Limit{}); err != nil {
		t.Fatalf("the owner's enqueue = %v", err)
	}
	if _, err := groups.TakeOver(ctx, g.URI, testOwner, groupstore.Owner{Task: "task-b"}, g.Expires, "t1"); err != nil {
		t.Fatal(err)
	}
	if err := queues.Enqueue(ctx, copyOf("2", testOwner), store.Limit{}); !errors.Is(err, store.ErrNotOwner) {
		t.Fatalf("the old owner's enqueue = %v", err)
	}
	if got, err := queues.Pending(ctx, "tel:+15550100002", "", t1, 10); err != nil || len(got) != 1 {
		t.Fatalf("queue %+v, %v", got, err)
	}
}
