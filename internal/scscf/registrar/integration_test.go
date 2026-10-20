//go:build integration

package registrar

import (
	"bytes"
	"context"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/smithy-go/logging"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state/dynamostore"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// dynamoPair is two registrars, each with its own DynamoDB client, over one
// set of tables in DynamoDB Local (make test-integration), as two scscf
// instances are.
func dynamoPair(t *testing.T, e *env) (*Registrar, *Registrar) {
	t.Helper()
	ep := os.Getenv("SCSCF_IT_DYNAMODB_ENDPOINT")
	if ep == "" {
		t.Fatal("SCSCF_IT_DYNAMODB_ENDPOINT must name the DynamoDB Local container")
	}
	// The SDK warns about every ConditionalCheckFailed of DynamoDB Local.
	awsCfg, err := config.LoadDefaultConfig(context.Background(), config.WithLogger(logging.Nop{}))
	if err != nil {
		t.Fatal(err)
	}
	api := func() *dynamodb.Client {
		return dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(ep) })
	}
	sfx := strconv.FormatInt(time.Now().UnixNano(), 36)
	c := dynamostore.Config{
		RegistrationsTable: "registrations-" + sfx, ChallengesTable: "challenges-" + sfx, SubscriptionsTable: "subscriptions-" + sfx,
		ChallengeKeys: []dynamostore.ChallengeKey{{ID: "k1", Key: bytes.Repeat([]byte{0x42}, dynamostore.KeySize)}},
	}
	if err := dynamostore.CreateTables(context.Background(), api(), c); err != nil {
		t.Fatal(err)
	}
	instance := func(seed byte) *Registrar {
		d, err := dynamostore.New(api(), c)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := sip.ParseURI("sip:scscf." + realm)
		g, err := New(Config{Store: d, HSS: e.hss, Realm: realm, ServiceRoute: u, NonceKey: testKey, Now: e.clock.Now, Rand: newRand(seed), Logger: newTestLogger(e.logs)})
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	return instance(1), instance(2)
}

// TestIntegrationAFloodOnTwoInstancesGetsTheSharedBudgetExactly: 300
// REGISTERs at once, from 300 flows, over two instances with their own
// clients, reach the HSS exactly ChallengeLimit times; the UE that got its
// challenge before answers it meanwhile, and registers after the window.
// From QA's probes on #223.
func TestIntegrationAFloodOnTwoInstancesGetsTheSharedBudgetExactly(t *testing.T) {
	e := newEnv(t)
	a, b := dynamoPair(t, e)
	u := e.akaUser(impi1, impu1)
	e.clock.advance(5 * time.Second)
	pending := a.Register(bg, u.request(600, ""), upstream)
	wantStatus(t, pending, 401)
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	start := make(chan struct{})
	for i := range 300 {
		req := attacker(t, impi1, impu1, i).request(600, "")
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			res := []*Registrar{a, b}[i%2].Register(bg, req, upstream)
			mu.Lock()
			codes[res.StatusCode]++
			mu.Unlock()
		}()
	}
	close(start)
	fin := b.Register(bg, u.request(600, u.answer(pending, 0)), upstream)
	wg.Wait()
	if mars, _ := e.hss.counts(); mars != DefaultChallengeLimit {
		t.Errorf("%d MARs, want the shared budget's %d; codes %v", mars, DefaultChallengeLimit, codes)
	}
	wantStatus(t, fin, 200)
	e.clock.advance(time.Minute)
	wantStatus(t, u.registerWith(a, 600), 200)
}

// TestIntegrationAForgedAUTSOnAnotherInstanceLeavesTheUEItsResync: from QA's
// probes on #223, on DynamoDB.
func TestIntegrationAForgedAUTSOnAnotherInstanceLeavesTheUEItsResync(t *testing.T) {
	e := newEnv(t)
	a, b := dynamoPair(t, e)
	u := e.akaUser(impi1, impu1)
	ev := attacker(t, impi1, impu1, 1)
	ch := ev.challengeOf(a.Register(bg, ev.request(600, ""), upstream), 0)
	b.Register(bg, ev.request(600, forgedAUTS(t, ev, ch)), upstream)
	e.clock.advance(10 * time.Second)
	c := u.challengeOf(b.Register(bg, u.request(600, ""), upstream), 0)
	wantStatus(t, a.Register(bg, u.request(600, resyncOf(u, c)), upstream), 401)
}
