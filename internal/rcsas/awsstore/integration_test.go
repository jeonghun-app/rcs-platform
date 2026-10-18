//go:build integration

package awsstore

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store/storetest"
)

// The integration test runs the store contract against DynamoDB Local
// (make test-integration), which checks the condition expressions and error
// codes the unit tests fake. RCSAS_IT_DYNAMODB_ENDPOINT names the container.

func integrationStore(t *testing.T) store.Store {
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
	if _, err := ddb.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:   aws.String(table),
		BillingMode: dtypes.BillingModePayPerRequest,
		AttributeDefinitions: []dtypes.AttributeDefinition{
			{AttributeName: aws.String(attrPK), AttributeType: dtypes.ScalarAttributeTypeS},
			{AttributeName: aws.String(attrSK), AttributeType: dtypes.ScalarAttributeTypeS},
		},
		KeySchema: []dtypes.KeySchemaElement{
			{AttributeName: aws.String(attrPK), KeyType: dtypes.KeyTypeHash},
			{AttributeName: aws.String(attrSK), KeyType: dtypes.KeyTypeRange},
		},
	}); err != nil {
		t.Fatalf("creating the table: %v", err)
	}
	s, err := New(ctx, Config{Table: table, Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Ready(ctx); err != nil {
		t.Fatalf("Ready = %v", err)
	}
	return s
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
	p.got[string(d.CPIM)]++
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
		o := messaging.Origin{Sender: "tel:+15550100001", Recipient: "tel:+15550100002", Mode: store.Standalone, Pager: true, CPIM: []byte(body)}
		if err := engines[i%2].Submit(t.Context(), o); err != nil {
			t.Fatal(err)
		}
	}
	p.online.Store(true)
	var wg sync.WaitGroup
	for _, e := range engines {
		wg.Add(1)
		go func() { defer wg.Done(); e.UserRegistered("tel:+15550100002") }()
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
