//go:build integration

package msrprelay

import (
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/dynamostore"
)

// storeHangGuard bounds a DynamoDB Local call in the integration tests: a
// store that does not answer in it is stuck, not slow.
const storeHangGuard = 2 * time.Minute

// TestIntegrationTwoRelayTasksShareBindingsInDynamoDB runs the cross-task
// rules end to end on DynamoDB Local (make test-integration): a binding
// allocated through the control API is bridged by whichever task the client
// reaches, and of two clients racing for it on two tasks one wins and the
// other gets 403.
func TestIntegrationTwoRelayTasksShareBindingsInDynamoDB(t *testing.T) {
	endpoint := os.Getenv("RELAY_IT_DYNAMODB_ENDPOINT")
	if endpoint == "" {
		t.Fatal("RELAY_IT_DYNAMODB_ENDPOINT must name the DynamoDB Local container")
	}
	ctx := t.Context()
	table := "msrp-relay-it-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ddb := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(endpoint) })
	if _, err := ddb.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:            aws.String(table),
		BillingMode:          types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{{AttributeName: aws.String(dynamostore.PartitionKey), AttributeType: types.ScalarAttributeTypeS}},
		KeySchema:            []types.KeySchemaElement{{AttributeName: aws.String(dynamostore.PartitionKey), KeyType: types.KeyTypeHash}},
	}); err != nil {
		t.Fatalf("creating the table: %v", err)
	}
	st, err := dynamostore.New(ctx, table, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	// The store's calls are bounded by the hang guard only: the test is of
	// the cross-task rules, and DynamoDB Local on a loaded host took longer
	// than the rig's 5 s, so the control API answered 503 (#255), as the
	// hss tests' Cx timeout did (#200, #225).
	r := newRigWithStore(t, 2, st, storeTimeout(storeHangGuard))

	// Allocated on one task, bridged on the other.
	b := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}})
	asH := newRecorder()
	r.as.session(t, "asddb1", b.coreLocal, asH)
	r.patch(b.id, map[string]any{"core_path": []string{r.as.uri("asddb1")}})
	s, err := r.dial(1, nil).open(t, b.clientPath, newRecorder())
	if err != nil {
		t.Fatalf("Open = %v", err)
	}
	send(t, s, "via dynamodb")
	if m := asH.message(t); string(m.Body) != "via dynamodb" {
		t.Fatalf("rcs-as got %q", m.Body)
	}

	// The race.
	b2 := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}})
	r.as.session(t, "asddb2", b2.coreLocal, newRecorder())
	r.patch(b2.id, map[string]any{"core_path": []string{r.as.uri("asddb2")}})
	clients := []*client{r.dial(0, nil), r.dial(1, nil)}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, c := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = c.open(t, b2.clientPath, newRecorder())
		}()
	}
	wg.Wait()
	if (errs[0] == nil) == (errs[1] == nil) {
		t.Fatalf("Open results %v and %v, want exactly one success", errs[0], errs[1])
	}
	for _, err := range errs {
		if err != nil && statusOf(err) != msrp.StatusForbidden {
			t.Fatalf("the loser got %v, want 403", err)
		}
	}
}
