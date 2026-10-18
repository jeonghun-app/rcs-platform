//go:build integration

package dynamostore

import (
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/store"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/store/storetest"
)

// The integration test runs the store contract against DynamoDB Local (make
// test-integration), which is where the condition expressions, the
// ReturnValuesOnConditionCheckFailure classification and the concurrent
// claim are checked against a real implementation. RELAY_IT_DYNAMODB_ENDPOINT
// names the container.

func TestIntegrationDynamoDBMeetsTheContract(t *testing.T) {
	endpoint := os.Getenv("RELAY_IT_DYNAMODB_ENDPOINT")
	if endpoint == "" {
		t.Fatal("RELAY_IT_DYNAMODB_ENDPOINT must name the DynamoDB Local container")
	}
	ctx := t.Context()
	table := "msrp-bindings-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ddb := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(endpoint) })
	// The table as docs/msrp-relay.md describes it for the infrastructure.
	if _, err := ddb.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:            aws.String(table),
		BillingMode:          types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{{AttributeName: aws.String(PartitionKey), AttributeType: types.ScalarAttributeTypeS}},
		KeySchema:            []types.KeySchemaElement{{AttributeName: aws.String(PartitionKey), KeyType: types.KeyTypeHash}},
	}); err != nil {
		t.Fatalf("creating the table: %v", err)
	}
	if _, err := ddb.UpdateTimeToLive(ctx, &dynamodb.UpdateTimeToLiveInput{
		TableName:               aws.String(table),
		TimeToLiveSpecification: &types.TimeToLiveSpecification{AttributeName: aws.String(TTLAttribute), Enabled: aws.Bool(true)},
	}); err != nil {
		t.Fatalf("enabling TTL: %v", err)
	}
	s, err := New(ctx, table, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	storetest.Run(t, func(*testing.T) store.Store { return s })
}
