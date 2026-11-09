//go:build integration

package awsstore

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store/storetest"
)

// The integration tests run the registry contract against DynamoDB Local
// (make test-integration), which checks the condition expressions and
// error codes the unit tests stub. MAAP_IT_DYNAMODB_ENDPOINT names the
// container.

// registryTable creates maap-registry as docs/maap.md defines it and
// returns the client.
func registryTable(t *testing.T) (*dynamodb.Client, string) {
	t.Helper()
	endpoint := os.Getenv("MAAP_IT_DYNAMODB_ENDPOINT")
	if endpoint == "" {
		t.Fatal("MAAP_IT_DYNAMODB_ENDPOINT must name the test container")
	}
	ctx := t.Context()
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ddb := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(endpoint) })
	table := "maap-registry-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	attr := func(name string) types.AttributeDefinition {
		return types.AttributeDefinition{AttributeName: aws.String(name), AttributeType: types.ScalarAttributeTypeS}
	}
	if _, err := ddb.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: aws.String(table), BillingMode: types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{attr(attrPK), attr(attrSK)},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String(attrPK), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String(attrSK), KeyType: types.KeyTypeRange},
		},
	}); err != nil {
		t.Fatalf("creating the table: %v", err)
	}
	return ddb, table
}

func TestIntegrationRegistryMeetsTheContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Registry { return NewRegistry(registryTable(t)) })
}

// resend sends every write that succeeds a second time, as the SDK does
// when an answer is lost, without the request token, as when DynamoDB no
// longer knows it, and answers what the second send got.
type resend struct{ DynamoAPI }

func (r resend) PutItem(ctx context.Context, in *dynamodb.PutItemInput, o ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	if _, err := r.DynamoAPI.PutItem(ctx, in, o...); err != nil {
		return nil, err
	}
	return r.DynamoAPI.PutItem(ctx, in, o...)
}

func (r resend) TransactWriteItems(ctx context.Context, in *dynamodb.TransactWriteItemsInput, o ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	if _, err := r.DynamoAPI.TransactWriteItems(ctx, in, o...); err != nil {
		return nil, err
	}
	again := *in
	again.ClientRequestToken = nil
	return r.DynamoAPI.TransactWriteItems(ctx, &again, o...)
}

func TestIntegrationAWriteSentAgainAfterItTookEffectStands(t *testing.T) {
	ddb, table := registryTable(t)
	r := NewRegistry(resend{ddb}, table)
	ctx := t.Context()
	c, err := r.Register(ctx, storetest.Chatbot())
	if err != nil {
		t.Fatalf("Register = %v", err)
	}
	if c, err = r.Update(ctx, c, c); err != nil || c.Version != 2 {
		t.Fatalf("Update = %+v, %v", c, err)
	}
	// A real conflict is still one.
	stale := c
	stale.Version = 1
	if _, err := r.Update(ctx, stale, stale); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale Update = %v", err)
	}
}

func TestIntegrationDeleteChatbotDeletesEveryItemOfItsPartition(t *testing.T) {
	ddb, table := registryTable(t)
	r := NewRegistry(ddb, table)
	ctx := t.Context()
	c, err := r.Register(ctx, storetest.Chatbot())
	if err != nil {
		t.Fatal(err)
	}
	// Items #710 will keep there, written behind the store's back.
	for _, sk := range []string{"k#one", "k#two"} {
		if _, err := ddb.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(table), Item: key("c#"+c.ID, sk)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.DeleteChatbot(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	for _, k := range []map[string]types.AttributeValue{key("c#"+c.ID, "k#one"), chatbotKey(c.ID), uriKey(c.URI)} {
		out, err := ddb.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(table), Key: k, ConsistentRead: aws.Bool(true)})
		if err != nil || len(out.Item) != 0 {
			t.Errorf("%v left: %v, %v", k[attrSK], out, err)
		}
	}
}
