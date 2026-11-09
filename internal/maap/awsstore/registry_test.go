package awsstore

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store/storetest"
)

// stubDynamo answers every call with err, or, when echo is set, fails each
// write's condition with the item it was sent as the stored one: what
// DynamoDB answers the SDK's second send of a write that took effect.
type stubDynamo struct {
	err    error
	echo   func(map[string]types.AttributeValue) map[string]types.AttributeValue
	status types.TableStatus
}

func (s *stubDynamo) DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &dynamodb.DescribeTableOutput{Table: &types.TableDescription{TableStatus: s.status}}, nil
}

func (s *stubDynamo) GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	return nil, s.err
}

func (s *stubDynamo) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	if s.echo != nil {
		return nil, &types.ConditionalCheckFailedException{Item: s.echo(in.Item)}
	}
	return nil, s.err
}

func (s *stubDynamo) DeleteItem(context.Context, *dynamodb.DeleteItemInput, ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	return nil, s.err
}

func (s *stubDynamo) Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	return nil, s.err
}

func (s *stubDynamo) TransactWriteItems(_ context.Context, in *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	if s.echo != nil {
		failed := types.CancellationReason{Code: aws.String("ConditionalCheckFailed")}
		first := failed
		first.Item = s.echo(in.TransactItems[0].Put.Item)
		return nil, &types.TransactionCanceledException{CancellationReasons: []types.CancellationReason{first, failed}}
	}
	return nil, s.err
}

func TestAStoreFailureIsNeitherNotFoundNorADetailOfTheRequest(t *testing.T) {
	c := storetest.Chatbot()
	r := NewRegistry(&stubDynamo{err: &smithy.GenericAPIError{Code: "ProvisionedThroughputExceededException", Message: "table maap-registry key " + c.URI}}, "maap-registry")
	ctx := context.Background()
	_, getErr := r.Chatbot(ctx, c.ID)
	_, regErr := r.Register(ctx, c)
	c.Version = 1
	_, updErr := r.Update(ctx, c, c)
	for _, err := range []error{getErr, regErr, updErr, r.DeleteChatbot(ctx, c.ID)} {
		if err == nil || errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrConflict) ||
			!strings.HasSuffix(err.Error(), ": ProvisionedThroughputExceededException") || strings.Contains(err.Error(), "bot-") {
			t.Errorf("error %v", err)
		}
	}
}

func TestAWriteSentAgainAfterItTookEffectStands(t *testing.T) {
	ctx := context.Background()
	c := storetest.Chatbot()
	same := func(item map[string]types.AttributeValue) map[string]types.AttributeValue { return item }
	r := NewRegistry(&stubDynamo{echo: same}, "maap-registry")
	got, err := r.Register(ctx, c)
	if err != nil || got.Version != 1 {
		t.Fatalf("Register = %+v, %v", got, err)
	}
	if got, err = r.Update(ctx, got, got); err != nil || got.Version != 2 {
		t.Fatalf("Update = %+v, %v", got, err)
	}
	// The same record by another writer is not this one's.
	other := func(item map[string]types.AttributeValue) map[string]types.AttributeValue {
		return map[string]types.AttributeValue{attrDoc: item[attrDoc], attrVersion: item[attrVersion], attrWriter: str("another")}
	}
	r = NewRegistry(&stubDynamo{echo: other}, "maap-registry")
	if _, err := r.Register(ctx, c); !errors.Is(err, store.ErrExists) {
		t.Fatalf("Register = %v", err)
	}
	if _, err := r.Update(ctx, got, got); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Update = %v", err)
	}
}

func TestAWriteThatMetATransactionIsAConflict(t *testing.T) {
	ctx := context.Background()
	r := NewRegistry(&stubDynamo{err: &types.TransactionConflictException{}}, "maap-registry")
	c := storetest.Chatbot()
	c.Version = 1
	if _, err := r.Update(ctx, c, c); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Update = %v", err)
	}
}

func TestReadyNeedsAnActiveTable(t *testing.T) {
	ctx := context.Background()
	stub := &stubDynamo{status: types.TableStatusActive}
	r := NewRegistry(stub, "maap-registry")
	if err := r.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	stub.status = types.TableStatusCreating
	if err := r.Ready(ctx); err == nil {
		t.Fatal("a table being created is ready")
	}
	stub.err = &smithy.GenericAPIError{Code: "ResourceNotFoundException", Message: "maap-registry"}
	if err := r.Ready(ctx); err == nil || err.Error() != "awsstore: describe table: ResourceNotFoundException" {
		t.Fatalf("Ready = %v", err)
	}
}

func TestNewNeedsNoRequest(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")
	if r, err := New(context.Background(), "maap-registry", "http://127.0.0.1:1"); err != nil || r.table != "maap-registry" {
		t.Fatalf("New = %v, %v", r, err)
	}
}
