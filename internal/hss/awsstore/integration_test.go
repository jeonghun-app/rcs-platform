//go:build integration

package awsstore

import (
	"context"
	"crypto/rand"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/smithy-go/logging"

	"github.com/jeonghun-app/rcs-platform/internal/hss/keyring"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store/storetest"
)

// The integration tests run the store contract against DynamoDB Local
// (make test-integration-hss), where the condition expressions,
// transactions and error codes the unit tests fake meet a real
// implementation. HSS_IT_DYNAMODB_ENDPOINT names the container.

// IntegrationTables creates a fresh pair of tables and returns a store on
// them.
func IntegrationTables(t *testing.T) *Dynamo {
	t.Helper()
	endpoint := os.Getenv("HSS_IT_DYNAMODB_ENDPOINT")
	if endpoint == "" {
		t.Fatal("HSS_IT_DYNAMODB_ENDPOINT must name the DynamoDB Local container")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// The SDK warns about every ConditionalCheckFailed answer of DynamoDB
	// Local (a checksum quirk); the store reports what matters.
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithLogger(logging.Nop{}))
	if err != nil {
		t.Fatal(err)
	}
	api := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(endpoint) })
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	c := Config{SubscribersTable: "subscribers-" + suffix, ProfilesTable: "service-profiles-" + suffix}
	if err := CreateTables(ctx, api, c); err != nil {
		t.Fatal(err)
	}
	return NewDynamo(api, c)
}

func TestIntegrationDynamoStoreMeetsTheContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store { return IntegrationTables(t) }, storetest.Options{ListingWait: 10 * time.Second})
}

func TestIntegrationTwoTasksOpenOneKeyring(t *testing.T) {
	d := IntegrationTables(t)
	ctx := context.Background()
	w := xorWrapper{}
	a, err := keyring.Open(ctx, w, d, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := keyring.Open(ctx, w, d, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := a.Seal([]byte("K"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.Open(sealed, []byte("aad")); err != nil || string(got) != "K" {
		t.Fatalf("second task: %q, %v", got, err)
	}
	if keys, _ := d.DataKeys(ctx); len(keys) != 1 {
		t.Fatalf("%d data keys stored", len(keys))
	}
}

type xorWrapper struct{}

func (xorWrapper) GenerateDataKey(context.Context) ([]byte, []byte, error) {
	k := make([]byte, keyring.DataKeySize)
	_, _ = rand.Read(k)
	return k, xorBytes(k), nil
}

func (xorWrapper) Unwrap(_ context.Context, w []byte) ([]byte, error) { return xorBytes(w), nil }

func xorBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ 0x5a
	}
	return out
}
