//go:build integration

package awsstore

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store/storetest"
)

// The integration tests run the store contract against an S3-compatible
// container and DynamoDB Local (make test-integration), which is where the
// SDK calls, condition expressions and error codes the unit tests fake are
// checked against a real implementation. FT_IT_S3_ENDPOINT and
// FT_IT_DYNAMODB_ENDPOINT name the containers.

func integrationStores(t *testing.T) *Stores {
	t.Helper()
	s3Endpoint, ddbEndpoint := os.Getenv("FT_IT_S3_ENDPOINT"), os.Getenv("FT_IT_DYNAMODB_ENDPOINT")
	if s3Endpoint == "" || ddbEndpoint == "" {
		t.Fatal("FT_IT_S3_ENDPOINT and FT_IT_DYNAMODB_ENDPOINT must name the test containers")
	}
	ctx := t.Context()
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	c := Config{
		Bucket: "ft-it-" + suffix, Prefix: "files/", Table: "files-" + suffix, SSE: "AES256",
		S3Endpoint: s3Endpoint, DynamoDBEndpoint: ddbEndpoint,
	}
	s, err := New(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s3c := s3.NewFromConfig(awsCfg, func(o *s3.Options) { o.BaseEndpoint = aws.String(s3Endpoint); o.UsePathStyle = true })
	if _, err := s3c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(c.Bucket)}); err != nil {
		t.Fatalf("creating the bucket: %v", err)
	}
	ddb := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(ddbEndpoint) })
	// The table as docs/ft-server.md describes it for the infrastructure.
	if _, err := ddb.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:            aws.String(c.Table),
		BillingMode:          dtypes.BillingModePayPerRequest,
		AttributeDefinitions: []dtypes.AttributeDefinition{{AttributeName: aws.String(attrPK), AttributeType: dtypes.ScalarAttributeTypeS}},
		KeySchema:            []dtypes.KeySchemaElement{{AttributeName: aws.String(attrPK), KeyType: dtypes.KeyTypeHash}},
	}); err != nil {
		t.Fatalf("creating the table: %v", err)
	}
	return s
}

func TestIntegrationStoresMeetTheContract(t *testing.T) {
	s := integrationStores(t)
	if err := s.Ready(t.Context()); err != nil {
		t.Fatalf("Ready = %v", err)
	}
	storetest.Metadata(t, func(*testing.T) store.Metadata { return s.Metadata })
	// S3 refuses a part other than the last below 5 MiB.
	storetest.Blobs(t, s.Blobs, 5<<20)
}

func TestIntegrationNonceCountsOnlyAdvance(t *testing.T) {
	s := integrationStores(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	for i, c := range []struct {
		nc   uint32
		want bool
	}{{1, true}, {1, false}, {5, true}, {4, false}} {
		got, err := s.NonceCounts.Advance(ctx, "alice", "nonce", c.nc, exp)
		if err != nil || got != c.want {
			t.Fatalf("step %d: %v, %v", i, got, err)
		}
	}
}
