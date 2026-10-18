//go:build integration

package hss

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/smithy-go/logging"

	"github.com/jeonghun-app/rcs-platform/internal/hss/awsstore"
)

// The SQN property of TestConcurrentMARsOnTwoTasksNeverShareASequenceNumber
// against DynamoDB Local (make test-integration): two HSS tasks, each
// with its own DynamoDB client, issue vectors for one subscriber at once,
// and only DynamoDB's conditional writes keep them apart.
func TestIntegrationConcurrentMARsOnTwoTasksShareNoSQN(t *testing.T) {
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
	client := func() *dynamodb.Client {
		return dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(endpoint) })
	}
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	c := awsstore.Config{SubscribersTable: "subscribers-" + suffix, ProfilesTable: "service-profiles-" + suffix}
	if err := awsstore.CreateTables(ctx, client(), c); err != nil {
		t.Fatal(err)
	}
	e := newEnvWith(t, awsstore.NewDynamo(client(), c))
	second := e.newHSS(func(o *Options) { o.Store = awsstore.NewDynamo(client(), c) })
	concurrentMARs(t, e, e.h, second)
}
