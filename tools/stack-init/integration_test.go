//go:build integration

package main

import (
	"bytes"
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	ftstore "github.com/jeonghun-app/rcs-platform/internal/ftserver/awsstore"
	hssstore "github.com/jeonghun-app/rcs-platform/internal/hss/awsstore"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/dynamostore"
)

// Against DynamoDB Local and S3Mock (make test-integration): the tables are
// created once, as the stores expect them, and a second run changes nothing.
func TestIntegrationTablesAreCreatedOnceAndAcceptedByTheStores(t *testing.T) {
	ddbEndpoint, s3Endpoint := os.Getenv("FT_IT_DYNAMODB_ENDPOINT"), os.Getenv("FT_IT_S3_ENDPOINT")
	if ddbEndpoint == "" || s3Endpoint == "" {
		t.Fatal("FT_IT_DYNAMODB_ENDPOINT and FT_IT_S3_ENDPOINT must name the test containers")
	}
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	c := tablesConfig{
		dynamoEndpoint: ddbEndpoint, s3Endpoint: s3Endpoint,
		hss:     hssstore.Config{SubscribersTable: "subs-" + suffix, ProfilesTable: "profiles-" + suffix},
		ftTable: "files-" + suffix, ftBucket: "ft-" + suffix, relayTable: "bindings-" + suffix,
	}
	ctx := t.Context()
	var first, second bytes.Buffer
	if err := createTables(ctx, c, &first); err != nil {
		t.Fatal(err)
	}
	if err := createTables(ctx, c, &second); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if strings.Count(first.String(), "created") != 5 || strings.Count(second.String(), "exists") != 5 {
		t.Fatalf("first run:\n%ssecond run:\n%s", first.String(), second.String())
	}

	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ddb := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(ddbEndpoint) })
	if err := hssstore.NewDynamo(ddb, c.hss).Ready(ctx); err != nil {
		t.Fatalf("the HSS store does not accept its tables: %v", err)
	}
	ft, err := ftstore.New(ctx, ftstore.Config{Bucket: c.ftBucket, Table: c.ftTable, SSE: "AES256", S3Endpoint: s3Endpoint, DynamoDBEndpoint: ddbEndpoint})
	if err == nil {
		err = ft.Ready(ctx)
	}
	if err != nil {
		t.Fatalf("the ft-server stores do not accept their table and bucket: %v", err)
	}
	relay, err := dynamostore.New(ctx, c.relayTable, ddbEndpoint)
	if err == nil {
		err = relay.Ready(ctx)
	}
	if err != nil {
		t.Fatalf("the msrp-relay store does not accept its table: %v", err)
	}
	for _, name := range []string{c.ftTable, c.relayTable} {
		ttl, err := ddb.DescribeTimeToLive(context.Background(), &dynamodb.DescribeTimeToLiveInput{TableName: aws.String(name)})
		if err != nil || ttl.TimeToLiveDescription.TimeToLiveStatus != types.TimeToLiveStatusEnabled ||
			aws.ToString(ttl.TimeToLiveDescription.AttributeName) != "ttl" {
			t.Fatalf("TTL of %s: %+v, %v", name, ttl, err)
		}
	}
}
