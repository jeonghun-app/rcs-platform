//go:build integration

package dynamostore

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

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state/statetest"
)

// The integration test runs the state contract against DynamoDB Local (make
// test-integration), where the condition expressions, the indexes and the
// error codes the fake imitates meet a real implementation.
// SCSCF_IT_DYNAMODB_ENDPOINT names the container.

func integrationAPI(t *testing.T) *dynamodb.Client {
	t.Helper()
	endpoint := os.Getenv("SCSCF_IT_DYNAMODB_ENDPOINT")
	if endpoint == "" {
		t.Fatal("SCSCF_IT_DYNAMODB_ENDPOINT must name the DynamoDB Local container")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// The SDK warns about every ConditionalCheckFailed answer of DynamoDB
	// Local (a checksum quirk); the store reports what matters.
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithLogger(logging.Nop{}))
	if err != nil {
		t.Fatal(err)
	}
	return dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(endpoint) })
}

func TestIntegrationDynamoStoreMeetsTheContract(t *testing.T) {
	api := integrationAPI(t)
	statetest.Run(t, func(t *testing.T) state.Store {
		suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
		c := Config{
			RegistrationsTable: "registrations-" + suffix, ChallengesTable: "auth-challenges-" + suffix,
			SubscriptionsTable: "reg-subscriptions-" + suffix, ChallengeKeys: [][]byte{testKey},
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := CreateTables(ctx, api, c); err != nil {
			t.Fatal(err)
		}
		d, err := New(api, c)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}, statetest.Options{
		// A second instance: its own client and store over the same tables.
		Second: func(t *testing.T, first state.Store) state.Store {
			f := first.(*Dynamo)
			d, err := New(integrationAPI(t), Config{
				RegistrationsTable: f.registrations, ChallengesTable: f.challenges,
				SubscriptionsTable: f.subscriptions, ChallengeKeys: [][]byte{testKey},
			})
			if err != nil {
				t.Fatal(err)
			}
			return d
		},
		ListingWait: 10 * time.Second,
	})
}
