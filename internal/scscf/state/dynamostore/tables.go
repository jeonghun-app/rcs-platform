package dynamostore

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// CreateTables creates the three tables as the package documentation defines
// them and waits until they are active. It is for DynamoDB Local (integration
// tests, the compose stack); in AWS the tables come from CloudFormation, which
// also turns on TTL on auth-challenges' expires.
func CreateTables(ctx context.Context, api *dynamodb.Client, c Config) error {
	d, err := New(api, Config{
		RegistrationsTable: c.RegistrationsTable, ChallengesTable: c.ChallengesTable,
		SubscriptionsTable: c.SubscriptionsTable, ChallengeKeys: [][]byte{make([]byte, KeySize)},
	})
	if err != nil {
		return err
	}
	s, n := types.ScalarAttributeTypeS, types.ScalarAttributeTypeN
	hash := func(name string) types.KeySchemaElement {
		return types.KeySchemaElement{AttributeName: aws.String(name), KeyType: types.KeyTypeHash}
	}
	rng := func(name string) types.KeySchemaElement {
		return types.KeySchemaElement{AttributeName: aws.String(name), KeyType: types.KeyTypeRange}
	}
	attr := func(name string, t types.ScalarAttributeType) types.AttributeDefinition {
		return types.AttributeDefinition{AttributeName: aws.String(name), AttributeType: t}
	}
	index := func(name string, keys ...types.KeySchemaElement) types.GlobalSecondaryIndex {
		return types.GlobalSecondaryIndex{IndexName: aws.String(name), KeySchema: keys,
			Projection: &types.Projection{ProjectionType: types.ProjectionTypeKeysOnly}}
	}
	tables := []*dynamodb.CreateTableInput{
		{
			TableName:            aws.String(d.registrations),
			AttributeDefinitions: []types.AttributeDefinition{attr(attrPK, s), attr(attrIMPI, s), attr(attrShard, s), attr(attrExpires, n)},
			KeySchema:            []types.KeySchemaElement{hash(attrPK)},
			GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
				index(IMPIIndex, hash(attrIMPI)), index(ExpiryIndex, hash(attrShard), rng(attrExpires)),
			},
		},
		{
			TableName:            aws.String(d.challenges),
			AttributeDefinitions: []types.AttributeDefinition{attr(attrPK, s), attr(attrSK, s)},
			KeySchema:            []types.KeySchemaElement{hash(attrPK), rng(attrSK)},
		},
		{
			TableName:            aws.String(d.subscriptions),
			AttributeDefinitions: []types.AttributeDefinition{attr(attrPK, s), attr(attrIMPU, s), attr(attrShard, s), attr(attrExpires, n)},
			KeySchema:            []types.KeySchemaElement{hash(attrPK)},
			GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
				index(IMPUIndex, hash(attrIMPU)), index(ExpiryIndex, hash(attrShard), rng(attrExpires)),
			},
		},
	}
	for _, t := range tables {
		t.BillingMode = types.BillingModePayPerRequest
		if _, err := api.CreateTable(ctx, t); err != nil {
			return sanitize("create table", err)
		}
	}
	for {
		if d.Ready(ctx) == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("dynamostore: the tables did not become active")
		case <-time.After(100 * time.Millisecond):
		}
	}
}
