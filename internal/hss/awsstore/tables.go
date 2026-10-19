package awsstore

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// CreateTables creates the two tables as docs/hss.md defines them for the
// infrastructure, and waits until they are active. It is for DynamoDB Local
// (integration tests, the compose stack); in AWS the tables come from
// CloudFormation with point-in-time recovery, which the wrapped data keys
// depend on.
func CreateTables(ctx context.Context, api *dynamodb.Client, c Config) error {
	str := types.ScalarAttributeTypeS
	pk := types.KeySchemaElement{AttributeName: aws.String(attrPK), KeyType: types.KeyTypeHash}
	_, err := api.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:   aws.String(c.SubscribersTable),
		BillingMode: types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String(attrPK), AttributeType: str},
			{AttributeName: aws.String(attrProfile), AttributeType: str},
		},
		KeySchema: []types.KeySchemaElement{pk},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{{
			IndexName:  aws.String(ProfileIndex),
			KeySchema:  []types.KeySchemaElement{{AttributeName: aws.String(attrProfile), KeyType: types.KeyTypeHash}},
			Projection: &types.Projection{ProjectionType: types.ProjectionTypeKeysOnly},
		}},
	})
	if err != nil {
		return sanitize("create subscribers table", err)
	}
	_, err = api.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:            aws.String(c.ProfilesTable),
		BillingMode:          types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{{AttributeName: aws.String(attrPK), AttributeType: str}},
		KeySchema:            []types.KeySchemaElement{pk},
	})
	if err != nil {
		return sanitize("create profiles table", err)
	}
	d := NewDynamo(api, c)
	for {
		if d.Ready(ctx) == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("awsstore: the tables did not become active")
		case <-time.After(100 * time.Millisecond):
		}
	}
}
