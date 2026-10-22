package awsstore

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// CreateMessagesTable creates the messages table as docs/rcs-as.md defines
// it, its expiry index included, and waits until it is active.
// CreateGroupsTable does the same for the groupchats table. They are for
// DynamoDB Local (integration tests, the compose stack); in AWS the tables
// come from CloudFormation, which also turns on TTL on ttl.
func CreateMessagesTable(ctx context.Context, api *dynamodb.Client, name string) error {
	return createTable(ctx, api, &dynamodb.CreateTableInput{
		TableName: aws.String(name),
		AttributeDefinitions: []types.AttributeDefinition{
			attribute(attrPK, types.ScalarAttributeTypeS), attribute(attrSK, types.ScalarAttributeTypeS),
			attribute(attrBucket, types.ScalarAttributeTypeS), attribute(attrExpires, types.ScalarAttributeTypeN),
		},
		KeySchema: []types.KeySchemaElement{keyElement(attrPK, types.KeyTypeHash), keyElement(attrSK, types.KeyTypeRange)},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{{
			IndexName: aws.String(IndexExpiry),
			KeySchema: []types.KeySchemaElement{keyElement(attrBucket, types.KeyTypeHash), keyElement(attrExpires, types.KeyTypeRange)},
			Projection: &types.Projection{
				ProjectionType:   types.ProjectionTypeInclude,
				NonKeyAttributes: []string{attrOwner, attrLease},
			},
		}},
	})
}

// CreateGroupsTable creates the groupchats table: the messages table's key
// schema, no index.
func CreateGroupsTable(ctx context.Context, api *dynamodb.Client, name string) error {
	return createTable(ctx, api, &dynamodb.CreateTableInput{
		TableName:            aws.String(name),
		AttributeDefinitions: []types.AttributeDefinition{attribute(attrPK, types.ScalarAttributeTypeS), attribute(attrSK, types.ScalarAttributeTypeS)},
		KeySchema:            []types.KeySchemaElement{keyElement(attrPK, types.KeyTypeHash), keyElement(attrSK, types.KeyTypeRange)},
	})
}

func createTable(ctx context.Context, api *dynamodb.Client, t *dynamodb.CreateTableInput) error {
	t.BillingMode = types.BillingModePayPerRequest
	if _, err := api.CreateTable(ctx, t); err != nil {
		return sanitize("create table", err)
	}
	table := NewWithClient(aws.ToString(t.TableName), api)
	for table.Ready(ctx) != nil {
		select {
		case <-ctx.Done():
			return errors.New("awsstore: the table did not become active")
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil
}

func attribute(name string, t types.ScalarAttributeType) types.AttributeDefinition {
	return types.AttributeDefinition{AttributeName: aws.String(name), AttributeType: t}
}

func keyElement(name string, t types.KeyType) types.KeySchemaElement {
	return types.KeySchemaElement{AttributeName: aws.String(name), KeyType: t}
}
