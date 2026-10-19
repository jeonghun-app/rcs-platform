package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	ftstore "github.com/jeonghun-app/rcs-platform/internal/ftserver/awsstore"
	hssstore "github.com/jeonghun-app/rcs-platform/internal/hss/awsstore"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/dynamostore"
)

// tablesConfig names the local endpoints and what to create there. The
// defaults are the services' own.
type tablesConfig struct {
	dynamoEndpoint, s3Endpoint string
	hss                        hssstore.Config
	ftTable, ftBucket          string
	relayTable                 string
}

func readTablesConfig(e environment) (tablesConfig, error) {
	var c tablesConfig
	var err1, err2, err3 error
	c.dynamoEndpoint, err1 = e.required("STACK_DYNAMODB_ENDPOINT")
	c.s3Endpoint, err2 = e.required("STACK_S3_ENDPOINT")
	c.ftBucket, err3 = e.required("FT_S3_BUCKET")
	if err := errors.Join(err1, err2, err3); err != nil {
		return c, &configError{msg: err.Error()}
	}
	c.hss = hssstore.Config{
		SubscribersTable: e.get("HSS_SUBSCRIBERS_TABLE", "subscribers"),
		ProfilesTable:    e.get("HSS_PROFILES_TABLE", "service-profiles"),
	}
	c.ftTable = e.get("FT_DYNAMODB_TABLE", "files")
	c.relayTable = e.get("RELAY_DYNAMODB_TABLE", "msrp-bindings")
	return c, nil
}

// createTables creates, as the service docs describe them for the
// infrastructure, whatever does not exist yet: hss's two tables
// (docs/hss.md, Tables), ft-server's files table and content bucket
// (docs/ft-server.md, Storage) and msrp-relay's bindings table
// (docs/msrp-relay.md, The bindings table).
func createTables(ctx context.Context, c tablesConfig, out io.Writer) error {
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("AWS configuration: %w", err)
	}
	ddb := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
		o.BaseEndpoint = aws.String(c.dynamoEndpoint)
		// DynamoDB Local's answer to a DescribeTable of a missing table
		// carries a CRC32 the SDK does not match, and the SDK warns about it
		// on every missing table; this tool talks to DynamoDB Local only.
		o.DisableValidateResponseChecksum = true
	})
	s3c := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(c.s3Endpoint)
		o.UsePathStyle = true
	})

	// The HSS creates its two tables together and waits for both.
	subs, err := tableExists(ctx, ddb, c.hss.SubscribersTable)
	if err != nil {
		return err
	}
	profiles, err := tableExists(ctx, ddb, c.hss.ProfilesTable)
	if err != nil {
		return err
	}
	switch {
	case subs && profiles:
		fmt.Fprintf(out, "table %s exists\ntable %s exists\n", c.hss.SubscribersTable, c.hss.ProfilesTable)
	case subs || profiles:
		// Creating the missing one alone would need a second copy of its
		// definition; a half-made stack is quicker to remove (make down).
		return errors.New("only one of the hss tables exists; run make down and make up")
	default:
		if err := hssstore.CreateTables(ctx, ddb, c.hss); err != nil {
			return err
		}
		fmt.Fprintf(out, "table %s created\ntable %s created\n", c.hss.SubscribersTable, c.hss.ProfilesTable)
	}
	for _, t := range []struct{ name, pk, ttl string }{
		{c.ftTable, ftstore.PartitionKey, ftstore.TTLAttribute},
		{c.relayTable, dynamostore.PartitionKey, dynamostore.TTLAttribute},
	} {
		if err := ensureKeyTable(ctx, ddb, t.name, t.pk, t.ttl, out); err != nil {
			return err
		}
	}
	return ensureBucket(ctx, s3c, c.ftBucket, out)
}

func tableExists(ctx context.Context, ddb *dynamodb.Client, name string) (bool, error) {
	_, err := ddb.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(name)})
	var nf *types.ResourceNotFoundException
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &nf):
		return false, nil
	}
	return false, fmt.Errorf("describe table %s: %w", name, err)
}

// ensureKeyTable creates a table with a string partition key and nothing
// else, on demand, with TTL on ttlAttr: the layout of ft-server's and
// msrp-relay's tables.
func ensureKeyTable(ctx context.Context, ddb *dynamodb.Client, name, pk, ttlAttr string, out io.Writer) error {
	exists, err := tableExists(ctx, ddb, name)
	if err != nil || exists {
		if exists {
			fmt.Fprintf(out, "table %s exists\n", name)
		}
		return err
	}
	_, err = ddb.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:            aws.String(name),
		BillingMode:          types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{{AttributeName: aws.String(pk), AttributeType: types.ScalarAttributeTypeS}},
		KeySchema:            []types.KeySchemaElement{{AttributeName: aws.String(pk), KeyType: types.KeyTypeHash}},
	})
	if err != nil {
		return fmt.Errorf("create table %s: %w", name, err)
	}
	if err := awaitActive(ctx, ddb, name); err != nil {
		return err
	}
	_, err = ddb.UpdateTimeToLive(ctx, &dynamodb.UpdateTimeToLiveInput{
		TableName:               aws.String(name),
		TimeToLiveSpecification: &types.TimeToLiveSpecification{AttributeName: aws.String(ttlAttr), Enabled: aws.Bool(true)},
	})
	if err != nil {
		return fmt.Errorf("TTL on table %s: %w", name, err)
	}
	fmt.Fprintf(out, "table %s created\n", name)
	return nil
}

// awaitActive waits until name is ACTIVE, which TTL needs.
func awaitActive(ctx context.Context, ddb *dynamodb.Client, name string) error {
	for {
		out, err := ddb.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(name)})
		if err == nil && out.Table.TableStatus == types.TableStatusActive {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("table %s did not become active", name)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func ensureBucket(ctx context.Context, s3c *s3.Client, name string, out io.Writer) error {
	_, err := s3c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(name)})
	var owned *s3types.BucketAlreadyOwnedByYou
	switch {
	case err == nil:
		fmt.Fprintf(out, "bucket %s created\n", name)
		return nil
	case errors.As(err, &owned):
		fmt.Fprintf(out, "bucket %s exists\n", name)
		return nil
	}
	return fmt.Errorf("create bucket %s: %w", name, err)
}
