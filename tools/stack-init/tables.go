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
	rcsasstore "github.com/jeonghun-app/rcs-platform/internal/rcsas/awsstore"
	scscfstore "github.com/jeonghun-app/rcs-platform/internal/scscf/state/dynamostore"
)

// tablesConfig names the local endpoints and what to create there. The
// defaults are the services' own.
type tablesConfig struct {
	dynamoEndpoint, s3Endpoint string
	hss                        hssstore.Config
	scscf                      scscfstore.Config
	ftTable, ftBucket          string
	relayTable                 string
	rcsasMessages, rcsasGroups string
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
	c.scscf = scscfstore.Config{
		RegistrationsTable: e.get("SCSCF_REGISTRATIONS_TABLE", scscfstore.DefaultRegistrationsTable),
		ChallengesTable:    e.get("SCSCF_CHALLENGES_TABLE", scscfstore.DefaultChallengesTable),
		SubscriptionsTable: e.get("SCSCF_SUBSCRIPTIONS_TABLE", scscfstore.DefaultSubscriptionsTable),
	}
	c.ftTable = e.get("FT_DYNAMODB_TABLE", "files")
	c.relayTable = e.get("RELAY_DYNAMODB_TABLE", "msrp-bindings")
	c.rcsasMessages = e.get("RCSAS_DYNAMODB_TABLE", "messages")
	c.rcsasGroups = e.get("RCSAS_GROUPCHATS_TABLE", "groupchats")
	return c, nil
}

// createTables creates, as the service docs describe them for the
// infrastructure, whatever does not exist yet: hss's two tables
// (docs/hss.md, Tables), scscf's three (docs/scscf-state.md), rcs-as's two
// (docs/rcs-as.md, the messages and groupchats tables), ft-server's files
// table and content bucket (docs/ft-server.md, Storage) and msrp-relay's
// bindings table (docs/msrp-relay.md, The bindings table).
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

	// hss, scscf and rcs-as each create their tables together and wait for
	// them.
	if err := ensureTableSet(ctx, ddb, "hss", []string{c.hss.SubscribersTable, c.hss.ProfilesTable},
		func() error { return hssstore.CreateTables(ctx, ddb, c.hss) }, out); err != nil {
		return err
	}
	if err := ensureTableSet(ctx, ddb, "scscf", []string{c.scscf.RegistrationsTable, c.scscf.ChallengesTable, c.scscf.SubscriptionsTable},
		func() error { return scscfstore.CreateTables(ctx, ddb, c.scscf) }, out); err != nil {
		return err
	}
	if err := ensureTableSet(ctx, ddb, "rcs-as", []string{c.rcsasMessages, c.rcsasGroups}, func() error {
		if err := rcsasstore.CreateMessagesTable(ctx, ddb, c.rcsasMessages); err != nil {
			return err
		}
		return rcsasstore.CreateGroupsTable(ctx, ddb, c.rcsasGroups)
	}, out); err != nil {
		return err
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

// ensureTableSet creates the tables of one service with create, unless they
// all exist. Creating some alone would need a second copy of their
// definitions; a half-made stack is quicker to remove (make down).
func ensureTableSet(ctx context.Context, ddb *dynamodb.Client, service string, names []string, create func() error, out io.Writer) error {
	found := 0
	for _, name := range names {
		exists, err := tableExists(ctx, ddb, name)
		if err != nil {
			return err
		}
		if exists {
			found++
		}
	}
	switch found {
	case len(names):
		for _, name := range names {
			fmt.Fprintf(out, "table %s exists\n", name)
		}
		return nil
	case 0:
	default:
		return fmt.Errorf("only some of the %s tables exist; run make down and make up", service)
	}
	if err := create(); err != nil {
		return err
	}
	for _, name := range names {
		fmt.Fprintf(out, "table %s created\n", name)
	}
	return nil
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
