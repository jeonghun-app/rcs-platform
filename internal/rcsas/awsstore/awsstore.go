// Package awsstore keeps rcs-as's store-and-forward queue and sent-message
// records in the DynamoDB messages table (docs/architecture.md §7). It is
// the only rcs-as package that imports the AWS SDK: the messaging engine
// talks to internal/rcsas/store, so it is tested against the memory backend
// and this package against DynamoDB Local (make test-integration).
//
// # Table layout
//
// One table, partition key pk and sort key sk (both strings), TTL attribute
// ttl, holds four kinds of item:
//
//	pk q#<len(recipient)>#<recipient>  sk <message id>   a queued message
//	pk c#<len(recipient)>#<recipient>  sk n              the queue's size
//	pk s#<len(sender)>#<sender>        sk <Message-ID>   a sent-message record
//	pk r#<len(recipient)>#<recipient>  sk t#<len(task)>#<task>  when the task's delivery last reached the recipient
//	pk r#<len(recipient)>#<recipient>  sk f#<len(task)>#<task>  when the task last took its registration on a new flow
//
// The length prefix keeps one identity from being a prefix-collision of
// another. A recipient's queue is one partition, read in sort-key order,
// which the engine makes the enqueue order. The size item is written in the
// same transaction as each enqueue and removal, which is what bounds a
// queue across tasks.
//
// The global secondary index expiry (partition key xb, sort key expires,
// projecting owner and lease_until) finds expired messages without reading
// the table: only queue items carry xb, one of ExpiryBuckets values chosen
// by recipient, so the index is sparse and no single index partition takes
// every write.
//
// Every table read is strongly consistent: a message may be claimed
// milliseconds after another task enqueued it. The index cannot be, which
// is harmless since Claim checks again. Claims are conditional updates
// (attribute_not_exists(owner) OR lease <= now), so exactly one task wins
// one; Release and Remove are conditional on the owner. Items carry their
// own expiry and the store checks it on every read, because DynamoDB TTL
// deletion can lag by days; the ttl attribute only keeps the table small.
//
// # Errors
//
// SDK errors are reduced to the operation and the AWS error code or the
// transport failure; the SDK's own messages carry request details, and keys
// here are subscriber identities.
package awsstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/logging"

	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// DynamoAPI is the part of the DynamoDB client the store uses;
// *dynamodb.Client has it.
type DynamoAPI interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
	DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
}

// Config says where the table is.
type Config struct {
	Table string
	// Endpoint replaces the AWS endpoint, for DynamoDB Local.
	Endpoint string
}

// New loads the AWS configuration from the environment (region, task role)
// and returns the store. It makes no request.
func New(ctx context.Context, c Config) (*Store, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithLogger(sdkLogger{}))
	if err != nil {
		return nil, fmt.Errorf("awsstore: loading the AWS configuration: %w", err)
	}
	ddb := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
		if c.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Endpoint)
		}
	})
	return NewWithClient(c.Table, ddb), nil
}

// NewWithClient returns a store over the given client.
func NewWithClient(table string, api DynamoAPI) *Store {
	return &Store{api: api, table: table}
}

// Ready checks that the table can be reached, for /readyz. It needs
// dynamodb:DescribeTable.
func (s *Store) Ready(ctx context.Context) error {
	out, err := s.api.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(s.table)})
	if err != nil {
		return sanitize("describe table", err)
	}
	if out.Table == nil || out.Table.TableStatus != "ACTIVE" {
		return errors.New("awsstore: the table is not active")
	}
	return nil
}

// sanitize reduces an SDK error to op and the error code or transport
// failure (see the package documentation).
func sanitize(op string, err error) error {
	for _, ctxErr := range []error{context.DeadlineExceeded, context.Canceled} {
		if errors.Is(err, ctxErr) {
			return fmt.Errorf("awsstore: %s: %w", op, ctxErr)
		}
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		return fmt.Errorf("awsstore: %s: %s", op, api.ErrorCode())
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("awsstore: %s: %s", op, ue.Err.Error())
	}
	return fmt.Errorf("awsstore: %s: request failed", op)
}

func errorCode(err error) string {
	var api smithy.APIError
	if errors.As(err, &api) {
		return api.ErrorCode()
	}
	return ""
}

// sdkLogger sends the SDK's warnings to the service's JSON log and drops
// its debug lines.
type sdkLogger struct{}

func (sdkLogger) Logf(c logging.Classification, format string, v ...any) {
	if c == logging.Warn {
		slog.Warn("aws sdk warning", slog.String("message", pii.Redact(fmt.Sprintf(format, v...))))
	}
}
