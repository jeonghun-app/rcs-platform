// Package awsstore keeps ft-server's files in S3 and their metadata in the
// DynamoDB files table (ADR 0003, docs/architecture.md §7). It is the only
// ft-server package that imports the AWS SDK: everything else talks to the
// interfaces of internal/ftserver/store, so the service logic is tested
// against memory backends and this package against S3 and DynamoDB
// containers (make test-integration).
//
// # Table layout
//
// One table, partition key pk (string), TTL attribute ttl, holds three kinds
// of item:
//
//	f#<file id>                       the upload record
//	t#<len(owner)>#<owner><tid>       the owner's tid, pointing at the file id
//	n#<len(user)>#<user><nonce>       the Digest nonce-count of (user, nonce)
//
// The length prefix keeps an owner ending in a digit or '#' from colliding
// with another owner and tid. A record and its tid item are created in one
// transaction, so a tid can never point at nothing or at two files.
//
// # Errors
//
// SDK errors are reduced to the operation, the AWS error code or the
// transport failure: the SDK's own messages carry request URLs, and an S3
// URL contains the object key, which is a file id and so a download
// capability. ErrNotFound, ErrExists and ErrConflict of package store are
// wrapped where they apply.
package awsstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/logging"

	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// Config says where the stores are.
type Config struct {
	Bucket string
	// Prefix is prepended to every object key, so one bucket can serve
	// several stacks.
	Prefix string
	Table  string
	// SSE is the server-side encryption of every object: "AES256" (SSE-S3)
	// or "aws:kms" (SSE-KMS with KMSKeyID, or the account's aws/s3 key when
	// that is empty).
	SSE      string
	KMSKeyID string
	// S3Endpoint and DynamoDBEndpoint replace the AWS endpoints, for local
	// containers; S3 then uses path-style addressing.
	S3Endpoint       string
	DynamoDBEndpoint string
	// Now is the clock for nonce-count expiry; time.Now when nil.
	Now func() time.Time
}

// Stores are the three stores ft-server needs, sharing SDK clients.
type Stores struct {
	Blobs       *Blobs
	Metadata    *Metadata
	NonceCounts *NonceCounts

	s3     S3API
	dynamo DynamoAPI
	bucket string
	table  string
}

// New loads the AWS configuration from the environment (region, task role)
// and returns the stores. It makes no request.
func New(ctx context.Context, c Config) (*Stores, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithLogger(sdkLogger{}))
	if err != nil {
		return nil, fmt.Errorf("awsstore: loading the AWS configuration: %w", err)
	}
	s3c := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if c.S3Endpoint != "" {
			o.BaseEndpoint = aws.String(c.S3Endpoint)
			o.UsePathStyle = true
		}
	})
	ddb := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
		if c.DynamoDBEndpoint != "" {
			o.BaseEndpoint = aws.String(c.DynamoDBEndpoint)
		}
	})
	return NewWithClients(c, s3c, ddb), nil
}

// NewWithClients returns stores over the given clients.
func NewWithClients(c Config, s3c S3API, ddb DynamoAPI) *Stores {
	now := c.Now
	if now == nil {
		now = time.Now
	}
	return &Stores{
		Blobs:       &Blobs{api: s3c, bucket: c.Bucket, prefix: c.Prefix, sse: c.SSE, kmsKeyID: c.KMSKeyID},
		Metadata:    &Metadata{api: ddb, table: c.Table},
		NonceCounts: &NonceCounts{api: ddb, table: c.Table, now: now},
		s3:          s3c,
		dynamo:      ddb,
		bucket:      c.Bucket,
		table:       c.Table,
	}
}

// Ready checks that the bucket and the table can be reached, for /readyz.
// It needs s3:ListBucket and dynamodb:DescribeTable.
func (s *Stores) Ready(ctx context.Context) error {
	if _, err := s.s3.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(s.bucket)}); err != nil {
		return sanitize("head bucket", err)
	}
	out, err := s.dynamo.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(s.table)})
	if err != nil {
		return sanitize("describe table", err)
	}
	if out.Table == nil || out.Table.TableStatus != "ACTIVE" {
		return errors.New("awsstore: the table is not active")
	}
	return nil
}

// sanitize reduces an SDK error to op and the error code or transport
// failure, without the request URL (see the package documentation).
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

// sdkLogger sends the SDK's warnings to the service's JSON log, where the
// SDK would otherwise print plain text on stderr, and drops its debug lines.
type sdkLogger struct{}

func (sdkLogger) Logf(c logging.Classification, format string, v ...any) {
	if c == logging.Warn {
		slog.Warn("aws sdk warning", slog.String("message", pii.Redact(fmt.Sprintf(format, v...))))
	}
}

// errorCode returns the AWS error code in err, or "".
func errorCode(err error) string {
	var api smithy.APIError
	if errors.As(err, &api) {
		return api.ErrorCode()
	}
	return ""
}
