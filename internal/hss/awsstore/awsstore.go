// Package awsstore keeps the HSS's subscribers and service profiles in
// DynamoDB and wraps its data keys with AWS KMS. It is the only HSS package
// that imports the AWS SDK: the HSS talks to the interfaces of
// internal/hss/store and internal/hss/keyring, so the service logic is tested
// against the memory backend, and this package against a strict fake in unit
// tests and DynamoDB Local in make test-integration.
//
// # Tables
//
// subscribers, partition key pk (string), with a global secondary index
// profile-index (partition key profile, keys only), holds three kinds of item:
//
//	s#<IMPI>   the subscription: version (number), profile (string),
//	           doc (binary, the store package's JSON document)
//	u#<IMPU>   the IMPU index: impi (string)
//	keyring    the wrapped data keys: one binary attribute key_<id> per key
//
// A subscription and the index items of its IMPUs are written in one
// transaction, each conditional (the subscription on its version, an IMPU on
// not belonging to another subscription), so an IMPU can never point at two
// subscriptions or at none. Only subscription items carry a profile
// attribute, so only they are in the index.
//
// service-profiles, partition key pk (string = profile ID), holds version and
// doc like a subscription.
//
// docs/hss.md lists the tables for the infrastructure. Reads are strongly
// consistent except the profile index, which DynamoDB keeps eventually
// consistent.
//
// # Errors
//
// SDK errors are reduced to the operation and the AWS error code or the
// transport failure, so that no request detail (keys are subscriber
// identities) reaches a log. store's errors are wrapped where they apply.
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
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/logging"

	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// Config says where the tables and the master key are.
type Config struct {
	SubscribersTable string
	ProfilesTable    string
	// KMSKeyID is the KMS key that wraps the data keys; empty when the HSS
	// uses a local key (dev and test).
	KMSKeyID string
	// DynamoDBEndpoint and KMSEndpoint replace the AWS endpoints, for local
	// containers.
	DynamoDBEndpoint string
	KMSEndpoint      string
}

// Clients are the SDK clients New makes from the environment's AWS
// configuration (region, ECS task role).
type Clients struct {
	DynamoDB *dynamodb.Client
	KMS      *kms.Client
}

// NewClients loads the AWS configuration and returns the clients. It makes
// no request.
func NewClients(ctx context.Context, c Config) (*Clients, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithLogger(sdkLogger{}))
	if err != nil {
		return nil, fmt.Errorf("awsstore: loading the AWS configuration: %w", sanitize("load configuration", err))
	}
	return &Clients{
		DynamoDB: dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
			if c.DynamoDBEndpoint != "" {
				o.BaseEndpoint = aws.String(c.DynamoDBEndpoint)
			}
		}),
		KMS: kms.NewFromConfig(awsCfg, func(o *kms.Options) {
			if c.KMSEndpoint != "" {
				o.BaseEndpoint = aws.String(c.KMSEndpoint)
			}
		}),
	}, nil
}

// sanitize reduces an SDK error to op and the error code or transport
// failure, without the request (see the package documentation).
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
