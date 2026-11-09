package awsstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/smithy-go/logging"

	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// New loads the AWS configuration from the environment (region, task role)
// and returns the registry in table; endpoint, when set, replaces the AWS
// endpoint, for DynamoDB Local. It makes no request.
func New(ctx context.Context, table, endpoint string) (*Registry, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithLogger(sdkLogger{}))
	if err != nil {
		return nil, fmt.Errorf("awsstore: loading the AWS configuration: %w", err)
	}
	ddb := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
	})
	return NewRegistry(ddb, table), nil
}

// Ready checks that the table can be reached and is ACTIVE, for /readyz.
// It needs dynamodb:DescribeTable.
func (r *Registry) Ready(ctx context.Context) error {
	out, err := r.api.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(r.table)})
	if err != nil {
		return sanitize("describe table", err)
	}
	if out.Table == nil || out.Table.TableStatus != "ACTIVE" {
		return errors.New("awsstore: the table is not active")
	}
	return nil
}

// sdkLogger sends the SDK's warnings to the service's log, redacted, and
// drops its debug lines, which may carry requests.
type sdkLogger struct{}

func (sdkLogger) Logf(c logging.Classification, format string, v ...any) {
	if c == logging.Warn {
		slog.Warn("aws sdk warning", slog.String("message", pii.Redact(fmt.Sprintf(format, v...))))
	}
}
