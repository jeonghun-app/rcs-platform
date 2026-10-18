// Package dynamostore keeps msrp-relay's bindings in the DynamoDB table
// msrp-bindings (ADR 0004, docs/architecture.md §7). It is the only relay
// package that imports the AWS SDK: the service logic is tested against the
// memory store, and this package against DynamoDB Local with the shared
// contract in internal/msrprelay/store/storetest (make test-integration).
//
// # Table layout
//
// Partition key pk (string, the binding id), TTL attribute ttl (epoch
// seconds), no sort key and no index: every access is by id, and reads must
// be strongly consistent, which a global secondary index cannot be.
//
//	pk                    binding id
//	core_path             rcs-as's a=path (absent until known)
//	client_endpoint_path  the client's a=path (absent until known)
//	core_local            the relay's core-side URI
//	expires_at            expiry, epoch milliseconds, checked on every access
//	ttl                   expiry, epoch seconds rounded up, for TTL cleanup
//	claimed_by            relay task and connection (absent until claimed)
//
// Every rule of the store contract is a condition expression on the one
// write that needs it, so two relay tasks can never both claim a binding,
// and a path is never overwritten, whatever the timing.
//
// # Errors
//
// SDK errors are reduced to the operation and the AWS error code or the
// transport failure; the SDK's messages carry request details that do not
// belong in a log.
package dynamostore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/logging"

	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/store"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// API is the part of the DynamoDB client the store uses; *dynamodb.Client
// has it.
type API interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	DeleteItem(context.Context, *dynamodb.DeleteItemInput, ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
}

// Attribute names.
const (
	attrPK         = "pk"
	attrCorePath   = "core_path"
	attrClientPath = "client_endpoint_path"
	attrCoreLocal  = "core_local"
	attrExpires    = "expires_at"
	attrTTL        = "ttl"
	attrClaimedBy  = "claimed_by"
)

// PartitionKey is the name of the table's partition key, for whoever
// creates the table.
const PartitionKey = attrPK

// TTLAttribute is the name of the table's TTL attribute.
const TTLAttribute = attrTTL

// Store is a store.Store in one DynamoDB table.
type Store struct {
	api   API
	table string
}

var _ store.Store = (*Store)(nil)

// New loads the AWS configuration from the environment (region, task role)
// and returns a Store for table. A non-empty endpoint replaces the AWS
// endpoint, for DynamoDB Local. It makes no request.
func New(ctx context.Context, table, endpoint string) (*Store, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithLogger(sdkLogger{}))
	if err != nil {
		return nil, fmt.Errorf("dynamostore: loading the AWS configuration: %w", err)
	}
	client := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
	})
	return NewWithClient(client, table), nil
}

// NewWithClient returns a Store over api.
func NewWithClient(api API, table string) *Store {
	return &Store{api: api, table: table}
}

func str(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }

func num(v int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
}

func key(id string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{attrPK: str(id)}
}

// ttlOf rounds up, so DynamoDB never removes a binding before it expires.
func ttlOf(t time.Time) int64 {
	s := t.Unix()
	if t.After(time.Unix(s, 0)) {
		s++
	}
	return s
}

// Create implements store.Store.
func (s *Store) Create(ctx context.Context, b store.Binding) error {
	if b.ClaimedBy != "" {
		return errors.New("dynamostore: create: a new binding cannot be claimed")
	}
	item := map[string]types.AttributeValue{
		attrPK:        str(b.ID),
		attrCoreLocal: str(b.CoreLocal),
		attrExpires:   num(b.ExpiresAt.UnixMilli()),
		attrTTL:       num(ttlOf(b.ExpiresAt)),
	}
	if b.CorePath != "" {
		item[attrCorePath] = str(b.CorePath)
	}
	if b.ClientEndpointPath != "" {
		item[attrClientPath] = str(b.ClientEndpointPath)
	}
	_, err := s.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                           aws.String(s.table),
		Item:                                item,
		ConditionExpression:                 aws.String("attribute_not_exists(#pk)"),
		ExpressionAttributeNames:            map[string]string{"#pk": attrPK},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	var failed *types.ConditionalCheckFailedException
	if errors.As(err, &failed) {
		// The SDK retries a write whose answer was lost; finding our own
		// item (its core_local carries a random session id) means the first
		// attempt landed.
		if old, err := decode(failed.Item); err == nil && old.CoreLocal == b.CoreLocal && old.ClaimedBy == "" {
			return nil
		}
		return fmt.Errorf("dynamostore: create: %w", store.ErrExists)
	}
	if err != nil {
		return sanitize("create", err)
	}
	return nil
}

// Get implements store.Store with a strongly consistent read.
func (s *Store) Get(ctx context.Context, id string, now time.Time) (store.Binding, error) {
	out, err := s.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(id),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return store.Binding{}, sanitize("get", err)
	}
	return live("get", out.Item, now)
}

// live decodes item and refuses one that is absent or expired at now.
func live(op string, item map[string]types.AttributeValue, now time.Time) (store.Binding, error) {
	if len(item) == 0 {
		return store.Binding{}, fmt.Errorf("dynamostore: %s: %w", op, store.ErrNotFound)
	}
	b, err := decode(item)
	if err != nil {
		return store.Binding{}, fmt.Errorf("dynamostore: %s: %w", op, err)
	}
	if b.Expired(now) {
		return store.Binding{}, fmt.Errorf("dynamostore: %s: %w", op, store.ErrNotFound)
	}
	return b, nil
}

// Update implements store.Store. The condition carries every rule, so a
// refused update writes nothing; the item returned with the refusal says
// which rule it was.
func (s *Store) Update(ctx context.Context, id string, u store.Update, now time.Time) (store.Binding, error) {
	names := map[string]string{"#pk": attrPK, "#e": attrExpires}
	values := map[string]types.AttributeValue{":now": num(now.UnixMilli())}
	var set []string
	cond := "attribute_exists(#pk) AND #e > :now"
	if !u.ExpiresAt.IsZero() {
		names["#ttl"] = attrTTL
		values[":e"] = num(u.ExpiresAt.UnixMilli())
		values[":ttl"] = num(ttlOf(u.ExpiresAt))
		set = append(set, "#e = :e", "#ttl = :ttl")
	}
	for _, p := range []struct{ attr, name, value, v string }{
		{attrCorePath, "#cp", ":cp", u.CorePath},
		{attrClientPath, "#cl", ":cl", u.ClientEndpointPath},
	} {
		if p.v == "" {
			continue
		}
		names[p.name] = p.attr
		values[p.value] = str(p.v)
		set = append(set, p.name+" = "+p.value)
		cond += " AND (attribute_not_exists(" + p.name + ") OR " + p.name + " = " + p.value + ")"
	}
	if len(set) == 0 {
		return s.Get(ctx, id, now)
	}
	out, err := s.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                           aws.String(s.table),
		Key:                                 key(id),
		UpdateExpression:                    aws.String("SET " + strings.Join(set, ", ")),
		ConditionExpression:                 aws.String(cond),
		ExpressionAttributeNames:            names,
		ExpressionAttributeValues:           values,
		ReturnValues:                        types.ReturnValueAllNew,
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	var failed *types.ConditionalCheckFailedException
	if errors.As(err, &failed) {
		if _, err := live("update", failed.Item, now); err != nil {
			return store.Binding{}, err
		}
		return store.Binding{}, fmt.Errorf("dynamostore: update: %w", store.ErrConflict)
	}
	if err != nil {
		return store.Binding{}, sanitize("update", err)
	}
	b, err := decode(out.Attributes)
	if err != nil {
		return store.Binding{}, fmt.Errorf("dynamostore: update: %w", err)
	}
	return b, nil
}

// Claim implements store.Store with one conditional write: whichever task's
// write lands first wins, and every other gets ErrClaimed.
func (s *Store) Claim(ctx context.Context, id, by string, now time.Time) (store.Binding, error) {
	out, err := s.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        aws.String(s.table),
		Key:              key(id),
		UpdateExpression: aws.String("SET #cb = :cb"),
		ConditionExpression: aws.String("attribute_exists(#pk) AND #e > :now AND attribute_not_exists(#cb)" +
			" AND attribute_exists(#cp) AND attribute_exists(#cl)"),
		ExpressionAttributeNames: map[string]string{
			"#pk": attrPK, "#e": attrExpires, "#cb": attrClaimedBy, "#cp": attrCorePath, "#cl": attrClientPath,
		},
		ExpressionAttributeValues:           map[string]types.AttributeValue{":now": num(now.UnixMilli()), ":cb": str(by)},
		ReturnValues:                        types.ReturnValueAllNew,
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	var failed *types.ConditionalCheckFailedException
	if errors.As(err, &failed) {
		b, err := live("claim", failed.Item, now)
		switch {
		case err != nil:
			return store.Binding{}, err
		case b.ClaimedBy == by:
			// An SDK retry of a claim that had landed: ours already.
			return b, nil
		case b.ClaimedBy != "":
			return store.Binding{}, fmt.Errorf("dynamostore: claim: %w", store.ErrClaimed)
		}
		return store.Binding{}, fmt.Errorf("dynamostore: claim: %w", store.ErrIncomplete)
	}
	if err != nil {
		return store.Binding{}, sanitize("claim", err)
	}
	b, err := decode(out.Attributes)
	if err != nil {
		return store.Binding{}, fmt.Errorf("dynamostore: claim: %w", err)
	}
	return b, nil
}

// Delete implements store.Store. It deletes unconditionally and looks at
// what was there to tell a live binding from an expired or missing one.
func (s *Store) Delete(ctx context.Context, id string, now time.Time) error {
	out, err := s.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:    aws.String(s.table),
		Key:          key(id),
		ReturnValues: types.ReturnValueAllOld,
	})
	if err != nil {
		return sanitize("delete", err)
	}
	_, err = live("delete", out.Attributes, now)
	return err
}

// Ready implements store.Store: the table exists and is active. It needs
// dynamodb:DescribeTable.
func (s *Store) Ready(ctx context.Context) error {
	out, err := s.api.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(s.table)})
	if err != nil {
		return sanitize("describe table", err)
	}
	if out.Table == nil || out.Table.TableStatus != types.TableStatusActive {
		return errors.New("dynamostore: the table is not active")
	}
	return nil
}

var errMalformed = errors.New("malformed item")

func decode(item map[string]types.AttributeValue) (store.Binding, error) {
	var b store.Binding
	var ok bool
	if b.ID, ok = stringAttr(item, attrPK, true); !ok {
		return b, errMalformed
	}
	if b.CoreLocal, ok = stringAttr(item, attrCoreLocal, true); !ok {
		return b, errMalformed
	}
	if b.CorePath, ok = stringAttr(item, attrCorePath, false); !ok {
		return b, errMalformed
	}
	if b.ClientEndpointPath, ok = stringAttr(item, attrClientPath, false); !ok {
		return b, errMalformed
	}
	if b.ClaimedBy, ok = stringAttr(item, attrClaimedBy, false); !ok {
		return b, errMalformed
	}
	n, isNum := item[attrExpires].(*types.AttributeValueMemberN)
	if !isNum {
		return b, errMalformed
	}
	ms, err := strconv.ParseInt(n.Value, 10, 64)
	if err != nil {
		return b, errMalformed
	}
	b.ExpiresAt = time.UnixMilli(ms).UTC()
	return b, nil
}

// stringAttr reads a string attribute; an absent optional one is "".
func stringAttr(item map[string]types.AttributeValue, name string, required bool) (string, bool) {
	v, present := item[name]
	if !present {
		return "", !required
	}
	s, ok := v.(*types.AttributeValueMemberS)
	if !ok || (required && s.Value == "") {
		return "", false
	}
	return s.Value, true
}

// sanitize reduces an SDK error to op and the error code or transport
// failure (see the package documentation). A context error stays
// recognisable with errors.Is, so the relay can count timeouts.
func sanitize(op string, err error) error {
	for _, ctxErr := range []error{context.DeadlineExceeded, context.Canceled} {
		if errors.Is(err, ctxErr) {
			return fmt.Errorf("dynamostore: %s: %w", op, ctxErr)
		}
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		return fmt.Errorf("dynamostore: %s: %s", op, api.ErrorCode())
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("dynamostore: %s: %s", op, ue.Err.Error())
	}
	return fmt.Errorf("dynamostore: %s: request failed", op)
}

// sdkLogger sends the SDK's warnings to the service's JSON log, where the
// SDK would otherwise print plain text on stderr, and drops its debug lines.
type sdkLogger struct{}

func (sdkLogger) Logf(c logging.Classification, format string, v ...any) {
	if c == logging.Warn {
		slog.Warn("aws sdk warning", slog.String("message", pii.Redact(fmt.Sprintf(format, v...))))
	}
}
