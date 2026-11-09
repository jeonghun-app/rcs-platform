// Package awsstore keeps maap's tables in DynamoDB. It is the only maap
// package that imports the AWS SDK: the service talks to the interfaces of
// internal/maap/store, so it is tested against the memory backends, and
// this package against DynamoDB Local (make test-integration).
//
// # maap-registry
//
// Partition key pk and sort key sk, both strings, no TTL; docs/maap.md
// has the definition for the infrastructure (#684):
//
//	pk c#<chatbot ID>  sk chatbot      the record: version, doc (store's JSON document), writer
//	pk u#<URI>         sk uri          the URI's reservation: chatbot (its ID), writer
//	pk c#<chatbot ID>  sk k#<key ID>   reserved for the chatbot's credentials (#710)
//
// Register writes the record and the reservation in one transaction, each
// on the condition that it does not exist, so one URI in normal form has
// one chatbot (T13). Update is a PutItem on the record's version. Every
// item of a chatbot but its reservation is in its partition, which is
// what DeleteChatbot deletes.
//
// Reads are strongly consistent. SDK errors are reduced to the operation
// and the AWS error code or the transport failure, so that no request
// detail reaches a log.
package awsstore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
)

// DynamoAPI is the part of the DynamoDB client the store uses;
// *dynamodb.Client has it.
type DynamoAPI interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	DeleteItem(context.Context, *dynamodb.DeleteItemInput, ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
}

// Attribute names and sort keys of maap-registry.
const (
	attrPK      = "pk"
	attrSK      = "sk"
	attrVersion = "version"
	attrDoc     = "doc"
	attrChatbot = "chatbot"
	// attrWriter is a random token of the write that stored an item: a
	// write whose answer was lost, which the SDK sends again and which
	// then fails its own condition, finds it and stands.
	attrWriter = "writer"
	skChatbot  = "chatbot"
	skURI      = "uri"
)

// Registry is a store.Registry in the maap-registry table.
type Registry struct {
	api   DynamoAPI
	table string
}

var _ store.Registry = (*Registry)(nil)

// NewRegistry returns the registry in table over api.
func NewRegistry(api DynamoAPI, table string) *Registry { return &Registry{api: api, table: table} }

func key(pk, sk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{attrPK: str(pk), attrSK: str(sk)}
}

func chatbotKey(id string) map[string]types.AttributeValue { return key("c#"+id, skChatbot) }
func uriKey(uri string) map[string]types.AttributeValue    { return key("u#"+uri, skURI) }

func str(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }

// sv is the string or number of an attribute, or "".
func sv(v types.AttributeValue) string {
	switch a := v.(type) {
	case *types.AttributeValueMemberS:
		return a.Value
	case *types.AttributeValueMemberN:
		return a.Value
	}
	return ""
}

func (r *Registry) item(c store.Chatbot, version int64) (map[string]types.AttributeValue, error) {
	doc, err := store.EncodeChatbot(c)
	if err != nil {
		return nil, err
	}
	item := chatbotKey(c.ID)
	item[attrVersion] = &types.AttributeValueMemberN{Value: strconv.FormatInt(version, 10)}
	item[attrDoc] = &types.AttributeValueMemberB{Value: doc}
	item[attrWriter] = str(rand.Text())
	return item, nil
}

func decode(item map[string]types.AttributeValue) (store.Chatbot, error) {
	doc, ok := item[attrDoc].(*types.AttributeValueMemberB)
	version, err := strconv.ParseInt(sv(item[attrVersion]), 10, 64)
	if !ok || err != nil {
		return store.Chatbot{}, fmt.Errorf("%w: chatbot item without doc or version", store.ErrInvalid)
	}
	return store.DecodeChatbot(doc.Value, version)
}

// mine reports whether cur, an item a write's condition failed on, is the
// one that write stored: the token decides, never the content, since two
// writers may compute the same record.
func mine(cur, wrote map[string]types.AttributeValue) bool {
	return sv(cur[attrWriter]) == sv(wrote[attrWriter]) && sv(cur[attrVersion]) == sv(wrote[attrVersion])
}

// Register implements store.Registry.
func (r *Registry) Register(ctx context.Context, c store.Chatbot) (store.Chatbot, error) {
	item, err := r.item(c, 1)
	if err != nil {
		return store.Chatbot{}, err
	}
	reservation := uriKey(c.URI)
	reservation[attrChatbot], reservation[attrWriter] = str(c.ID), item[attrWriter]
	absent, names := aws.String("attribute_not_exists(#pk)"), map[string]string{"#pk": attrPK}
	_, err = r.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		ClientRequestToken: aws.String(sv(item[attrWriter])),
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{
				TableName: aws.String(r.table), Item: item, ConditionExpression: absent, ExpressionAttributeNames: names,
				ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
			}},
			{Put: &types.Put{TableName: aws.String(r.table), Item: reservation, ConditionExpression: absent, ExpressionAttributeNames: names}},
		},
	})
	reasons := cancelled(err)
	switch {
	case len(reasons) == 2 && failed(reasons[0]):
		if mine(reasons[0].Item, item) {
			break // the SDK sent again a register that had taken effect
		}
		return store.Chatbot{}, fmt.Errorf("awsstore: register: %w", store.ErrExists)
	case len(reasons) == 2 && failed(reasons[1]):
		return store.Chatbot{}, fmt.Errorf("awsstore: register: %w", store.ErrURITaken)
	case raced(err):
		return store.Chatbot{}, fmt.Errorf("awsstore: register: %w", store.ErrConflict)
	case err != nil:
		return store.Chatbot{}, sanitize("register", err)
	}
	return decode(item)
}

// Chatbot implements store.Registry.
func (r *Registry) Chatbot(ctx context.Context, id string) (store.Chatbot, error) {
	out, err := r.api.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(r.table), Key: chatbotKey(id), ConsistentRead: aws.Bool(true)})
	if err != nil {
		return store.Chatbot{}, sanitize("get chatbot", err)
	}
	if len(out.Item) == 0 {
		return store.Chatbot{}, fmt.Errorf("awsstore: get chatbot: %w", store.ErrNotFound)
	}
	return decode(out.Item)
}

// Update implements store.Registry.
func (r *Registry) Update(ctx context.Context, old, c store.Chatbot) (store.Chatbot, error) {
	if old.ID != c.ID || old.URI != c.URI {
		return store.Chatbot{}, fmt.Errorf("%w: a chatbot's ID and URI never change", store.ErrInvalid)
	}
	item, err := r.item(c, old.Version+1)
	if err != nil {
		return store.Chatbot{}, err
	}
	_, err = r.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(r.table), Item: item, ConditionExpression: aws.String("#v = :v"),
		ExpressionAttributeNames:            map[string]string{"#v": attrVersion},
		ExpressionAttributeValues:           map[string]types.AttributeValue{":v": &types.AttributeValueMemberN{Value: strconv.FormatInt(old.Version, 10)}},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	var ccf *types.ConditionalCheckFailedException
	switch {
	case errors.As(err, &ccf):
		if len(ccf.Item) == 0 {
			return store.Chatbot{}, fmt.Errorf("awsstore: update chatbot: %w", store.ErrNotFound)
		}
		if !mine(ccf.Item, item) {
			return store.Chatbot{}, fmt.Errorf("awsstore: update chatbot: %w", store.ErrConflict)
		}
		// The SDK sent again an update that had taken effect.
	case raced(err):
		return store.Chatbot{}, fmt.Errorf("awsstore: update chatbot: %w", store.ErrConflict)
	case err != nil:
		return store.Chatbot{}, sanitize("update chatbot", err)
	}
	return decode(item)
}

// DeleteChatbot implements store.ChatbotDeleter. The record goes last,
// with its URI's reservation, so that a deletion that failed part way
// still finds the URI when it is called again.
func (r *Registry) DeleteChatbot(ctx context.Context, id string) error {
	in := &dynamodb.QueryInput{
		TableName: aws.String(r.table), ConsistentRead: aws.Bool(true),
		KeyConditionExpression:    aws.String("#pk = :pk"),
		ProjectionExpression:      aws.String("#pk, #sk"),
		ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#sk": attrSK},
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": str("c#" + id)},
	}
	for {
		out, err := r.api.Query(ctx, in)
		if err != nil {
			return sanitize("delete chatbot", err)
		}
		for _, it := range out.Items {
			if sv(it[attrSK]) == skChatbot {
				continue
			}
			if _, err := r.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(r.table), Key: it}); err != nil {
				return sanitize("delete chatbot", err)
			}
		}
		if len(out.LastEvaluatedKey) == 0 {
			break
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
	c, err := r.Chatbot(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	_, err = r.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		ClientRequestToken: aws.String(rand.Text()),
		TransactItems: []types.TransactWriteItem{
			{Delete: &types.Delete{TableName: aws.String(r.table), Key: chatbotKey(id)}},
			{Delete: &types.Delete{
				TableName: aws.String(r.table), Key: uriKey(c.URI),
				ConditionExpression:       aws.String("attribute_not_exists(#pk) OR #chatbot = :id"),
				ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#chatbot": attrChatbot},
				ExpressionAttributeValues: map[string]types.AttributeValue{":id": str(id)},
			}},
		},
	})
	switch reasons := cancelled(err); {
	case len(reasons) == 2 && failed(reasons[1]):
		return fmt.Errorf("%w: the chatbot's URI is reserved for another", store.ErrInvalid)
	case raced(err):
		return fmt.Errorf("awsstore: delete chatbot: %w", store.ErrConflict)
	case err != nil:
		return sanitize("delete chatbot", err)
	}
	return nil
}

// cancelled returns the reasons of a cancelled transaction, nil for any
// other error.
func cancelled(err error) []types.CancellationReason {
	var tc *types.TransactionCanceledException
	if errors.As(err, &tc) {
		return tc.CancellationReasons
	}
	return nil
}

func failed(r types.CancellationReason) bool { return aws.ToString(r.Code) == "ConditionalCheckFailed" }

// raced reports whether a write lost to a concurrent transaction on one of
// its items, which the SDK does not retry: to the caller, a conflict.
func raced(err error) bool {
	var conflict *types.TransactionConflictException
	if errors.As(err, &conflict) {
		return true
	}
	for _, r := range cancelled(err) {
		if aws.ToString(r.Code) == "TransactionConflict" {
			return true
		}
	}
	return false
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
