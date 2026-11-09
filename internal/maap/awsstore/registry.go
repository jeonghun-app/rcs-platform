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
//	pk c#<chatbot ID>  sk chatbot      the record: version, registration, uri, doc (store's JSON document), writer
//	                                   or, once deleted, a tombstone: deleted
//	pk u#<URI>         sk uri          the URI's reservation: chatbot (its ID), writer
//	pk c#<chatbot ID>  sk k#<key ID>   reserved for the chatbot's credentials (#710)
//
// Register writes the record and the reservation in one transaction, each
// on the condition that it does not exist, so one URI in normal form has
// one chatbot (T13) and a deleted ID is not used again. Update is a
// PutItem on the record's version, registration and URI. Every item of a
// chatbot but its reservation is in its partition, which is what
// DeleteChatbot deletes; it reads only the record's plain attributes, never
// the document, so that a release can delete what a newer one wrote.
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
	DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
}

// Attribute names and sort keys of maap-registry.
const (
	attrPK           = "pk"
	attrSK           = "sk"
	attrVersion      = "version"
	attrRegistration = "registration"
	attrURI          = "uri"
	attrDoc          = "doc"
	attrDeleted      = "deleted"
	attrChatbot      = "chatbot"
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
	// pageSize bounds DeleteChatbot's query pages, for tests; 0 is
	// DynamoDB's own (1 MB).
	pageSize int32
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

func num(v int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
}

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

// gone reports whether item is no chatbot: absent, or a tombstone.
func gone(item map[string]types.AttributeValue) bool {
	_, deleted := item[attrDeleted]
	return len(item) == 0 || deleted
}

func (r *Registry) item(c store.Chatbot, version int64, registration string) (map[string]types.AttributeValue, error) {
	doc, err := store.EncodeChatbot(c)
	if err != nil {
		return nil, err
	}
	item := chatbotKey(c.ID)
	item[attrVersion], item[attrRegistration], item[attrURI] = num(version), str(registration), str(c.URI)
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
	c, err := store.DecodeChatbot(doc.Value, version)
	c.Registration = sv(item[attrRegistration])
	return c, err
}

// mine reports whether cur, an item a write's condition failed on, is the
// one that write stored: the token decides, never the content, since two
// writers may compute the same record.
func mine(cur, wrote map[string]types.AttributeValue) bool {
	return sv(cur[attrWriter]) == sv(wrote[attrWriter]) && sv(cur[attrVersion]) == sv(wrote[attrVersion])
}

// Register implements store.Registry.
func (r *Registry) Register(ctx context.Context, c store.Chatbot) (store.Chatbot, error) {
	item, err := r.item(c, 1, rand.Text())
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
		switch {
		case mine(reasons[0].Item, item):
			// The SDK sent again a register that had taken effect.
		case gone(reasons[0].Item):
			return store.Chatbot{}, fmt.Errorf("awsstore: register: %w", store.ErrDeleted)
		default:
			return store.Chatbot{}, fmt.Errorf("awsstore: register: %w", store.ErrExists)
		}
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
	if gone(out.Item) {
		return store.Chatbot{}, fmt.Errorf("awsstore: get chatbot: %w", store.ErrNotFound)
	}
	return decode(out.Item)
}

// Update implements store.Registry. Its condition holds the stored URI to
// c's, so that a caller's old with another URI changes nothing.
func (r *Registry) Update(ctx context.Context, old, c store.Chatbot) (store.Chatbot, error) {
	if old.ID != c.ID {
		return store.Chatbot{}, fmt.Errorf("%w: a chatbot's ID never changes", store.ErrInvalid)
	}
	item, err := r.item(c, old.Version+1, old.Registration)
	if err != nil {
		return store.Chatbot{}, err
	}
	_, err = r.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(r.table), Item: item, ConditionExpression: aws.String("#v = :v AND #reg = :reg AND #uri = :uri"),
		ExpressionAttributeNames: map[string]string{"#v": attrVersion, "#reg": attrRegistration, "#uri": attrURI},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":v": num(old.Version), ":reg": str(old.Registration), ":uri": str(c.URI),
		},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	var ccf *types.ConditionalCheckFailedException
	switch {
	case errors.As(err, &ccf):
		cur := ccf.Item
		switch {
		case gone(cur):
			return store.Chatbot{}, fmt.Errorf("awsstore: update chatbot: %w", store.ErrNotFound)
		case mine(cur, item):
			// The SDK sent again an update that had taken effect.
		case sv(cur[attrVersion]) == sv(num(old.Version)) && sv(cur[attrRegistration]) == old.Registration:
			return store.Chatbot{}, fmt.Errorf("%w: a chatbot's URI never changes", store.ErrInvalid)
		default:
			return store.Chatbot{}, fmt.Errorf("awsstore: update chatbot: %w", store.ErrConflict)
		}
	case raced(err):
		return store.Chatbot{}, fmt.Errorf("awsstore: update chatbot: %w", store.ErrConflict)
	case err != nil:
		return store.Chatbot{}, sanitize("update chatbot", err)
	}
	return decode(item)
}

// DeleteChatbot implements store.ChatbotDeleter. The record turns into a
// tombstone first, on the condition of the registration read, with its
// URI's reservation; the chatbot's other items (#710's credentials) go
// after it. So no credential is deleted from a chatbot that stays, a
// change meanwhile (which cannot move the URI) does not stop the deletion,
// and a deletion that failed part way finishes its clean-up under the
// tombstone when it is called again.
func (r *Registry) DeleteChatbot(ctx context.Context, id string) error {
	for attempt := 0; ; attempt++ {
		out, err := r.api.GetItem(ctx, &dynamodb.GetItemInput{
			TableName: aws.String(r.table), Key: chatbotKey(id), ConsistentRead: aws.Bool(true),
			ProjectionExpression:     aws.String("#reg, #uri, #deleted"),
			ExpressionAttributeNames: map[string]string{"#reg": attrRegistration, "#uri": attrURI, "#deleted": attrDeleted},
		})
		if err != nil {
			return sanitize("delete chatbot", err)
		}
		if len(out.Item) == 0 {
			return nil
		}
		if gone(out.Item) {
			break
		}
		err = r.tombstone(ctx, id, out.Item)
		switch {
		case raced(err) && attempt < conflictAttempts-1:
			continue // read again: the other write may have been a deletion
		case raced(err):
			return sanitize("delete chatbot", err)
		case err != nil:
			return err
		}
		break
	}
	return r.deleteRest(ctx, id)
}

// conflictAttempts bounds the tries of a tombstone write that keeps
// meeting another transaction on the record.
const conflictAttempts = 3

// tombstone replaces the record read with a tombstone and deletes its
// URI's reservation, in one transaction.
func (r *Registry) tombstone(ctx context.Context, id string, read map[string]types.AttributeValue) error {
	tomb := chatbotKey(id)
	tomb[attrDeleted] = &types.AttributeValueMemberBOOL{Value: true}
	_, err := r.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		ClientRequestToken: aws.String(rand.Text()),
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{
				TableName: aws.String(r.table), Item: tomb,
				ConditionExpression:                 aws.String("#reg = :reg"),
				ExpressionAttributeNames:            map[string]string{"#reg": attrRegistration},
				ExpressionAttributeValues:           map[string]types.AttributeValue{":reg": str(sv(read[attrRegistration]))},
				ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
			}},
			{Delete: &types.Delete{
				TableName: aws.String(r.table), Key: uriKey(sv(read[attrURI])),
				ConditionExpression:       aws.String("attribute_not_exists(#pk) OR #chatbot = :id"),
				ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#chatbot": attrChatbot},
				ExpressionAttributeValues: map[string]types.AttributeValue{":id": str(id)},
			}},
		},
	})
	switch reasons := cancelled(err); {
	case len(reasons) == 2 && failed(reasons[0]) && gone(reasons[0].Item):
		return nil // deleted meanwhile, by this call's resent request or another
	case len(reasons) == 2 && failed(reasons[0]):
		// IDs are never registered again, so the registration cannot move.
		return fmt.Errorf("%w: the chatbot's registration changed", store.ErrInvalid)
	case len(reasons) == 2 && failed(reasons[1]):
		return fmt.Errorf("%w: the chatbot's URI is reserved for another", store.ErrInvalid)
	case raced(err):
		return err
	case err != nil:
		return sanitize("delete chatbot", err)
	}
	return nil
}

// deleteRest deletes every item of the chatbot's partition but its
// tombstone.
func (r *Registry) deleteRest(ctx context.Context, id string) error {
	in := &dynamodb.QueryInput{
		TableName: aws.String(r.table), ConsistentRead: aws.Bool(true),
		KeyConditionExpression:    aws.String("#pk = :pk"),
		ProjectionExpression:      aws.String("#pk, #sk"),
		ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#sk": attrSK},
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": str("c#" + id)},
	}
	if r.pageSize > 0 {
		in.Limit = aws.Int32(r.pageSize)
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
			return nil
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
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
