package awsstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
)

// TableAPI is the part of the DynamoDB client the stores of maap-requests
// and maap-counters use; *dynamodb.Client has it.
type TableAPI interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	BatchWriteItem(context.Context, *dynamodb.BatchWriteItemInput, ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error)
	DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
}

// Attribute names of maap-requests; ttl is the table's TTL attribute.
const (
	attrTTL       = "ttl"
	attrMessageID = "message_id"
	attrAnswer    = "answer"
	attrState     = "state"
	attrAccepted  = "accepted"
	attrUpdated   = "updated"
)

// Requests is a store.Requests in the maap-requests table: partition key
// pk and sort key sk, both strings, TTL on ttl.
//
//	pk c#<chatbot ID>  sk i#<key>         an idempotency record: digest, message_id, answer, created, ttl, writer
//	pk c#<chatbot ID>  sk m#<Message-ID>  a message's status: state, accepted, updated, ttl, writer
//
// A chatbot's items are its partition, which DeleteChatbot deletes
// without a Scan. A write racing the deletion leaves an item under an ID
// the registry never registers again, which no chatbot reads; its TTL
// or a repeated deletion removes it.
type Requests struct {
	api       TableAPI
	table     string
	statusTTL time.Duration
	// pageSize bounds DeleteChatbot's query pages, for tests.
	pageSize int32
}

var _ store.Requests = (*Requests)(nil)

// NewRequests returns the requests table over api, which keeps statuses
// for statusTTL.
func NewRequests(api TableAPI, table string, statusTTL time.Duration) *Requests {
	return &Requests{api: api, table: table, statusTTL: statusTTL}
}

func requestKey(chatbotID, idemKey string) map[string]types.AttributeValue {
	return key("c#"+chatbotID, "i#"+idemKey)
}

// Remember implements store.Requests. The record is put on the condition
// that none is live, so an expired item that TTL has not deleted yet is
// written over; a put sent again after its answer was lost finds its own
// writer token.
func (r *Requests) Remember(ctx context.Context, rec store.Idempotency, now time.Time) (store.Idempotency, bool, error) {
	if err := store.CheckIdempotency(rec); err != nil {
		return store.Idempotency{}, false, err
	}
	rec.Created = store.Seconds(now)
	writer := rand.Text()
	item := requestKey(rec.Chatbot, rec.Key)
	item[attrDigest] = &types.AttributeValueMemberB{Value: rec.Digest[:]}
	item[attrMessageID], item[attrCreated] = str(rec.MessageID), num(rec.Created.Unix())
	item[attrTTL], item[attrWriter] = num(rec.Created.Add(store.IdempotencyTTL).Unix()), str(writer)
	if len(rec.Answer) > 0 {
		item[attrAnswer] = &types.AttributeValueMemberB{Value: rec.Answer}
	} else {
		rec.Answer = nil
	}
	_, err := r.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(r.table), Item: item,
		ConditionExpression:                 aws.String("attribute_not_exists(#pk) OR #ttl <= :now"),
		ExpressionAttributeNames:            map[string]string{"#pk": attrPK, "#ttl": attrTTL},
		ExpressionAttributeValues:           map[string]types.AttributeValue{":now": num(now.Unix())},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	var ccf *types.ConditionalCheckFailedException
	switch {
	case errors.As(err, &ccf) && sv(ccf.Item[attrWriter]) == writer:
		return rec, true, nil // the SDK sent again a put that had taken effect
	case errors.As(err, &ccf):
		old, err := decodeIdempotency(rec.Chatbot, rec.Key, ccf.Item)
		switch {
		case err != nil:
			return store.Idempotency{}, false, err
		case old.Digest != rec.Digest:
			return store.Idempotency{}, false, fmt.Errorf("awsstore: remember request: %w", store.ErrKeyReused)
		}
		return old, false, nil
	case err != nil:
		return store.Idempotency{}, false, sanitize("remember request", err)
	}
	return rec, true, nil
}

func statusKey(chatbotID, messageID string) map[string]types.AttributeValue {
	return key("c#"+chatbotID, "m#"+messageID)
}

// Accept implements store.Requests: a put on the condition that no live
// status exists, which leaves one there as it is.
func (r *Requests) Accept(ctx context.Context, chatbotID, messageID string, now time.Time) error {
	if err := store.CheckStatus(store.Status{Chatbot: chatbotID, MessageID: messageID, State: store.Accepted}); err != nil {
		return err
	}
	at := store.Seconds(now).Unix()
	item := statusKey(chatbotID, messageID)
	item[attrState], item[attrAccepted], item[attrUpdated] = str(string(store.Accepted)), num(at), num(at)
	item[attrTTL], item[attrWriter] = num(at+int64(r.statusTTL/time.Second)), str(rand.Text())
	_, err := r.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(r.table), Item: item,
		ConditionExpression:       aws.String("attribute_not_exists(#pk) OR #ttl <= :now"),
		ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#ttl": attrTTL},
		ExpressionAttributeValues: map[string]types.AttributeValue{":now": num(now.Unix())},
	})
	var ccf *types.ConditionalCheckFailedException
	if err != nil && !errors.As(err, &ccf) {
		return sanitize("accept status", err)
	}
	return nil
}

// Status implements store.Requests.
func (r *Requests) Status(ctx context.Context, chatbotID, messageID string, now time.Time) (store.Status, error) {
	if !store.ValidID(chatbotID) || !store.ValidMessageID(messageID) {
		return store.Status{}, fmt.Errorf("awsstore: get status: %w", store.ErrNotFound)
	}
	out, err := r.api.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(r.table), Key: statusKey(chatbotID, messageID), ConsistentRead: aws.Bool(true)})
	if err != nil {
		return store.Status{}, sanitize("get status", err)
	}
	if len(out.Item) == 0 {
		return store.Status{}, fmt.Errorf("awsstore: get status: %w", store.ErrNotFound)
	}
	st, ttl, err := decodeStatus(chatbotID, messageID, out.Item)
	switch {
	case err != nil:
		return store.Status{}, err
	case ttl <= now.Unix():
		return store.Status{}, fmt.Errorf("awsstore: get status: %w", store.ErrNotFound)
	}
	return st, nil
}

// Advance implements store.Requests: an update on the condition that the
// status is live and in a state before the new one. An update the SDK
// sent again after it took effect finds its own writer token.
func (r *Requests) Advance(ctx context.Context, chatbotID, messageID string, state store.StatusState, now time.Time) (bool, error) {
	if err := store.CheckAdvance(chatbotID, messageID, state); err != nil {
		return false, err
	}
	writer := rand.Text()
	values := map[string]types.AttributeValue{
		":state": str(string(state)), ":now": num(now.Unix()), ":at": num(store.Seconds(now).Unix()), ":w": str(writer),
	}
	from := make([]string, len(state.Before()))
	for i, s := range state.Before() {
		from[i] = ":from" + strconv.Itoa(i)
		values[from[i]] = str(string(s))
	}
	_, err := r.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(r.table), Key: statusKey(chatbotID, messageID),
		UpdateExpression:                    aws.String("SET #state = :state, #updated = :at, #w = :w"),
		ConditionExpression:                 aws.String("#ttl > :now AND #state IN (" + strings.Join(from, ", ") + ")"),
		ExpressionAttributeNames:            map[string]string{"#state": attrState, "#updated": attrUpdated, "#w": attrWriter, "#ttl": attrTTL},
		ExpressionAttributeValues:           values,
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	var ccf *types.ConditionalCheckFailedException
	switch {
	case errors.As(err, &ccf):
		ttl, _ := number(ccf.Item, attrTTL)
		switch {
		case sv(ccf.Item[attrWriter]) == writer:
			return true, nil // the SDK sent again an update that had taken effect
		case len(ccf.Item) == 0 || ttl <= now.Unix():
			// An update makes no item: the condition fails on an absent one.
			return false, fmt.Errorf("awsstore: advance status: %w", store.ErrNotFound)
		}
		return false, nil
	case err != nil:
		return false, sanitize("advance status", err)
	}
	return true, nil
}

// decodeStatus reads a stored status strictly, with its ttl.
func decodeStatus(chatbotID, messageID string, item map[string]types.AttributeValue) (store.Status, int64, error) {
	accepted, okA := number(item, attrAccepted)
	updated, okU := number(item, attrUpdated)
	ttl, okT := number(item, attrTTL)
	st := store.Status{
		Chatbot: chatbotID, MessageID: messageID, State: store.StatusState(text(item, attrState)),
		Accepted: time.Unix(accepted, 0).UTC(), Updated: time.Unix(updated, 0).UTC(),
	}
	if err := store.CheckStatus(st); err != nil || !okA || !okU || !okT {
		return store.Status{}, 0, fmt.Errorf("%w: a damaged status", store.ErrInvalid)
	}
	return st, ttl, nil
}

// decodeIdempotency reads a stored record strictly: one that is not
// whole is damaged, never a record with a short digest.
func decodeIdempotency(chatbotID, key string, item map[string]types.AttributeValue) (store.Idempotency, error) {
	digest, ok := item[attrDigest].(*types.AttributeValueMemberB)
	answer, hasAnswer := item[attrAnswer].(*types.AttributeValueMemberB)
	created, createdOK := number(item, attrCreated)
	// A ttl that is no number would keep the record live for ever.
	_, ttlOK := number(item, attrTTL)
	if !ok || len(digest.Value) != sha256.Size || !createdOK || !ttlOK || item[attrAnswer] != nil && !hasAnswer {
		return store.Idempotency{}, fmt.Errorf("%w: a damaged idempotency record", store.ErrInvalid)
	}
	rec := store.Idempotency{
		Chatbot: chatbotID, Key: key, Digest: [sha256.Size]byte(digest.Value),
		MessageID: text(item, attrMessageID), Created: time.Unix(created, 0).UTC(),
	}
	if hasAnswer && len(answer.Value) > 0 {
		rec.Answer = answer.Value
	}
	if err := store.CheckIdempotency(rec); err != nil {
		return store.Idempotency{}, err
	}
	return rec, nil
}

// text returns what an item holds in a string attribute, or "".
func text(item map[string]types.AttributeValue, name string) string {
	if s, ok := item[name].(*types.AttributeValueMemberS); ok {
		return s.Value
	}
	return ""
}

// number returns the integer an item holds in a number attribute.
func number(item map[string]types.AttributeValue, name string) (int64, bool) {
	n, ok := item[name].(*types.AttributeValueMemberN)
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseInt(n.Value, 10, 64)
	return v, err == nil
}

// DeleteChatbot implements store.ChatbotDeleter.
func (r *Requests) DeleteChatbot(ctx context.Context, chatbotID string) error {
	return deletePartition(ctx, r.api, r.table, "c#"+chatbotID, r.pageSize)
}

// Ready checks the table for /readyz, as the registry's Ready does.
func (r *Requests) Ready(ctx context.Context) error { return ready(ctx, r.api, r.table) }

// batchAttempts bounds the sends of a batch whose items DynamoDB keeps
// leaving unprocessed (throttling); a deletion that gives up is a store
// failure, and a repeat goes on where it stopped.
const batchAttempts = 8

// batchWait is the first pause before a batch is sent again, doubling
// after; a variable for tests.
var batchWait = 50 * time.Millisecond

// deletePartition deletes every item of partition pk, 25 at a time, the
// most a BatchWriteItem takes: a chatbot at its daily send limit holds
// many thousand statuses, which one DeleteItem each would take minutes to
// delete.
func deletePartition(ctx context.Context, api TableAPI, table, pk string, pageSize int32) error {
	in := &dynamodb.QueryInput{
		TableName: aws.String(table), ConsistentRead: aws.Bool(true),
		KeyConditionExpression:    aws.String("#pk = :pk"),
		ProjectionExpression:      aws.String("#pk, #sk"),
		ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#sk": attrSK},
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": str(pk)},
	}
	if pageSize > 0 {
		in.Limit = aws.Int32(pageSize)
	}
	for {
		out, err := api.Query(ctx, in)
		if err != nil {
			return sanitize("query chatbot", err)
		}
		for items := out.Items; len(items) > 0; {
			n := min(len(items), 25)
			if err := deleteBatch(ctx, api, table, items[:n]); err != nil {
				return err
			}
			items = items[n:]
		}
		if len(out.LastEvaluatedKey) == 0 {
			return nil
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
}

func deleteBatch(ctx context.Context, api TableAPI, table string, keys []map[string]types.AttributeValue) error {
	reqs := make([]types.WriteRequest, len(keys))
	for i, k := range keys {
		reqs[i] = types.WriteRequest{DeleteRequest: &types.DeleteRequest{Key: key(sv(k[attrPK]), sv(k[attrSK]))}}
	}
	for attempt, wait := 0, batchWait; ; attempt, wait = attempt+1, 2*wait {
		out, err := api.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{RequestItems: map[string][]types.WriteRequest{table: reqs}})
		if err != nil {
			return sanitize("delete chatbot", err)
		}
		if reqs = out.UnprocessedItems[table]; len(reqs) == 0 {
			return nil
		}
		if attempt == batchAttempts-1 {
			return errors.New("awsstore: delete chatbot: items left unprocessed")
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("awsstore: delete chatbot: %w", ctx.Err())
		case <-time.After(wait):
		}
	}
}
