package awsstore

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// retention is how long an item outlives its own expiry before DynamoDB's
// TTL deletes it: long enough for an operator to look into a lost message,
// short enough that the table does not grow without bound.
const retention = 7 * 24 * time.Hour

// Attribute names.
const (
	attrPK           = "pk"
	attrSK           = "sk"
	attrTTL          = "ttl"
	attrSender       = "sender"
	attrConversation = "conversation"
	attrContribution = "contribution"
	attrInReplyTo    = "in_reply_to"
	attrMode         = "mode"
	attrNotification = "notification"
	attrMessageID    = "message_id"
	attrCPIM         = "cpim"
	attrEnqueued     = "enqueued"
	attrExpires      = "expires"
	attrOwner        = "owner"
	attrLease        = "lease_until"
	attrRecipients   = "recipients"
	attrDispositions = "dispositions"
)

// MaxCPIMSize is the largest message body the table takes. A DynamoDB item
// holds at most 400 KB, names and values together; the rest leaves room for
// the identities and other attributes beside the body.
const MaxCPIMSize = 380 << 10

// ErrTooLarge reports a message beyond MaxCPIMSize.
var ErrTooLarge = errors.New("awsstore: message larger than an item holds")

const (
	queuePrefix = "q#"
	sentPrefix  = "s#"
)

// Store is a store.Store in the DynamoDB messages table.
type Store struct {
	api   DynamoAPI
	table string
}

var _ store.Store = (*Store)(nil)

func identityKey(prefix, identity string) string {
	return prefix + strconv.Itoa(len(identity)) + "#" + identity
}

func key(pk, sk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{attrPK: str(pk), attrSK: str(sk)}
}

func str(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }

func num(v int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
}

// stamp encodes a time with nanoseconds, so a round trip keeps it exact.
func stamp(t time.Time) types.AttributeValue { return num(t.UnixNano()) }

// ttlOf is the DynamoDB TTL, in epoch seconds, of an item valid until t.
func ttlOf(t time.Time) types.AttributeValue { return num(t.Add(retention).Unix()) }

// Enqueue implements store.Store.
func (s *Store) Enqueue(ctx context.Context, m store.Message) error {
	if len(m.CPIM) > MaxCPIMSize {
		return ErrTooLarge
	}
	item := map[string]types.AttributeValue{
		attrPK:           str(identityKey(queuePrefix, m.Recipient)),
		attrSK:           str(m.ID),
		attrSender:       str(m.Sender),
		attrMode:         num(int64(m.Mode)),
		attrNotification: &types.AttributeValueMemberBOOL{Value: m.Notification},
		attrCPIM:         &types.AttributeValueMemberB{Value: m.CPIM},
		attrEnqueued:     stamp(m.Enqueued),
		attrExpires:      stamp(m.Expires),
		attrTTL:          ttlOf(m.Expires),
	}
	for name, v := range map[string]string{
		attrConversation: m.Conversation, attrContribution: m.Contribution,
		attrInReplyTo: m.InReplyTo, attrMessageID: m.MessageID,
	} {
		if v != "" {
			item[name] = str(v)
		}
	}
	_, err := s.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                aws.String(s.table),
		Item:                     item,
		ConditionExpression:      aws.String("attribute_not_exists(#pk)"),
		ExpressionAttributeNames: map[string]string{"#pk": attrPK},
	})
	if errorCode(err) == "ConditionalCheckFailedException" {
		return fmt.Errorf("awsstore: enqueue: %w", store.ErrExists)
	}
	if err != nil {
		return sanitize("enqueue", err)
	}
	return nil
}

// freeAt is the condition of a message nobody holds at :now.
const freeAt = "(attribute_not_exists(#owner) OR #lease <= :now)"

// Pending implements store.Store: the recipient's partition in sort-key
// order, filtered to free, unexpired messages, page by page until limit.
func (s *Store) Pending(ctx context.Context, recipient, after string, now time.Time, limit int) ([]store.Message, error) {
	if limit <= 0 {
		return nil, nil
	}
	in := &dynamodb.QueryInput{
		TableName:              aws.String(s.table),
		ConsistentRead:         aws.Bool(true),
		KeyConditionExpression: aws.String("#pk = :pk"),
		FilterExpression:       aws.String(freeAt + " AND #expires > :now"),
		ExpressionAttributeNames: map[string]string{
			"#pk": attrPK, "#owner": attrOwner, "#lease": attrLease, "#expires": attrExpires,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": str(identityKey(queuePrefix, recipient)), ":now": stamp(now),
		},
		ScanIndexForward: aws.Bool(true),
	}
	if after != "" {
		// A key condition, so DynamoDB starts reading after it rather than
		// reading and filtering out the messages before it.
		in.KeyConditionExpression = aws.String("#pk = :pk AND #sk > :after")
		in.ExpressionAttributeNames["#sk"] = attrSK
		in.ExpressionAttributeValues[":after"] = str(after)
	}
	var out []store.Message
	for {
		page, err := s.api.Query(ctx, in)
		if err != nil {
			return nil, sanitize("query queue", err)
		}
		for _, item := range page.Items {
			m, err := decodeMessage(item)
			if err != nil {
				return nil, err
			}
			out = append(out, m)
			if len(out) == limit {
				return out, nil
			}
		}
		if len(page.LastEvaluatedKey) == 0 {
			return out, nil
		}
		in.ExclusiveStartKey = page.LastEvaluatedKey
	}
}

// Claim implements store.Store.
func (s *Store) Claim(ctx context.Context, recipient, id, owner string, now, until time.Time) (store.Message, error) {
	k := key(identityKey(queuePrefix, recipient), id)
	out, err := s.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.table),
		Key:                 k,
		UpdateExpression:    aws.String("SET #owner = :owner, #lease = :until"),
		ConditionExpression: aws.String("attribute_exists(#pk) AND " + freeAt),
		ExpressionAttributeNames: map[string]string{
			"#pk": attrPK, "#owner": attrOwner, "#lease": attrLease,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":owner": str(owner), ":until": stamp(until), ":now": stamp(now),
		},
		ReturnValues: types.ReturnValueAllNew,
	})
	if errorCode(err) == "ConditionalCheckFailedException" {
		return store.Message{}, s.whyRefused(ctx, "claim", k)
	}
	if err != nil {
		return store.Message{}, sanitize("claim", err)
	}
	return decodeMessage(out.Attributes)
}

// Release implements store.Store.
func (s *Store) Release(ctx context.Context, recipient, id, owner string) error {
	k := key(identityKey(queuePrefix, recipient), id)
	_, err := s.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.table),
		Key:                       k,
		UpdateExpression:          aws.String("REMOVE #owner, #lease"),
		ConditionExpression:       aws.String("#owner = :owner"),
		ExpressionAttributeNames:  map[string]string{"#owner": attrOwner, "#lease": attrLease},
		ExpressionAttributeValues: map[string]types.AttributeValue{":owner": str(owner)},
	})
	if errorCode(err) == "ConditionalCheckFailedException" {
		return s.whyRefused(ctx, "release", k)
	}
	if err != nil {
		return sanitize("release", err)
	}
	return nil
}

// Remove implements store.Store.
func (s *Store) Remove(ctx context.Context, recipient, id, owner string) error {
	k := key(identityKey(queuePrefix, recipient), id)
	_, err := s.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 aws.String(s.table),
		Key:                       k,
		ConditionExpression:       aws.String("#owner = :owner"),
		ExpressionAttributeNames:  map[string]string{"#owner": attrOwner},
		ExpressionAttributeValues: map[string]types.AttributeValue{":owner": str(owner)},
	})
	if errorCode(err) == "ConditionalCheckFailedException" {
		return s.whyRefused(ctx, "remove", k)
	}
	if err != nil {
		return sanitize("remove", err)
	}
	return nil
}

// whyRefused tells a missing item from one held by someone else, after a
// conditional write failed.
func (s *Store) whyRefused(ctx context.Context, op string, k map[string]types.AttributeValue) error {
	out, err := s.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.table), Key: k, ConsistentRead: aws.Bool(true),
		ProjectionExpression: aws.String("#pk"), ExpressionAttributeNames: map[string]string{"#pk": attrPK},
	})
	if err != nil {
		return sanitize(op, err)
	}
	if len(out.Item) == 0 {
		return fmt.Errorf("awsstore: %s: %w", op, store.ErrNotFound)
	}
	return fmt.Errorf("awsstore: %s: %w", op, store.ErrConflict)
}

// Expired implements store.Store with a paged, filtered Scan of the queue
// items. It reads the whole table each sweep, which is fine while the
// table holds what offline users have not received; an expiry index is the
// step up (docs/rcs-as.md).
func (s *Store) Expired(ctx context.Context, now time.Time, limit int) ([]store.Message, error) {
	if limit <= 0 {
		return nil, nil
	}
	in := &dynamodb.ScanInput{
		TableName:        aws.String(s.table),
		ConsistentRead:   aws.Bool(true),
		FilterExpression: aws.String("begins_with(#pk, :q) AND #expires <= :now AND " + freeAt),
		ExpressionAttributeNames: map[string]string{
			"#pk": attrPK, "#expires": attrExpires, "#owner": attrOwner, "#lease": attrLease,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{":q": str(queuePrefix), ":now": stamp(now)},
	}
	var out []store.Message
	for {
		page, err := s.api.Scan(ctx, in)
		if err != nil {
			return nil, sanitize("scan for expired", err)
		}
		for _, item := range page.Items {
			m, err := decodeMessage(item)
			if err != nil {
				return nil, err
			}
			out = append(out, m)
			if len(out) == limit {
				return out, nil
			}
		}
		if len(page.LastEvaluatedKey) == 0 {
			return out, nil
		}
		in.ExclusiveStartKey = page.LastEvaluatedKey
	}
}

// RecordSent implements store.Store.
func (s *Store) RecordSent(ctx context.Context, r store.Sent, now time.Time) error {
	recipients := make([]types.AttributeValue, len(r.Recipients))
	for i, v := range r.Recipients {
		recipients[i] = str(v)
	}
	_, err := s.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.table),
		Item: map[string]types.AttributeValue{
			attrPK:           str(identityKey(sentPrefix, r.Sender)),
			attrSK:           str(r.MessageID),
			attrRecipients:   &types.AttributeValueMemberL{Value: recipients},
			attrDispositions: num(int64(r.Dispositions)),
			attrExpires:      stamp(r.Expires),
			attrTTL:          ttlOf(r.Expires),
		},
		ConditionExpression:       aws.String("attribute_not_exists(#pk) OR #expires <= :now"),
		ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#expires": attrExpires},
		ExpressionAttributeValues: map[string]types.AttributeValue{":now": stamp(now)},
	})
	if errorCode(err) == "ConditionalCheckFailedException" {
		return fmt.Errorf("awsstore: record sent: %w", store.ErrExists)
	}
	if err != nil {
		return sanitize("record sent", err)
	}
	return nil
}

// Sent implements store.Store.
func (s *Store) Sent(ctx context.Context, sender, messageID string, now time.Time) (store.Sent, error) {
	out, err := s.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.table), Key: key(identityKey(sentPrefix, sender), messageID), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return store.Sent{}, sanitize("get sent", err)
	}
	if len(out.Item) == 0 {
		return store.Sent{}, fmt.Errorf("awsstore: get sent: %w", store.ErrNotFound)
	}
	r := store.Sent{Sender: sender, MessageID: messageID}
	var dispositions int64
	var expires time.Time
	err = errors.Join(
		getNum(out.Item, attrDispositions, &dispositions),
		getTime(out.Item, attrExpires, &expires),
	)
	if l, ok := out.Item[attrRecipients].(*types.AttributeValueMemberL); ok {
		for _, v := range l.Value {
			sv, ok := v.(*types.AttributeValueMemberS)
			if !ok {
				err = errors.Join(err, errors.New("recipient is not a string"))
				continue
			}
			r.Recipients = append(r.Recipients, sv.Value)
		}
	} else {
		err = errors.Join(err, errors.New("recipients missing"))
	}
	if err != nil {
		return store.Sent{}, fmt.Errorf("awsstore: decoding a sent record: %w", err)
	}
	if !expires.After(now) {
		return store.Sent{}, fmt.Errorf("awsstore: get sent: %w", store.ErrNotFound)
	}
	r.Dispositions, r.Expires = imdn.Disposition(dispositions), expires
	return r, nil
}

func decodeMessage(item map[string]types.AttributeValue) (store.Message, error) {
	var m store.Message
	var pk string
	var mode int64
	err := errors.Join(
		getString(item, attrPK, &pk, true),
		getString(item, attrSK, &m.ID, true),
		getString(item, attrSender, &m.Sender, true),
		getString(item, attrConversation, &m.Conversation, false),
		getString(item, attrContribution, &m.Contribution, false),
		getString(item, attrInReplyTo, &m.InReplyTo, false),
		getString(item, attrMessageID, &m.MessageID, false),
		getString(item, attrOwner, &m.Owner, false),
		getNum(item, attrMode, &mode),
		getTime(item, attrEnqueued, &m.Enqueued),
		getTime(item, attrExpires, &m.Expires),
	)
	if _, ok := item[attrLease]; ok {
		err = errors.Join(err, getTime(item, attrLease, &m.LeaseUntil))
	}
	if b, ok := item[attrCPIM].(*types.AttributeValueMemberB); ok {
		m.CPIM = b.Value
	} else {
		err = errors.Join(err, errors.New("cpim missing"))
	}
	if b, ok := item[attrNotification].(*types.AttributeValueMemberBOOL); ok {
		m.Notification = b.Value
	}
	recipient, ok := strings.CutPrefix(pk, queuePrefix)
	if ok {
		_, recipient, ok = strings.Cut(recipient, "#")
	}
	if !ok {
		err = errors.Join(err, errors.New("not a queue key"))
	}
	if err != nil {
		return store.Message{}, fmt.Errorf("awsstore: decoding a queued message: %w", err)
	}
	m.Recipient, m.Mode = recipient, store.Mode(mode)
	return m, nil
}

func getString(item map[string]types.AttributeValue, name string, dst *string, required bool) error {
	v, ok := item[name]
	if !ok {
		if required {
			return fmt.Errorf("%s missing", name)
		}
		return nil
	}
	s, ok := v.(*types.AttributeValueMemberS)
	if !ok {
		return fmt.Errorf("%s is not a string", name)
	}
	*dst = s.Value
	return nil
}

func getNum(item map[string]types.AttributeValue, name string, dst *int64) error {
	v, ok := item[name].(*types.AttributeValueMemberN)
	if !ok {
		return fmt.Errorf("%s missing", name)
	}
	n, err := strconv.ParseInt(v.Value, 10, 64)
	if err != nil {
		return fmt.Errorf("%s is not an integer", name)
	}
	*dst = n
	return nil
}

func getTime(item map[string]types.AttributeValue, name string, dst *time.Time) error {
	var n int64
	if err := getNum(item, name, &n); err != nil {
		return err
	}
	*dst = time.Unix(0, n).UTC()
	return nil
}
