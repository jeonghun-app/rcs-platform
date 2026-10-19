package awsstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// retention is how long a queue item or size item outlives its own expiry
// before DynamoDB's TTL deletes it. The sweep removes expired messages
// itself; the TTL is only the backstop for one it never reached, and a
// message body is kept no longer than that. Sent records carry no content
// and expire exactly (threat model T10).
const retention = 24 * time.Hour

// ExpiryBuckets is how many partitions of the expiry index queue items are
// spread over.
const ExpiryBuckets = 16

// IndexExpiry is the expiry index's name.
const IndexExpiry = "expiry"

// Attribute names.
const (
	attrPK           = "pk"
	attrSK           = "sk"
	attrTTL          = "ttl"
	attrBucket       = "xb"
	attrSender       = "sender"
	attrAuthor       = "author"
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
	attrSeen         = "seen"
	attrCount        = "count"
	attrSize         = "size"
	attrRecounted    = "recounted_at"
	attrBytes        = "bytes"
)

// MaxCPIMSize is the largest message body the table takes. A DynamoDB item
// holds at most 400 KB, names and values together; the rest leaves room for
// the identities and other attributes beside the body.
const MaxCPIMSize = 380 << 10

// ErrTooLarge reports a message beyond MaxCPIMSize.
var ErrTooLarge = errors.New("awsstore: message larger than an item holds")

const (
	queuePrefix = "q#"
	sizePrefix  = "c#"
	sentPrefix  = "s#"
	sizeSK      = "n"
	senderSK    = "s#"
)

const conditionFailed = "ConditionalCheckFailedException"

// Store is a store.Store in the DynamoDB messages table.
type Store struct {
	api   DynamoAPI
	table string
}

var _ store.Store = (*Store)(nil)

func identityKey(prefix, identity string) string {
	return prefix + strconv.Itoa(len(identity)) + "#" + identity
}

// bucket spreads queues over the expiry index's partitions.
func bucket(recipient string) string {
	h := fnv.New32a()
	h.Write([]byte(recipient))
	return fmt.Sprintf("x#%02d", h.Sum32()%ExpiryBuckets)
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

// ttlOf is the DynamoDB TTL, in epoch seconds, of an item kept until t.
func ttlOf(t time.Time) types.AttributeValue { return num(t.Unix()) }

// canceled reports which items of a cancelled transaction failed their
// condition.
func canceled(err error) (failed []bool, ok bool) {
	var tce *types.TransactionCanceledException
	if !errors.As(err, &tce) {
		return nil, false
	}
	for _, r := range tce.CancellationReasons {
		failed = append(failed, aws.ToString(r.Code) == "ConditionalCheckFailed")
	}
	return failed, true
}

// sizeUpdate adds count and bytes to a size item, conditional on the
// bounds that are not zero. An enqueue (a zero ttl means a removal) also
// moves the item's TTL to that of the message: messages are enqueued in
// time order with one lifetime, so that only ever lengthens it, and the
// size item outlives every message it counts. A removal leaves the TTL
// alone, since the messages still counted may live longer than the one
// removed.
func (s *Store) sizeUpdate(k map[string]types.AttributeValue, count, bytes int64, maxCount int, maxBytes int64, ttl time.Time) *types.Update {
	u := &types.Update{
		TableName:        aws.String(s.table),
		Key:              k,
		UpdateExpression: aws.String("ADD #count :count, #bytes :bytes"),
		ExpressionAttributeNames: map[string]string{
			"#count": attrCount, "#bytes": attrBytes,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":count": num(count), ":bytes": num(bytes),
		},
	}
	if !ttl.IsZero() {
		u.UpdateExpression = aws.String("ADD #count :count, #bytes :bytes SET #ttl = :ttl")
		u.ExpressionAttributeNames["#ttl"] = attrTTL
		u.ExpressionAttributeValues[":ttl"] = ttlOf(ttl)
	}
	var bounds []string
	if maxCount > 0 {
		bounds = append(bounds, "#count < :maxCount")
		u.ExpressionAttributeValues[":maxCount"] = num(int64(maxCount))
	}
	if maxBytes > 0 {
		bounds = append(bounds, "#bytes <= :room")
		u.ExpressionAttributeValues[":room"] = num(maxBytes - bytes)
	}
	if len(bounds) > 0 {
		u.ConditionExpression = aws.String("attribute_not_exists(#count) OR (" + strings.Join(bounds, " AND ") + ")")
	}
	return u
}

// queueSizeKey is the size item of recipient's queue; senderSizeKey the
// size item of what sender has in it.
func queueSizeKey(recipient string) map[string]types.AttributeValue {
	return key(identityKey(sizePrefix, recipient), sizeSK)
}

func senderSizeKey(recipient, sender string) map[string]types.AttributeValue {
	return key(identityKey(sizePrefix, recipient), identityKey(senderSK, sender))
}

// Enqueue implements store.Store: the message, its queue's size and its
// sender's share of it in one transaction, the sizes conditional on l. The
// SDK gives the transaction an idempotency token, so its own retry of one
// that took effect succeeds.
//
// The sizes are kept by this store, so an item deleted another way (by
// DynamoDB's TTL, or by hand) would count for ever. A refusal therefore
// counts the queue, corrects a size that is too high, and tries again;
// at most once per RecountInterval per queue, since a count reads the
// whole partition and a full queue may be refused many times a minute.
func (s *Store) Enqueue(ctx context.Context, m store.Message, l store.Limit) error {
	err := s.enqueue(ctx, m, l)
	if !errors.Is(err, store.ErrQueueFull) && !errors.Is(err, store.ErrSenderShareFull) {
		return err
	}
	if !s.mayRecount(ctx, m.Recipient, m.Enqueued) {
		return err
	}
	fixed, cerr := s.recount(ctx, m.Recipient, m.Sender)
	if cerr != nil || !fixed {
		return err
	}
	return s.enqueue(ctx, m, l)
}

func (s *Store) enqueue(ctx context.Context, m store.Message, l store.Limit) error {
	if len(m.CPIM) > MaxCPIMSize {
		return ErrTooLarge
	}
	switch {
	case l.Bytes > 0 && m.Size() > l.Bytes:
		return fmt.Errorf("awsstore: enqueue: %w", store.ErrQueueFull)
	case l.SenderBytes > 0 && m.Size() > l.SenderBytes:
		return fmt.Errorf("awsstore: enqueue: %w", store.ErrSenderShareFull)
	}
	ttl := m.Expires.Add(retention)
	item := map[string]types.AttributeValue{
		attrPK:           str(identityKey(queuePrefix, m.Recipient)),
		attrSK:           str(m.ID),
		attrBucket:       str(bucket(m.Recipient)),
		attrSender:       str(m.Sender),
		attrMode:         num(int64(m.Mode)),
		attrNotification: &types.AttributeValueMemberBOOL{Value: m.Notification},
		attrCPIM:         &types.AttributeValueMemberB{Value: m.CPIM},
		attrSize:         num(m.Size()),
		attrEnqueued:     stamp(m.Enqueued),
		attrExpires:      stamp(m.Expires),
		attrTTL:          ttlOf(ttl),
	}
	for name, v := range map[string]string{
		attrConversation: m.Conversation, attrContribution: m.Contribution,
		attrInReplyTo: m.InReplyTo, attrMessageID: m.MessageID, attrAuthor: m.Author,
	} {
		if v != "" {
			item[name] = str(v)
		}
	}
	items := []types.TransactWriteItem{
		{Put: &types.Put{
			TableName:                aws.String(s.table),
			Item:                     item,
			ConditionExpression:      aws.String("attribute_not_exists(#pk)"),
			ExpressionAttributeNames: map[string]string{"#pk": attrPK},
		}},
		{Update: s.sizeUpdate(queueSizeKey(m.Recipient), 1, m.Size(), l.Count, l.Bytes, ttl)},
	}
	if !m.Notification {
		items = append(items, types.TransactWriteItem{Update: s.sizeUpdate(senderSizeKey(m.Recipient, m.Sender), 1, m.Size(), l.SenderCount, l.SenderBytes, ttl)})
	}
	_, err := s.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	if failed, ok := canceled(err); ok {
		switch {
		case len(failed) > 0 && failed[0]:
			return fmt.Errorf("awsstore: enqueue: %w", store.ErrExists)
		case len(failed) > 1 && failed[1]:
			return fmt.Errorf("awsstore: enqueue: %w", store.ErrQueueFull)
		case len(failed) > 2 && failed[2]:
			return fmt.Errorf("awsstore: enqueue: %w", store.ErrSenderShareFull)
		}
	}
	if err != nil {
		return sanitize("enqueue", err)
	}
	return nil
}

// RecountInterval is how often one queue may be counted again.
const RecountInterval = 10 * time.Minute

// mayRecount takes recipient's turn to count its queue at now, with a
// conditional update of the queue's size item: of the tasks refused at
// once, one counts, and none again within RecountInterval.
func (s *Store) mayRecount(ctx context.Context, recipient string, now time.Time) bool {
	_, err := s.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                aws.String(s.table),
		Key:                      queueSizeKey(recipient),
		UpdateExpression:         aws.String("SET #recounted = :now"),
		ConditionExpression:      aws.String("attribute_not_exists(#recounted) OR #recounted <= :before"),
		ExpressionAttributeNames: map[string]string{"#recounted": attrRecounted},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":now": stamp(now), ":before": stamp(now.Add(-RecountInterval)),
		},
	})
	return err == nil
}

// recount counts recipient's queue, and what sender has in it, and sets
// any size item that says more to what is there. It reports whether it
// corrected one. Each correction is conditional on the size item being
// unchanged since it was read, before the queue was: a size that moved
// meanwhile reflects an enqueue or removal the count may have missed.
func (s *Store) recount(ctx context.Context, recipient, sender string) (bool, error) {
	type size struct{ count, bytes int64 }
	read := func(k map[string]types.AttributeValue) (size, error) {
		out, err := s.api.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(s.table), Key: k, ConsistentRead: aws.Bool(true)})
		if err != nil {
			return size{}, sanitize("recount", err)
		}
		var z size
		_ = getNum(out.Item, attrCount, &z.count)
		_ = getNum(out.Item, attrBytes, &z.bytes)
		return z, nil
	}
	queueKey, senderKey := queueSizeKey(recipient), senderSizeKey(recipient, sender)
	queueWas, err := read(queueKey)
	if err != nil {
		return false, err
	}
	senderWas, err := read(senderKey)
	if err != nil {
		return false, err
	}
	var queueIs, senderIs size
	in := &dynamodb.QueryInput{
		TableName:                 aws.String(s.table),
		ConsistentRead:            aws.Bool(true),
		KeyConditionExpression:    aws.String("#pk = :pk"),
		ProjectionExpression:      aws.String("#sender, #size, #notification"),
		ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#sender": attrSender, "#size": attrSize, "#notification": attrNotification},
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": str(identityKey(queuePrefix, recipient))},
	}
	for {
		page, err := s.api.Query(ctx, in)
		if err != nil {
			return false, sanitize("recount", err)
		}
		for _, item := range page.Items {
			var n int64
			_ = getNum(item, attrSize, &n)
			queueIs.count, queueIs.bytes = queueIs.count+1, queueIs.bytes+n
			note, _ := item[attrNotification].(*types.AttributeValueMemberBOOL)
			if sv, _ := item[attrSender].(*types.AttributeValueMemberS); sv != nil && sv.Value == sender && (note == nil || !note.Value) {
				senderIs.count, senderIs.bytes = senderIs.count+1, senderIs.bytes+n
			}
		}
		if len(page.LastEvaluatedKey) == 0 {
			break
		}
		in.ExclusiveStartKey = page.LastEvaluatedKey
	}
	fixed := false
	for _, c := range []struct {
		k        map[string]types.AttributeValue
		was, now size
	}{{queueKey, queueWas, queueIs}, {senderKey, senderWas, senderIs}} {
		if c.now.count >= c.was.count && c.now.bytes >= c.was.bytes {
			continue
		}
		_, err := s.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName:                aws.String(s.table),
			Key:                      c.k,
			UpdateExpression:         aws.String("SET #count = :count, #bytes = :bytes"),
			ConditionExpression:      aws.String("#count = :wasCount AND #bytes = :wasBytes"),
			ExpressionAttributeNames: map[string]string{"#count": attrCount, "#bytes": attrBytes},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":count": num(c.now.count), ":bytes": num(c.now.bytes),
				":wasCount": num(c.was.count), ":wasBytes": num(c.was.bytes),
			},
		})
		switch {
		case err == nil:
			fixed = true
		case errorCode(err) != conditionFailed:
			return fixed, sanitize("recount", err)
		}
	}
	return fixed, nil
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
	if errorCode(err) == conditionFailed {
		item, err := s.current(ctx, "claim", k)
		if err != nil {
			return store.Message{}, err
		}
		m, err := decodeMessage(item)
		if err != nil {
			return store.Message{}, err
		}
		if m.Owner == owner && m.LeaseUntil.Equal(until) {
			// The SDK repeated a claim whose answer was lost.
			return m, nil
		}
		return store.Message{}, fmt.Errorf("awsstore: claim: %w", store.ErrConflict)
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
	if errorCode(err) == conditionFailed {
		item, err := s.current(ctx, "release", k)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, held := item[attrOwner]; !held {
			return nil
		}
		return fmt.Errorf("awsstore: release: %w", store.ErrConflict)
	}
	if err != nil {
		return sanitize("release", err)
	}
	return nil
}

// Remove implements store.Store: the message and its share of the queue's
// and its sender's sizes in one transaction.
func (s *Store) Remove(ctx context.Context, m store.Message, owner string) error {
	k := key(identityKey(queuePrefix, m.Recipient), m.ID)
	items := []types.TransactWriteItem{
		{Delete: &types.Delete{
			TableName:                 aws.String(s.table),
			Key:                       k,
			ConditionExpression:       aws.String("#owner = :owner"),
			ExpressionAttributeNames:  map[string]string{"#owner": attrOwner},
			ExpressionAttributeValues: map[string]types.AttributeValue{":owner": str(owner)},
		}},
		{Update: s.sizeUpdate(queueSizeKey(m.Recipient), -1, -m.Size(), 0, 0, time.Time{})},
	}
	if !m.Notification {
		items = append(items, types.TransactWriteItem{Update: s.sizeUpdate(senderSizeKey(m.Recipient, m.Sender), -1, -m.Size(), 0, 0, time.Time{})})
	}
	_, err := s.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	if failed, ok := canceled(err); ok && len(failed) > 0 && failed[0] {
		_, err := s.current(ctx, "remove", k)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("awsstore: remove: %w", store.ErrConflict)
	}
	if err != nil {
		return sanitize("remove", err)
	}
	return nil
}

// current reads an item after a conditional write failed, to tell a
// missing item from one in another state.
func (s *Store) current(ctx context.Context, op string, k map[string]types.AttributeValue) (map[string]types.AttributeValue, error) {
	out, err := s.api.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(s.table), Key: k, ConsistentRead: aws.Bool(true)})
	if err != nil {
		return nil, sanitize(op, err)
	}
	if len(out.Item) == 0 {
		return nil, fmt.Errorf("awsstore: %s: %w", op, store.ErrNotFound)
	}
	return out.Item, nil
}

// expiryCursor is where Expired stopped: a bucket and the index key of the
// last message returned from it.
type expiryCursor struct {
	Bucket int               `json:"b"`
	Key    map[string]string `json:"k,omitempty"`
}

func (c expiryCursor) startKey() map[string]types.AttributeValue {
	if c.Key == nil {
		return nil
	}
	return map[string]types.AttributeValue{
		attrPK: str(c.Key[attrPK]), attrSK: str(c.Key[attrSK]),
		attrBucket: str(c.Key[attrBucket]), attrExpires: &types.AttributeValueMemberN{Value: c.Key[attrExpires]},
	}
}

func (c expiryCursor) encode() string {
	b, _ := json.Marshal(c)
	return string(b)
}

// Expired implements store.Store over the expiry index, bucket by bucket.
func (s *Store) Expired(ctx context.Context, now time.Time, cursor string, limit int) ([]store.Message, string, error) {
	if limit <= 0 {
		return nil, cursor, nil
	}
	var at expiryCursor
	if cursor != "" {
		if err := json.Unmarshal([]byte(cursor), &at); err != nil || at.Bucket < 0 || at.Bucket >= ExpiryBuckets {
			at = expiryCursor{} // from a different layout: start over
		}
	}
	var out []store.Message
	for ; at.Bucket < ExpiryBuckets; at = (expiryCursor{Bucket: at.Bucket + 1}) {
		in := &dynamodb.QueryInput{
			TableName:              aws.String(s.table),
			IndexName:              aws.String(IndexExpiry),
			KeyConditionExpression: aws.String("#xb = :b AND #expires <= :now"),
			FilterExpression:       aws.String(freeAt),
			ExpressionAttributeNames: map[string]string{
				"#xb": attrBucket, "#expires": attrExpires, "#owner": attrOwner, "#lease": attrLease,
			},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":b": str(fmt.Sprintf("x#%02d", at.Bucket)), ":now": stamp(now),
			},
			ExclusiveStartKey: at.startKey(),
		}
		for {
			page, err := s.api.Query(ctx, in)
			if err != nil {
				return out, at.encode(), sanitize("query expired", err)
			}
			for _, item := range page.Items {
				m, k, err := decodeExpired(item)
				if err != nil {
					return out, at.encode(), err
				}
				out = append(out, m)
				at.Key = k
				if len(out) == limit {
					return out, at.encode(), nil
				}
			}
			if len(page.LastEvaluatedKey) == 0 {
				break
			}
			in.ExclusiveStartKey = page.LastEvaluatedKey
			at.Key = plainKey(page.LastEvaluatedKey)
		}
	}
	return out, "", nil
}

func plainKey(k map[string]types.AttributeValue) map[string]string {
	out := map[string]string{}
	for name, v := range k {
		switch v := v.(type) {
		case *types.AttributeValueMemberS:
			out[name] = v.Value
		case *types.AttributeValueMemberN:
			out[name] = v.Value
		}
	}
	return out
}

func decodeExpired(item map[string]types.AttributeValue) (store.Message, map[string]string, error) {
	var m store.Message
	var pk, xb string
	err := errors.Join(
		getString(item, attrPK, &pk, true),
		getString(item, attrSK, &m.ID, true),
		getString(item, attrBucket, &xb, true),
		getTime(item, attrExpires, &m.Expires),
	)
	recipient, ok := queueRecipient(pk)
	if !ok {
		err = errors.Join(err, errors.New("not a queue key"))
	}
	if err != nil {
		return store.Message{}, nil, fmt.Errorf("awsstore: decoding an expired message: %w", err)
	}
	m.Recipient = recipient
	return m, plainKey(map[string]types.AttributeValue{attrPK: item[attrPK], attrSK: item[attrSK], attrBucket: item[attrBucket], attrExpires: item[attrExpires]}), nil
}

// RecordSent implements store.Store. The record carries an empty map of
// the notifications accepted so far (MarkNotified).
func (s *Store) RecordSent(ctx context.Context, r store.Sent, now time.Time) error {
	recipients := make([]types.AttributeValue, len(r.Recipients))
	for i, v := range r.Recipients {
		recipients[i] = str(v)
	}
	item := map[string]types.AttributeValue{
		attrPK:           str(identityKey(sentPrefix, r.Sender)),
		attrSK:           str(r.MessageID),
		attrRecipients:   &types.AttributeValueMemberL{Value: recipients},
		attrDispositions: num(int64(r.Dispositions)),
		attrExpires:      stamp(r.Expires),
		attrTTL:          ttlOf(r.Expires),
		attrSeen:         &types.AttributeValueMemberM{Value: map[string]types.AttributeValue{}},
	}
	if r.Author != "" {
		item[attrAuthor] = str(r.Author)
	}
	_, err := s.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                 aws.String(s.table),
		Item:                      item,
		ConditionExpression:       aws.String("attribute_not_exists(#pk) OR #expires <= :now"),
		ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#expires": attrExpires},
		ExpressionAttributeValues: map[string]types.AttributeValue{":now": stamp(now)},
	})
	if errorCode(err) == conditionFailed {
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
		getString(out.Item, attrAuthor, &r.Author, false),
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

// MarkNotified implements store.Store with an entry of the record's seen
// map, set only when absent or set by the same attempt.
func (s *Store) MarkNotified(ctx context.Context, sender, messageID, mark, token string, now time.Time) error {
	k := key(identityKey(sentPrefix, sender), messageID)
	_, err := s.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.table),
		Key:                       k,
		UpdateExpression:          aws.String("SET #seen.#k = :token"),
		ConditionExpression:       aws.String("#expires > :now AND (attribute_not_exists(#seen.#k) OR #seen.#k = :token)"),
		ExpressionAttributeNames:  map[string]string{"#seen": attrSeen, "#k": mark, "#expires": attrExpires},
		ExpressionAttributeValues: map[string]types.AttributeValue{":token": str(token), ":now": stamp(now)},
	})
	if errorCode(err) == conditionFailed {
		item, err := s.current(ctx, "mark notified", k)
		if err != nil {
			return err
		}
		var expires time.Time
		if err := getTime(item, attrExpires, &expires); err != nil || !expires.After(now) {
			return fmt.Errorf("awsstore: mark notified: %w", store.ErrNotFound)
		}
		return fmt.Errorf("awsstore: mark notified: %w", store.ErrExists)
	}
	if err != nil {
		return sanitize("mark notified", err)
	}
	return nil
}

// UnmarkNotified implements store.Store.
func (s *Store) UnmarkNotified(ctx context.Context, sender, messageID, mark, token string) error {
	_, err := s.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.table),
		Key:                       key(identityKey(sentPrefix, sender), messageID),
		UpdateExpression:          aws.String("REMOVE #seen.#k"),
		ConditionExpression:       aws.String("#seen.#k = :token"),
		ExpressionAttributeNames:  map[string]string{"#seen": attrSeen, "#k": mark},
		ExpressionAttributeValues: map[string]types.AttributeValue{":token": str(token)},
	})
	if err != nil && errorCode(err) != conditionFailed {
		return sanitize("unmark notified", err)
	}
	return nil
}

func queueRecipient(pk string) (string, bool) {
	rest, ok := strings.CutPrefix(pk, queuePrefix)
	if !ok {
		return "", false
	}
	n, recipient, ok := strings.Cut(rest, "#")
	if !ok || n != strconv.Itoa(len(recipient)) {
		return "", false
	}
	return recipient, true
}

func decodeMessage(item map[string]types.AttributeValue) (store.Message, error) {
	var m store.Message
	var pk string
	var mode int64
	err := errors.Join(
		getString(item, attrPK, &pk, true),
		getString(item, attrSK, &m.ID, true),
		getString(item, attrSender, &m.Sender, true),
		getString(item, attrAuthor, &m.Author, false),
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
	recipient, ok := queueRecipient(pk)
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
