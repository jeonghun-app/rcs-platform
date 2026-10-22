package awsstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/content"
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
	attrGroup        = "group"
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
	attrMarkCount    = "marks"
	attrDateTime     = "datetime"
	attrSummary      = "summary"
	// The two fields of a seen entry: the token of the attempt that set
	// it, and the status the notification reported.
	attrMarkToken  = "t"
	attrMarkStatus = "s"
	attrCount      = "count"
	attrSize       = "size"
	attrRecounted  = "recounted_at"
	attrBytes      = "bytes"
	attrReached    = "reached_at"
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
	// reachedPrefix keys a recipient's reached marks (#605), in a
	// partition of their own, so that neither the queue's reads nor its
	// recounts meet them; reachedSK prefixes each task's.
	reachedPrefix = "r#"
	reachedSK     = "t#"
	senderSK      = "s#"
)

const conditionFailed = "ConditionalCheckFailedException"

// Store is a store.Store in the DynamoDB messages table.
type Store struct {
	api   DynamoAPI
	table string
	// groups is the groupchats table, which a fenced enqueue
	// (store.Message.Fence) checks the group's owner item in.
	groups string
}

// SetGroupsTable names the groupchats table, for fenced enqueues (#121).
func (s *Store) SetGroupsTable(table string) { s.groups = table }

// GroupsTable is the table SetGroupsTable named.
func (s *Store) GroupsTable() string { return s.groups }

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

// conflicted reports whether a write lost to a concurrent transaction on
// one of its items: an UpdateItem that met a transaction, or a transaction
// cancelled for another one. The SDK retries neither.
func conflicted(err error) bool {
	var conflict *types.TransactionConflictException
	if errors.As(err, &conflict) {
		return true
	}
	var tce *types.TransactionCanceledException
	if errors.As(err, &tce) {
		for _, r := range tce.CancellationReasons {
			if aws.ToString(r.Code) == "TransactionConflict" {
				return true
			}
		}
	}
	return false
}

// conflictAttempts bounds the tries of a write to a group's sent record,
// which a summary's removal (a transaction) and notifiers' marks (single
// updates) may hit at once.
const conflictAttempts = 3

// retryConflicts runs write until it does not lose to a concurrent
// transaction, conflictAttempts times at most with a short jittered pause
// between, and then reports store.ErrBusy.
func retryConflicts(ctx context.Context, op string, write func() error) error {
	for i := range conflictAttempts {
		err := write()
		if !conflicted(err) {
			return err
		}
		if i == conflictAttempts-1 {
			break
		}
		pause := time.Duration(10<<i)*time.Millisecond + rand.N(time.Duration(10<<i)*time.Millisecond)
		select {
		case <-time.After(pause):
		case <-ctx.Done():
			return sanitize(op, ctx.Err())
		}
	}
	return fmt.Errorf("awsstore: %s: %w", op, store.ErrBusy)
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
	var shares []string
	if share, ok := m.ShareKey(); ok {
		shares = append(shares, share)
	}
	if m.InGroupTotal() {
		shares = append(shares, store.GroupNotifications)
	}
	if m.InSummaryTotal() {
		shares = append(shares, store.GroupSummaries)
	}
	fixed, cerr := s.recount(ctx, m.Recipient, shares...)
	if cerr != nil || !fixed {
		return err
	}
	return s.enqueue(ctx, m, l)
}

func (s *Store) enqueue(ctx context.Context, m store.Message, l store.Limit) error {
	if m.CPIM.Len() > MaxCPIMSize {
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
		attrSummary:      &types.AttributeValueMemberBOOL{Value: m.Summary},
		attrSize:         num(m.Size()),
		attrEnqueued:     stamp(m.Enqueued),
		attrExpires:      stamp(m.Expires),
		attrTTL:          ttlOf(ttl),
	}
	if !m.Summary {
		// A summary has no body of its own. The Bytes of an empty Body are
		// nil, which the SDK would write as null: an empty CPIM, nil or
		// not, goes out as an empty binary. Before #547 a nil one went out
		// as null.
		cpim := m.CPIM.Bytes()
		if cpim == nil {
			cpim = []byte{}
		}
		item[attrCPIM] = &types.AttributeValueMemberB{Value: cpim}
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
	if share, ok := m.ShareKey(); ok {
		items = append(items, types.TransactWriteItem{Update: s.sizeUpdate(senderSizeKey(m.Recipient, share), 1, m.Size(), l.SenderCount, l.SenderBytes, ttl)})
	}
	if m.InGroupTotal() {
		items = append(items, types.TransactWriteItem{Update: s.sizeUpdate(senderSizeKey(m.Recipient, store.GroupNotifications), 1, m.Size(), l.GroupCount, l.GroupBytes, ttl)})
	}
	if m.InSummaryTotal() {
		items = append(items, types.TransactWriteItem{Update: s.sizeUpdate(senderSizeKey(m.Recipient, store.GroupSummaries), 1, m.Size(), l.SummaryCount, l.SummaryBytes, ttl)})
	}
	if f := m.Fence; f != nil {
		if s.groups == "" {
			return errors.New("awsstore: enqueue: a fence without the groups table")
		}
		// Last: the owner item of the group, in the groupchats table, as
		// every write of the group checks it (Groups.fence).
		items = append(items, types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
			TableName:                aws.String(s.groups),
			Key:                      ownerKey(f.Group),
			ConditionExpression:      aws.String(fenceCondition),
			ExpressionAttributeNames: map[string]string{"#task": attrTask, "#epoch": attrEpoch},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":task": str(f.Task), ":epoch": num(f.Epoch),
			},
		}})
	}
	_, err := s.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	if failed, ok := canceled(err); ok {
		if m.Fence != nil && len(failed) == len(items) && failed[len(failed)-1] {
			return fmt.Errorf("awsstore: enqueue: %w", store.ErrNotOwner)
		}
		if m.Fence != nil && len(failed) == len(items) {
			failed = failed[:len(failed)-1]
		}
		switch {
		case len(failed) > 0 && failed[0]:
			return fmt.Errorf("awsstore: enqueue: %w", store.ErrExists)
		case len(failed) > 1 && failed[1]:
			return fmt.Errorf("awsstore: enqueue: %w", store.ErrQueueFull)
		case slices.Contains(failed[min(2, len(failed)):], true):
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

// sharesOf are the shares a projected queue item counts against: its
// Message.ShareKey, and GroupNotifications for a group notification.
func sharesOf(item map[string]types.AttributeValue) []string {
	m := projected(item)
	var out []string
	if k, ok := m.ShareKey(); ok {
		out = append(out, k)
	}
	if m.InGroupTotal() {
		out = append(out, store.GroupNotifications)
	}
	if m.InSummaryTotal() {
		out = append(out, store.GroupSummaries)
	}
	return out
}

// projected is what a recount projects of a queue item.
func projected(item map[string]types.AttributeValue) store.Message {
	var m store.Message
	var mode int64
	_ = getString(item, attrSender, &m.Sender, false)
	_ = getString(item, attrAuthor, &m.Author, false)
	_ = getNum(item, attrMode, &mode)
	if b, ok := item[attrNotification].(*types.AttributeValueMemberBOOL); ok {
		m.Notification = b.Value
	}
	if b, ok := item[attrSummary].(*types.AttributeValueMemberBOOL); ok {
		m.Summary = b.Value
	}
	m.Mode = store.Mode(mode)
	return m
}

// recount counts recipient's queue, and what each of shares holds of it
// (Message.ShareKey, store.GroupNotifications), and sets any size item that
// says more to what is there. It reports whether it corrected one. Each
// correction is conditional on the size item being unchanged since it was
// read, before the queue was: a size that moved meanwhile reflects an
// enqueue or removal the count may have missed.
func (s *Store) recount(ctx context.Context, recipient string, shares ...string) (bool, error) {
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
	type counted struct {
		k        map[string]types.AttributeValue
		was, now size
	}
	all := []*counted{{k: queueSizeKey(recipient)}}
	byShare := map[string]*counted{}
	for _, share := range shares {
		c := &counted{k: senderSizeKey(recipient, share)}
		all, byShare[share] = append(all, c), c
	}
	for _, c := range all {
		was, err := read(c.k)
		if err != nil {
			return false, err
		}
		c.was = was
	}
	in := &dynamodb.QueryInput{
		TableName:              aws.String(s.table),
		ConsistentRead:         aws.Bool(true),
		KeyConditionExpression: aws.String("#pk = :pk"),
		ProjectionExpression:   aws.String("#sender, #author, #mode, #size, #notification, #summary"),
		ExpressionAttributeNames: map[string]string{
			"#pk": attrPK, "#sender": attrSender, "#author": attrAuthor, "#mode": attrMode, "#size": attrSize, "#notification": attrNotification,
			"#summary": attrSummary,
		},
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
			all[0].now.count, all[0].now.bytes = all[0].now.count+1, all[0].now.bytes+n
			for _, k := range sharesOf(item) {
				if c := byShare[k]; c != nil {
					c.now.count, c.now.bytes = c.now.count+1, c.now.bytes+n
				}
			}
		}
		if len(page.LastEvaluatedKey) == 0 {
			break
		}
		in.ExclusiveStartKey = page.LastEvaluatedKey
	}
	fixed := false
	for _, c := range all {
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
	if share, ok := m.ShareKey(); ok {
		items = append(items, types.TransactWriteItem{Update: s.sizeUpdate(senderSizeKey(m.Recipient, share), -1, -m.Size(), 0, 0, time.Time{})})
	}
	if m.InGroupTotal() {
		items = append(items, types.TransactWriteItem{Update: s.sizeUpdate(senderSizeKey(m.Recipient, store.GroupNotifications), -1, -m.Size(), 0, 0, time.Time{})})
	}
	if m.InSummaryTotal() {
		items = append(items, types.TransactWriteItem{Update: s.sizeUpdate(senderSizeKey(m.Recipient, store.GroupSummaries), -1, -m.Size(), 0, 0, time.Time{})})
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

// RemoveSummary implements store.Store: Remove's transaction with a
// condition check that the sent record's mark count is unchanged, or the
// record gone.
func (s *Store) RemoveSummary(ctx context.Context, m store.Message, owner string, marks int64) error {
	return retryConflicts(ctx, "remove summary", func() error { return s.removeSummary(ctx, m, owner, marks) })
}

func (s *Store) removeSummary(ctx context.Context, m store.Message, owner string, marks int64) error {
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
		{Update: s.sizeUpdate(senderSizeKey(m.Recipient, store.GroupSummaries), -1, -m.Size(), 0, 0, time.Time{})},
		{ConditionCheck: &types.ConditionCheck{
			TableName:                 aws.String(s.table),
			Key:                       key(identityKey(sentPrefix, m.Sender), m.MessageID),
			ConditionExpression:       aws.String("attribute_not_exists(#pk) OR #marks = :marks"),
			ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#marks": attrMarkCount},
			ExpressionAttributeValues: map[string]types.AttributeValue{":marks": num(marks)},
		}},
	}
	_, err := s.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	if conflicted(err) {
		return err
	}
	if failed, ok := canceled(err); ok {
		switch {
		case len(failed) > 0 && failed[0]:
			_, err := s.current(ctx, "remove summary", k)
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			return fmt.Errorf("awsstore: remove summary: %w", store.ErrConflict)
		case len(failed) > 3 && failed[3]:
			return fmt.Errorf("awsstore: remove summary: %w", store.ErrMarksChanged)
		}
	}
	if err != nil {
		return sanitize("remove summary", err)
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
		attrMarkCount:    num(0),
	}
	if r.DateTime != "" {
		item[attrDateTime] = str(r.DateTime)
	}
	if r.Author != "" {
		item[attrAuthor] = str(r.Author)
	}
	if r.Group != "" {
		item[attrGroup] = str(r.Group)
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
		getString(out.Item, attrGroup, &r.Group, false),
		getString(out.Item, attrDateTime, &r.DateTime, false),
		getNum(out.Item, attrMarkCount, &r.MarkCount),
	)
	if seen, ok := out.Item[attrSeen].(*types.AttributeValueMemberM); ok {
		r.Marks = make(map[string]string, len(seen.Value))
		for k, v := range seen.Value {
			var status string
			if e, ok := v.(*types.AttributeValueMemberM); ok {
				err = errors.Join(err, getString(e.Value, attrMarkStatus, &status, false))
			} else {
				err = errors.Join(err, errors.New("seen entry is not a map"))
			}
			r.Marks[k] = status
		}
	}
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
// map, set only when absent, and a count of the entries ever set. The
// count makes a repeat unsafe to apply again, so a refusal reads the entry
// back: the same token is the attempt's own, landed already.
func (s *Store) MarkNotified(ctx context.Context, sender, messageID, mark, status, token string, now time.Time) error {
	return retryConflicts(ctx, "mark notified", func() error { return s.markNotified(ctx, sender, messageID, mark, status, token, now) })
}

func (s *Store) markNotified(ctx context.Context, sender, messageID, mark, status, token string, now time.Time) error {
	k := key(identityKey(sentPrefix, sender), messageID)
	_, err := s.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.table),
		Key:                 k,
		UpdateExpression:    aws.String("SET #seen.#k = :entry ADD #marks :one"),
		ConditionExpression: aws.String("#expires > :now AND attribute_not_exists(#seen.#k)"),
		ExpressionAttributeNames: map[string]string{
			"#seen": attrSeen, "#k": mark, "#expires": attrExpires, "#marks": attrMarkCount,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":entry": &types.AttributeValueMemberM{Value: map[string]types.AttributeValue{attrMarkToken: str(token), attrMarkStatus: str(status)}},
			":one":   num(1), ":now": stamp(now),
		},
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
		if seen, ok := item[attrSeen].(*types.AttributeValueMemberM); ok {
			if e, ok := seen.Value[mark].(*types.AttributeValueMemberM); ok {
				var t string
				if getString(e.Value, attrMarkToken, &t, true) == nil && t == token {
					return nil
				}
			}
		}
		return fmt.Errorf("awsstore: mark notified: %w", store.ErrExists)
	}
	if conflicted(err) {
		return err
	}
	if err != nil {
		return sanitize("mark notified", err)
	}
	return nil
}

// UnmarkNotified implements store.Store. It leaves the count, which only
// grows.
func (s *Store) UnmarkNotified(ctx context.Context, sender, messageID, mark, token string) error {
	_, err := s.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.table),
		Key:                       key(identityKey(sentPrefix, sender), messageID),
		UpdateExpression:          aws.String("REMOVE #seen.#k"),
		ConditionExpression:       aws.String("#seen.#k.#t = :token"),
		ExpressionAttributeNames:  map[string]string{"#seen": attrSeen, "#k": mark, "#t": attrMarkToken},
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
	if b, ok := item[attrNotification].(*types.AttributeValueMemberBOOL); ok {
		m.Notification = b.Value
	}
	if b, ok := item[attrSummary].(*types.AttributeValueMemberBOOL); ok {
		m.Summary = b.Value
	}
	if b, ok := item[attrCPIM].(*types.AttributeValueMemberB); ok {
		m.CPIM = content.BodyOf(b.Value)
	} else if !m.Summary {
		err = errors.Join(err, errors.New("cpim missing"))
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

// MarkReached implements store.Store. A task's mark is an item of its
// own, put over its last one.
func (s *Store) MarkReached(ctx context.Context, recipient, task string, at, expires time.Time) error {
	item := key(identityKey(reachedPrefix, recipient), identityKey(reachedSK, task))
	item[attrTask] = str(task)
	item[attrReached] = stamp(at)
	item[attrExpires] = stamp(expires)
	item[attrTTL] = ttlOf(expires)
	if _, err := s.api.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(s.table), Item: item}); err != nil {
		return sanitize("mark reached", err)
	}
	return nil
}

// Reached implements store.Store: a consistent query of the recipient's
// marks, one item per task that delivered to it lately.
func (s *Store) Reached(ctx context.Context, recipient string, now time.Time) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	in := &dynamodb.QueryInput{
		TableName:                 aws.String(s.table),
		KeyConditionExpression:    aws.String("#pk = :pk"),
		ExpressionAttributeNames:  map[string]string{"#pk": attrPK},
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": str(identityKey(reachedPrefix, recipient))},
		ConsistentRead:            aws.Bool(true),
	}
	for {
		page, err := s.api.Query(ctx, in)
		if err != nil {
			return nil, sanitize("query reached", err)
		}
		for _, item := range page.Items {
			var task string
			var at, expires time.Time
			if err := errors.Join(getString(item, attrTask, &task, true), getTime(item, attrReached, &at), getTime(item, attrExpires, &expires)); err != nil {
				return nil, fmt.Errorf("awsstore: query reached: %w", err)
			}
			if expires.After(now) {
				out[task] = at
			}
		}
		if len(page.LastEvaluatedKey) == 0 {
			return out, nil
		}
		in.ExclusiveStartKey = page.LastEvaluatedKey
	}
}
