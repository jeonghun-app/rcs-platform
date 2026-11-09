package awsstore

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
)

// Subscribers is a store.Subscribers in the maap-subscribers table (see the
// package documentation): an alias is a subscriber's item, which names the
// alias ID, and the chatbot's item, which names the subscriber, written
// and deleted together in one transaction.
type Subscribers struct {
	api   DynamoAPI
	table string
	// pageSize bounds DeleteChatbot's query pages, for tests.
	pageSize int32
	// pace is the time between DeleteChatbot's transactions.
	pace time.Duration
}

// deletePace spaces a chatbot's alias deletions: at most 100 a second,
// about 200 write units on the chatbot's partition and 400 on the table,
// so that a large deletion does not throttle the lookups and writes of
// other chatbots (#753 review). A 20 s request (#709's deleteBudget)
// deletes about 2,000.
const deletePace = 10 * time.Millisecond

var _ store.Subscribers = (*Subscribers)(nil)

// NewSubscribers returns the table over api.
func NewSubscribers(api DynamoAPI, table string) *Subscribers {
	return &Subscribers{api: api, table: table, pace: deletePace}
}

// Subscribers returns the subscribers' table over r's client.
func (r *Registry) Subscribers(table string) *Subscribers { return NewSubscribers(r.api, table) }

// Ready checks the table as Registry.Ready does its own.
func (s *Subscribers) Ready(ctx context.Context) error { return NewRegistry(s.api, s.table).Ready(ctx) }

// Attribute names of alias items.
const (
	attrAlias      = "alias"
	attrSubscriber = "subscriber"
	attrAnonymous  = "anonymous"
	// attrExpires is the table's TTL attribute: when the alias expires
	// unless used again, in Unix seconds.
	attrExpires = "expires"
)

// subscriberKey is the subscriber's item of an alias: its sort key puts
// the anonymity before the chatbot ID, which holds no "#".
func subscriberKey(a store.Alias) map[string]types.AttributeValue {
	anonymous := "0"
	if a.Anonymous {
		anonymous = "1"
	}
	return key("s#"+a.Subscriber, "a#"+anonymous+"#"+a.Chatbot)
}

func chatbotAliasKey(chatbotID, aliasID string) map[string]types.AttributeValue {
	return key("c#"+chatbotID, "a#"+aliasID)
}

// times sets a's use and expiry on item.
func times(item map[string]types.AttributeValue, a store.Alias) map[string]types.AttributeValue {
	item[attrCreated], item[attrUsed] = num(a.Created.Unix()), num(a.LastUsed.Unix())
	item[attrExpires] = num(a.LastUsed.Add(store.AliasLifetime).Unix())
	return item
}

// Alias implements store.Subscribers. An expired alias is replaced on the
// condition that its item still holds the alias and use read. A write
// that fails its condition reads again: what it finds, another call's
// alias or the one this call's earlier send stored before its answer was
// lost, is the answer.
func (s *Subscribers) Alias(ctx context.Context, want store.Alias) (store.Alias, error) {
	if !store.ValidAliasID(want.ID) || !store.ValidID(want.Chatbot) || !store.ValidSubscriber(want.Subscriber) {
		return store.Alias{}, fmt.Errorf("%w: a malformed alias", store.ErrInvalid)
	}
	want.Created = store.Seconds(want.Created)
	want.LastUsed = want.Created
	absent, names := aws.String("attribute_not_exists(#pk)"), map[string]string{"#pk": attrPK}
	for attempt := 0; attempt < conflictAttempts; attempt++ {
		out, err := s.api.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(s.table), Key: subscriberKey(want), ConsistentRead: aws.Bool(true)})
		if err != nil {
			return store.Alias{}, sanitize("get alias", err)
		}
		var cur store.Alias
		if len(out.Item) != 0 {
			if cur, err = decodeAlias(want, out.Item); err != nil {
				return store.Alias{}, err
			}
			if !cur.Expired(want.Created) {
				return cur, nil
			}
		}
		mine := times(subscriberKey(want), want)
		mine[attrAlias] = str(want.ID)
		theirs := times(chatbotAliasKey(want.Chatbot, want.ID), want)
		theirs[attrSubscriber], theirs[attrAnonymous] = str(want.Subscriber), &types.AttributeValueMemberBOOL{Value: want.Anonymous}
		put := &types.Put{TableName: aws.String(s.table), Item: mine, ConditionExpression: absent, ExpressionAttributeNames: names}
		items := []types.TransactWriteItem{
			{Put: put},
			{Put: &types.Put{TableName: aws.String(s.table), Item: theirs, ConditionExpression: absent, ExpressionAttributeNames: names}},
		}
		if cur.ID != "" {
			put.ConditionExpression = aws.String("#alias = :alias AND #used = :used")
			put.ExpressionAttributeNames = map[string]string{"#alias": attrAlias, "#used": attrUsed}
			put.ExpressionAttributeValues = map[string]types.AttributeValue{":alias": str(cur.ID), ":used": num(cur.LastUsed.Unix())}
			items = append(items, types.TransactWriteItem{Delete: &types.Delete{
				TableName: aws.String(s.table), Key: chatbotAliasKey(cur.Chatbot, cur.ID),
			}})
		}
		_, err = s.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
			ClientRequestToken: aws.String(rand.Text()), TransactItems: items,
		})
		reasons := cancelled(err)
		switch {
		case len(reasons) >= 2 && failed(reasons[0]), raced(err):
			// An alias stored or used meanwhile: read it.
		case len(reasons) >= 2 && failed(reasons[1]):
			return store.Alias{}, fmt.Errorf("%w: the alias ID is taken", store.ErrInvalid)
		case err != nil:
			return store.Alias{}, sanitize("store alias", err)
		default:
			return want, nil
		}
	}
	return store.Alias{}, fmt.Errorf("awsstore: store alias: %w", store.ErrConflict)
}

// decodeAlias reads the alias of kind's chatbot, subscriber and anonymity
// from the subscriber's item, which names the alias ID.
func decodeAlias(kind store.Alias, item map[string]types.AttributeValue) (store.Alias, error) {
	kind.ID = sv(item[attrAlias])
	return decodeTimes(kind, item)
}

// decodeTimes reads a's creation and last use from item.
func decodeTimes(a store.Alias, item map[string]types.AttributeValue) (store.Alias, error) {
	created, err1 := strconv.ParseInt(sv(item[attrCreated]), 10, 64)
	used, err2 := strconv.ParseInt(sv(item[attrUsed]), 10, 64)
	if err1 != nil || err2 != nil || !store.ValidAliasID(a.ID) || !store.ValidSubscriber(a.Subscriber) {
		return store.Alias{}, fmt.Errorf("%w: a damaged alias", store.ErrInvalid)
	}
	a.Created, a.LastUsed = time.Unix(created, 0).UTC(), time.Unix(used, 0).UTC()
	return a, nil
}

// Resolve implements store.Subscribers.
func (s *Subscribers) Resolve(ctx context.Context, chatbotID, aliasID string, now time.Time) (store.Alias, error) {
	notFound := fmt.Errorf("awsstore: resolve alias: %w", store.ErrNotFound)
	if !store.ValidAliasID(aliasID) || !store.ValidID(chatbotID) {
		return store.Alias{}, notFound
	}
	out, err := s.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.table), Key: chatbotAliasKey(chatbotID, aliasID), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return store.Alias{}, sanitize("resolve alias", err)
	}
	if len(out.Item) == 0 {
		return store.Alias{}, notFound
	}
	a, err := decodeChatbotAlias(chatbotID, aliasID, out.Item)
	switch {
	case err != nil:
		return store.Alias{}, err
	case a.Expired(now):
		return store.Alias{}, notFound
	}
	return a, nil
}

// decodeChatbotAlias reads the alias with the ID from the chatbot's item,
// which names the subscriber.
func decodeChatbotAlias(chatbotID, aliasID string, item map[string]types.AttributeValue) (store.Alias, error) {
	anonymous, ok := item[attrAnonymous].(*types.AttributeValueMemberBOOL)
	if !ok {
		return store.Alias{}, fmt.Errorf("%w: a damaged alias", store.ErrInvalid)
	}
	return decodeTimes(store.Alias{ID: aliasID, Chatbot: chatbotID, Subscriber: sv(item[attrSubscriber]), Anonymous: anonymous.Value}, item)
}

// Used implements store.Subscribers. Both items move together, each on
// the condition that it is still a's and was used before at.
func (s *Subscribers) Used(ctx context.Context, a store.Alias, at time.Time) error {
	if !store.ValidAliasID(a.ID) || !store.ValidID(a.Chatbot) || !store.ValidSubscriber(a.Subscriber) {
		return nil
	}
	update := func(k map[string]types.AttributeValue, owner, value string) types.TransactWriteItem {
		return types.TransactWriteItem{Update: &types.Update{
			TableName: aws.String(s.table), Key: k,
			UpdateExpression: aws.String("SET #used = :at, #expires = :expires"),
			// Not before the use stored, nor once the alias expired: a
			// late write never brings an expired alias back.
			ConditionExpression:      aws.String("#owner = :owner AND #used < :at AND #used > :expired"),
			ExpressionAttributeNames: map[string]string{"#used": attrUsed, "#expires": attrExpires, "#owner": owner},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":at": num(at.Unix()), ":expires": num(at.Add(store.AliasLifetime).Unix()), ":owner": str(value),
				":expired": num(at.Add(-store.AliasLifetime).Unix()),
			},
		}}
	}
	_, err := s.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		ClientRequestToken: aws.String(rand.Text()),
		TransactItems: []types.TransactWriteItem{
			update(subscriberKey(a), attrAlias, a.ID), update(chatbotAliasKey(a.Chatbot, a.ID), attrSubscriber, a.Subscriber),
		},
	})
	if err != nil && !raced(err) && !slices.ContainsFunc(cancelled(err), failed) {
		return sanitize("record alias use", err)
	}
	// Gone, replaced, used later, or used by another task at the same time.
	return nil
}

// DeleteChatbot implements store.ChatbotDeleter. Each of the chatbot's
// items goes with its subscriber's item, whose key names the chatbot too:
// that item is the chatbot's whatever alias it names. A damaged one goes
// alone, logged without its value. The transactions are spaced by pace;
// when ctx ends first, it stops between two of them and logs how many it
// deleted, and a later call deletes the rest.
func (s *Subscribers) DeleteChatbot(ctx context.Context, chatbotID string) error {
	deleted := 0
	err := s.deleteAliases(ctx, chatbotID, &deleted)
	if err != nil && ctx.Err() != nil {
		slog.Info("awsstore: a chatbot's alias deletion stopped before the end",
			slog.String("chatbot", chatbotID), slog.Int("aliases_deleted", deleted))
	}
	return err
}

func (s *Subscribers) deleteAliases(ctx context.Context, chatbotID string, deleted *int) error {
	in := &dynamodb.QueryInput{
		TableName: aws.String(s.table), ConsistentRead: aws.Bool(true),
		KeyConditionExpression:    aws.String("#pk = :pk AND begins_with(#sk, :prefix)"),
		ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#sk": attrSK},
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": str("c#" + chatbotID), ":prefix": str("a#")},
	}
	if s.pageSize > 0 {
		in.Limit = aws.Int32(s.pageSize)
	}
	for {
		out, err := s.api.Query(ctx, in)
		if err != nil {
			return sanitize("query chatbot aliases", err)
		}
		for _, it := range out.Items {
			if err := pause(ctx, *deleted, s.pace); err != nil {
				return fmt.Errorf("awsstore: delete chatbot aliases: %w", err)
			}
			if err := s.deleteAlias(ctx, chatbotID, it); err != nil {
				return err
			}
			*deleted++
		}
		if len(out.LastEvaluatedKey) == 0 {
			return nil
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
}

func (s *Subscribers) deleteAlias(ctx context.Context, chatbotID string, item map[string]types.AttributeValue) error {
	mine := key(sv(item[attrPK]), sv(item[attrSK]))
	aliasID := sv(item[attrSK])[len("a#"):]
	a, err := decodeChatbotAlias(chatbotID, aliasID, item)
	if err != nil {
		slog.Warn("awsstore: a damaged alias item was deleted alone", slog.String("chatbot", chatbotID))
		if _, err := s.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(s.table), Key: mine}); err != nil {
			return sanitize("delete alias", err)
		}
		return nil
	}
	for attempt := 0; ; attempt++ {
		_, err = s.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
			ClientRequestToken: aws.String(rand.Text()),
			TransactItems: []types.TransactWriteItem{
				{Delete: &types.Delete{TableName: aws.String(s.table), Key: mine}},
				{Delete: &types.Delete{TableName: aws.String(s.table), Key: subscriberKey(a)}},
			},
		})
		switch {
		case raced(err) && attempt < conflictAttempts-1:
			continue // a use or a replacement at the same time
		case err != nil:
			return sanitize("delete alias", err)
		}
		return nil
	}
}
