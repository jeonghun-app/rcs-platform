package awsstore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
)

// Attribute names of maap-counters, besides ttl and writer.
const (
	attrFull  = "full"
	attrCount = "n"
)

// Counters is a store.Counters in the maap-counters table: partition key
// pk and sort key sk, both strings, TTL on ttl.
//
//	pk c#<chatbot ID>  sk m#<name>         a chatbot's bucket: full (Unix nanoseconds), ttl, writer
//	pk c#<chatbot ID>  sk d#<day>#<name>   a chatbot's count of a UTC day (YYYY-MM-DD): n, ttl, writer
//	pk n#<name>        sk m, d#<day>       a counter of all chatbots, the same
//
// A bucket is the time it is full again (store.TakeBucket), so a take is
// one conditional update, never a read and a write: concurrent takes do
// not lose updates, and DynamoDB orders them. A chatbot's counters are
// its partition, as in maap-requests; counters of all chatbots spread
// over partitions of their own.
type Counters struct {
	api   TableAPI
	table string
	// pageSize bounds DeleteChatbot's query pages, for tests.
	pageSize int32
}

var _ store.Counters = (*Counters)(nil)

// NewCounters returns the counters table over api.
func NewCounters(api TableAPI, table string) *Counters { return &Counters{api: api, table: table} }

func counterKey(c store.Counter, kind string) map[string]types.AttributeValue {
	if c.Chatbot == "" {
		return key("n#"+c.Name, kind)
	}
	return key("c#"+c.Chatbot, kind+"#"+c.Name)
}

// takeAttempts bounds the updates of one take. With one now per take, a
// take that finds the bucket busy then finds it busy again, or idle only
// if a deletion came between, so the bound is met only by deletions
// racing the take: a store failure then, never a refusal.
const takeAttempts = 4

// TakeMinute implements store.Counters. The update is of one of two
// kinds, chosen by what DynamoDB answered the last: an idle bucket
// (absent, or full by now) is set full at now plus an interval; a busy
// one, full after now, gets an interval more if it holds a token. The
// first try is the idle kind, which a bucket under its rate mostly is,
// so a take costs one write, two at worst. An update the SDK sent again
// after it took effect finds its own writer token: a busy update is also
// conditional on the token, so that it never adds twice.
func (s *Counters) TakeMinute(ctx context.Context, c store.Counter, perMinute int64, now time.Time) (store.Take, error) {
	if err := store.CheckCounter(c, perMinute); err != nil {
		return store.Take{}, err
	}
	interval, burst := store.Bucket(perMinute)
	at, writer := now.UnixNano(), rand.Text()
	edge := at + (burst-1)*int64(interval)
	// The item may go once the bucket is full again, at edge+interval at
	// the latest: an absent bucket is a full one.
	ttl := (edge+int64(interval))/int64(time.Second) + 1
	values := map[string]types.AttributeValue{":now": num(at), ":ttl": num(ttl), ":w": str(writer)}
	names := map[string]string{"#full": attrFull, "#ttl": attrTTL, "#w": attrWriter}
	busy := false
	for range takeAttempts {
		in := &dynamodb.UpdateItemInput{
			TableName: aws.String(s.table), Key: counterKey(c, "m"),
			UpdateExpression:                    aws.String("SET #full = :next, #ttl = :ttl, #w = :w"),
			ConditionExpression:                 aws.String("attribute_not_exists(#full) OR #full <= :now"),
			ExpressionAttributeNames:            names,
			ExpressionAttributeValues:           map[string]types.AttributeValue{":next": num(at + int64(interval))},
			ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
		}
		if busy {
			in.UpdateExpression = aws.String("SET #full = #full + :i, #ttl = :ttl, #w = :w")
			in.ConditionExpression = aws.String("#full > :now AND #full <= :edge AND (attribute_not_exists(#w) OR #w <> :w)")
			in.ExpressionAttributeValues = map[string]types.AttributeValue{":i": num(int64(interval)), ":edge": num(edge)}
		}
		for k, v := range values {
			in.ExpressionAttributeValues[k] = v
		}
		_, err := s.api.UpdateItem(ctx, in)
		var ccf *types.ConditionalCheckFailedException
		if !errors.As(err, &ccf) {
			if err != nil {
				return store.Take{}, sanitize("take from bucket", err)
			}
			return store.Take{Taken: true}, nil
		}
		if sv(ccf.Item[attrWriter]) == writer {
			return store.Take{Taken: true}, nil // the SDK sent again an update that had taken effect
		}
		full, ok := number(ccf.Item, attrFull)
		switch {
		case len(ccf.Item) > 0 && !ok:
			return store.Take{}, fmt.Errorf("%w: a damaged bucket", store.ErrInvalid)
		case full > edge:
			return store.Take{Wait: time.Duration(full - edge)}, nil
		}
		busy = ok && full > at
	}
	return store.Take{}, errors.New("awsstore: take from bucket: the bucket kept being deleted")
}

// TakeDay implements store.Counters: one update, adding one on the
// condition that the count is under the limit and that this take's own
// token is not there yet, which a send again after the update took effect
// finds.
func (s *Counters) TakeDay(ctx context.Context, c store.Counter, perDay int64, now time.Time) (store.Take, error) {
	if err := store.CheckCounter(c, perDay); err != nil {
		return store.Take{}, err
	}
	end, writer := store.DayEnd(now), rand.Text()
	_, err := s.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.table), Key: counterKey(c, "d#"+end.AddDate(0, 0, -1).Format(time.DateOnly)),
		UpdateExpression:         aws.String("SET #ttl = :ttl, #w = :w ADD #n :one"),
		ConditionExpression:      aws.String("(attribute_not_exists(#n) OR #n < :limit) AND (attribute_not_exists(#w) OR #w <> :w)"),
		ExpressionAttributeNames: map[string]string{"#n": attrCount, "#ttl": attrTTL, "#w": attrWriter},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			// The item outlives its day by an hour, for tasks whose clocks
			// are behind.
			":one": num(1), ":limit": num(perDay), ":ttl": num(end.Add(time.Hour).Unix()), ":w": str(writer),
		},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	var ccf *types.ConditionalCheckFailedException
	switch {
	case errors.As(err, &ccf) && sv(ccf.Item[attrWriter]) == writer:
		return store.Take{Taken: true}, nil // the SDK sent again an update that had taken effect
	case errors.As(err, &ccf):
		if _, ok := number(ccf.Item, attrCount); !ok {
			return store.Take{}, fmt.Errorf("%w: a damaged day count", store.ErrInvalid)
		}
		return store.Take{Wait: end.Sub(now)}, nil
	case err != nil:
		return store.Take{}, sanitize("take from day count", err)
	}
	return store.Take{Taken: true}, nil
}

// GiveBackMinute implements store.Counters: one update moving full an
// interval earlier, on the condition that it is after at, so that a full
// bucket (full by at) gets nothing; full may then fall before now, which
// is a full bucket too. The writer token makes a give-back the SDK sent
// again return one token only.
func (s *Counters) GiveBackMinute(ctx context.Context, c store.Counter, perMinute int64, at time.Time) error {
	if err := store.CheckCounter(c, perMinute); err != nil {
		return err
	}
	interval, _ := store.Bucket(perMinute)
	return s.giveBack(ctx, counterKey(c, "m"), "SET #a = #a - :step, #w = :w", attrFull,
		map[string]types.AttributeValue{":step": num(int64(interval)), ":floor": num(at.UnixNano())})
}

// GiveBackDay implements store.Counters: one update taking one from the
// count of at's day while it is above zero.
func (s *Counters) GiveBackDay(ctx context.Context, c store.Counter, at time.Time) error {
	if err := store.CheckCounter(c, 1); err != nil {
		return err
	}
	return s.giveBack(ctx, counterKey(c, "d#"+store.DayEnd(at).AddDate(0, 0, -1).Format(time.DateOnly)), "SET #w = :w ADD #a :step", attrCount,
		map[string]types.AttributeValue{":step": num(-1), ":floor": num(0)})
}

// giveBack runs update on the item at key on the condition that its
// attribute is above :floor and that this call's token is not there yet.
// A failed condition is a bucket already full, a day already at zero, an
// item gone, or this call's own update sent again: nothing to do, all.
func (s *Counters) giveBack(ctx context.Context, k map[string]types.AttributeValue, update, attr string, values map[string]types.AttributeValue) error {
	values[":w"] = str(rand.Text())
	_, err := s.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.table), Key: k,
		UpdateExpression:          aws.String(update),
		ConditionExpression:       aws.String("#a > :floor AND (attribute_not_exists(#w) OR #w <> :w)"),
		ExpressionAttributeNames:  map[string]string{"#a": attr, "#w": attrWriter},
		ExpressionAttributeValues: values,
	})
	var ccf *types.ConditionalCheckFailedException
	if err != nil && !errors.As(err, &ccf) {
		return sanitize("give back", err)
	}
	return nil
}

// DeleteChatbot implements store.ChatbotDeleter.
func (s *Counters) DeleteChatbot(ctx context.Context, chatbotID string) error {
	return deletePartition(ctx, s.api, s.table, "c#"+chatbotID, s.pageSize)
}

// Ready checks the table for /readyz, as the registry's Ready does.
func (s *Counters) Ready(ctx context.Context) error { return ready(ctx, s.api, s.table) }
