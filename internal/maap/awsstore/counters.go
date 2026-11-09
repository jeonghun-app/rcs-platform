package awsstore

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

// Attribute names of maap-counters, besides ttl and writer.
const (
	attrFull     = "full"
	attrReturned = "returned"
	attrCount    = "n"
	skCounter    = "c"
)

// Counters is a store.Counters in the maap-counters table: partition key
// pk and sort key sk, both strings, TTL on ttl. Every counter has a
// partition of its own (lead decision on #713, after the operations
// review of #751), so no chatbot's counters share a key, and the name is
// kept only as an HMAC, so that no subscriber identifier in it reaches a
// key, CloudTrail or Contributor Insights:
//
//	pk c#<chatbot ID>#m#<HMAC of the name>         sk c  a chatbot's bucket: full, returned (nanoseconds), ttl, writer
//	pk c#<chatbot ID>#d#<YYYY-MM-DD>#<HMAC>        sk c  a chatbot's count of a UTC day: n, ttl, writer
//	pk n#m#<HMAC>, n#d#<YYYY-MM-DD>#<HMAC>         sk c  the same, for a counter of all chatbots
//
// A bucket is the time it is full again (store.TakeBucket), so a take is
// one conditional update, never a read and a write: concurrent takes do
// not lose updates, and DynamoDB orders them. Counters are never deleted
// but by their TTL, a day and an hour at most: a deleted chatbot's ID is
// never registered again, so nothing reads them.
type Counters struct {
	api   TableAPI
	table string
	// nameKey keys the HMAC that stands for a counter's name.
	nameKey []byte
}

// NewCounters returns the counters table over api; key (RCS_PII_HMAC_KEY)
// keys the names, through a subkey of their own. Rotating it starts every
// counter again.
func NewCounters(api TableAPI, table string, key secret.Key) *Counters {
	sub := hmac.New(sha256.New, key.Reveal())
	sub.Write([]byte("maap-counters name"))
	return &Counters{api: api, table: table, nameKey: sub.Sum(nil)}
}

func (s *Counters) key(c store.Counter, kind string) map[string]types.AttributeValue {
	mac := hmac.New(sha256.New, s.nameKey)
	mac.Write([]byte(c.Name))
	name := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if c.Chatbot == "" {
		return key("n#"+kind+"#"+name, skCounter)
	}
	return key("c#"+c.Chatbot+"#"+kind+"#"+name, skCounter)
}

func dayKind(at time.Time) string {
	return "d#" + store.DayEnd(at).AddDate(0, 0, -1).Format(time.DateOnly)
}

// takeAttempts bounds the updates of one take, and of one give-back. With one now per take, a
// take that finds the bucket busy finds it busy again, unless a give-back
// or a deletion came between and made it idle: each attempt after the
// first follows another writer's success, so the bound is met only when
// others keep changing the bucket, and is then a store failure.
const takeAttempts = 64

// sendOnce sends a request without the SDK's retries, for a give-back:
// one sent again after another writer's update would return a token
// twice, which no condition can tell without a token per take on the item,
// which would grow it on a hot bucket (#751 review). One lost is not sent
// again, which counts the refused request: the safe side.
func sendOnce(o *dynamodb.Options) { o.RetryMaxAttempts = 1 }

// TakeMinute implements store.Counters. The update is of one of two
// kinds, chosen by what DynamoDB answered the last: an idle bucket
// (absent, or full by now) is set full at now plus an interval; a busy
// one, full after now, gets an interval more if it holds a token. The
// first try is the idle kind, which a bucket under its rate mostly is,
// so a take costs one write, two near the rate. An update the SDK sent
// again after it took effect finds its own writer token: a busy update is
// also conditional on the token, so that it never adds twice; a
// give-back leaves the token as it is.
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
			TableName: aws.String(s.table), Key: s.key(c, "m"),
			UpdateExpression:                    aws.String("SET #full = :next, #ttl = :ttl, #w = :w"),
			ConditionExpression:                 aws.String("attribute_not_exists(#full) OR #full <= :now"),
			ExpressionAttributeNames:            names,
			ExpressionAttributeValues:           map[string]types.AttributeValue{":next": num(at + int64(interval))},
			ReturnValues:                        types.ReturnValueAllNew,
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
		out, err := s.api.UpdateItem(ctx, in)
		var ccf *types.ConditionalCheckFailedException
		if !errors.As(err, &ccf) {
			if err != nil {
				return store.Take{}, sanitize("take from bucket", err)
			}
			return s.taken(out.Attributes, now)
		}
		if sv(ccf.Item[attrWriter]) == writer {
			return s.taken(ccf.Item, now) // the SDK sent again an update that had taken effect
		}
		full, ok := number(ccf.Item, attrFull)
		switch {
		case len(ccf.Item) > 0 && !ok:
			return store.Take{}, fmt.Errorf("%w: a damaged bucket", store.ErrInvalid)
		case full > edge:
			return store.Take{Wait: time.Duration(full - edge), At: now}, nil
		}
		busy = ok && full > at
	}
	return store.Take{}, errors.New("awsstore: take from bucket: the bucket kept changing")
}

func (s *Counters) taken(item map[string]types.AttributeValue, now time.Time) (store.Take, error) {
	full, okF := number(item, attrFull)
	returned, okR := number(item, attrReturned)
	if !okF || item[attrReturned] != nil && !okR {
		return store.Take{}, fmt.Errorf("%w: a damaged bucket", store.ErrInvalid)
	}
	return store.Take{Taken: true, At: now, Full: time.Unix(0, full), Returned: time.Duration(returned)}, nil
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
		TableName: aws.String(s.table), Key: s.key(c, dayKind(now)),
		UpdateExpression:         aws.String("SET #ttl = :ttl, #w = :w ADD #n :one"),
		ConditionExpression:      aws.String("(attribute_not_exists(#n) OR #n < :limit) AND (attribute_not_exists(#w) OR #w <> :w)"),
		ExpressionAttributeNames: map[string]string{"#n": attrCount, "#ttl": attrTTL, "#w": attrWriter},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			// The item outlives its day by an hour, for tasks whose clocks
			// are behind and give-backs of its last takes.
			":one": num(1), ":limit": num(perDay), ":ttl": num(end.Add(time.Hour).Unix()), ":w": str(writer),
		},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	var ccf *types.ConditionalCheckFailedException
	switch {
	case errors.As(err, &ccf) && sv(ccf.Item[attrWriter]) == writer:
		return store.Take{Taken: true, At: now}, nil // the SDK sent again an update that had taken effect
	case errors.As(err, &ccf):
		if _, ok := number(ccf.Item, attrCount); !ok {
			return store.Take{}, fmt.Errorf("%w: a damaged day count", store.ErrInvalid)
		}
		return store.Take{Wait: end.Sub(now), At: now}, nil
	case err != nil:
		return store.Take{}, sanitize("take from day count", err)
	}
	return store.Take{Taken: true, At: now}, nil
}

// GiveBackMinute implements store.Counters: a strongly consistent read of
// the bucket, then an update, sent once, to what store.GiveBackBucket
// says, on the condition that full and returned are still the ones read;
// another writer between them makes it read again.
func (s *Counters) GiveBackMinute(ctx context.Context, c store.Counter, perMinute int64, taken store.Take, now time.Time) error {
	if err := store.CheckCounter(c, perMinute); err != nil || !taken.Taken {
		return err
	}
	k := s.key(c, "m")
	names := map[string]string{"#full": attrFull, "#r": attrReturned}
	for range takeAttempts {
		out, err := s.api.GetItem(ctx, &dynamodb.GetItemInput{
			TableName: aws.String(s.table), Key: k, ConsistentRead: aws.Bool(true),
			ProjectionExpression: aws.String("#full, #r"), ExpressionAttributeNames: names,
		})
		if err != nil {
			return sanitize("give back", err)
		}
		full, okF := number(out.Item, attrFull)
		returned, okR := number(out.Item, attrReturned)
		if !okF || out.Item[attrReturned] != nil && !okR {
			return nil // absent, a full bucket; or damaged, which a take reports
		}
		next, total := store.GiveBackBucket(time.Unix(0, full), time.Duration(returned), perMinute, taken, now)
		if total == time.Duration(returned) {
			return nil
		}
		in := &dynamodb.UpdateItemInput{
			TableName: aws.String(s.table), Key: k,
			UpdateExpression: aws.String("SET #full = :next, #r = :total"), ConditionExpression: aws.String("#full = :full AND #r = :r"),
			ExpressionAttributeNames: names,
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":full": num(full), ":r": num(returned), ":next": num(next.UnixNano()), ":total": num(int64(total)),
			},
		}
		if !okR {
			in.ConditionExpression = aws.String("#full = :full AND attribute_not_exists(#r)")
			delete(in.ExpressionAttributeValues, ":r")
		}
		_, err = s.api.UpdateItem(ctx, in, sendOnce)
		var ccf *types.ConditionalCheckFailedException
		switch {
		case errors.As(err, &ccf):
			continue
		case err != nil:
			return sanitize("give back", err)
		}
		return nil
	}
	return errors.New("awsstore: give back: the bucket kept changing")
}

// GiveBackDay implements store.Counters: one update, sent once, taking one
// from the count of the take's day while it is above zero.
func (s *Counters) GiveBackDay(ctx context.Context, c store.Counter, taken store.Take) error {
	if err := store.CheckCounter(c, 1); err != nil || !taken.Taken {
		return err
	}
	_, err := s.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.table), Key: s.key(c, dayKind(taken.At)),
		UpdateExpression:          aws.String("ADD #n :minus"),
		ConditionExpression:       aws.String("#n > :zero"),
		ExpressionAttributeNames:  map[string]string{"#n": attrCount},
		ExpressionAttributeValues: map[string]types.AttributeValue{":minus": num(-1), ":zero": num(0)},
	}, sendOnce)
	var ccf *types.ConditionalCheckFailedException
	if err != nil && !errors.As(err, &ccf) {
		return sanitize("give back", err)
	}
	return nil
}

// Ready checks the table for /readyz, as the registry's Ready does.
func (s *Counters) Ready(ctx context.Context) error { return ready(ctx, s.api, s.table) }
