package awsstore

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store/storetest"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

// failWith answers every update with a failed condition on the item old
// returns for it, and counts the updates.
func failWith(s *tableStub, n *int, old func(in *dynamodb.UpdateItemInput) map[string]types.AttributeValue) {
	s.update = func(in *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
		*n++
		return nil, &types.ConditionalCheckFailedException{Item: old(in)}
	}
}

// What DynamoDB answers the SDK's second send of a take that took effect
// is this take's own token: taken, though the bucket or day is now full.
// Another writer's is a refusal.
func TestATakeSentAgainFindsItsOwnUpdate(t *testing.T) {
	s, calls := &tableStub{}, 0
	c := NewCounters(s, "maap-counters", testKey)
	full := storetest.Now.Add(10 * time.Second)
	for _, tc := range []struct {
		writer func(*dynamodb.UpdateItemInput) string
		want   store.Take
	}{
		{func(in *dynamodb.UpdateItemInput) string { return sv(in.ExpressionAttributeValues[":w"]) }, store.Take{Taken: true, Returned: 7}},
		{func(*dynamodb.UpdateItemInput) string { return "another" }, store.Take{Wait: time.Second}},
	} {
		failWith(s, &calls, func(in *dynamodb.UpdateItemInput) map[string]types.AttributeValue {
			// A full bucket of 60 a minute, and a full day of 2.
			return map[string]types.AttributeValue{
				attrFull: num(full.UnixNano()), attrReturned: num(7), attrCount: num(2), attrWriter: str(tc.writer(in)),
			}
		})
		got, err := c.TakeMinute(context.Background(), storetest.Counter("cb-1"), 60, storetest.Now)
		if err != nil || got.Taken != tc.want.Taken || got.Wait != tc.want.Wait || got.Returned != tc.want.Returned ||
			got.Taken && !got.Full.Equal(full) || !got.At.Equal(storetest.Now) {
			t.Errorf("TakeMinute = %+v, %v; want %+v", got, err, tc.want)
		}
		want := !tc.want.Taken
		if got, err := c.TakeDay(context.Background(), storetest.Counter("cb-1"), 2, storetest.Now); err != nil ||
			got.Taken == want || want && got.Wait != store.DayEnd(storetest.Now).Sub(storetest.Now) {
			t.Errorf("TakeDay = %+v, %v", got, err)
		}
	}
}

// A store failure, a damaged item, and a bucket that changes under every
// update of a take or a give-back are errors, never refusals, and name no
// counter.
func TestACounterFailureIsNoRefusal(t *testing.T) {
	ctx, counter := context.Background(), storetest.Counter("cb-1")
	s := &tableStub{err: &smithy.GenericAPIError{Code: "ThrottlingException", Message: "key " + counter.Name}}
	c := NewCounters(s, "maap-counters", testKey)
	_, minuteErr := c.TakeMinute(ctx, counter, 60, storetest.Now)
	_, dayErr := c.TakeDay(ctx, counter, 60, storetest.Now)
	some := store.Take{Taken: true, At: storetest.Now, Full: storetest.Now.Add(5 * time.Second)}
	giveBackErrs := []error{c.GiveBackMinute(ctx, counter, 60, some, storetest.Now), c.GiveBackDay(ctx, counter, some)}
	calls := 0
	failWith(s, &calls, func(*dynamodb.UpdateItemInput) map[string]types.AttributeValue {
		return map[string]types.AttributeValue{attrFull: str("1"), attrCount: str("1")}
	})
	_, damagedMinute := c.TakeMinute(ctx, counter, 60, storetest.Now)
	_, damagedDay := c.TakeDay(ctx, counter, 60, storetest.Now)
	// Busy, then idle, then busy...: what only give-backs or deletions
	// between the updates make.
	calls = 0
	failWith(s, &calls, func(in *dynamodb.UpdateItemInput) map[string]types.AttributeValue {
		if in.ExpressionAttributeValues[":edge"] != nil {
			return nil
		}
		return map[string]types.AttributeValue{attrFull: num(storetest.Now.Add(time.Second).UnixNano())}
	})
	_, changedErr := c.TakeMinute(ctx, counter, 60, storetest.Now)
	if calls != takeAttempts {
		t.Errorf("%d updates, want %d", calls, takeAttempts)
	}
	// A give-back whose bucket changes after every read.
	calls = 0
	s.get = func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
		return &dynamodb.GetItemOutput{Item: map[string]types.AttributeValue{attrFull: num(storetest.Now.Add(3 * time.Second).UnixNano())}}, nil
	}
	giveBackErrs = append(giveBackErrs, c.GiveBackMinute(ctx, counter, 60, some, storetest.Now))
	if calls != takeAttempts {
		t.Errorf("%d give-back updates, want %d", calls, takeAttempts)
	}
	for _, err := range append(giveBackErrs, minuteErr, dayErr, damagedMinute, damagedDay, changedErr) {
		if err == nil || strings.Contains(err.Error(), counter.Name) {
			t.Errorf("error = %v", err)
		}
	}
	if !errors.Is(damagedMinute, store.ErrInvalid) || !errors.Is(damagedDay, store.ErrInvalid) {
		t.Errorf("damaged = %v, %v", damagedMinute, damagedDay)
	}
}

// A give-back to a bucket whose returned total is damaged writes
// nothing: a total it cannot read could return any amount.
func TestAGiveBackToADamagedBucketWritesNothing(t *testing.T) {
	updates := 0
	s := &tableStub{
		get: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: map[string]types.AttributeValue{
				attrFull: num(storetest.Now.Add(3 * time.Second).UnixNano()), attrReturned: str("x"),
			}}, nil
		},
		update: func(*dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			updates++
			return &dynamodb.UpdateItemOutput{}, nil
		},
	}
	some := store.Take{Taken: true, At: storetest.Now, Full: storetest.Now.Add(5 * time.Second)}
	if err := NewCounters(s, "maap-counters", testKey).GiveBackMinute(context.Background(), storetest.Counter("cb-1"), 60, some, storetest.Now); err != nil || updates != 0 {
		t.Fatalf("GiveBackMinute = %v after %d updates", err, updates)
	}
}

// A give-back is sent once: the SDK would send it again after an answer
// lost, and after another writer's update it would then count twice.
func TestAGiveBackIsSentOnce(t *testing.T) {
	var opts []func(*dynamodb.Options)
	s := &tableStub{
		get: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: map[string]types.AttributeValue{attrFull: num(storetest.Now.Add(3 * time.Second).UnixNano())}}, nil
		},
		update: func(*dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			return &dynamodb.UpdateItemOutput{}, nil
		},
	}
	s.onUpdate = func(o []func(*dynamodb.Options)) { opts = o }
	c := NewCounters(s, "maap-counters", testKey)
	some := store.Take{Taken: true, At: storetest.Now, Full: storetest.Now.Add(5 * time.Second)}
	for _, give := range []func() error{
		func() error {
			return c.GiveBackMinute(context.Background(), storetest.Counter("cb-1"), 60, some, storetest.Now)
		},
		func() error { return c.GiveBackDay(context.Background(), storetest.Counter("cb-1"), some) },
	} {
		opts = nil
		if err := give(); err != nil {
			t.Fatal(err)
		}
		o := dynamodb.Options{RetryMaxAttempts: 3}
		for _, f := range opts {
			f(&o)
		}
		if len(opts) == 0 || o.RetryMaxAttempts != 1 {
			t.Fatalf("a give-back sent with %d attempts", o.RetryMaxAttempts)
		}
	}
}

// A counter's key holds no name, which may name a subscriber, but an HMAC
// of it under the table's key, and every counter has a partition of its
// own (lead decision on #713).
func TestACounterKeyHoldsAKeyedNameOnly(t *testing.T) {
	var pks []string
	s := &tableStub{update: func(in *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
		pks = append(pks, sv(in.Key[attrPK]))
		return &dynamodb.UpdateItemOutput{Attributes: map[string]types.AttributeValue{attrFull: num(1)}}, nil
	}}
	one := store.Counter{Chatbot: "cb-1", Name: "sends/tel:+15550100001"}
	other := store.Counter{Chatbot: "cb-1", Name: "sends/tel:+15550100002"}
	for _, k := range []secret.Key{testKey, secret.NewString("another-key-0123456789abcdef0123456789")} {
		c := NewCounters(s, "maap-counters", k)
		for _, x := range []store.Counter{one, other, {Name: one.Name}} {
			if _, err := c.TakeMinute(context.Background(), x, 60, storetest.Now); err != nil {
				t.Fatal(err)
			}
			if _, err := c.TakeDay(context.Background(), x, 60, storetest.Now); err != nil {
				t.Fatal(err)
			}
		}
	}
	// The HMAC is under a subkey of its own, so that no other use of the
	// key gives the same value.
	sub := hmac.New(sha256.New, testKey.Reveal())
	sub.Write([]byte("maap-counters name"))
	mac := hmac.New(sha256.New, sub.Sum(nil))
	mac.Write([]byte(one.Name))
	if want := "c#cb-1#m#" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)); pks[0] != want {
		t.Fatalf("key %q, want %q", pks[0], want)
	}
	seen := map[string]bool{}
	for _, pk := range pks {
		if seen[pk] || strings.Contains(pk, "555") || strings.Contains(pk, "sends") ||
			!strings.HasPrefix(pk, "c#cb-1#") && !strings.HasPrefix(pk, "n#") {
			t.Fatalf("keys %q", pks)
		}
		seen[pk] = true
	}
}

// A bucket's item may go once the bucket is full again, a day's an hour
// after the day: an absent item is a full bucket or an unused day, and
// TTL deletes late.
func TestCountersCarryTheirTTL(t *testing.T) {
	var ttls []string
	c := NewCounters(&tableStub{update: func(in *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
		ttls = append(ttls, sv(in.ExpressionAttributeValues[":ttl"]))
		return &dynamodb.UpdateItemOutput{Attributes: map[string]types.AttributeValue{attrFull: num(1)}}, nil
	}}, "maap-counters", testKey)
	at := storetest.Now.Add(300 * time.Millisecond)
	if _, err := c.TakeMinute(context.Background(), storetest.Counter("cb-1"), 60, at); err != nil {
		t.Fatal(err)
	}
	if _, err := c.TakeDay(context.Background(), storetest.Counter("cb-1"), 60, at); err != nil {
		t.Fatal(err)
	}
	// A bucket of 60 a minute taken from at now is full again 10 s later
	// at most.
	want := []string{strconv.FormatInt(storetest.Now.Add(11*time.Second).Unix(), 10), strconv.FormatInt(store.DayEnd(at).Add(time.Hour).Unix(), 10)}
	if !slices.Equal(ttls, want) {
		t.Fatalf("ttl = %v, want %v", ttls, want)
	}
}
