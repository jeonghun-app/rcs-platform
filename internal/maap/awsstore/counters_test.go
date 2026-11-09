package awsstore

import (
	"context"
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
	c := NewCounters(s, "maap-counters")
	for _, tc := range []struct {
		writer func(*dynamodb.UpdateItemInput) string
		want   store.Take
	}{
		{func(in *dynamodb.UpdateItemInput) string { return sv(in.ExpressionAttributeValues[":w"]) }, store.Take{Taken: true}},
		{func(*dynamodb.UpdateItemInput) string { return "another" }, store.Take{Wait: time.Second}},
	} {
		failWith(s, &calls, func(in *dynamodb.UpdateItemInput) map[string]types.AttributeValue {
			// A full bucket of 60 a minute, and a full day of 2.
			return map[string]types.AttributeValue{
				attrFull: num(storetest.Now.Add(10 * time.Second).UnixNano()), attrCount: num(2), attrWriter: str(tc.writer(in)),
			}
		})
		if got, err := c.TakeMinute(context.Background(), storetest.Counter("cb-1"), 60, storetest.Now); err != nil || got != tc.want {
			t.Errorf("TakeMinute = %+v, %v; want %+v", got, err, tc.want)
		}
		want := tc.want
		if !want.Taken {
			want.Wait = store.DayEnd(storetest.Now).Sub(storetest.Now)
		}
		if got, err := c.TakeDay(context.Background(), storetest.Counter("cb-1"), 2, storetest.Now); err != nil || got != want {
			t.Errorf("TakeDay = %+v, %v; want %+v", got, err, want)
		}
	}
}

// A store failure, a damaged item, and a bucket deleted under every
// update of a take are errors, never refusals, and name no counter.
func TestACounterFailureIsNoRefusal(t *testing.T) {
	ctx, counter := context.Background(), storetest.Counter("cb-1")
	s := &tableStub{err: &smithy.GenericAPIError{Code: "ThrottlingException", Message: "key " + counter.Name}}
	c := NewCounters(s, "maap-counters")
	_, minuteErr := c.TakeMinute(ctx, counter, 60, storetest.Now)
	_, dayErr := c.TakeDay(ctx, counter, 60, storetest.Now)
	giveBackErrs := []error{c.GiveBackMinute(ctx, counter, 60, storetest.Now), c.GiveBackDay(ctx, counter, storetest.Now)}
	calls := 0
	failWith(s, &calls, func(*dynamodb.UpdateItemInput) map[string]types.AttributeValue {
		return map[string]types.AttributeValue{attrFull: str("1"), attrCount: str("1")}
	})
	_, damagedMinute := c.TakeMinute(ctx, counter, 60, storetest.Now)
	_, damagedDay := c.TakeDay(ctx, counter, 60, storetest.Now)
	// Busy, then gone, then busy...: what only deletions between the
	// updates make.
	calls = 0
	failWith(s, &calls, func(in *dynamodb.UpdateItemInput) map[string]types.AttributeValue {
		if in.ExpressionAttributeValues[":edge"] != nil {
			return nil
		}
		return map[string]types.AttributeValue{attrFull: num(storetest.Now.Add(time.Second).UnixNano())}
	})
	_, deletedErr := c.TakeMinute(ctx, counter, 60, storetest.Now)
	if calls != takeAttempts {
		t.Errorf("%d updates, want %d", calls, takeAttempts)
	}
	for _, err := range append(giveBackErrs, minuteErr, dayErr, damagedMinute, damagedDay, deletedErr, c.DeleteChatbot(ctx, "cb-1")) {
		if err == nil || strings.Contains(err.Error(), counter.Name) {
			t.Errorf("error = %v", err)
		}
	}
	if !errors.Is(damagedMinute, store.ErrInvalid) || !errors.Is(damagedDay, store.ErrInvalid) {
		t.Errorf("damaged = %v, %v", damagedMinute, damagedDay)
	}
}

// A bucket's item may go once the bucket is full again, a day's an hour
// after the day: an absent item is a full bucket or an unused day, and
// TTL deletes late.
func TestCountersCarryTheirTTL(t *testing.T) {
	var ttls []string
	c := NewCounters(&tableStub{update: func(in *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
		ttls = append(ttls, sv(in.ExpressionAttributeValues[":ttl"]))
		return &dynamodb.UpdateItemOutput{}, nil
	}}, "maap-counters")
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
