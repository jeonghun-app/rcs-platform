//go:build integration

package awsstore

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store/storetest"
)

// maap-subscribers has maap-registry's keys, so registryTable makes it.

func TestIntegrationSubscribersMeetTheContract(t *testing.T) {
	storetest.RunSubscribers(t, func(t *testing.T) store.Subscribers { return NewSubscribers(registryTable(t)) })
}

func TestIntegrationAnAliasStoredOnTheFirstSendStands(t *testing.T) {
	ddb, table := registryTable(t)
	s := NewSubscribers(resend{ddb}, table)
	at := time.Unix(1_800_000_000, 0).UTC()
	// Over no alias, then over an expired one.
	for _, now := range []time.Time{at, at.Add(store.AliasLifetime)} {
		want := storetest.Alias("cb-1", storetest.Subscriber, false, now)
		got, err := s.Alias(t.Context(), want)
		want.LastUsed = now
		if err != nil || got != want {
			t.Fatalf("Alias = %+v, %v", got, err)
		}
		if _, err := s.Resolve(t.Context(), want.Chatbot, want.ID, now); err != nil {
			t.Fatalf("Resolve = %v", err)
		}
	}
}

// A deletion meets what no write of this release leaves but a race or a
// newer release may: an item of the chatbot whose subscriber's item names
// another alias, and a damaged one. Both go, with the subscriber's item.
func TestIntegrationADeletionFinishesOverStrayAndDamagedItems(t *testing.T) {
	ddb, table := registryTable(t)
	s := NewSubscribers(ddb, table)
	s.pageSize = 1
	ctx := t.Context()
	at := time.Unix(1_800_000_000, 0).UTC()
	live, err := s.Alias(ctx, storetest.Alias("cb-1", storetest.Subscriber, false, at))
	if err != nil {
		t.Fatal(err)
	}
	stray := live
	stray.ID = storetest.AliasID()
	strayItem := times(chatbotAliasKey("cb-1", stray.ID), stray)
	strayItem[attrSubscriber], strayItem[attrAnonymous] = str(stray.Subscriber), &types.AttributeValueMemberBOOL{Value: false}
	put(t, ddb, table, strayItem)
	put(t, ddb, table, key("c#cb-1", "a#damaged"))
	// Without its anonymity, an alias is damaged, never a normal one.
	noFlag := times(chatbotAliasKey("cb-2", stray.ID), stray)
	noFlag[attrSubscriber] = str(stray.Subscriber)
	put(t, ddb, table, noFlag)
	if _, err := s.Resolve(ctx, "cb-2", stray.ID, at); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("Resolve without the anonymity = %v", err)
	}
	if err := s.DeleteChatbot(ctx, "cb-1"); err != nil {
		t.Fatal(err)
	}
	for _, k := range []map[string]types.AttributeValue{
		subscriberKey(live), chatbotAliasKey("cb-1", live.ID), chatbotAliasKey("cb-1", stray.ID), key("c#cb-1", "a#damaged"),
	} {
		out, err := ddb.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(table), Key: k, ConsistentRead: aws.Bool(true)})
		if err != nil || len(out.Item) != 0 {
			t.Errorf("%v %v left: %v", k[attrPK], k[attrSK], err)
		}
	}
}

// The TTL attribute of both items is the last use plus 180 days, and
// moves with it, so DynamoDB never deletes a live alias.
func TestIntegrationBothItemsExpire180DaysAfterTheLastUse(t *testing.T) {
	ddb, table := registryTable(t)
	s := NewSubscribers(ddb, table)
	ctx := t.Context()
	at := time.Unix(1_800_000_000, 0).UTC()
	a, err := s.Alias(ctx, storetest.Alias("cb-1", storetest.Subscriber, true, at))
	if err != nil {
		t.Fatal(err)
	}
	for _, used := range []time.Time{at, at.Add(time.Hour)} {
		if err := s.Used(ctx, a, used); err != nil {
			t.Fatal(err)
		}
		for _, k := range []map[string]types.AttributeValue{subscriberKey(a), chatbotAliasKey(a.Chatbot, a.ID)} {
			out, err := ddb.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(table), Key: k, ConsistentRead: aws.Bool(true)})
			if want := strconv.FormatInt(used.Add(store.AliasLifetime).Unix(), 10); err != nil || sv(out.Item[attrExpires]) != want {
				t.Fatalf("%v: expires %v, %v; want %s", k[attrPK], out.Item[attrExpires], err, want)
			}
		}
	}
}

// afterRead runs f once, after the first read.
type afterRead struct {
	DynamoAPI
	done atomic.Bool
	f    func()
}

func (a *afterRead) GetItem(ctx context.Context, in *dynamodb.GetItemInput, o ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	out, err := a.DynamoAPI.GetItem(ctx, in, o...)
	if a.done.CompareAndSwap(false, true) {
		a.f()
	}
	return out, err
}

// A use written between the read of an expired alias and its replacement,
// by a task that resolved it in time, keeps it: the replacement's
// condition holds the use read.
func TestIntegrationAUseMeanwhileKeepsAnAliasFromReplacement(t *testing.T) {
	ddb, table := registryTable(t)
	s := NewSubscribers(ddb, table)
	ctx := t.Context()
	at := time.Unix(1_800_000_000, 0).UTC()
	old, err := s.Alias(ctx, storetest.Alias("cb-1", storetest.Subscriber, false, at))
	if err != nil {
		t.Fatal(err)
	}
	now := at.Add(store.AliasLifetime)
	hooked := NewSubscribers(&afterRead{DynamoAPI: ddb, f: func() {
		if err := s.Used(ctx, old, now.Add(-time.Second)); err != nil {
			t.Error(err)
		}
	}}, table)
	if got, err := hooked.Alias(ctx, storetest.Alias("cb-1", storetest.Subscriber, false, now)); err != nil || got.ID != old.ID {
		t.Fatalf("Alias = %+v, %v; want %s kept", got, err, old.ID)
	}
}
