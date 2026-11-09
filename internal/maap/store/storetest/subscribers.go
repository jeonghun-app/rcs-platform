package storetest

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
)

// Subscriber is a subscriber of the checks (allowed-test-identifiers.txt).
const Subscriber = "tel:+15550100001"

var aliasEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// AliasID returns a fresh alias ID, made at run time so that no alias
// is written in the clear in the repository (#714).
func AliasID() string {
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return strings.ToLower(aliasEncoding.EncodeToString(id))
}

// Alias returns a fresh alias of the chatbot ID and subscriber, made at
// created.
func Alias(chatbotID, subscriber string, anonymous bool, created time.Time) store.Alias {
	return store.Alias{ID: AliasID(), Chatbot: chatbotID, Subscriber: subscriber, Anonymous: anonymous, Created: created}
}

// RunSubscribers runs every alias check against tables from newTable.
func RunSubscribers(t *testing.T, newTable func(t *testing.T) store.Subscribers) {
	for _, tc := range []struct {
		name  string
		check func(*testing.T, store.Subscribers)
	}{
		{"AnAliasReadsBackBothWays", aliasReadsBack},
		{"AliasesOfOneSubscriberShareNothing", aliasesShareNothing},
		{"ConcurrentCallsStoreOneAlias", concurrentAliases},
		{"AnAliasUnusedFor180DaysExpires", aliasExpires},
		{"DeletingAChatbotDeletesItsAliasesOnly", deleteDeletesAliases},
	} {
		t.Run(tc.name, func(t *testing.T) { tc.check(t, newTable(t)) })
	}
}

func alias(t *testing.T, s store.Subscribers, want store.Alias) store.Alias {
	t.Helper()
	got, err := s.Alias(context.Background(), want)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func resolves(t *testing.T, s store.Subscribers, a store.Alias, now time.Time) bool {
	t.Helper()
	got, err := s.Resolve(context.Background(), a.Chatbot, a.ID, now)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false
	case err != nil:
		t.Fatal(err)
	case !reflect.DeepEqual(got, a):
		t.Fatalf("Resolve = %+v\nwant %+v", got, a)
	}
	return true
}

func aliasReadsBack(t *testing.T, s store.Subscribers) {
	ctx := context.Background()
	want := Alias(Chatbot().ID, Subscriber, false, at.Add(700*time.Millisecond).In(time.FixedZone("KST", 9*3600)))
	got := alias(t, s, want)
	want.Created, want.LastUsed = at, at
	if !reflect.DeepEqual(got, want) || got.Created.Location() != time.UTC {
		t.Fatalf("Alias = %+v\nwant %+v", got, want)
	}
	// A second call gets the stored alias, not its own.
	if again := alias(t, s, Alias(want.Chatbot, Subscriber, false, at.Add(time.Hour))); !reflect.DeepEqual(again, want) {
		t.Fatalf("a second Alias = %+v", again)
	}
	if !resolves(t, s, want, at) {
		t.Fatal("the alias does not resolve")
	}
	for _, other := range []store.Alias{{Chatbot: Chatbot().ID, ID: want.ID}, {Chatbot: want.Chatbot, ID: AliasID()}} {
		if resolves(t, s, other, at) {
			t.Fatalf("%+v resolves", other)
		}
	}
	// What a backend never stores is refused, and reads nothing.
	for _, bad := range []store.Alias{
		{ID: strings.ToUpper(AliasID()), Chatbot: want.Chatbot, Subscriber: Subscriber},
		{ID: AliasID()[1:], Chatbot: want.Chatbot, Subscriber: Subscriber},
		{ID: AliasID(), Chatbot: "c#x", Subscriber: Subscriber},
		{ID: AliasID(), Chatbot: want.Chatbot, Subscriber: "tel:15550100001"},
		{ID: AliasID(), Chatbot: want.Chatbot, Subscriber: "sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org"},
	} {
		if _, err := s.Alias(ctx, bad); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Alias(%+v) = %v", bad, err)
		}
	}
	if _, err := s.Resolve(ctx, want.Chatbot, strings.ToUpper(want.ID), at); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Resolve of the ID in upper case = %v", err)
	}
	// An ID that another alias of the chatbot holds is refused.
	taken := Alias(want.Chatbot, "tel:+15550100002", false, at)
	taken.ID = want.ID
	if _, err := s.Alias(ctx, taken); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("Alias with a taken ID = %v", err)
	}
}

func aliasesShareNothing(t *testing.T, s store.Subscribers) {
	a, b := Chatbot().ID, Chatbot().ID
	seen := map[string]bool{}
	var all []store.Alias
	for _, chatbotID := range []string{a, b} {
		for _, anonymous := range []bool{false, true} {
			got := alias(t, s, Alias(chatbotID, Subscriber, anonymous, at))
			if seen[got.ID] || got.Chatbot != chatbotID || got.Anonymous != anonymous {
				t.Fatalf("Alias of %s, anonymous %v = %+v", chatbotID, anonymous, got)
			}
			seen[got.ID] = true
			all = append(all, got)
		}
	}
	// Each resolves at its own chatbot only, to its own anonymity.
	for _, x := range all {
		for _, y := range all {
			if y.Chatbot != x.Chatbot && resolves(t, s, store.Alias{Chatbot: y.Chatbot, ID: x.ID}, at) {
				t.Fatalf("%s's alias resolves at %s", x.Chatbot, y.Chatbot)
			}
		}
		if !resolves(t, s, x, at) {
			t.Fatalf("%+v does not resolve", x)
		}
	}
}

func concurrentAliases(t *testing.T, s store.Subscribers) {
	chatbotID := Chatbot().ID
	// Over no alias, then over an expired one.
	for _, now := range []time.Time{at, at.Add(store.AliasLifetime)} {
		wants := make([]store.Alias, 8)
		gots := make([]store.Alias, len(wants))
		errs := race(len(wants), func(i int) (err error) {
			wants[i] = Alias(chatbotID, Subscriber, false, now)
			gots[i], err = s.Alias(context.Background(), wants[i])
			return err
		})
		for i := range gots {
			if errs[i] != nil || gots[i] != gots[0] {
				t.Fatalf("call %d = %+v, %v; call 0 = %+v", i, gots[i], errs[i], gots[0])
			}
			if wants[i].ID != gots[0].ID && resolves(t, s, wants[i], now) {
				t.Fatalf("a losing alias resolves")
			}
		}
		if !resolves(t, s, gots[0], now) {
			t.Fatal("the winning alias does not resolve")
		}
	}
}

func aliasExpires(t *testing.T, s store.Subscribers) {
	ctx := context.Background()
	old := alias(t, s, Alias(Chatbot().ID, Subscriber, true, at))
	last := at.Add(store.AliasLifetime - time.Second)
	if !resolves(t, s, old, last) || alias(t, s, Alias(old.Chatbot, Subscriber, true, last)).ID != old.ID {
		t.Fatal("the alias expired early")
	}
	if resolves(t, s, old, last.Add(time.Second)) {
		t.Fatal("the alias resolves after 180 days unused")
	}
	// A use extends it; an earlier one is not written over it.
	used := at.Add(100 * 24 * time.Hour)
	for _, u := range []time.Time{used.Add(500 * time.Millisecond), used.Add(-time.Hour)} {
		if err := s.Used(ctx, old, u); err != nil {
			t.Fatal(err)
		}
	}
	old.LastUsed = used
	if !resolves(t, s, old, last.Add(time.Second)) || resolves(t, s, old, used.Add(store.AliasLifetime)) {
		t.Fatal("the use did not move the expiry to 180 days after it")
	}
	// A use written after the expiry, by a late or slow writer, does not
	// bring the alias back.
	late := used.Add(store.AliasLifetime + time.Hour)
	if err := s.Used(ctx, old, late); err != nil {
		t.Fatal(err)
	}
	if resolves(t, s, old, late) || !resolves(t, s, old, used) {
		t.Fatal("a use after the expiry changed the alias")
	}
	// Past it, a new alias replaces the old, which never resolves again.
	now := used.Add(store.AliasLifetime)
	fresh := alias(t, s, Alias(old.Chatbot, Subscriber, true, now))
	if fresh.ID == old.ID || resolves(t, s, old, used) || !resolves(t, s, fresh, now) {
		t.Fatalf("after expiry: %+v", fresh)
	}
	if err := s.Used(ctx, old, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if resolves(t, s, old, used) || !resolves(t, s, fresh, now) {
		t.Fatal("a use of the replaced alias changed what resolves")
	}
}

func deleteDeletesAliases(t *testing.T, s store.Subscribers) {
	ctx := context.Background()
	gone, kept := Chatbot().ID, Chatbot().ID
	var aliases []store.Alias
	for _, sub := range []string{Subscriber, "tel:+15550100002"} {
		for _, anonymous := range []bool{false, true} {
			aliases = append(aliases, alias(t, s, Alias(gone, sub, anonymous, at)))
		}
	}
	other := alias(t, s, Alias(kept, Subscriber, false, at))
	for range 2 {
		if err := s.DeleteChatbot(ctx, gone); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range aliases {
		if resolves(t, s, a, at) {
			t.Fatalf("%+v resolves after the deletion", a)
		}
		// Its subscriber's side went too: a new alias is stored.
		if again := alias(t, s, Alias(gone, a.Subscriber, a.Anonymous, at)); again.ID == a.ID {
			t.Fatal("the deletion left the subscriber's item")
		}
	}
	if !resolves(t, s, other, at) {
		t.Fatal("the deletion took another chatbot's alias")
	}
}
