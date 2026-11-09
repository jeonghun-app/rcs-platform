// Package storetest checks that a store.Registry meets the contract the
// operator API relies on. The memory backend runs it in unit tests and the
// DynamoDB backend against DynamoDB Local (make test-integration).
package storetest

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
)

// Domain is the chatbot domain of the checks (MCC 001, MNC 01).
const Domain = "botplatform.mnc001.mcc001.3gppnetwork.org"

var seq atomic.Int64

// Chatbot returns a fresh chatbot with every field set, so that a backend
// shared by subtests never sees an ID or URI twice.
func Chatbot() store.Chatbot {
	n := fmt.Sprintf("%d-%d", time.Now().UnixNano(), seq.Add(1))
	return store.Chatbot{
		ID: "cb-" + n, URI: "sip:bot-" + n + ".acme@" + Domain, DisplayName: "Acme <Support>",
		OutOfService: "Back soon.", Webhook: store.Webhook{URL: "https://bot.example.com/hook", Verified: true},
		Permissions: store.Permissions{MSISDN: true, StartConversations: true},
		Limits:      store.Limits{SendsPerMinute: 60, SendsPerDay: 1000, RequestsPerMinute: 120},
		Sources:     []string{"192.0.2.0/24", "2001:db8::/32"}, State: store.Active,
	}
}

// Run runs every check against registries from newRegistry.
func Run(t *testing.T, newRegistry func(t *testing.T) store.Registry) {
	t.Run("RegisteredChatbotReadsBack", func(t *testing.T) { readsBack(t, newRegistry(t)) })
	t.Run("ASecondChatbotWithTheSameURIIsTaken", func(t *testing.T) { taken(t, newRegistry(t)) })
	t.Run("OnlyOneOfConcurrentRegistersOfAURIWins", func(t *testing.T) { concurrentRegisters(t, newRegistry(t)) })
	t.Run("AURINotInNormalFormIsRefused", func(t *testing.T) { notNormal(t, newRegistry(t)) })
	t.Run("UpdateNeedsTheVersionRead", func(t *testing.T) { versions(t, newRegistry(t)) })
	t.Run("OnlyOneOfConcurrentUpdatesWins", func(t *testing.T) { concurrentUpdates(t, newRegistry(t)) })
	t.Run("DeleteFreesTheURIAndARepeatIsHarmless", func(t *testing.T) { deletes(t, newRegistry(t)) })
	t.Run("ADeletedIDIsNeverRegisteredAgain", func(t *testing.T) { tombstone(t, newRegistry(t)) })
	t.Run("ADeleteRacingUpdatesStillDeletes", func(t *testing.T) { deleteRacingUpdates(t, newRegistry(t)) })
}

func equal(t *testing.T, got, want store.Chatbot) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

func readsBack(t *testing.T, r store.Registry) {
	ctx := context.Background()
	c := Chatbot()
	got, err := r.Register(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if got.Registration == "" {
		t.Fatal("no registration token")
	}
	c.Version, c.Registration = 1, got.Registration
	equal(t, got, c)
	got, err = r.Chatbot(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, got, c)
	// The fewest fields a chatbot has round-trip too.
	bare := store.Chatbot{ID: Chatbot().ID, URI: Chatbot().URI, State: store.Suspended}
	if _, err := r.Register(ctx, bare); err != nil {
		t.Fatal(err)
	}
	got, _ = r.Chatbot(ctx, bare.ID)
	if got.Registration == c.Registration {
		t.Fatal("two registrations share a token")
	}
	bare.Version, bare.Registration = 1, got.Registration
	equal(t, got, bare)
	if _, err := r.Chatbot(ctx, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Chatbot of nobody = %v", err)
	}
}

func taken(t *testing.T, r store.Registry) {
	ctx := context.Background()
	c := Chatbot()
	if _, err := r.Register(ctx, c); err != nil {
		t.Fatal(err)
	}
	other := Chatbot()
	other.URI = c.URI
	if _, err := r.Register(ctx, other); !errors.Is(err, store.ErrURITaken) {
		t.Fatalf("Register of a taken URI = %v", err)
	}
	// Nothing of the refused chatbot was stored.
	if _, err := r.Chatbot(ctx, other.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("refused chatbot reads %v", err)
	}
	again := Chatbot()
	again.ID = c.ID
	if _, err := r.Register(ctx, again); !errors.Is(err, store.ErrExists) {
		t.Fatalf("Register of a taken ID = %v", err)
	}
	// With both taken, the ID is the answer.
	if _, err := r.Register(ctx, c); !errors.Is(err, store.ErrExists) {
		t.Fatalf("Register of a taken ID and URI = %v", err)
	}
	// again's URI is still free.
	again.ID = Chatbot().ID
	if _, err := r.Register(ctx, again); err != nil {
		t.Fatalf("Register of the free URI = %v", err)
	}
}

// race runs n calls of f at once and returns their errors.
func race(n int, f func(i int) error) []error {
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { errs[i] = f(i) })
	}
	wg.Wait()
	return errs
}

// oneWins checks that exactly one call succeeded and every other lost with
// one of the given errors.
func oneWins(t *testing.T, errs []error, lost ...error) {
	t.Helper()
	won := 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case !slices.ContainsFunc(lost, func(e error) bool { return errors.Is(err, e) }):
			t.Errorf("a losing call = %v", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d calls won", won)
	}
}

func concurrentRegisters(t *testing.T, r store.Registry) {
	uri := Chatbot().URI
	oneWins(t, race(8, func(int) error {
		c := Chatbot()
		c.URI = uri
		_, err := r.Register(context.Background(), c)
		return err
	}), store.ErrURITaken, store.ErrConflict)
}

func notNormal(t *testing.T, r store.Registry) {
	ctx := context.Background()
	c := Chatbot()
	for _, uri := range []string{
		"sip:Bot@" + Domain, "sip:bot@" + Domain + ";tk=on", "sip:bot@BOTPLATFORM.mnc001.mcc001.3gppnetwork.org",
		"SIP:bot@" + Domain, "sip:bot@" + Domain + ":5060", "tel:+15550100001", "",
	} {
		c.URI = uri
		if _, err := r.Register(ctx, c); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Register of %q = %v", uri, err)
		}
	}
	if _, err := r.Chatbot(ctx, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a refused chatbot was stored: %v", err)
	}
}

func versions(t *testing.T, r store.Registry) {
	ctx := context.Background()
	c, err := r.Register(ctx, Chatbot())
	if err != nil {
		t.Fatal(err)
	}
	next := c
	next.DisplayName, next.State = "Acme", store.Suspended
	got, err := r.Update(ctx, c, next)
	if err != nil {
		t.Fatal(err)
	}
	next.Version = 2
	equal(t, got, next)
	stored, _ := r.Chatbot(ctx, c.ID)
	equal(t, stored, next)
	// A change computed from version 1 lost to the one just made.
	if _, err := r.Update(ctx, c, c); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Update from a stale version = %v", err)
	}
	forged := next
	forged.Registration = "another"
	if _, err := r.Update(ctx, forged, forged); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Update from another registration = %v", err)
	}
	// The stored URI decides, not the caller's old: a URI changed on both
	// sides is refused too, and stays free.
	moved := next
	moved.URI = Chatbot().URI
	for _, old := range []store.Chatbot{next, moved} {
		if _, err := r.Update(ctx, old, moved); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("Update of the URI = %v", err)
		}
	}
	if stored, _ := r.Chatbot(ctx, c.ID); stored.URI != c.URI || stored.Version != 2 {
		t.Fatalf("a refused Update changed the chatbot: %+v", stored)
	}
	other := Chatbot()
	other.URI = moved.URI
	if _, err := r.Register(ctx, other); err != nil {
		t.Fatalf("Register of the URI an Update was refused = %v", err)
	}
	gone := Chatbot()
	gone.Version = 1
	if _, err := r.Update(ctx, gone, gone); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Update of nothing = %v", err)
	}
}

func concurrentUpdates(t *testing.T, r store.Registry) {
	ctx := context.Background()
	c, err := r.Register(ctx, Chatbot())
	if err != nil {
		t.Fatal(err)
	}
	oneWins(t, race(8, func(i int) error {
		next := c
		next.DisplayName = fmt.Sprintf("Acme %d", i)
		_, err := r.Update(ctx, c, next)
		return err
	}), store.ErrConflict)
	if got, _ := r.Chatbot(ctx, c.ID); got.Version != 2 {
		t.Fatalf("version %d after one update", got.Version)
	}
}

func deletes(t *testing.T, r store.Registry) {
	ctx := context.Background()
	c, err := r.Register(ctx, Chatbot())
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := r.DeleteChatbot(ctx, c.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.Chatbot(ctx, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted chatbot reads %v", err)
	}
	if _, err := r.Update(ctx, c, c); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Update of a deleted chatbot = %v", err)
	}
	// Its URI is free for another chatbot.
	next := Chatbot()
	next.URI = c.URI
	if _, err := r.Register(ctx, next); err != nil {
		t.Fatalf("Register of a freed URI = %v", err)
	}
	if err := r.DeleteChatbot(ctx, "nobody"); err != nil {
		t.Fatalf("DeleteChatbot of nobody = %v", err)
	}
}

// tombstone runs the sequence of the #731 review: an update read before a
// delete never lands on a chatbot registered again under the ID, since
// the ID is not registered again, and the old URI goes to someone else.
func tombstone(t *testing.T, r store.Registry) {
	ctx := context.Background()
	x, err := r.Register(ctx, Chatbot())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteChatbot(ctx, x.ID); err != nil {
		t.Fatal(err)
	}
	again := Chatbot()
	again.ID = x.ID
	if _, err := r.Register(ctx, again); !errors.Is(err, store.ErrDeleted) {
		t.Fatalf("Register of a deleted ID = %v", err)
	}
	if _, err := r.Update(ctx, x, x); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Update read before the delete = %v", err)
	}
	y := Chatbot()
	y.URI = x.URI
	if _, err := r.Register(ctx, y); err != nil {
		t.Fatal(err)
	}
	// The deleted ID is the answer, though its old URI is taken too.
	if _, err := r.Register(ctx, x); !errors.Is(err, store.ErrDeleted) {
		t.Fatalf("Register of a deleted ID at a taken URI = %v", err)
	}
	if err := r.DeleteChatbot(ctx, x.ID); err != nil {
		t.Fatalf("DeleteChatbot of a deleted ID = %v", err)
	}
	if got, err := r.Chatbot(ctx, y.ID); err != nil || got.URI != x.URI {
		t.Fatalf("y after x's deletes: %+v, %v", got, err)
	}
	z := Chatbot()
	z.URI = x.URI
	if _, err := r.Register(ctx, z); !errors.Is(err, store.ErrURITaken) {
		t.Fatalf("Register of y's URI = %v", err)
	}
}

// deleteRacingUpdates: a change at the same time does not stop a deletion,
// and no change lands after it.
func deleteRacingUpdates(t *testing.T, r store.Registry) {
	ctx := context.Background()
	c, err := r.Register(ctx, Chatbot())
	if err != nil {
		t.Fatal(err)
	}
	errs := race(8, func(i int) error {
		if i == 0 {
			return r.DeleteChatbot(ctx, c.ID)
		}
		_, err := r.Update(ctx, c, c)
		return err
	})
	if errs[0] != nil {
		t.Fatalf("DeleteChatbot = %v", errs[0])
	}
	for _, err := range errs[1:] {
		if err != nil && !errors.Is(err, store.ErrConflict) && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Update = %v", err)
		}
	}
	if _, err := r.Chatbot(ctx, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("chatbot after the race: %v", err)
	}
	next := Chatbot()
	next.URI = c.URI
	if _, err := r.Register(ctx, next); err != nil {
		t.Fatalf("Register of the freed URI = %v", err)
	}
}
