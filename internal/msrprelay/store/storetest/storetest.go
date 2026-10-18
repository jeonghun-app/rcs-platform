// Package storetest is the contract every msrp-relay binding store meets. The
// memory backend runs it in unit tests and the DynamoDB backend against
// DynamoDB Local (make test-integration), so a rule the relay relies on
// across tasks, such as one claim per binding, is checked on both.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/store"
)

// Start is the time the contract runs at. It has a sub-millisecond part so
// that a backend that does not keep ExpiresAt to the millisecond shows.
var Start = time.Date(2026, 3, 1, 12, 0, 0, 123456789, time.UTC)

const (
	corePath   = "msrp://10.0.1.5:2855/c0reside;tcp"
	clientPath = "msrp://client.invalid:7777/cl1ents1de;tcp"
	coreLocal  = "msrp://10.0.2.9:9/r3laycore;tcp"
)

// Run runs the contract against stores from open. Each subtest uses fresh
// ids, so open may return the same store every time.
func Run(t *testing.T, open func(t *testing.T) store.Store) {
	t.Run("CreatedBindingReadsBack", func(t *testing.T) { createdBindingReadsBack(t, open(t)) })
	t.Run("CreateRefusesATakenID", func(t *testing.T) { createRefusesATakenID(t, open(t)) })
	t.Run("ExpiredBindingIsNotFound", func(t *testing.T) { expiredBindingIsNotFound(t, open(t)) })
	t.Run("PathsAreSetOnce", func(t *testing.T) { pathsAreSetOnce(t, open(t)) })
	t.Run("ExpiryMovesBothWays", func(t *testing.T) { expiryMovesBothWays(t, open(t)) })
	t.Run("UpdateOfAMissingOrExpiredBindingFails", func(t *testing.T) { updateOfMissingFails(t, open(t)) })
	t.Run("ClaimNeedsALiveCompleteUnclaimedBinding", func(t *testing.T) { claimRules(t, open(t)) })
	t.Run("OnlyOneConcurrentClaimWins", func(t *testing.T) { oneClaimWins(t, open(t)) })
	t.Run("ClaimedBindingStillExtends", func(t *testing.T) { claimedStillExtends(t, open(t)) })
	t.Run("DeleteRemovesExpiredBindingsToo", func(t *testing.T) { deleteRules(t, open(t)) })
	t.Run("Ready", func(t *testing.T) {
		if err := open(t).Ready(context.Background()); err != nil {
			t.Fatalf("Ready = %v", err)
		}
	})
}

func newID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func create(t *testing.T, s store.Store, b store.Binding) store.Binding {
	t.Helper()
	if b.ID == "" {
		b.ID = newID(t)
	}
	if b.CoreLocal == "" {
		b.CoreLocal = coreLocal
	}
	if b.ExpiresAt.IsZero() {
		b.ExpiresAt = Start.Add(time.Minute)
	}
	if err := s.Create(context.Background(), b); err != nil {
		t.Fatalf("Create = %v", err)
	}
	b.ExpiresAt = b.ExpiresAt.Truncate(store.Precision)
	return b
}

func get(t *testing.T, s store.Store, id string, now time.Time) store.Binding {
	t.Helper()
	b, err := s.Get(context.Background(), id, now)
	if err != nil {
		t.Fatalf("Get = %v", err)
	}
	return b
}

func want(t *testing.T, err, target error, what string) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s = %v, want %v", what, err, target)
	}
}

func same(t *testing.T, got, want store.Binding) {
	t.Helper()
	if got.ID != want.ID || got.CorePath != want.CorePath || got.ClientEndpointPath != want.ClientEndpointPath ||
		got.CoreLocal != want.CoreLocal || !got.ExpiresAt.Equal(want.ExpiresAt) || got.ClaimedBy != want.ClaimedBy {
		t.Fatalf("binding\n got %+v\nwant %+v", got, want)
	}
}

func createdBindingReadsBack(t *testing.T, s store.Store) {
	b := create(t, s, store.Binding{CorePath: corePath})
	same(t, get(t, s, b.ID, Start), b)
	c := create(t, s, store.Binding{ClientEndpointPath: clientPath})
	same(t, get(t, s, c.ID, Start), c)
	_, err := s.Get(context.Background(), newID(t), Start)
	want(t, err, store.ErrNotFound, "Get of an unknown id")
}

func createRefusesATakenID(t *testing.T, s store.Store) {
	b := create(t, s, store.Binding{})
	want(t, s.Create(context.Background(), b), store.ErrExists, "second Create")
	// An expired binding still holds its id until it is deleted.
	old := create(t, s, store.Binding{ExpiresAt: Start.Add(time.Second)})
	want(t, s.Create(context.Background(), old), store.ErrExists, "Create over an expired binding")
	if err := s.Create(context.Background(), store.Binding{ID: newID(t), CoreLocal: coreLocal, ExpiresAt: Start.Add(time.Minute), ClaimedBy: "x"}); err == nil {
		t.Fatal("Create accepted a claimed binding")
	}
}

func expiredBindingIsNotFound(t *testing.T, s store.Store) {
	b := create(t, s, store.Binding{CorePath: corePath, ClientEndpointPath: clientPath})
	get(t, s, b.ID, b.ExpiresAt.Add(-store.Precision))
	_, err := s.Get(context.Background(), b.ID, b.ExpiresAt)
	want(t, err, store.ErrNotFound, "Get at the expiry")
	_, err = s.Claim(context.Background(), b.ID, "task-a/1", b.ExpiresAt)
	want(t, err, store.ErrNotFound, "Claim at the expiry")
}

func pathsAreSetOnce(t *testing.T, s store.Store) {
	ctx := context.Background()
	b := create(t, s, store.Binding{CorePath: corePath})
	got, err := s.Update(ctx, b.ID, store.Update{ClientEndpointPath: clientPath}, Start)
	if err != nil {
		t.Fatalf("Update = %v", err)
	}
	b.ClientEndpointPath = clientPath
	same(t, got, b)
	// Setting the same values again changes nothing and succeeds, so pcscf
	// may retry.
	if got, err = s.Update(ctx, b.ID, store.Update{CorePath: corePath, ClientEndpointPath: clientPath}, Start); err != nil {
		t.Fatalf("idempotent Update = %v", err)
	}
	same(t, got, b)
	later := Start.Add(time.Hour)
	_, err = s.Update(ctx, b.ID, store.Update{CorePath: "msrp://10.0.1.6:2855/other;tcp", ExpiresAt: later}, Start)
	want(t, err, store.ErrConflict, "Update to another core path")
	_, err = s.Update(ctx, b.ID, store.Update{ClientEndpointPath: "msrp://client.invalid:7777/other;tcp"}, Start)
	want(t, err, store.ErrConflict, "Update to another client path")
	// A refused update changes nothing, the expiry included.
	same(t, get(t, s, b.ID, Start), b)
}

func expiryMovesBothWays(t *testing.T, s store.Store) {
	ctx := context.Background()
	b := create(t, s, store.Binding{})
	later := Start.Add(30 * time.Minute)
	got, err := s.Update(ctx, b.ID, store.Update{ExpiresAt: later}, Start)
	if err != nil {
		t.Fatalf("Update = %v", err)
	}
	if !got.ExpiresAt.Equal(later.Truncate(store.Precision)) {
		t.Fatalf("ExpiresAt = %v, want %v", got.ExpiresAt, later)
	}
	get(t, s, b.ID, Start.Add(10*time.Minute))
	sooner := Start.Add(5 * time.Second)
	if _, err := s.Update(ctx, b.ID, store.Update{ExpiresAt: sooner}, Start); err != nil {
		t.Fatalf("Update = %v", err)
	}
	_, err = s.Get(ctx, b.ID, Start.Add(10*time.Second))
	want(t, err, store.ErrNotFound, "Get after a shortened expiry")
}

func updateOfMissingFails(t *testing.T, s store.Store) {
	ctx := context.Background()
	_, err := s.Update(ctx, newID(t), store.Update{ExpiresAt: Start.Add(time.Hour)}, Start)
	want(t, err, store.ErrNotFound, "Update of an unknown id")
	b := create(t, s, store.Binding{})
	// An expired binding cannot be revived.
	_, err = s.Update(ctx, b.ID, store.Update{ExpiresAt: Start.Add(time.Hour)}, b.ExpiresAt)
	want(t, err, store.ErrNotFound, "Update of an expired binding")
}

func claimRules(t *testing.T, s store.Store) {
	ctx := context.Background()
	_, err := s.Claim(ctx, newID(t), "task-a/1", Start)
	want(t, err, store.ErrNotFound, "Claim of an unknown id")

	half := create(t, s, store.Binding{CorePath: corePath})
	_, err = s.Claim(ctx, half.ID, "task-a/1", Start)
	want(t, err, store.ErrIncomplete, "Claim without the client path")
	half2 := create(t, s, store.Binding{ClientEndpointPath: clientPath})
	_, err = s.Claim(ctx, half2.ID, "task-a/1", Start)
	want(t, err, store.ErrIncomplete, "Claim without the core path")

	b := create(t, s, store.Binding{CorePath: corePath, ClientEndpointPath: clientPath})
	got, err := s.Claim(ctx, b.ID, "task-a/1", Start)
	if err != nil {
		t.Fatalf("Claim = %v", err)
	}
	b.ClaimedBy = "task-a/1"
	same(t, got, b)
	same(t, get(t, s, b.ID, Start), b)
	_, err = s.Claim(ctx, b.ID, "task-b/7", Start)
	want(t, err, store.ErrClaimed, "second Claim")
	_, err = s.Claim(ctx, b.ID, "task-a/1", Start)
	want(t, err, store.ErrClaimed, "Claim again by the same claimant")
	// Expiry is checked first: a claimed binding that expired is gone.
	_, err = s.Claim(ctx, b.ID, "task-b/7", b.ExpiresAt)
	want(t, err, store.ErrNotFound, "Claim of an expired claimed binding")
}

func oneClaimWins(t *testing.T, s store.Store) {
	b := create(t, s, store.Binding{CorePath: corePath, ClientEndpointPath: clientPath})
	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = s.Claim(context.Background(), b.ID, "task-"+string(rune('a'+i))+"/1", Start)
		}()
	}
	wg.Wait()
	won := 0
	for i, err := range errs {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, store.ErrClaimed):
			t.Fatalf("claim %d = %v, want ErrClaimed", i, err)
		}
	}
	if won != 1 {
		t.Fatalf("%d claims succeeded, want exactly 1", won)
	}
}

func claimedStillExtends(t *testing.T, s store.Store) {
	ctx := context.Background()
	b := create(t, s, store.Binding{CorePath: corePath, ClientEndpointPath: clientPath})
	if _, err := s.Claim(ctx, b.ID, "task-a/1", Start); err != nil {
		t.Fatalf("Claim = %v", err)
	}
	later := Start.Add(time.Hour)
	got, err := s.Update(ctx, b.ID, store.Update{ExpiresAt: later, CorePath: corePath}, Start)
	if err != nil {
		t.Fatalf("Update of a claimed binding = %v", err)
	}
	if got.ClaimedBy != "task-a/1" || !got.ExpiresAt.Equal(later.Truncate(store.Precision)) {
		t.Fatalf("after Update: %+v", got)
	}
}

func deleteRules(t *testing.T, s store.Store) {
	ctx := context.Background()
	b := create(t, s, store.Binding{})
	if err := s.Delete(ctx, b.ID, Start); err != nil {
		t.Fatalf("Delete = %v", err)
	}
	_, err := s.Get(ctx, b.ID, Start)
	want(t, err, store.ErrNotFound, "Get after Delete")
	want(t, s.Delete(ctx, b.ID, Start), store.ErrNotFound, "second Delete")

	old := create(t, s, store.Binding{ExpiresAt: Start.Add(time.Second)})
	want(t, s.Delete(ctx, old.ID, Start.Add(time.Minute)), store.ErrNotFound, "Delete of an expired binding")
	// It is gone all the same: the id can be created again.
	if err := s.Create(ctx, store.Binding{ID: old.ID, CoreLocal: coreLocal, ExpiresAt: Start.Add(time.Hour)}); err != nil {
		t.Fatalf("Create after deleting an expired binding = %v", err)
	}
}
