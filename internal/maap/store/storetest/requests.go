package storetest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
)

// Now is the time the request and counter checks start at.
var Now = time.Date(2026, 11, 9, 10, 30, 0, 0, time.UTC)

// MessageID returns a random Message-ID in maap's form.
func MessageID() string {
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return hex.EncodeToString(id)
}

// Idempotency returns a fresh pending record of the chatbot, with a
// random key, digest and Message-ID.
func Idempotency(chatbotID string) store.Idempotency {
	return store.Idempotency{
		Chatbot: chatbotID, Key: "k_" + rand.Text(), Digest: sha256.Sum256([]byte(rand.Text())), MessageID: MessageID(),
	}
}

// RunRequests runs every check against the tables from newRequests.
func RunRequests(t *testing.T, newRequests func(t *testing.T) store.Requests) {
	for _, tc := range []struct {
		name  string
		check func(*testing.T, store.Requests)
	}{
		{"TheFirstRequestIsKeptPendingAndReturnedToItsRepeats", remembers},
		{"OnlyTheWriterSettlesOrForgetsARecord", settles},
		{"AKeyIsTheChatbotsOwn", keysPerChatbot},
		{"ARecordIsKeptTwentyFourHoursJudgedAtRead", recordExpiry},
		{"OnlyOneOfConcurrentRequestsWithAKeyIsKept", concurrentRemembers},
		{"AMalformedRecordIsNotStored", malformedRecords},
		{"DeletingAChatbotDeletesOnlyItsRecords", deletesRecords},
	} {
		t.Run(tc.name, func(t *testing.T) { tc.check(t, newRequests(t)) })
	}
}

// pending is rec as Remember keeps it at created.
func pending(rec store.Idempotency, created time.Time) store.Idempotency {
	rec.Created, rec.Pending = created, true
	return rec
}

// remember calls Remember and checks it kept want, stored by this call
// (with a writer token of its own) or not (without one); it returns the
// record kept.
func remember(t *testing.T, r store.Requests, rec store.Idempotency, now time.Time, want store.Idempotency, fresh bool) store.Idempotency {
	t.Helper()
	got, stored, err := r.Remember(context.Background(), rec, now)
	if err != nil {
		t.Fatalf("Remember = %v", err)
	}
	if stored != fresh || got.Chatbot != want.Chatbot || got.Key != want.Key || got.Digest != want.Digest ||
		got.MessageID != want.MessageID || got.Pending != want.Pending || !bytes.Equal(got.Answer, want.Answer) ||
		!got.Created.Equal(want.Created) || got.Created.Location() != time.UTC || (got.Writer != "") != fresh {
		t.Fatalf("Remember = %+v, stored %v\nwant %+v, stored %v", got, stored, want, fresh)
	}
	return got
}

func remembers(t *testing.T, r store.Requests) {
	first := Idempotency(Chatbot().ID)
	kept := pending(first, Now.Truncate(time.Second))
	remember(t, r, first, Now.Add(400*time.Millisecond), kept, true)
	// A repeat of the request, with the Message-ID a retry would have
	// made, gets the first record, pending.
	again := Idempotency(first.Chatbot)
	again.Key, again.Digest = first.Key, first.Digest
	remember(t, r, again, Now.Add(time.Minute), kept, false)
	other := Idempotency(first.Chatbot)
	other.Key = first.Key
	if _, _, err := r.Remember(context.Background(), other, Now.Add(time.Minute)); !errors.Is(err, store.ErrKeyReused) {
		t.Fatalf("another request with the key = %v", err)
	}
	// It changed nothing.
	remember(t, r, again, Now.Add(2*time.Minute), kept, false)
}

func settles(t *testing.T, r store.Requests) {
	ctx := context.Background()
	rec := Idempotency(Chatbot().ID)
	mine := remember(t, r, rec, Now, pending(rec, Now), true)
	answer := []byte(`{"message_id":"` + rec.MessageID + `"}`)
	// Another writer, an expired record, and no record are refused.
	if err := r.Settle(ctx, rec.Chatbot, rec.Key, "another", answer, Now); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Settle by another writer = %v", err)
	}
	if err := r.Forget(ctx, rec.Chatbot, rec.Key, "another"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Forget by another writer = %v", err)
	}
	if err := r.Settle(ctx, rec.Chatbot, rec.Key, mine.Writer, answer, Now.Add(store.IdempotencyTTL)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Settle of an expired record = %v", err)
	}
	if err := r.Settle(ctx, rec.Chatbot, "k_none", mine.Writer, answer, Now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Settle of no record = %v", err)
	}
	remember(t, r, rec, Now, pending(rec, Now), false)
	// The writer settles it, twice harmlessly; repeats get the answer.
	for range 2 {
		if err := r.Settle(ctx, rec.Chatbot, rec.Key, mine.Writer, answer, Now.Add(time.Second)); err != nil {
			t.Fatalf("Settle = %v", err)
		}
	}
	settled := pending(rec, Now)
	settled.Pending, settled.Answer = false, answer
	remember(t, r, rec, Now.Add(time.Minute), settled, false)
	// The longest answer and an empty one settle too.
	for _, a := range [][]byte{bytes.Repeat([]byte{0xff}, store.MaxAnswerBytes), nil} {
		if err := r.Settle(ctx, rec.Chatbot, rec.Key, mine.Writer, a, Now); err != nil {
			t.Fatalf("Settle of %d bytes = %v", len(a), err)
		}
		settled.Answer = a
		remember(t, r, rec, Now, settled, false)
	}
	if err := r.Settle(ctx, rec.Chatbot, rec.Key, mine.Writer, make([]byte, store.MaxAnswerBytes+1), Now); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("Settle of an answer over its size = %v", err)
	}
	// Forgotten by its writer, twice harmlessly, the key takes a request
	// again, whose writer the first no longer is.
	for range 2 {
		if err := r.Forget(ctx, rec.Chatbot, rec.Key, mine.Writer); err != nil {
			t.Fatalf("Forget = %v", err)
		}
	}
	next := Idempotency(rec.Chatbot)
	next.Key = rec.Key
	remember(t, r, next, Now, pending(next, Now), true)
	if err := r.Forget(ctx, rec.Chatbot, rec.Key, mine.Writer); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Forget by the old writer = %v", err)
	}
	if err := r.Settle(ctx, rec.Chatbot, rec.Key, mine.Writer, answer, Now); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Settle by the old writer = %v", err)
	}
	for _, err := range []error{
		r.Settle(ctx, "c#1", rec.Key, mine.Writer, answer, Now), r.Forget(ctx, rec.Chatbot, "a\r\nb", mine.Writer),
	} {
		if !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("a malformed key = %v", err)
		}
	}
}

func keysPerChatbot(t *testing.T, r store.Requests) {
	a := Idempotency(Chatbot().ID)
	b := Idempotency(Chatbot().ID)
	b.Key = a.Key
	for _, rec := range []store.Idempotency{a, b} {
		remember(t, r, rec, Now, pending(rec, Now), true)
	}
}

func recordExpiry(t *testing.T, r store.Requests) {
	first := Idempotency(Chatbot().ID)
	kept := pending(first, Now)
	remember(t, r, first, Now, kept, true)
	remember(t, r, first, Now.Add(store.IdempotencyTTL-time.Second), kept, false)
	// At 24 hours the record is gone, whether or not the item still is,
	// and the key takes another request.
	later := Idempotency(first.Chatbot)
	later.Key = first.Key
	kept = pending(later, Now.Add(store.IdempotencyTTL))
	remember(t, r, later, kept.Created, kept, true)
	remember(t, r, later, kept.Created.Add(time.Hour), kept, false)
}

func concurrentRemembers(t *testing.T, r store.Requests) {
	chatbotID, key := Chatbot().ID, "k_"+rand.Text()
	// Requests that differ: one is kept, the others are refused.
	recs := make([]store.Idempotency, 16)
	errs := race(len(recs), func(i int) error {
		recs[i] = Idempotency(chatbotID)
		recs[i].Key = key
		_, fresh, err := r.Remember(context.Background(), recs[i], Now)
		if err == nil && !fresh {
			return errors.New("a different request replayed another")
		}
		return err
	})
	oneWins(t, errs, store.ErrKeyReused)
	// Repeats of one request: all get the one kept, and one writer only.
	same := Idempotency(chatbotID)
	ids := make([]string, 16)
	var stored atomic.Int32
	errs = race(len(ids), func(i int) error {
		rec := same
		rec.MessageID = MessageID()
		got, fresh, err := r.Remember(context.Background(), rec, Now)
		if fresh {
			stored.Add(1)
		}
		ids[i] = got.MessageID
		return err
	})
	for i, err := range errs {
		if err != nil || ids[i] != ids[0] {
			t.Fatalf("repeat %d = %q, %v; first %q", i, ids[i], err, ids[0])
		}
	}
	if n := stored.Load(); n != 1 {
		t.Fatalf("%d repeats stored the request", n)
	}
}

func malformedRecords(t *testing.T, r store.Requests) {
	cases := map[string]func(*store.Idempotency){
		"empty key":        func(rec *store.Idempotency) { rec.Key = "" },
		"key over 64":      func(rec *store.Idempotency) { rec.Key = strings.Repeat("k", 65) },
		"key with a space": func(rec *store.Idempotency) { rec.Key = "a b" },
		"key with CR LF":   func(rec *store.Idempotency) { rec.Key = "a\r\nb" },
		"key with a NUL":   func(rec *store.Idempotency) { rec.Key = "a\x00" },
		"key not ASCII":    func(rec *store.Idempotency) { rec.Key = "clé" },
		"bad chatbot ID":   func(rec *store.Idempotency) { rec.Chatbot = "c#1" },
		"upper-case hex":   func(rec *store.Idempotency) { rec.MessageID = "A" + rec.MessageID[1:] },
		"short Message-ID": func(rec *store.Idempotency) { rec.MessageID = rec.MessageID[1:] },
		"an answer":        func(rec *store.Idempotency) { rec.Answer = []byte("{}") },
	}
	for name, mutate := range cases {
		rec := Idempotency(Chatbot().ID)
		mutate(&rec)
		if _, _, err := r.Remember(context.Background(), rec, Now); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%s: Remember = %v", name, err)
		}
	}
	// The longest key is stored.
	rec := Idempotency(Chatbot().ID)
	rec.Key = strings.Repeat("-", 64)
	remember(t, r, rec, Now, pending(rec, Now), true)
}

func deletesRecords(t *testing.T, r store.Requests) {
	ctx := context.Background()
	gone, stays := Idempotency(Chatbot().ID), Idempotency(Chatbot().ID)
	var more []store.Idempotency
	for range 30 {
		more = append(more, Idempotency(gone.Chatbot))
	}
	for _, rec := range append(more, gone, stays) {
		if _, _, err := r.Remember(ctx, rec, Now); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 { // a repeat finds nothing
		if err := r.DeleteChatbot(ctx, gone.Chatbot); err != nil {
			t.Fatalf("DeleteChatbot = %v", err)
		}
	}
	if err := r.DeleteChatbot(ctx, Chatbot().ID); err != nil {
		t.Fatalf("DeleteChatbot of an unknown chatbot = %v", err)
	}
	for _, rec := range append(more, gone) {
		other := Idempotency(rec.Chatbot)
		other.Key = rec.Key
		remember(t, r, other, Now, pending(other, Now), true)
	}
	remember(t, r, stays, Now, pending(stays, Now), false)
}
