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

// StatusTTL is the status TTL of the tables RunRequests checks.
const StatusTTL = 48 * time.Hour

// MessageID returns a random Message-ID in maap's form.
func MessageID() string {
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return hex.EncodeToString(id)
}

// Idempotency returns a fresh record of the chatbot, with a random key,
// digest, Message-ID and answer.
func Idempotency(chatbotID string) store.Idempotency {
	return store.Idempotency{
		Chatbot: chatbotID, Key: "k_" + rand.Text(), Digest: sha256.Sum256([]byte(rand.Text())),
		MessageID: MessageID(), Answer: []byte(`{"message_id":"` + MessageID() + `"}`),
	}
}

// RunRequests runs every check against the tables from newRequests,
// which keep statuses for StatusTTL.
func RunRequests(t *testing.T, newRequests func(t *testing.T) store.Requests) {
	for _, tc := range []struct {
		name  string
		check func(*testing.T, store.Requests)
	}{
		{"TheFirstRequestIsKeptAndReturnedToItsRepeats", remembers},
		{"AKeyIsTheChatbotsOwn", keysPerChatbot},
		{"ARecordIsKeptTwentyFourHoursJudgedAtRead", recordExpiry},
		{"OnlyOneOfConcurrentRequestsWithAKeyIsKept", concurrentRemembers},
		{"AMalformedRecordIsNotStored", malformedRecords},
		{"DeletingAChatbotDeletesOnlyItsRecords", deletesRecords},
		{"AStatusIsTheOwningChatbotsOnly", statusOwner},
		{"AStatusOnlyMovesOn", statusAdvances},
		{"AStatusIsKeptForTheStatusTTLJudgedAtRead", statusExpiry},
		{"ConcurrentNotificationsEndInTheLastState", concurrentAdvances},
	} {
		t.Run(tc.name, func(t *testing.T) { tc.check(t, newRequests(t)) })
	}
}

// remember calls Remember and checks it kept want, stored by this call
// or not.
func remember(t *testing.T, r store.Requests, rec store.Idempotency, now time.Time, want store.Idempotency, fresh bool) {
	t.Helper()
	got, stored, err := r.Remember(context.Background(), rec, now)
	if err != nil {
		t.Fatalf("Remember = %v", err)
	}
	if stored != fresh || got.Chatbot != want.Chatbot || got.Key != want.Key || got.Digest != want.Digest ||
		got.MessageID != want.MessageID || !bytes.Equal(got.Answer, want.Answer) || !got.Created.Equal(want.Created) ||
		got.Created.Location() != time.UTC {
		t.Fatalf("Remember = %+v, stored %v\nwant %+v, stored %v", got, stored, want, fresh)
	}
}

func remembers(t *testing.T, r store.Requests) {
	first := Idempotency(Chatbot().ID)
	kept := first
	kept.Created = Now.Truncate(time.Second)
	remember(t, r, first, Now.Add(400*time.Millisecond), kept, true)
	// A repeat of the request, with the Message-ID and answer a retry
	// would have made, gets the first ones.
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
	// A record without an answer keeps none.
	bare := Idempotency(first.Chatbot)
	bare.Answer = nil
	kept = bare
	kept.Created = Now
	remember(t, r, bare, Now, kept, true)
	remember(t, r, bare, Now, kept, false)
}

func keysPerChatbot(t *testing.T, r store.Requests) {
	a := Idempotency(Chatbot().ID)
	b := Idempotency(Chatbot().ID)
	b.Key = a.Key
	for _, rec := range []store.Idempotency{a, b} {
		kept := rec
		kept.Created = Now
		remember(t, r, rec, Now, kept, true)
	}
}

func recordExpiry(t *testing.T, r store.Requests) {
	first := Idempotency(Chatbot().ID)
	kept := first
	kept.Created = Now
	remember(t, r, first, Now, kept, true)
	remember(t, r, first, Now.Add(store.IdempotencyTTL-time.Second), kept, false)
	// At 24 hours the record is gone, whether or not the item still is,
	// and the key takes another request.
	later := Idempotency(first.Chatbot)
	later.Key = first.Key
	kept = later
	kept.Created = Now.Add(store.IdempotencyTTL)
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
	// Repeats of one request: all get the one kept.
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
		"empty key":            func(rec *store.Idempotency) { rec.Key = "" },
		"key over 64":          func(rec *store.Idempotency) { rec.Key = strings.Repeat("k", 65) },
		"key with a space":     func(rec *store.Idempotency) { rec.Key = "a b" },
		"key with CR LF":       func(rec *store.Idempotency) { rec.Key = "a\r\nb" },
		"key with a NUL":       func(rec *store.Idempotency) { rec.Key = "a\x00" },
		"key not ASCII":        func(rec *store.Idempotency) { rec.Key = "clé" },
		"bad chatbot ID":       func(rec *store.Idempotency) { rec.Chatbot = "c#1" },
		"upper-case hex":       func(rec *store.Idempotency) { rec.MessageID = "A" + rec.MessageID[1:] },
		"short Message-ID":     func(rec *store.Idempotency) { rec.MessageID = rec.MessageID[1:] },
		"answer over its size": func(rec *store.Idempotency) { rec.Answer = make([]byte, store.MaxAnswerBytes+1) },
	}
	for name, mutate := range cases {
		rec := Idempotency(Chatbot().ID)
		mutate(&rec)
		if _, _, err := r.Remember(context.Background(), rec, Now); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%s: Remember = %v", name, err)
		}
	}
	// The longest key and answer are stored.
	rec := Idempotency(Chatbot().ID)
	rec.Key, rec.Answer = strings.Repeat("-", 64), bytes.Repeat([]byte{0xff}, store.MaxAnswerBytes)
	kept := rec
	kept.Created = Now
	remember(t, r, rec, Now, kept, true)
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
		if err := r.Accept(ctx, rec.Chatbot, rec.MessageID, Now); err != nil {
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
		if _, err := r.Status(ctx, rec.Chatbot, rec.MessageID, Now); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a deleted chatbot's status = %v", err)
		}
		other := Idempotency(rec.Chatbot)
		other.Key = rec.Key
		kept := other
		kept.Created = Now
		remember(t, r, other, Now, kept, true)
	}
	kept := stays
	kept.Created = Now
	remember(t, r, stays, Now, kept, false)
	if st, err := r.Status(ctx, stays.Chatbot, stays.MessageID, Now); err != nil || st.State != store.Accepted {
		t.Fatalf("another chatbot's status = %+v, %v", st, err)
	}
}

// status checks the chatbot's status of the message.
func status(t *testing.T, r store.Requests, chatbotID, messageID string, now time.Time, want store.Status) {
	t.Helper()
	got, err := r.Status(context.Background(), chatbotID, messageID, now)
	if err != nil || got != want || got.Accepted.Location() != time.UTC {
		t.Fatalf("Status = %+v, %v\nwant %+v", got, err, want)
	}
}

func statusOwner(t *testing.T, r store.Requests) {
	ctx := context.Background()
	owner, other, id := Chatbot().ID, Chatbot().ID, MessageID()
	if err := r.Accept(ctx, owner, id, Now.Add(300*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	status(t, r, owner, id, Now, store.Status{Chatbot: owner, MessageID: id, State: store.Accepted, Accepted: Now, Updated: Now})
	for _, k := range [][2]string{{other, id}, {owner, MessageID()}, {owner, strings.ToUpper(id)}, {owner, "../" + id}} {
		if _, err := r.Status(ctx, k[0], k[1], Now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Status(%q, %q) = %v", k[0], k[1], err)
		}
	}
	if _, err := r.Advance(ctx, other, id, store.Delivered, Now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another chatbot's Advance = %v", err)
	}
	if err := r.Accept(ctx, owner, id[1:], Now); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("Accept of a malformed Message-ID = %v", err)
	}
	if err := r.Accept(ctx, "c#1", id, Now); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("Accept of a malformed chatbot ID = %v", err)
	}
}

func statusAdvances(t *testing.T, r store.Requests) {
	ctx := context.Background()
	chatbotID, id := Chatbot().ID, MessageID()
	if err := r.Accept(ctx, chatbotID, id, Now); err != nil {
		t.Fatal(err)
	}
	want := store.Status{Chatbot: chatbotID, MessageID: id, State: store.Accepted, Accepted: Now, Updated: Now}
	for i, step := range []struct {
		state   store.StatusState
		changed bool
	}{
		{store.Delivered, true}, {store.Delivered, false}, {store.Failed, false},
		{store.Displayed, true}, {store.Delivered, false}, {store.Displayed, false},
	} {
		at := Now.Add(time.Duration(i+1) * time.Minute)
		changed, err := r.Advance(ctx, chatbotID, id, step.state, at)
		if err != nil || changed != step.changed {
			t.Fatalf("step %d: Advance(%s) = %v, %v", i, step.state, changed, err)
		}
		if changed {
			want.State, want.Updated = step.state, at
		}
		status(t, r, chatbotID, id, at, want)
	}
	// An accept sent again leaves the status as it is.
	if err := r.Accept(ctx, chatbotID, id, Now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	status(t, r, chatbotID, id, Now.Add(time.Hour), want)
	// A failure ends a status too, and a display still follows it.
	failed := MessageID()
	_ = r.Accept(ctx, chatbotID, failed, Now)
	for _, s := range []store.StatusState{store.Failed, store.Displayed} {
		if changed, err := r.Advance(ctx, chatbotID, failed, s, Now); !changed || err != nil {
			t.Fatalf("Advance(%s) = %v, %v", s, changed, err)
		}
	}
	if _, err := r.Advance(ctx, chatbotID, id, store.Accepted, Now); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("Advance(accepted) = %v", err)
	}
}

func statusExpiry(t *testing.T, r store.Requests) {
	ctx := context.Background()
	chatbotID, id := Chatbot().ID, MessageID()
	if err := r.Accept(ctx, chatbotID, id, Now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Advance(ctx, chatbotID, id, store.Delivered, Now.Add(StatusTTL-time.Second)); err != nil {
		t.Fatal(err)
	}
	end := Now.Add(StatusTTL)
	if _, err := r.Status(ctx, chatbotID, id, end); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Status at the TTL = %v", err)
	}
	if _, err := r.Advance(ctx, chatbotID, id, store.Displayed, end); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Advance at the TTL = %v", err)
	}
	// An expired item still there is written over.
	if err := r.Accept(ctx, chatbotID, id, end); err != nil {
		t.Fatal(err)
	}
	status(t, r, chatbotID, id, end, store.Status{Chatbot: chatbotID, MessageID: id, State: store.Accepted, Accepted: end, Updated: end})
}

func concurrentAdvances(t *testing.T, r store.Requests) {
	ctx := context.Background()
	chatbotID, id := Chatbot().ID, MessageID()
	if err := r.Accept(ctx, chatbotID, id, Now); err != nil {
		t.Fatal(err)
	}
	var displayed atomic.Int32
	errs := race(16, func(i int) error {
		state := []store.StatusState{store.Delivered, store.Displayed}[i%2]
		changed, err := r.Advance(ctx, chatbotID, id, state, Now)
		if changed && state == store.Displayed {
			displayed.Add(1)
		}
		return err
	})
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := displayed.Load(); n != 1 {
		t.Fatalf("%d calls displayed the message", n)
	}
	status(t, r, chatbotID, id, Now, store.Status{Chatbot: chatbotID, MessageID: id, State: store.Displayed, Accepted: Now, Updated: Now})
}
