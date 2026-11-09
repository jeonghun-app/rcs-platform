package maap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store/storetest"
)

// countedSubscribers counts the reads and use writes of a table in memory,
// and fails the writes while failing is set.
type countedSubscribers struct {
	*store.MemorySubscribers
	mu      sync.Mutex
	reads   int
	uses    []time.Time
	failing bool
}

func (c *countedSubscribers) Resolve(ctx context.Context, chatbotID, aliasID string, now time.Time) (store.Alias, error) {
	c.mu.Lock()
	c.reads++
	c.mu.Unlock()
	return c.MemorySubscribers.Resolve(ctx, chatbotID, aliasID, now)
}

func (c *countedSubscribers) Used(ctx context.Context, a store.Alias, at time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.uses = append(c.uses, at)
	if c.failing {
		return errors.New("awsstore: record alias use: ThrottlingException")
	}
	return c.MemorySubscribers.Used(ctx, a, at)
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestAliases(t *testing.T) (*aliases, *countedSubscribers, *clock, *bytes.Buffer) {
	t.Helper()
	subs := &countedSubscribers{MemorySubscribers: store.NewMemorySubscribers()}
	c := &clock{time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)}
	var logs bytes.Buffer
	// Each alias ID is drawn from bytes 0x00, 0x01, ... in turn.
	random := bytes.NewReader(func() []byte {
		b := make([]byte, 4096)
		for i := range b {
			b[i] = byte(i / aliasIDRandom)
		}
		return b
	}())
	return newAliases(subs, aliasHost, random, c.now, slog.New(slog.NewJSONHandler(&logs, nil))), subs, c, &logs
}

func TestAChatbotSeesTheMSISDNOnlyWithThePermissionAndNeverInAnAnonymousConversation(t *testing.T) {
	a, _, _, _ := newTestAliases(t)
	ctx := context.Background()
	// The first alias ID drawn is 128 zero bits, the next 0x01 bytes.
	first, second := strings.Repeat("a", 26), strings.Repeat("aeaqcaib", 3)+"ae" // made at run time (#714)
	alias := func(id string) string { return "sip:" + id + "@" + aliasHost + ";user=rcstk" }
	for _, tc := range []struct {
		msisdn, anonymous bool
		want              string
	}{
		{false, false, alias(first)},
		{false, true, alias(second)},
		{true, false, storetest.Subscriber},
		{true, true, alias(second)},
	} {
		c := store.Chatbot{ID: "cb-1", Permissions: store.Permissions{MSISDN: tc.msisdn}}
		got, err := a.identifier(ctx, c, storetest.Subscriber, tc.anonymous)
		if err != nil || got != tc.want {
			t.Errorf("MSISDN %v, anonymous %v: %q, %v; want %q", tc.msisdn, tc.anonymous, got, err, tc.want)
		}
	}
	for _, anonymous := range []bool{false, true} {
		if _, err := a.identifier(ctx, store.Chatbot{ID: "cb-1", Permissions: store.Permissions{MSISDN: true}},
			"sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org", anonymous); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("a subscriber not in tel form, anonymous %v: %v", anonymous, err)
		}
	}
	// A failing source of randomness is an error, never an alias.
	a.random = strings.NewReader("short")
	if got, err := a.identifier(ctx, store.Chatbot{ID: "cb-2"}, storetest.Subscriber, false); err == nil {
		t.Fatalf("identifier = %q", got)
	}
}

func TestAnAliasIDNotInItsOneFormIsRefusedUnreadAndUnlogged(t *testing.T) {
	a, subs, _, logs := newTestAliases(t)
	ctx := context.Background()
	id := "ab" + storetest.AliasID()[2:] // so that its first character has a case
	for _, bad := range []string{strings.ToUpper(id), strings.ToUpper(id[:1]) + id[1:], id[1:], id + "a", id[1:] + "1", id[1:] + "=", ""} {
		_, err := a.resolve(ctx, "cb-1", bad)
		if !errors.Is(err, errMalformedAlias) || bad != "" && strings.Contains(strings.ToLower(err.Error()), strings.ToLower(bad)) {
			t.Errorf("resolve(%q) = %v", bad, err)
		}
	}
	if subs.reads != 0 || logs.Len() != 0 {
		t.Fatalf("%d reads, log %s", subs.reads, logs)
	}
	if _, err := a.resolve(ctx, "cb-1", id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("resolve of an unknown alias = %v", err)
	}
}

func TestAnAliasUseIsWrittenAtMostHourlyPerTaskAndExpiresAfter180Days(t *testing.T) {
	a, subs, c, logs := newTestAliases(t)
	ctx := context.Background()
	bot := store.Chatbot{ID: "cb-1"}
	uri, err := a.identifier(ctx, bot, storetest.Subscriber, false)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSuffix(strings.TrimPrefix(uri, "sip:"), "@"+aliasHost+";user=rcstk")
	step := func(d time.Duration, wantUses int) {
		t.Helper()
		c.t = c.t.Add(d)
		if _, err := a.resolve(ctx, bot.ID, id); err != nil {
			t.Fatal(err)
		}
		if _, err := a.identifier(ctx, bot, storetest.Subscriber, false); err != nil {
			t.Fatal(err)
		}
		a.writes.Wait()
		if len(subs.uses) != wantUses {
			t.Fatalf("%d use writes, want %d", len(subs.uses), wantUses)
		}
	}
	step(0, 0)              // storing it was its use
	step(59*time.Minute, 0) // within the hour
	step(time.Minute, 1)    // an hour after
	written := c.t
	step(30*time.Minute, 1) // within the hour again
	subs.failing = true
	step(30*time.Minute, 2) // a write that fails...
	step(59*time.Minute, 2) // ...waits for the next hour
	step(time.Minute, 3)
	// Each failure an hour apart is logged; within a minute, one line
	// stands for the rest.
	a.warn(c.t, store.Alias{Chatbot: bot.ID, ID: id}, errors.New("again"))
	a.warn(c.t.Add(warnEvery), store.Alias{Chatbot: bot.ID, ID: id}, errors.New("again"))
	out := logs.String()
	if n := strings.Count(out, "recording an alias's use failed"); n != 3 || !strings.Contains(out, `"not_logged_since":1`) ||
		strings.Contains(out, id) || !strings.Contains(out, `"alias":`) {
		t.Fatalf("%d warnings, log %s", n, out)
	}
	subs.failing = false
	// Unused for 180 days since the last write that succeeded, it expires:
	// it no longer resolves, and the subscriber gets a new one. (The store
	// contract checks the second before; a resolve then would be a use.)
	c.t = written.Add(store.AliasLifetime)
	if _, err := a.resolve(ctx, bot.ID, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("resolve after 180 days unused = %v", err)
	}
	if again, err := a.identifier(ctx, bot, storetest.Subscriber, false); err != nil || again == uri {
		t.Fatalf("identifier after expiry = %q, %v", again, err)
	}
}

// The last uses a task remembers are dropped once over an hour old and
// many, at most once per 30 s, so they stay one entry per alias used in
// the last hour.
func TestRememberedUsesAreDroppedOnceAnHourOld(t *testing.T) {
	a, _, c, _ := newTestAliases(t)
	ctx := context.Background()
	fill := func() {
		for i := range sweepAt {
			a.used[[2]string{"cb-1", fmt.Sprint(i)}] = c.t.Add(-useInterval)
		}
	}
	fill()
	if _, err := a.identifier(ctx, store.Chatbot{ID: "cb-1"}, storetest.Subscriber, false); err != nil || len(a.used) != 1 {
		t.Fatalf("after the first sweep: %d, %v", len(a.used), err)
	}
	fill()
	c.t = c.t.Add(cacheTTL - time.Nanosecond)
	if _, err := a.identifier(ctx, store.Chatbot{ID: "cb-1"}, storetest.Subscriber, true); err != nil || len(a.used) != sweepAt+2 {
		t.Fatalf("within 30 s: %d, %v", len(a.used), err)
	}
}

// A chatbot's sends to an alias are its uses too, not only the
// subscriber's messages.
func TestAResolveRecordsTheAliasUse(t *testing.T) {
	a, subs, c, _ := newTestAliases(t)
	ctx := context.Background()
	if _, err := a.identifier(ctx, store.Chatbot{ID: "cb-1"}, storetest.Subscriber, false); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(useInterval)
	if _, err := a.resolve(ctx, "cb-1", strings.Repeat("a", 26)); err != nil {
		t.Fatal(err)
	}
	a.writes.Wait()
	if len(subs.uses) != 1 || !subs.uses[0].Equal(c.t) {
		t.Fatalf("use writes %v", subs.uses)
	}
}
