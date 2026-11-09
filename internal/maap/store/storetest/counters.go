package storetest

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
)

// Counter returns a fresh counter of the chatbot, or of all chatbots for
// "".
func Counter(chatbotID string) store.Counter {
	return store.Counter{Chatbot: chatbotID, Name: "sends/tel:+15550100001/" + Chatbot().ID}
}

// RunCounters runs every check against pairs of tables from newCounters:
// two tasks' views of one table.
func RunCounters(t *testing.T, newCounters func(t *testing.T) (store.Counters, store.Counters)) {
	for _, tc := range []struct {
		name  string
		check func(*testing.T, store.Counters, store.Counters)
	}{
		{"ABucketGivesItsBurstThenOneAnInterval", bucketTakes},
		{"AnIdleBucketHoldsItsBurstOnly", idleBucket},
		{"ADayCountsToItsLimitUntilMidnight", dayTakes},
		{"TwoTasksTakingAtOnceNeverExceedACounter", concurrentTakes},
		{"CountersAreApart", countersApart},
		{"DeletingAChatbotDeletesOnlyItsCounters", deletesCounters},
		{"AMalformedCounterOrLimitIsRefused", malformedCounters},
		{"AGiveBackReturnsOneButNeverPastTheBurst", giveBacks},
		{"GiveBacksAndTakesAtOnceNeverExceedACounter", concurrentGiveBacks},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newCounters(t)
			tc.check(t, a, b)
		})
	}
}

// take checks what a take answers.
func take(t *testing.T, take func(store.Counter, int64, time.Time) (store.Take, error), c store.Counter, limit int64, now time.Time, want store.Take) {
	t.Helper()
	got, err := take(c, limit, now)
	if err != nil || got != want {
		t.Fatalf("take at %v = %+v, %v; want %+v", now.Sub(Now), got, err, want)
	}
}

func minute(r store.Counters) func(store.Counter, int64, time.Time) (store.Take, error) {
	return func(c store.Counter, n int64, now time.Time) (store.Take, error) {
		return r.TakeMinute(context.Background(), c, n, now)
	}
}

func day(r store.Counters) func(store.Counter, int64, time.Time) (store.Take, error) {
	return func(c store.Counter, n int64, now time.Time) (store.Take, error) {
		return r.TakeDay(context.Background(), c, n, now)
	}
}

var granted = store.Take{Taken: true}

func bucketTakes(t *testing.T, a, b store.Counters) {
	c := Counter(Chatbot().ID)
	// 60 a minute: a burst of 10, one a second after.
	for i := range 10 {
		take(t, minute([]store.Counters{a, b}[i%2]), c, 60, Now, granted)
	}
	// Refused takes change nothing, on either task.
	for range 3 {
		take(t, minute(a), c, 60, Now, store.Take{Wait: time.Second})
		take(t, minute(b), c, 60, Now.Add(400*time.Millisecond), store.Take{Wait: 600 * time.Millisecond})
	}
	take(t, minute(b), c, 60, Now.Add(time.Second), granted)
	take(t, minute(a), c, 60, Now.Add(time.Second), store.Take{Wait: time.Second})
	take(t, minute(a), c, 60, Now.Add(2500*time.Millisecond), granted)
	take(t, minute(a), c, 60, Now.Add(2500*time.Millisecond), store.Take{Wait: 500 * time.Millisecond})
	// A rate under 6 a minute has a burst of 1, and 7 a minute rounds its
	// interval up, never giving more than the rate.
	slow := Counter(Chatbot().ID)
	take(t, minute(a), slow, 5, Now, granted)
	take(t, minute(b), slow, 5, Now, store.Take{Wait: 12 * time.Second})
	odd := Counter("")
	for range 2 {
		take(t, minute(a), odd, 7, Now, granted)
	}
	take(t, minute(b), odd, 7, Now, store.Take{Wait: 8571428572})
}

func idleBucket(t *testing.T, a, b store.Counters) {
	c := Counter(Chatbot().ID)
	take(t, minute(a), c, 6000, Now, granted)
	later := Now.Add(time.Hour)
	for range 1000 {
		take(t, minute(b), c, 6000, later, granted)
	}
	take(t, minute(a), c, 6000, later, store.Take{Wait: 10 * time.Millisecond})
}

func dayTakes(t *testing.T, a, b store.Counters) {
	c := Counter(Chatbot().ID)
	evening := time.Date(2026, 11, 9, 23, 0, 0, 0, time.UTC)
	for i := range 3 {
		take(t, day([]store.Counters{a, b}[i%2]), c, 3, evening, granted)
	}
	for range 2 {
		take(t, day(b), c, 3, evening, store.Take{Wait: time.Hour})
	}
	// A limit set higher counts on from what the day took.
	take(t, day(a), c, 4, evening.Add(30*time.Minute), granted)
	take(t, day(a), c, 4, evening.Add(30*time.Minute), store.Take{Wait: 30 * time.Minute})
	// The day is UTC's, whatever the caller's zone.
	take(t, day(b), c, 3, evening.Add(time.Hour).In(time.FixedZone("UTC-5", -5*3600)), granted)
}

func concurrentTakes(t *testing.T, a, b store.Counters) {
	for _, tc := range []struct {
		take  func(store.Counters) func(store.Counter, int64, time.Time) (store.Take, error)
		limit int64
		want  int32 // the burst, or the day's limit
	}{{minute, 60, 10}, {day, 7, 7}} {
		c := Counter(Chatbot().ID)
		var n atomic.Int32
		errs := race(40, func(i int) error {
			got, err := tc.take([]store.Counters{a, b}[i%2])(c, tc.limit, Now)
			if got.Taken {
				n.Add(1)
			}
			return err
		})
		if err := errors.Join(errs...); err != nil || n.Load() != tc.want {
			t.Fatalf("%d got1 of %d, %v", n.Load(), tc.want, err)
		}
	}
}

func countersApart(t *testing.T, a, _ store.Counters) {
	c := Counter(Chatbot().ID)
	other := c
	other.Chatbot = Chatbot().ID
	all := c
	all.Chatbot = ""
	renamed := c
	renamed.Name += "x"
	for _, x := range []store.Counter{c, other, all, renamed} {
		take(t, minute(a), x, 5, Now, granted)
		take(t, day(a), x, 1, Now, granted)
	}
	// A minute's bucket and a day's count of one name are apart too.
	take(t, minute(a), c, 5, Now, store.Take{Wait: 12 * time.Second})
	take(t, day(a), c, 1, Now, store.Take{Wait: store.DayEnd(Now).Sub(Now)})
}

func deletesCounters(t *testing.T, a, b store.Counters) {
	ctx := context.Background()
	chatbotID := Chatbot().ID
	var mine []store.Counter
	for range 30 {
		mine = append(mine, Counter(chatbotID))
	}
	other, all := Counter(Chatbot().ID), Counter("")
	all.Name = mine[0].Name
	for _, c := range append(mine, other, all) {
		take(t, minute(a), c, 5, Now, granted)
		take(t, day(a), c, 1, Now, granted)
	}
	// A repeat finds nothing, and no chatbot ID, not even "", deletes the
	// counters of all chatbots.
	for _, id := range []string{chatbotID, chatbotID, ""} {
		if err := b.DeleteChatbot(ctx, id); err != nil {
			t.Fatalf("DeleteChatbot(%q) = %v", id, err)
		}
	}
	for _, c := range mine {
		take(t, minute(a), c, 5, Now, granted)
		take(t, day(a), c, 1, Now, granted)
	}
	for _, c := range []store.Counter{other, all} {
		take(t, minute(a), c, 5, Now, store.Take{Wait: 12 * time.Second})
	}
}

func malformedCounters(t *testing.T, a, _ store.Counters) {
	good := Counter(Chatbot().ID)
	for name, tc := range map[string]struct {
		c     store.Counter
		limit int64
	}{
		"bad chatbot ID":    {store.Counter{Chatbot: "c#1", Name: good.Name}, 1},
		"no name":           {store.Counter{Chatbot: good.Chatbot}, 1},
		"a space":           {store.Counter{Name: "a b"}, 1},
		"a CR LF":           {store.Counter{Name: "a\r\nb"}, 1},
		"not ASCII":         {store.Counter{Name: "é"}, 1},
		"a name over bound": {store.Counter{Name: strings.Repeat("n", store.MaxCounterName+1)}, 1},
		"no limit":          {good, 0},
		"a negative limit":  {good, -1},
		"a limit too high":  {good, store.MaxLimit + 1},
	} {
		for _, f := range []func(store.Counters) func(store.Counter, int64, time.Time) (store.Take, error){minute, day} {
			if _, err := f(a)(tc.c, tc.limit, Now); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("%s: take = %v", name, err)
			}
		}
		if err := a.GiveBackMinute(context.Background(), tc.c, tc.limit, Now); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%s: GiveBackMinute = %v", name, err)
		}
		if tc.limit == 1 {
			if err := a.GiveBackDay(context.Background(), tc.c, Now); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("%s: GiveBackDay = %v", name, err)
			}
		}
	}
	// The longest name and the highest limit are got1.
	long := store.Counter{Name: strings.Repeat("~", store.MaxCounterName)}
	take(t, minute(a), long, store.MaxLimit, Now, granted)
	take(t, day(a), long, store.MaxLimit, Now, granted)
}

// drain takes from the counter at now until it refuses, and returns how
// many it took.
func drain(t *testing.T, take func(store.Counter, int64, time.Time) (store.Take, error), c store.Counter, limit int64, now time.Time) int {
	t.Helper()
	for n := 0; ; n++ {
		got, err := take(c, limit, now)
		if err != nil {
			t.Fatal(err)
		}
		if !got.Taken {
			return n
		}
	}
}

func giveBacks(t *testing.T, a, b store.Counters) {
	ctx := context.Background()
	c := Counter(Chatbot().ID)
	// A bucket of 60 a minute: what is given back is taken again, once.
	if n := drain(t, minute(a), c, 60, Now); n != 10 {
		t.Fatalf("took %d, want the burst of 10", n)
	}
	if err := b.GiveBackMinute(ctx, c, 60, Now); err != nil {
		t.Fatal(err)
	}
	if n := drain(t, minute(a), c, 60, Now); n != 1 {
		t.Fatalf("took %d after a give-back", n)
	}
	// Give-backs to a full bucket, used or never, add nothing.
	for _, x := range []store.Counter{c, Counter(Chatbot().ID)} {
		later := Now.Add(time.Hour)
		take(t, minute(a), x, 60, later, granted)
		for range 3 {
			if err := b.GiveBackMinute(ctx, x, 60, later); err != nil {
				t.Fatal(err)
			}
		}
		if n := drain(t, minute(a), x, 60, later); n != 10 {
			t.Fatalf("took %d from a full bucket given back to, want 10", n)
		}
	}
	// A day: the same, and never under zero.
	d := Counter(Chatbot().ID)
	for range 3 {
		if err := b.GiveBackDay(ctx, d, Now); err != nil {
			t.Fatal(err)
		}
	}
	if n := drain(t, day(a), d, 3, Now); n != 3 {
		t.Fatalf("took %d of a day of 3 given back to while empty", n)
	}
	if err := b.GiveBackDay(ctx, d, Now); err != nil {
		t.Fatal(err)
	}
	if n := drain(t, day(a), d, 3, Now); n != 1 {
		t.Fatalf("took %d after a day's give-back", n)
	}
	// A day taken from and given back to twice is at zero, not under.
	z := Counter(Chatbot().ID)
	take(t, day(a), z, 3, Now, granted)
	for range 2 {
		if err := b.GiveBackDay(ctx, z, Now); err != nil {
			t.Fatal(err)
		}
	}
	if n := drain(t, day(a), z, 3, Now); n != 3 {
		t.Fatalf("took %d of a day of 3 given back to past zero", n)
	}
	// A give-back is to the take's day, not the next.
	_ = b.GiveBackDay(ctx, d, Now.Add(24*time.Hour))
	if n := drain(t, day(a), d, 3, Now); n != 0 {
		t.Fatalf("the next day's give-back returned %d to this one", n)
	}
}

func concurrentGiveBacks(t *testing.T, a, b store.Counters) {
	ctx := context.Background()
	for _, tc := range []struct {
		take     func(store.Counters) func(store.Counter, int64, time.Time) (store.Take, error)
		giveBack func(store.Counters, store.Counter) error
		limit    int64
		full     int // the burst, or the day's limit
	}{
		{minute, func(r store.Counters, c store.Counter) error { return r.GiveBackMinute(ctx, c, 60, Now) }, 60, 10},
		{day, func(r store.Counters, c store.Counter) error { return r.GiveBackDay(ctx, c, Now) }, 7, 7},
	} {
		c := Counter(Chatbot().ID)
		if n := drain(t, tc.take(a), c, tc.limit, Now); n != tc.full {
			t.Fatalf("took %d, want %d", n, tc.full)
		}
		// Half the calls give one back, half take, from both tasks: a take
		// wins only what a give-back returned, and every give-back, from
		// an empty counter, returns one.
		var took atomic.Int32
		errs := race(2*tc.full, func(i int) error {
			r := []store.Counters{a, b}[i/2%2]
			if i%2 == 0 {
				return tc.giveBack(r, c)
			}
			got, err := tc.take(r)(c, tc.limit, Now)
			if got.Taken {
				took.Add(1)
			}
			return err
		})
		if err := errors.Join(errs...); err != nil {
			t.Fatal(err)
		}
		if left := drain(t, tc.take(b), c, tc.limit, Now); int(took.Load())+left != tc.full {
			t.Fatalf("took %d during and %d after %d give-backs", took.Load(), left, tc.full)
		}
	}
}
