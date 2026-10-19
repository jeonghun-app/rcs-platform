package group

import (
	"errors"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
)

// RCSAS_GROUP_IDLE_TTL at the service: creating and every roster change
// set the expiry to IdleTTL from then; messages alone keep a group alive,
// writing its activity at most once per TouchInterval and not just after
// a change; a group nobody uses ends IdleTTL after its last use.
func TestAGroupInUseLivesAndAnIdleOneEnds(t *testing.T) {
	const idle = 48 * time.Hour
	r := newRig(t, Config{IdleTTL: idle, SenderRate: rateOff, FanoutRate: rateOff})
	stored := func() (time.Time, time.Time) {
		t.Helper()
		g, err := r.groups.Get(t.Context(), r.n.all()[0].Group, r.clock.Now())
		if err != nil {
			t.Fatal(err)
		}
		return g.Active, g.Expires
	}
	g, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: []Invitee{{Identity: bob}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, expires := stored(); !expires.Equal(r.clock.Now().Add(idle)) {
		t.Fatalf("a new group expires at %v, want IdleTTL from now", expires)
	}
	r.clock.Advance(time.Hour)
	if _, err := r.s.Join(t.Context(), g.URI, bob, ""); err != nil {
		t.Fatal(err)
	}
	if active, expires := stored(); !active.Equal(r.clock.Now()) || !expires.Equal(r.clock.Now().Add(idle)) {
		t.Fatalf("after a change: active %v, expires %v", active, expires)
	}
	write := func() {
		t.Helper()
		if _, err := r.s.Recipients(t.Context(), g.URI, alice, messaging.GroupText); err != nil {
			t.Fatalf("at %v: %v", r.clock.Now(), err)
		}
	}
	// Just after a change, a message writes nothing more.
	r.clock.Advance(30 * time.Minute)
	write()
	if n := r.m.get("group.touched"); n != 0 {
		t.Fatalf("touched %d times within TouchInterval of a change", n)
	}
	// Eight days of a message every quarter of an hour, four IdleTTLs:
	// one touch an hour, each moving the expiry to IdleTTL after it.
	for range 8 * 24 * 4 {
		r.clock.Advance(15 * time.Minute)
		write()
	}
	if n := r.m.get("group.touched"); n != 8*24 {
		t.Fatalf("touched %d times in 192 hours, want once an hour", n)
	}
	last := r.clock.Now().Add(-30 * time.Minute)
	if active, expires := stored(); !active.Equal(last) || !expires.Equal(last.Add(idle)) {
		t.Fatalf("after the messages: active %v, expires %v; last touch %v", active, expires, last)
	}
	// Then nobody writes: the group lasts until IdleTTL after the last
	// touch, and not a moment longer.
	r.clock.Advance(idle - 31*time.Minute)
	if _, err := r.s.Get(t.Context(), g.URI); err != nil {
		t.Fatalf("a minute before its expiry: %v", err)
	}
	r.clock.Advance(time.Minute)
	if _, err := r.s.Get(t.Context(), g.URI); !errors.Is(err, ErrNoGroup) {
		t.Fatalf("after IdleTTL unused: %v", err)
	}
	if _, err := r.s.Recipients(t.Context(), g.URI, alice, messaging.GroupText); rejected(err) != messaging.ReasonNoGroup {
		t.Fatalf("writing to an ended group: %v", err)
	}
}

// The interval is per group, not per sender: two participants writing in
// it make one touch.
func TestAGroupIsTouchedOncePerIntervalWhoeverWrites(t *testing.T) {
	r := newRig(t, Config{SenderRate: rateOff, FanoutRate: rateOff})
	g := r.create(bob)
	r.clock.Advance(2 * time.Hour)
	if _, err := r.s.Recipients(t.Context(), g.URI, alice, messaging.GroupText); err != nil {
		t.Fatal(err)
	}
	if _, err := r.s.Recipients(t.Context(), g.URI, bob, messaging.GroupText); err != nil {
		t.Fatal(err)
	}
	if n := r.m.get("group.touched"); n != 1 {
		t.Fatalf("touched %d times", n)
	}
}

func rejected(err error) messaging.Reason {
	var r *messaging.Rejection
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}
