package statetest

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

func sameChallenge(a, b *state.Challenge) bool { return reflect.DeepEqual(a, b) }

// pausedListing holds a sweep after it listed, as an instance busy with the
// items before does.
type pausedListing struct {
	state.Registrations
	listed, release chan struct{}
}

func (p pausedListing) ExpiringRegistrations(ctx context.Context, now time.Time, limit int) ([]*state.Registration, error) {
	regs, err := p.Registrations.ExpiringRegistrations(ctx, now, limit)
	close(p.listed)
	<-p.release
	return regs, err
}

// testSweepFromAStaleListing: B lists an expired registration, A sweeps and
// deletes it, the UA registers again, then B goes on. The new registration
// must survive, which it can only if its version is not the old one's.
func testSweepFromAStaleListing(t *testing.T, a, b state.Store, o Options) {
	must(a.SaveRegistration(ctx(t), Registration(IMPI1, IMPU1, -time.Minute)))(t)
	eventually(t, o, "the index to list it", func() bool {
		return len(must(b.ExpiringRegistrations(ctx(t), T0, 10))(t)) == 1
	})
	p := pausedListing{Registrations: b, listed: make(chan struct{}), release: make(chan struct{})}
	handledB := 0
	done := make(chan error)
	go func() {
		_, err := state.SweepRegistrations(ctx(t), p, T0, 10, func(_, _ *state.Registration) error { handledB++; return nil })
		done <- err
	}()
	<-p.listed
	if _, err := state.SweepRegistrations(ctx(t), a, T0, 10, func(_, _ *state.Registration) error { return nil }); err != nil {
		t.Fatal(err)
	}
	must(a.SaveRegistration(ctx(t), Registration(IMPI1, IMPU1, time.Hour)))(t)
	close(p.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	got, err := a.Registration(ctx(t), IMPU1)
	if err != nil || len(got.Contacts) != 1 || handledB != 0 {
		t.Fatalf("fresh registration: %v, B handled %d expiries", err, handledB)
	}
}

func testStaleSaveAfterRecreate(t *testing.T, a, b state.Store, _ Options) {
	r := must(a.SaveRegistration(ctx(t), Registration(IMPI1, IMPU2, time.Hour)))(t)
	stale := must(b.Registration(ctx(t), IMPU2))(t)
	if err := a.DeleteRegistration(ctx(t), r); err != nil {
		t.Fatal(err)
	}
	must(a.SaveRegistration(ctx(t), Registration(IMPI1, IMPU2, 2*time.Hour)))(t)
	_, err := b.SaveRegistration(ctx(t), stale)
	wantErr(t, err, state.ErrConflict)
	wantErr(t, b.DeleteRegistration(ctx(t), stale), state.ErrConflict)
}

func testStaleSubscriptionSave(t *testing.T, a, b state.Store, _ Options) {
	s := must(a.SaveSubscription(ctx(t), Subscription("s1", IMPU1, time.Hour)))(t)
	stale := must(b.Subscription(ctx(t), "s1"))(t)
	if err := a.DeleteSubscription(ctx(t), s); err != nil {
		t.Fatal(err)
	}
	must(a.SaveSubscription(ctx(t), Subscription("s1", IMPU1, 2*time.Hour)))(t)
	_, err := b.SaveSubscription(ctx(t), stale)
	wantErr(t, err, state.ErrConflict)
}

// testImpossibleKeys: keys a client chooses, such as the empty nonce of a first
// REGISTER (TS 24.229 §5.1.1.2.1) or one longer than any the S-CSCF issues,
// are not found, never a storage error.
func testImpossibleKeys(t *testing.T, a, _ state.Store, _ Options) {
	long := strings.Repeat("n", 2*state.MaxNonce+100)
	for _, k := range [][2]string{{IMPI1, ""}, {IMPI1, long}, {"", "nonce"}, {strings.Repeat("i", 3000), "nonce"}} {
		_, err := a.TakeChallenge(ctx(t), k[0], k[1], T0)
		wantErr(t, err, state.ErrNotFound)
	}
	for _, impu := range []string{"", strings.Repeat("u", 3000)} {
		_, err := a.Registration(ctx(t), impu)
		wantErr(t, err, state.ErrNotFound)
		_, err = a.Subscription(ctx(t), impu)
		wantErr(t, err, state.ErrNotFound)
		_, _, err = a.NextNotify(ctx(t), impu)
		wantErr(t, err, state.ErrNotFound)
		_, err = a.Profile(ctx(t), impu)
		wantErr(t, err, state.ErrNotFound)
		if regs := must(a.RegistrationsOf(ctx(t), impu))(t); len(regs) != 0 {
			t.Error("an impossible IMPI lists registrations")
		}
		if subs := must(a.SubscriptionsOf(ctx(t), impu))(t); len(subs) != 0 {
			t.Error("an impossible IMPU lists subscriptions")
		}
	}
	wantErr(t, a.AddChallenge(ctx(t), Challenge(IMPI1, strings.Repeat("n", state.MaxNonce+1), time.Minute)), state.ErrInvalid)
	if err := a.AddChallenge(ctx(t), Challenge(IMPI1, strings.Repeat("n", state.MaxNonce), time.Minute)); err != nil {
		t.Errorf("a nonce of MaxNonce bytes: %v", err)
	}
}

// testItemSize: what Validate accepts fits every backend, and what would not
// fit is refused by every backend with ErrInvalid.
func testItemSize(t *testing.T, a, _ state.Store, _ Options) {
	big := Registration(IMPI1, IMPU1)
	tag := "+g.x=\"" + strings.Repeat("x", 4000) + "\""
	for range state.MaxContacts {
		c := Registration(IMPI1, IMPU1, time.Hour).Contacts[0]
		c.FeatureTags = []string{tag, tag, tag}
		big.Contacts = append(big.Contacts, c)
	}
	_, err := a.SaveRegistration(ctx(t), big)
	wantErr(t, err, state.ErrInvalid)
	big.Contacts = big.Contacts[:state.MaxContacts/2]
	must(a.SaveRegistration(ctx(t), big))(t)
}

func testBoundaries(t *testing.T, a, _ state.Store, _ Options) {
	at := func(tm time.Time) *state.Registration {
		r := Registration(IMPI1, IMPU1, time.Hour)
		r.Contacts[0].Expires = tm
		return r
	}
	_, err := a.SaveRegistration(ctx(t), at(time.Date(1969, 12, 31, 23, 59, 59, 0, time.UTC)))
	wantErr(t, err, state.ErrInvalid)
	must(a.SaveRegistration(ctx(t), at(time.Unix(0, 0).UTC())))(t)

	wantErr(t, a.SaveProfile(ctx(t), IMPI1, make([]byte, state.MaxUserData+1), T0), state.ErrInvalid)
	if err := a.SaveProfile(ctx(t), IMPI1, make([]byte, state.MaxUserData), T0); err != nil {
		t.Errorf("a profile of MaxUserData bytes: %v", err)
	}

	long := Challenge(IMPI1, "n", time.Minute)
	long.Expires = long.Issued.Add(state.MaxChallengeLifetime + time.Second)
	wantErr(t, a.AddChallenge(ctx(t), long), state.ErrInvalid)
	ok := Challenge(IMPI1, "m", time.Minute)
	ok.Expires = ok.Issued.Add(state.MaxChallengeLifetime)
	if err := a.AddChallenge(ctx(t), ok); err != nil {
		t.Errorf("a challenge living MaxChallengeLifetime: %v", err)
	}

	noExpiry := Subscription("s1", IMPU1, time.Hour)
	noExpiry.Terminated, noExpiry.Expires = true, time.Time{}
	_, err = a.SaveSubscription(ctx(t), noExpiry)
	wantErr(t, err, state.ErrInvalid)
	over := Subscription("s2", IMPU1, time.Hour)
	over.CSeq = state.MaxCounter + 1
	_, err = a.SaveSubscription(ctx(t), over)
	wantErr(t, err, state.ErrInvalid)
}

// testSweepRetry: a deregistration whose handle fails, as when the HSS cannot
// take the SAR, stays, and once the lease has passed another instance retries
// it; when that succeeds the registration goes.
func testSweepRetry(t *testing.T, a, b state.Store, o Options) {
	must(a.SaveRegistration(ctx(t), Registration(IMPI1, IMPU1, -time.Minute)))(t)
	eventually(t, o, "the index to list it", func() bool {
		return len(must(a.ExpiringRegistrations(ctx(t), T0, 10))(t)) == 1
	})
	failing := errors.New("SAR failed")
	n, err := state.SweepRegistrations(ctx(t), a, T0, 10, func(_, _ *state.Registration) error { return failing })
	if n != 1 || !errors.Is(err, failing) {
		t.Fatalf("first sweep: %d handled, %v", n, err)
	}
	if got := must(b.Registration(ctx(t), IMPU1))(t); len(got.Contacts) != 0 || got.Deregistering.IsZero() {
		t.Fatalf("after the failure: %+v", got)
	}
	called := 0
	if _, err := state.SweepRegistrations(ctx(t), b, T0.Add(state.SweepLease/2), 10, func(_, _ *state.Registration) error {
		called++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if called != 0 {
		t.Fatal("a sweep within the lease retried the deregistration")
	}
	later := T0.Add(state.SweepLease + time.Second)
	eventually(t, o, "the index to list it again", func() bool {
		return len(must(b.ExpiringRegistrations(ctx(t), later, 10))(t)) == 1
	})
	if _, err := state.SweepRegistrations(ctx(t), b, later, 10, func(before, after *state.Registration) error {
		called++
		if len(before.Contacts) != 0 || len(after.Contacts) != 0 {
			t.Error("a retried deregistration has contacts")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("the retry was handled %d times", called)
	}
	_, err = a.Registration(ctx(t), IMPU1)
	wantErr(t, err, state.ErrNotFound)
}

// testTerminatedGrace: a subscription another instance claimed is not deleted
// before TerminatedGrace from the claim, however long ago it expired.
func testTerminatedGrace(t *testing.T, a, b state.Store, o Options) {
	must(a.SaveSubscription(ctx(t), Subscription("s1", IMPU1, -time.Hour)))(t)
	eventually(t, o, "the index to list it", func() bool {
		return len(must(b.ExpiringSubscriptions(ctx(t), T0, 10))(t)) == 1
	})
	var final error
	if _, err := state.SweepSubscriptions(ctx(t), a, T0, 10, func(s *state.Subscription) {
		// Another instance sweeps while the claimer sends the final NOTIFY.
		if _, err := state.SweepSubscriptions(ctx(t), b, T0.Add(time.Second), 10, func(*state.Subscription) {
			t.Error("a claimed subscription was handled twice")
		}); err != nil {
			t.Error(err)
		}
		_, _, final = a.NextNotify(ctx(t), s.ID)
	}); err != nil {
		t.Fatal(err)
	}
	if final != nil {
		t.Fatalf("the final NOTIFY found no subscription: %v", final)
	}
	_, err := a.Subscription(ctx(t), "s1")
	wantErr(t, err, state.ErrNotFound)

	// One the S-CSCF ended itself, with the grace ahead, goes after it.
	ended := Subscription("s2", IMPU1, time.Hour)
	ended.Terminated, ended.Expires = true, T0.Add(state.TerminatedGrace)
	must(a.SaveSubscription(ctx(t), ended))(t)
	if _, err := state.SweepSubscriptions(ctx(t), b, T0, 10, func(*state.Subscription) {}); err != nil {
		t.Fatal(err)
	}
	must(a.Subscription(ctx(t), "s2"))(t)
	later := T0.Add(state.TerminatedGrace + time.Second)
	eventually(t, o, "the index to list it", func() bool {
		return len(must(b.ExpiringSubscriptions(ctx(t), later, 10))(t)) == 1
	})
	if _, err := state.SweepSubscriptions(ctx(t), b, later, 10, func(*state.Subscription) {
		t.Error("a Terminated subscription was handled")
	}); err != nil {
		t.Fatal(err)
	}
	_, err = a.Subscription(ctx(t), "s2")
	wantErr(t, err, state.ErrNotFound)
}

func testCounterLimit(t *testing.T, a, b state.Store, _ Options) {
	s := Subscription("s1", IMPU1, time.Hour)
	s.CSeq = state.MaxCounter - 1
	must(a.SaveSubscription(ctx(t), s))(t)
	if c, _, err := b.NextNotify(ctx(t), "s1"); err != nil || c != state.MaxCounter {
		t.Fatalf("NextNotify below the limit = %d, %v", c, err)
	}
	_, _, err := b.NextNotify(ctx(t), "s1")
	wantErr(t, err, state.ErrExhausted)
	if got := must(a.Subscription(ctx(t), "s1"))(t); got.CSeq != state.MaxCounter {
		t.Errorf("stored CSeq %d", got.CSeq)
	}
}

func testProfiles(t *testing.T, a, b state.Store, _ Options) {
	if err := a.SaveProfile(ctx(t), IMPI1, []byte("<IMSSubscription>1</IMSSubscription>"), T0); err != nil {
		t.Fatal(err)
	}
	if err := b.SaveProfile(ctx(t), IMPI1, []byte("<IMSSubscription>2</IMSSubscription>"), T0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// An SAA received before the PPR that followed it, saved late, loses.
	wantErr(t, a.SaveProfile(ctx(t), IMPI1, []byte("<IMSSubscription>1</IMSSubscription>"), T0), state.ErrConflict)
	// Saving the same one again, as an SDK resend does, is fine.
	if err := b.SaveProfile(ctx(t), IMPI1, []byte("<IMSSubscription>2</IMSSubscription>"), T0.Add(time.Second)); err != nil {
		t.Errorf("saving the stored profile again: %v", err)
	}
	if got := must(a.Profile(ctx(t), IMPI1))(t); string(got) != "<IMSSubscription>2</IMSSubscription>" {
		t.Errorf("profile %q, want the one received last", got)
	}
	// A profile is not a registration: no listing or sweep sees it.
	if regs := must(a.RegistrationsOf(ctx(t), IMPI1))(t); len(regs) != 0 {
		t.Error("a profile is listed as a registration")
	}
	if regs := must(a.ExpiringRegistrations(ctx(t), T0.Add(24*time.Hour), 10))(t); len(regs) != 0 {
		t.Error("a profile is listed as expiring")
	}
	if err := b.DeleteProfile(ctx(t), IMPI1); err != nil {
		t.Fatal(err)
	}
	_, err := a.Profile(ctx(t), IMPI1)
	wantErr(t, err, state.ErrNotFound)
	if err := b.DeleteProfile(ctx(t), IMPI1); err != nil {
		t.Errorf("deleting no profile: %v", err)
	}
	wantErr(t, a.SaveProfile(ctx(t), IMPI1, nil, T0), state.ErrInvalid)
	wantErr(t, a.SaveProfile(ctx(t), IMPI1, []byte("x"), time.Time{}), state.ErrInvalid)
}
