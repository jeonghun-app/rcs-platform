package statetest

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync"
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
	got, err := a.Registration(ctx(t), Key1(IMPU1))
	if err != nil || len(got.Contacts) != 1 || handledB != 0 {
		t.Fatalf("fresh registration: %v, B handled %d expiries", err, handledB)
	}
}

func testStaleSaveAfterRecreate(t *testing.T, a, b state.Store, _ Options) {
	r := must(a.SaveRegistration(ctx(t), Registration(IMPI1, IMPU2, time.Hour)))(t)
	stale := must(b.Registration(ctx(t), Key1(IMPU2)))(t)
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
		_, err := a.Registration(ctx(t), Key1(impu))
		wantErr(t, err, state.ErrNotFound)
		_, err = a.Subscription(ctx(t), impu)
		wantErr(t, err, state.ErrNotFound)
		_, _, err = a.NextNotify(ctx(t), impu, 0)
		wantErr(t, err, state.ErrNotFound)
		for _, k := range []state.SetKey{{IMPI: IMPI1, IMPU: impu}, {IMPI: impu, IMPU: IMPU1}} {
			_, err = a.Profile(ctx(t), k, T0)
			wantErr(t, err, state.ErrNotFound)
			if err := a.DeleteProfile(ctx(t), k); err != nil {
				t.Errorf("deleting an impossible profile: %v", err)
			}
			wantErr(t, a.KeepProfile(ctx(t), k, T0.Add(time.Hour), T0), state.ErrNotFound)
		}
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

	wantErr(t, a.SaveProfile(ctx(t), Profile(Set1, make([]byte, state.MaxUserData+1), T0)), state.ErrInvalid)
	if err := a.SaveProfile(ctx(t), Profile(Set1, make([]byte, state.MaxUserData), T0)); err != nil {
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
	if got := must(b.Registration(ctx(t), Key1(IMPU1)))(t); len(got.Contacts) != 0 || got.Deregistering.IsZero() {
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
	_, err = a.Registration(ctx(t), Key1(IMPU1))
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
		_, _, final = a.NextNotify(ctx(t), s.ID, state.FinalNotify)
		finish(t, a, s.ID)
	}); err != nil {
		t.Fatal(err)
	}
	if final != nil {
		t.Fatalf("the final NOTIFY found no subscription: %v", final)
	}
	_, err := a.Subscription(ctx(t), "s1")
	wantErr(t, err, state.ErrNotFound)

	// One the S-CSCF ended itself, with the grace ahead, its final NOTIFY
	// sent without an answer, is handed over after it, to send it again.
	ended := Subscription("s2", IMPU1, time.Hour)
	ended.Terminated, ended.Expires, ended.NotifiedOf = true, T0.Add(state.TerminatedGrace), state.FinalNotify
	must(a.SaveSubscription(ctx(t), ended))(t)
	if _, err := state.SweepSubscriptions(ctx(t), b, T0, 10, func(*state.Subscription) {}); err != nil {
		t.Fatal(err)
	}
	must(a.Subscription(ctx(t), "s2"))(t)
	later := T0.Add(state.TerminatedGrace + time.Second)
	eventually(t, o, "the index to list it", func() bool {
		return len(must(b.ExpiringSubscriptions(ctx(t), later, 10))(t)) == 1
	})
	handled := 0
	if _, err := state.SweepSubscriptions(ctx(t), b, later, 10, func(s *state.Subscription) {
		handled++
		finish(t, b, s.ID)
	}); err != nil {
		t.Fatal(err)
	}
	if handled != 1 {
		t.Errorf("handed over %d times after its grace", handled)
	}
	_, err = a.Subscription(ctx(t), "s2")
	wantErr(t, err, state.ErrNotFound)
}

func testCounterLimit(t *testing.T, a, b state.Store, _ Options) {
	s := Subscription("s1", IMPU1, time.Hour)
	s.CSeq = state.MaxCounter - 1
	must(a.SaveSubscription(ctx(t), s))(t)
	if c, _, err := b.NextNotify(ctx(t), "s1", 0); err != nil || c != state.MaxCounter {
		t.Fatalf("NextNotify below the limit = %d, %v", c, err)
	}
	_, _, err := b.NextNotify(ctx(t), "s1", 0)
	wantErr(t, err, state.ErrExhausted)
	if got := must(a.Subscription(ctx(t), "s1"))(t); got.CSeq != state.MaxCounter {
		t.Errorf("stored CSeq %d", got.CSeq)
	}
}

func testProfiles(t *testing.T, a, b state.Store, _ Options) {
	if err := a.SaveProfile(ctx(t), Profile(Set1, []byte("<IMSSubscription>1</IMSSubscription>"), T0)); err != nil {
		t.Fatal(err)
	}
	if err := b.SaveProfile(ctx(t), Profile(Set1, []byte("<IMSSubscription>2</IMSSubscription>"), T0.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	// An SAA received before the PPR that followed it, saved late, loses.
	wantErr(t, a.SaveProfile(ctx(t), Profile(Set1, []byte("<IMSSubscription>1</IMSSubscription>"), T0)), state.ErrConflict)
	// Saving the same one again, as an SDK resend does, is fine.
	if err := b.SaveProfile(ctx(t), Profile(Set1, []byte("<IMSSubscription>2</IMSSubscription>"), T0.Add(time.Second))); err != nil {
		t.Errorf("saving the stored profile again: %v", err)
	}
	if got := must(a.Profile(ctx(t), Set1, T0))(t); string(got.UserData) != "<IMSSubscription>2</IMSSubscription>" {
		t.Errorf("profile %q, want the one received last", got.UserData)
	}
	// A profile is not a registration: no listing or sweep sees it.
	if regs := must(a.RegistrationsOf(ctx(t), IMPI1))(t); len(regs) != 0 {
		t.Error("a profile is listed as a registration")
	}
	if regs := must(a.ExpiringRegistrations(ctx(t), T0.Add(24*time.Hour), 10))(t); len(regs) != 0 {
		t.Error("a profile is listed as expiring")
	}
	if err := b.DeleteProfile(ctx(t), Set1); err != nil {
		t.Fatal(err)
	}
	_, err := a.Profile(ctx(t), Set1, T0)
	wantErr(t, err, state.ErrNotFound)
	if err := b.DeleteProfile(ctx(t), Set1); err != nil {
		t.Errorf("deleting no profile: %v", err)
	}
	wantErr(t, a.SaveProfile(ctx(t), Profile(Set1, nil, T0)), state.ErrInvalid)
	wantErr(t, a.SaveProfile(ctx(t), Profile(Set1, []byte("x"), time.Time{})), state.ErrInvalid)
	forever := Profile(Set1, []byte("x"), T0)
	forever.KeepUntil = time.Time{}
	wantErr(t, a.SaveProfile(ctx(t), forever), state.ErrInvalid)
	wantErr(t, a.SaveProfile(ctx(t), Profile(state.SetKey{IMPI: IMPI1}, []byte("x"), T0)), state.ErrInvalid)
	wantErr(t, a.SaveProfile(ctx(t), Profile(state.SetKey{IMPI: IMPI1, IMPU: "sip:+15550100001@IMS.MNC001.MCC001.3GPPNETWORK.ORG"}, []byte("x"), T0)), state.ErrInvalid)
}

// testProfilesPerSet: the HSS sends User-Data per implicit registration set,
// so two sets of one IMPI are two profiles, each ordered on its own.
func testProfilesPerSet(t *testing.T, a, b state.Store, _ Options) {
	one, two := "<IMSSubscription>set 1</IMSSubscription>", "<IMSSubscription>set 2</IMSSubscription>"
	if err := a.SaveProfile(ctx(t), Profile(Set1, []byte(one), T0.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	// Received before set 1's, yet not refused: the order is per set.
	if err := b.SaveProfile(ctx(t), Profile(Set2, []byte(two), T0)); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[state.SetKey]string{Set1: one, Set2: two} {
		for _, s := range []state.Store{a, b} {
			if got := must(s.Profile(ctx(t), k, T0))(t); string(got.UserData) != want {
				t.Errorf("profile of %s = %q, want %q", k.IMPU, got.UserData, want)
			}
		}
	}
	if err := b.DeleteProfile(ctx(t), Set2); err != nil {
		t.Fatal(err)
	}
	_, err := a.Profile(ctx(t), Set2, T0)
	wantErr(t, err, state.ErrNotFound)
	if got := must(a.Profile(ctx(t), Set1, T0))(t); string(got.UserData) != one {
		t.Errorf("deleting set 2 changed set 1 to %q", got.UserData)
	}
}

// testPPRForOneSet: a PPR carries one set's User-Data and replaces that set's
// profile only.
func testPPRForOneSet(t *testing.T, a, b state.Store, _ Options) {
	saa1, saa2, ppr := "<IMSSubscription>saa 1</IMSSubscription>", "<IMSSubscription>saa 2</IMSSubscription>", "<IMSSubscription>ppr 2</IMSSubscription>"
	if err := a.SaveProfile(ctx(t), Profile(Set1, []byte(saa1), T0)); err != nil {
		t.Fatal(err)
	}
	if err := a.SaveProfile(ctx(t), Profile(Set2, []byte(saa2), T0)); err != nil {
		t.Fatal(err)
	}
	if err := b.SaveProfile(ctx(t), Profile(Set2, []byte(ppr), T0.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	if got := must(a.Profile(ctx(t), Set2, T0))(t); string(got.UserData) != ppr {
		t.Errorf("set 2 = %q, want the PPR's", got.UserData)
	}
	if got := must(a.Profile(ctx(t), Set1, T0))(t); string(got.UserData) != saa1 {
		t.Errorf("a PPR for set 2 changed set 1 to %q", got.UserData)
	}
	// Set 1's next SAA, received before the PPR, still counts: it is later
	// than set 1's stored profile.
	if err := a.SaveProfile(ctx(t), Profile(Set1, []byte("<IMSSubscription>saa 1 again</IMSSubscription>"), T0.Add(time.Second))); err != nil {
		t.Errorf("a later SAA for set 1: %v", err)
	}
}

// testIdentities: a set's identities point at its one record, through items
// of their own, with the same optimistic concurrency as registrations. The
// store does not tie the two: the S-CSCF writes the items before the record
// that commits them (Identity).
func testIdentities(t *testing.T, a, b state.Store, _ Options) {
	r := Registration(IMPI1, IMPU1, time.Hour)
	r.Identities = append(r.Identities, state.SetIdentity{IMPU: TEL1}, state.SetIdentity{IMPU: IMPU2, Barred: true})
	r.Incarnation = 42
	must(a.SaveRegistration(ctx(t), r))(t)
	for _, id := range r.Identities {
		must(a.SaveIdentity(ctx(t), &state.Identity{IMPU: id.IMPU, Set: Set1, Incarnation: 42, Barred: id.Barred, KeepUntil: T0.Add(48 * time.Hour)}, T0))(t)
	}
	for _, id := range r.Identities {
		got := must(b.Identity(ctx(t), id.IMPU, T0))(t)
		if got.Set != Set1 || got.Incarnation != 42 || got.Barred != id.Barred {
			t.Errorf("%s points at %+v", id.IMPU, got)
		}
		reg := must(b.Registration(ctx(t), got.Set))(t)
		if len(reg.Identities) != 3 || reg.Incarnation != 42 {
			t.Errorf("the set read back as %+v", reg)
		}
	}
	// Two private identities' sets with the same default identity are two
	// records. (One IMPU naming both, a shared public identity of TS 23.228
	// §4.3.3.4, is out of scope: an Identity names one set.)
	other := Registration(IMPI2, IMPU1, 2*time.Hour)
	other.Incarnation = 43
	must(b.SaveRegistration(ctx(t), other))(t)
	if got := must(a.Registration(ctx(t), Set1))(t); got.Incarnation != 42 || len(got.Contacts) != 1 || !got.Contacts[0].Expires.Equal(T0.Add(time.Hour)) {
		t.Errorf("IMPI1's set read back as %+v", got)
	}
	if got := must(a.Registration(ctx(t), state.SetKey{IMPI: IMPI2, IMPU: IMPU1}))(t); got.Incarnation != 43 {
		t.Errorf("IMPI2's set read back as %+v", got)
	}
	// An identity item is not a registration: no listing or sweep sees it.
	if regs := must(b.RegistrationsOf(ctx(t), IMPI1))(t); len(regs) != 1 {
		t.Errorf("RegistrationsOf lists %d, want the one set", len(regs))
	}
	tel := must(a.Identity(ctx(t), TEL1, T0))(t)
	_, err := b.SaveIdentity(ctx(t), &state.Identity{IMPU: TEL1, Set: Set1, Incarnation: 42, KeepUntil: T0.Add(48 * time.Hour)}, T0)
	wantErr(t, err, state.ErrExists)
	moved := *tel
	moved.Set, moved.Incarnation = Set2, 7
	must(b.SaveIdentity(ctx(t), &moved, T0))(t)
	wantErr(t, a.DeleteIdentity(ctx(t), tel), state.ErrConflict)
	if got := must(a.Identity(ctx(t), TEL1, T0))(t); got.Set != Set2 {
		t.Errorf("a stale delete changed %+v", got)
	}
	again := must(a.Identity(ctx(t), TEL1, T0))(t)
	if err := a.DeleteIdentity(ctx(t), again); err != nil {
		t.Fatal(err)
	}
	_, err = b.Identity(ctx(t), TEL1, T0)
	wantErr(t, err, state.ErrNotFound)
	wantErr(t, b.DeleteIdentity(ctx(t), again), state.ErrNotFound)
	for _, bad := range []*state.Identity{
		{IMPU: "not an impu", Set: Set1, Incarnation: 1, KeepUntil: T0.Add(time.Hour)},
		{IMPU: TEL1, Set: state.SetKey{IMPI: IMPI1}, Incarnation: 1, KeepUntil: T0.Add(time.Hour)},
		{IMPU: TEL1, Set: Set1, KeepUntil: T0.Add(time.Hour)},
		{IMPU: TEL1, Set: Set1, Incarnation: 1},
	} {
		_, err := a.SaveIdentity(ctx(t), bad, T0)
		wantErr(t, err, state.ErrInvalid)
	}
	for _, impu := range []string{"", strings.Repeat("u", 3000), "set#" + IMPI1 + "#" + IMPU1, "profile#" + IMPI1 + "#" + IMPU1} {
		_, err := a.Identity(ctx(t), impu, T0)
		wantErr(t, err, state.ErrNotFound)
		wantErr(t, a.DeleteIdentity(ctx(t), &state.Identity{IMPU: impu, Version: 1}), state.ErrNotFound)
	}
	// Barred is kept, and nothing read aliases what is stored.
	got := must(a.Registration(ctx(t), Set1))(t)
	if !got.Identities[2].Barred {
		t.Error("a barred identity read back as not barred")
	}
	got.Identities[0].IMPU = "sip:changed@" + Domain
	if again := must(a.Registration(ctx(t), Set1))(t); again.Identities[0].IMPU != IMPU1 {
		t.Error("changing a read registration's Identities changed the stored one")
	}
	id := must(a.Identity(ctx(t), IMPU2, T0))(t)
	id.Barred = false
	if again := must(a.Identity(ctx(t), IMPU2, T0))(t); !again.Barred {
		t.Error("changing a read identity changed the stored one")
	}
	// An item may name a record not saved yet: the store takes it, and the
	// record is simply not found.
	ahead := must(a.SaveIdentity(ctx(t), &state.Identity{IMPU: IMPU3, Set: Set2, Incarnation: 9, KeepUntil: T0.Add(time.Hour)}, T0))(t)
	if got := must(b.Identity(ctx(t), IMPU3, T0))(t); got.Set != Set2 || got.Version != ahead.Version {
		t.Errorf("an item ahead of its record: %+v", got)
	}
	_, err = b.Registration(ctx(t), Set2)
	wantErr(t, err, state.ErrNotFound)
}

// testIdentityKeepUntil: an identity a failed deregistration left is gone at
// its KeepUntil, which KeepIdentity only moves later.
func testIdentityKeepUntil(t *testing.T, a, b state.Store, _ Options) {
	i := &state.Identity{IMPU: IMPU1, Set: Set1, Incarnation: 1, KeepUntil: T0.Add(time.Hour + 500*time.Millisecond)}
	must(a.SaveIdentity(ctx(t), i, T0))(t)
	got := must(b.Identity(ctx(t), IMPU1, T0))(t)
	if !got.KeepUntil.Equal(T0.Add(time.Hour)) {
		t.Errorf("kept until %v, want it to the second", got.KeepUntil)
	}
	_, err := b.Identity(ctx(t), IMPU1, T0.Add(time.Hour))
	wantErr(t, err, state.ErrNotFound)
	if err := b.KeepIdentity(ctx(t), IMPU1, T0.Add(25*time.Hour), T0); err != nil {
		t.Fatal(err)
	}
	if err := a.KeepIdentity(ctx(t), IMPU1, T0.Add(2*time.Hour), T0); err != nil {
		t.Fatal(err)
	}
	if got := must(a.Identity(ctx(t), IMPU1, T0.Add(24*time.Hour)))(t); !got.KeepUntil.Equal(T0.Add(25 * time.Hour)) {
		t.Errorf("after KeepIdentity: %+v", got)
	}
	wantErr(t, a.KeepIdentity(ctx(t), IMPU2, T0.Add(time.Hour), T0), state.ErrNotFound)
	wantErr(t, a.KeepIdentity(ctx(t), IMPU1, T0.Add(50*time.Hour), T0.Add(25*time.Hour)), state.ErrNotFound)

	// Past its KeepUntil the item may still be stored, as DynamoDB's TTL
	// lags, but nobody can name it by its version: a create takes its place,
	// at any second from KeepUntil on and not before.
	other := state.Identity{IMPU: IMPU1, Set: Set2, Incarnation: 7, KeepUntil: T0.Add(72 * time.Hour)}
	_, err = b.SaveIdentity(ctx(t), &other, T0.Add(25*time.Hour-time.Second))
	wantErr(t, err, state.ErrExists)
	saved := must(b.SaveIdentity(ctx(t), &other, T0.Add(25*time.Hour)))(t)
	if got := must(a.Identity(ctx(t), IMPU1, T0.Add(25*time.Hour)))(t); got.Set != Set2 || got.Incarnation != 7 || got.Version != saved.Version {
		t.Errorf("the identity created over an expired one: %+v", got)
	}
}

// testIdentityKeepNeverUndone: a save from a read made before a KeepIdentity
// would bring KeepUntil back; the KeepIdentity changed the version, so the
// save gets ErrConflict, reads again and keeps the later KeepUntil.
func testIdentityKeepNeverUndone(t *testing.T, a, b state.Store, _ Options) {
	must(a.SaveIdentity(ctx(t), &state.Identity{IMPU: TEL1, Set: Set1, Incarnation: 3, KeepUntil: T0.Add(30 * time.Hour)}, T0))(t)
	read := must(a.Identity(ctx(t), TEL1, T0))(t)
	if err := b.KeepIdentity(ctx(t), TEL1, T0.Add(200*time.Hour), T0); err != nil {
		t.Fatal(err)
	}
	barred := *read
	barred.Barred = true
	_, err := a.SaveIdentity(ctx(t), &barred, T0)
	wantErr(t, err, state.ErrConflict)
	again := must(a.Identity(ctx(t), TEL1, T0))(t)
	if !again.KeepUntil.Equal(T0.Add(200 * time.Hour)) {
		t.Fatalf("kept until %v after the refused save, want the KeepIdentity's", again.KeepUntil)
	}
	// A KeepIdentity that moves nothing leaves the version, so the reader's
	// save goes through.
	if err := b.KeepIdentity(ctx(t), TEL1, T0.Add(100*time.Hour), T0); err != nil {
		t.Fatal(err)
	}
	again.Barred = true
	if got := must(a.SaveIdentity(ctx(t), again, T0))(t); !got.Barred || !got.KeepUntil.Equal(T0.Add(200*time.Hour)) {
		t.Errorf("saved from the second read: %+v", got)
	}
}

// testInterruptedDeregistration: a sweep's handler deletes the set's
// identities before SweepRegistrations deletes the record; cut short in
// between, the record keeps its lease, and the next sweep after it does the
// rest, so nothing of the set remains.
func testInterruptedDeregistration(t *testing.T, a, b state.Store, o Options) {
	r := Registration(IMPI1, IMPU1, -time.Minute)
	r.Identities = append(r.Identities, state.SetIdentity{IMPU: TEL1})
	must(a.SaveRegistration(ctx(t), r))(t)
	for _, impu := range []string{IMPU1, TEL1} {
		must(a.SaveIdentity(ctx(t), &state.Identity{IMPU: impu, Set: Set1, Incarnation: 1, KeepUntil: T0.Add(24 * time.Hour)}, T0))(t)
	}
	eventually(t, o, "the index to list it", func() bool {
		return len(must(a.ExpiringRegistrations(ctx(t), T0, 10))(t)) == 1
	})
	handle := func(s state.Store, fail bool) func(before, after *state.Registration) error {
		return func(_, after *state.Registration) error {
			for _, id := range after.Identities {
				if i, err := s.Identity(ctx(t), id.IMPU, T0); err == nil {
					if err := s.DeleteIdentity(ctx(t), i); err != nil {
						return err
					}
				}
			}
			if fail {
				return errors.New("the instance stopped")
			}
			return nil
		}
	}
	if _, err := state.SweepRegistrations(ctx(t), a, T0, 10, handle(a, true)); err == nil {
		t.Fatal("the cut-short sweep reported no error")
	}
	later := T0.Add(state.SweepLease + time.Second)
	eventually(t, o, "the index to list it again", func() bool {
		return len(must(b.ExpiringRegistrations(ctx(t), later, 10))(t)) == 1
	})
	if _, err := state.SweepRegistrations(ctx(t), b, later, 10, handle(b, false)); err != nil {
		t.Fatal(err)
	}
	_, err := a.Registration(ctx(t), Set1)
	wantErr(t, err, state.ErrNotFound)
	for _, impu := range []string{IMPU1, TEL1} {
		_, err := a.Identity(ctx(t), impu, T0)
		wantErr(t, err, state.ErrNotFound)
	}
}

// testSaveProfileKeepsKeepUntil: a profile saved again, as a PPR does, with a
// KeepUntil earlier than the one stored (which a registration on another
// instance just extended) keeps the later one, or the profile could run out
// while its bindings live. From QA's review of #184.
func testSaveProfileKeepsKeepUntil(t *testing.T, a, b state.Store, _ Options) {
	if err := a.SaveProfile(ctx(t), Profile(Set1, []byte("<IMSSubscription>1</IMSSubscription>"), T0)); err != nil {
		t.Fatal(err)
	}
	long := T0.Add(166*time.Hour + 40*time.Minute + state.ProfileGrace)
	if err := a.KeepProfile(ctx(t), Set1, long, T0); err != nil {
		t.Fatal(err)
	}
	ppr := Profile(Set1, []byte("<IMSSubscription>2</IMSSubscription>"), T0.Add(time.Minute))
	ppr.KeepUntil = T0.Add(25*time.Hour + 10*time.Minute)
	if err := b.SaveProfile(ctx(t), ppr); err != nil {
		t.Fatal(err)
	}
	got := must(a.Profile(ctx(t), Set1, T0.Add(100*time.Hour)))(t)
	if string(got.UserData) != "<IMSSubscription>2</IMSSubscription>" || !got.KeepUntil.Equal(long) {
		t.Errorf("after the PPR: %q kept until %v, want the PPR's data kept until %v", got.UserData, got.KeepUntil, long)
	}
	// A save refused because a later profile is stored still raises
	// KeepUntil to its own: the SAA of a long registration that lost to a
	// PPR must not leave the profile kept only as long as the PPR said
	// (#184 QA).
	ppr2 := Profile(Set2, []byte("<IMSSubscription>ppr</IMSSubscription>"), T0.Add(time.Millisecond))
	ppr2.KeepUntil = T0.Add(state.ProfileGrace)
	if err := a.SaveProfile(ctx(t), ppr2); err != nil {
		t.Fatal(err)
	}
	saa := Profile(Set2, []byte("<IMSSubscription>saa</IMSSubscription>"), T0)
	saa.KeepUntil = T0.Add(600000*time.Second + state.ProfileGrace)
	wantErr(t, b.SaveProfile(ctx(t), saa), state.ErrConflict)
	if got := must(a.Profile(ctx(t), Set2, T0.Add(48*time.Hour)))(t); string(got.UserData) != "<IMSSubscription>ppr</IMSSubscription>" || !got.KeepUntil.Equal(saa.KeepUntil) {
		t.Errorf("after the refused SAA: %q kept until %v, want the PPR's kept until %v", got.UserData, got.KeepUntil, saa.KeepUntil)
	}
	// A later KeepUntil from the save does count.
	later := Profile(Set1, []byte("<IMSSubscription>3</IMSSubscription>"), T0.Add(2*time.Minute))
	later.KeepUntil = long.Add(time.Hour)
	if err := b.SaveProfile(ctx(t), later); err != nil {
		t.Fatal(err)
	}
	if got := must(a.Profile(ctx(t), Set1, T0))(t); !got.KeepUntil.Equal(long.Add(time.Hour)) {
		t.Errorf("kept until %v, want the save's later one", got.KeepUntil)
	}
}

// testProfileKeepUntil: KeepUntil is kept to the second, and from then on the
// profile is not found on any backend, however late DynamoDB's TTL is.
func testProfileKeepUntil(t *testing.T, a, b state.Store, _ Options) {
	p := Profile(Set1, []byte("<IMSSubscription>1</IMSSubscription>"), T0)
	p.KeepUntil = T0.Add(time.Hour + 500*time.Millisecond)
	if err := a.SaveProfile(ctx(t), p); err != nil {
		t.Fatal(err)
	}
	got := must(b.Profile(ctx(t), Set1, T0))(t)
	if got.Key != Set1 || !got.Received.Equal(T0) || !got.KeepUntil.Equal(T0.Add(time.Hour)) {
		t.Errorf("read back %v, received %v, kept until %v", got.Key, got.Received, got.KeepUntil)
	}
	must(b.Profile(ctx(t), Set1, T0.Add(time.Hour-time.Nanosecond)))(t)
	_, err := b.Profile(ctx(t), Set1, T0.Add(time.Hour))
	wantErr(t, err, state.ErrNotFound)
}

// testKeepProfile: KeepProfile only moves KeepUntil later, and touches
// nothing else.
func testKeepProfile(t *testing.T, a, b state.Store, _ Options) {
	p := Profile(Set1, []byte("<IMSSubscription>1</IMSSubscription>"), T0)
	p.KeepUntil = T0.Add(time.Hour)
	if err := a.SaveProfile(ctx(t), p); err != nil {
		t.Fatal(err)
	}
	if err := b.KeepProfile(ctx(t), Set1, T0.Add(25*time.Hour), T0); err != nil {
		t.Fatal(err)
	}
	// An instance that computed an earlier time does not bring it closer.
	if err := a.KeepProfile(ctx(t), Set1, T0.Add(2*time.Hour), T0); err != nil {
		t.Errorf("keeping a profile for less than it is kept: %v", err)
	}
	got := must(a.Profile(ctx(t), Set1, T0.Add(24*time.Hour)))(t)
	if !got.KeepUntil.Equal(T0.Add(25*time.Hour)) || string(got.UserData) != string(p.UserData) || !got.Received.Equal(T0) {
		t.Errorf("after KeepProfile: kept until %v, %q received %v", got.KeepUntil, got.UserData, got.Received)
	}
	older := Profile(Set1, []byte("<IMSSubscription>0</IMSSubscription>"), T0.Add(-time.Second))
	older.KeepUntil = T0.Add(time.Hour)
	wantErr(t, a.SaveProfile(ctx(t), older), state.ErrConflict)
	wantErr(t, b.KeepProfile(ctx(t), Set2, T0.Add(25*time.Hour), T0), state.ErrNotFound)
	// Past KeepUntil the profile is gone for KeepProfile as for Profile.
	wantErr(t, b.KeepProfile(ctx(t), Set1, T0.Add(50*time.Hour), T0.Add(25*time.Hour)), state.ErrNotFound)

	// KeepProfile keeps to the second, as SaveProfile does.
	q := Profile(Set2, []byte("<IMSSubscription>2</IMSSubscription>"), T0)
	q.KeepUntil = T0.Add(time.Hour)
	if err := a.SaveProfile(ctx(t), q); err != nil {
		t.Fatal(err)
	}
	if err := b.KeepProfile(ctx(t), Set2, T0.Add(2*time.Hour+500*time.Millisecond), T0); err != nil {
		t.Fatal(err)
	}
	must(a.Profile(ctx(t), Set2, T0.Add(2*time.Hour-time.Nanosecond)))(t)
	_, err := a.Profile(ctx(t), Set2, T0.Add(2*time.Hour+100*time.Millisecond))
	wantErr(t, err, state.ErrNotFound)
}

// Unregistered returns the record of an unregistered user of impu's set
// (its default identity impu), whose unregistered state ends at until.
func Unregistered(impi, impu string, until time.Time) *state.Registration {
	r := Registration(impi, impu)
	r.Unregistered = until
	return r
}

// testUnregisteredLifeCycle: the record of an unregistered user is read back
// by any instance, is left alone by sweeps until its state ends, and is then
// claimed and deleted like a registration whose last contact expired.
func testUnregisteredLifeCycle(t *testing.T, a, b state.Store, o Options) {
	end := T0.Add(time.Hour)
	must(a.SaveRegistration(ctx(t), Unregistered(IMPI1, IMPU1, end)))(t)
	if err := a.SaveProfile(ctx(t), Profile(Set1, []byte("<IMSSubscription>1</IMSSubscription>"), T0)); err != nil {
		t.Fatal(err)
	}
	// A later terminating request, on another instance, finds the record
	// and through it the stored profile.
	r := must(b.Registration(ctx(t), Key1(IMPU1)))(t)
	if !r.Unregistered.Equal(end) || len(r.Contacts) != 0 || !r.Deregistering.IsZero() {
		t.Fatalf("read back %+v", r)
	}
	must(b.Profile(ctx(t), r.Key, T0.Add(30*time.Minute)))(t)

	before := end.Add(-time.Second)
	if regs := must(b.ExpiringRegistrations(ctx(t), before, 10))(t); len(regs) != 0 {
		t.Error("an unregistered record is listed before its state ends")
	}
	n, err := state.SweepRegistrations(ctx(t), b, before, 10, func(_, _ *state.Registration) error {
		t.Error("a sweep handled an unregistered record before its state ended")
		return nil
	})
	if n != 0 || err != nil {
		t.Fatalf("sweep before the end: %d, %v", n, err)
	}

	eventually(t, o, "the index to list it", func() bool {
		return len(must(a.ExpiringRegistrations(ctx(t), end, 10))(t)) == 1
	})
	called := 0
	n, err = state.SweepRegistrations(ctx(t), a, end, 10, func(before, after *state.Registration) error {
		called++
		if before.Unregistered.IsZero() || !after.Deregistering.Equal(end.Add(state.SweepLease)) {
			t.Errorf("handled %+v then %+v", before, after)
		}
		return nil
	})
	if n != 1 || called != 1 || err != nil {
		t.Fatalf("sweep at the end: %d handled, %d calls, %v", n, called, err)
	}
	_, err = b.Registration(ctx(t), Key1(IMPU1))
	wantErr(t, err, state.ErrNotFound)

	withContact := Unregistered(IMPI1, IMPU2, end)
	withContact.Contacts = Registration(IMPI1, IMPU2, time.Hour).Contacts
	_, err = a.SaveRegistration(ctx(t), withContact)
	wantErr(t, err, state.ErrInvalid)
}

// testRegisterEndsUnregistered: a REGISTER turns the record of an
// unregistered user into a registration with one save conditional on the
// version read, so a copy read before it can no longer be saved.
func testRegisterEndsUnregistered(t *testing.T, a, b state.Store, _ Options) {
	end := T0.Add(time.Hour)
	stale := must(a.SaveRegistration(ctx(t), Unregistered(IMPI1, IMPU1, end)))(t)
	r := must(b.Registration(ctx(t), Key1(IMPU1)))(t)
	r.Unregistered = time.Time{}
	r.Contacts = Registration(IMPI1, IMPU1, 2*time.Hour).Contacts
	registered := must(b.SaveRegistration(ctx(t), r))(t)
	if !registered.SweepAt().Equal(T0.Add(2 * time.Hour)) {
		t.Errorf("SweepAt %v, want the contact's expiry", registered.SweepAt())
	}
	n, err := state.SweepRegistrations(ctx(t), a, end, 10, func(_, _ *state.Registration) error {
		t.Error("a sweep at the old end of the unregistered state handled the registration")
		return nil
	})
	if n != 0 || err != nil {
		t.Fatalf("sweep: %d, %v", n, err)
	}
	stale.Deregistering = end.Add(state.SweepLease)
	_, err = a.SaveRegistration(ctx(t), stale)
	wantErr(t, err, state.ErrConflict)
	if got := must(a.Registration(ctx(t), Key1(IMPU1)))(t); !got.Unregistered.IsZero() || len(got.Contacts) != 1 {
		t.Errorf("after the stale save: %+v", got)
	}
}

// testUnregisteredRetry: a sweep that claims an unregistered record and fails
// to end the state leaves it unlisted for the lease, and the retry after it
// still sees the record as an unregistered user's.
func testUnregisteredRetry(t *testing.T, a, b state.Store, o Options) {
	end := T0.Add(time.Hour)
	must(a.SaveRegistration(ctx(t), Unregistered(IMPI1, IMPU1, end)))(t)
	eventually(t, o, "the index to list it", func() bool {
		return len(must(a.ExpiringRegistrations(ctx(t), end, 10))(t)) == 1
	})
	n, err := state.SweepRegistrations(ctx(t), a, end, 10, func(_, _ *state.Registration) error { return errors.New("HSS down") })
	if n != 1 || err == nil {
		t.Fatalf("first sweep: %d, %v", n, err)
	}
	// Claimed: due at the end of the lease, not at end, which has passed.
	if regs := must(b.ExpiringRegistrations(ctx(t), end.Add(30*time.Second), 10))(t); len(regs) != 0 {
		t.Error("a claimed record is listed within its lease")
	}
	later := end.Add(state.SweepLease + time.Second)
	eventually(t, o, "the index to list it again", func() bool {
		return len(must(b.ExpiringRegistrations(ctx(t), later, 10))(t)) == 1
	})
	called := 0
	if _, err := state.SweepRegistrations(ctx(t), b, later, 10, func(before, _ *state.Registration) error {
		called++
		if before.Unregistered.IsZero() {
			t.Error("the retry lost the unregistered state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("handled %d times", called)
	}
	_, err = a.Registration(ctx(t), Key1(IMPU1))
	wantErr(t, err, state.ErrNotFound)
}

// testDeleteProfileIf: a deregistration deletes the profile it read, never
// one another instance saved since for a registration of its own.
func testDeleteProfileIf(t *testing.T, a, b state.Store, _ Options) {
	if err := a.SaveProfile(ctx(t), Profile(Set1, []byte("<IMSSubscription>1</IMSSubscription>"), T0)); err != nil {
		t.Fatal(err)
	}
	// Another instance's SAA, received later, replaced it.
	if err := b.SaveProfile(ctx(t), Profile(Set1, []byte("<IMSSubscription>2</IMSSubscription>"), T0.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	wantErr(t, a.DeleteProfileIf(ctx(t), Set1, T0), state.ErrConflict)
	if got := must(a.Profile(ctx(t), Set1, T0))(t); string(got.UserData) != "<IMSSubscription>2</IMSSubscription>" {
		t.Errorf("profile %q after a refused delete", got.UserData)
	}
	if err := b.DeleteProfileIf(ctx(t), Set1, T0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := a.Profile(ctx(t), Set1, T0)
	wantErr(t, err, state.ErrNotFound)
	if err := a.DeleteProfileIf(ctx(t), Set1, T0); err != nil {
		t.Errorf("deleting no profile: %v", err)
	}
	if err := a.DeleteProfileIf(ctx(t), state.SetKey{IMPI: IMPI1}, T0); err != nil {
		t.Errorf("deleting an impossible profile: %v", err)
	}
}

// testAttemptCounts: every instance counts into one count per IMPI, kind,
// scope and window, concurrent counts are all counted, and an attempt can be
// given back.
func testAttemptCounts(t *testing.T, a, b state.Store, _ Options) {
	w, exp := T0, T0.Add(2*time.Minute)
	at := state.Attempt{IMPI: IMPI1, Kind: state.AttemptChallenge, Window: w}
	for i, s := range []state.Store{a, b, a} {
		if n := must(s.CountAttempt(ctx(t), at, 1, exp))(t); n != int64(i+1) {
			t.Fatalf("count %d, want %d", n, i+1)
		}
	}
	if n := must(b.CountAttempt(ctx(t), at, -1, exp))(t); n != 2 {
		t.Errorf("after giving one back: %d, want 2", n)
	}
	flow := state.FlowScope("flow-token")
	// Another IMPI, kind, scope or window counts apart.
	for _, c := range []state.Attempt{
		{IMPI: IMPI2, Kind: state.AttemptChallenge, Window: w},
		{IMPI: IMPI1, Kind: state.AttemptResync, Window: w},
		{IMPI: IMPI1, Kind: state.AttemptChallenge, Scope: flow, Window: w},
		{IMPI: IMPI1, Kind: state.AttemptChallenge, Scope: state.FlowScope("another"), Window: w},
		{IMPI: IMPI1, Kind: state.AttemptChallenge, Window: w.Add(time.Minute)},
	} {
		if n := must(b.CountAttempt(ctx(t), c, 1, c.Window.Add(2*time.Minute)))(t); n != 1 {
			t.Errorf("%+v counted %d, want a count of its own", c, n)
		}
	}
	resync := state.Attempt{IMPI: IMPI1, Kind: state.AttemptResync, Window: w}
	var wg sync.WaitGroup
	for range 8 {
		for _, s := range []state.Store{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.CountAttempt(ctx(t), resync, 1, exp); err != nil {
					t.Error(err)
				}
			}()
		}
	}
	wg.Wait()
	if n := must(a.CountAttempt(ctx(t), resync, 1, exp))(t); n != 18 {
		t.Errorf("after 16 concurrent counts and 2 others: %d", n)
	}
	for _, bad := range []struct {
		at  state.Attempt
		n   int64
		exp time.Time
	}{
		{state.Attempt{IMPI: "not an impi", Kind: state.AttemptChallenge, Window: w}, 1, exp},
		{state.Attempt{IMPI: IMPI1, Kind: "other", Window: w}, 1, exp},
		{state.Attempt{IMPI: IMPI1, Kind: state.AttemptChallenge, Scope: "#flow", Window: w}, 1, exp},
		{state.Attempt{IMPI: IMPI1, Kind: state.AttemptChallenge, Scope: strings.ToUpper(flow), Window: w}, 1, exp},
		{at, 2, exp},
		{at, 1, w},
	} {
		_, err := a.CountAttempt(ctx(t), bad.at, bad.n, bad.exp)
		wantErr(t, err, state.ErrInvalid)
	}
}

// testAttemptCountNotAChallenge: counts are kept beside the challenges, so no
// challenge may have a nonce that names one, and taking one finds nothing
// and leaves the count.
func testAttemptCountNotAChallenge(t *testing.T, a, _ state.Store, _ Options) {
	w := T0
	for _, scope := range []string{"", state.FlowScope("flow-token")} {
		at := state.Attempt{IMPI: IMPI1, Kind: state.AttemptChallenge, Scope: scope, Window: w}
		must(a.CountAttempt(ctx(t), at, 1, w.Add(time.Minute)))(t)
		nonce := state.ReservedNoncePrefix + "count#" + state.AttemptChallenge + "#" + scope + "#" + strconv.FormatInt(w.Unix(), 10)
		_, err := a.TakeChallenge(ctx(t), IMPI1, nonce, T0)
		wantErr(t, err, state.ErrNotFound)
		if n := must(a.CountAttempt(ctx(t), at, 1, w.Add(time.Minute)))(t); n != 2 {
			t.Errorf("count %d after a take of it, want 2", n)
		}
	}
	wantErr(t, a.AddChallenge(ctx(t), Challenge(IMPI1, state.ReservedNoncePrefix+"x", time.Minute)), state.ErrInvalid)
}

// testReassertSweep: a live registration whose Reassert has come is handed to
// one sweep, which claims it for a lease, and is due again only when that
// lease ends or the handler moves Reassert.
func testReassertSweep(t *testing.T, a, b state.Store, o Options) {
	r := Registration(IMPI1, IMPU1, time.Hour)
	r.Reassert, r.ReassertAttempts = T0.Add(time.Minute), 1
	must(a.SaveRegistration(ctx(t), r))(t)
	if regs := must(b.ExpiringRegistrations(ctx(t), T0, 10))(t); len(regs) != 0 {
		t.Error("listed before its Reassert")
	}
	at := T0.Add(time.Minute)
	eventually(t, o, "the index to list it", func() bool {
		return len(must(b.ExpiringRegistrations(ctx(t), at, 10))(t)) == 1
	})
	called := 0
	sweep := func(s state.Store, now time.Time) {
		t.Helper()
		if _, err := state.SweepRegistrations(ctx(t), s, now, 10, func(before, after *state.Registration) error {
			called++
			if !before.ReassertDue(now) || len(after.Contacts) != 1 || !after.Reassert.Equal(now.Add(state.SweepLease)) {
				t.Errorf("handled %+v then %+v", before, after)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	sweep(a, at)
	sweep(b, at.Add(state.SweepLease/2))
	if called != 1 {
		t.Fatalf("handled %d times within the lease", called)
	}
	if got := must(a.Registration(ctx(t), Key1(IMPU1)))(t); len(got.Contacts) != 1 || got.ReassertAttempts != 1 {
		t.Errorf("after the sweep: %+v", got)
	}
	bad := Registration(IMPI1, IMPU2, time.Hour)
	bad.ReassertAttempts = state.MaxReassertAttempts + 1
	_, err := a.SaveRegistration(ctx(t), bad)
	wantErr(t, err, state.ErrInvalid)
}

// testReviveTakesANewIncarnation: a record claimed for a deregistration that
// a save brings back, with bindings or as an unregistered user's record, must
// carry a new incarnation, or the deregistration would delete the identities
// of the registration that took it over (#184 QA). Claiming it again keeps
// the incarnation, as does any save of a record not claimed.
func testReviveTakesANewIncarnation(t *testing.T, a, b state.Store, _ Options) {
	live := must(a.SaveRegistration(ctx(t), Registration(IMPI1, IMPU1, time.Hour)))(t)
	lease := live.Clone()
	lease.Contacts, lease.Deregistering = nil, T0.Add(state.SweepLease)
	leased := must(b.SaveRegistration(ctx(t), lease))(t)

	back := leased.Clone()
	back.Contacts, back.Deregistering = live.Contacts, time.Time{}
	_, err := a.SaveRegistration(ctx(t), back)
	wantErr(t, err, state.ErrInvalid)
	unregistered := leased.Clone()
	unregistered.Deregistering, unregistered.Unregistered = time.Time{}, T0.Add(time.Hour)
	_, err = b.SaveRegistration(ctx(t), unregistered)
	wantErr(t, err, state.ErrInvalid)
	// Nor can a binding come back with the lease kept, which would revive
	// the record without its Deregistering going.
	bound := leased.Clone()
	bound.Contacts = live.Contacts
	_, err = a.SaveRegistration(ctx(t), bound)
	wantErr(t, err, state.ErrInvalid)
	// A stale version is a conflict whatever it carries.
	stale := back.Clone()
	stale.Version = live.Version
	_, err = a.SaveRegistration(ctx(t), stale)
	wantErr(t, err, state.ErrConflict)

	again := leased.Clone()
	again.Deregistering = T0.Add(2 * state.SweepLease)
	reclaimed := must(a.SaveRegistration(ctx(t), again))(t)
	back.Version, back.Incarnation = reclaimed.Version, leased.Incarnation+1
	revived := must(b.SaveRegistration(ctx(t), back))(t)
	refreshed := revived.Clone()
	refreshed.Contacts[0].Expires = T0.Add(2 * time.Hour)
	must(a.SaveRegistration(ctx(t), refreshed))(t)
	if got := must(b.Registration(ctx(t), Set1))(t); got.Incarnation != leased.Incarnation+1 || len(got.Contacts) != 1 {
		t.Errorf("after the revival: %+v", got)
	}
}

// testReassertGoesWithTheSet: a set whose Reassert is due and whose last
// binding has expired too is claimed for its deregistration with Reassert
// cleared, so that no handler tells the HSS a dead set is registered here.
func testReassertGoesWithTheSet(t *testing.T, a, b state.Store, o Options) {
	r := Registration(IMPI1, IMPU1, time.Minute)
	r.Reassert, r.ReassertAttempts = T0.Add(time.Minute), 2
	must(a.SaveRegistration(ctx(t), r))(t)
	at := T0.Add(time.Minute)
	eventually(t, o, "the index to list it", func() bool {
		return len(must(b.ExpiringRegistrations(ctx(t), at, 10))(t)) == 1
	})
	handled := 0
	if _, err := state.SweepRegistrations(ctx(t), b, at, 10, func(_, after *state.Registration) error {
		handled++
		if len(after.Contacts) != 0 || !after.Reassert.IsZero() || after.ReassertAttempts != 0 || after.ReassertDue(at) {
			t.Errorf("claimed as %+v", after)
		}
		return errors.New("the HSS is out of reach")
	}); err == nil || handled != 1 {
		t.Fatalf("handled %d, %v", handled, err)
	}
	if got := must(a.Registration(ctx(t), Set1))(t); !got.Reassert.IsZero() || got.ReassertDue(at.Add(state.SweepLease)) {
		t.Errorf("stored as %+v", got)
	}
}

// testRefusedSaveKeepsAGoneProfileGone: a save refused for a later profile
// raises KeepUntil only of a profile still there at the save's Received, as
// KeepProfile would; one already gone stays gone.
func testRefusedSaveKeepsAGoneProfileGone(t *testing.T, a, b state.Store, _ Options) {
	p := Profile(Set1, []byte("<IMSSubscription>later</IMSSubscription>"), T0.Add(2*time.Hour))
	p.KeepUntil = T0.Add(time.Hour)
	if err := a.SaveProfile(ctx(t), p); err != nil {
		t.Fatal(err)
	}
	late := Profile(Set1, []byte("<IMSSubscription>earlier</IMSSubscription>"), T0.Add(90*time.Minute))
	late.KeepUntil = T0.Add(50 * time.Hour)
	wantErr(t, b.SaveProfile(ctx(t), late), state.ErrConflict)
	_, err := a.Profile(ctx(t), Set1, T0.Add(3*time.Hour))
	wantErr(t, err, state.ErrNotFound)
}
