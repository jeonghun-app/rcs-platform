// Package statetest checks a state.Store against the behaviour the S-CSCF
// relies on when several instances share it (ADR 0005). The memory backend runs
// it in every unit test run, the DynamoDB backend against a strict fake there
// and against DynamoDB Local in make test-integration, so the backends cannot
// drift apart.
package statetest

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// Test identities: MCC 001 / MNC 01 and the fictional +1 555 0100 range, as
// .github/allowed-test-identifiers.txt requires.
const (
	Domain = "ims.mnc001.mcc001.3gppnetwork.org"
	IMPI1  = "001010000000001@" + Domain
	IMPI2  = "001010000000002@" + Domain
	IMPU1  = "sip:+15550100001@" + Domain
	TEL1   = "tel:+15550100001"
	IMPU2  = "sip:+15550100002@" + Domain
	IMPU3  = "sip:+15550100003@" + Domain
)

// Two implicit registration sets of IMPI1, by their default IMPUs.
var (
	Set1 = state.SetKey{IMPI: IMPI1, IMPU: IMPU1}
	Set2 = state.SetKey{IMPI: IMPI1, IMPU: IMPU2}
)

// Profile returns a profile of k kept until two days after T0.
func Profile(k state.SetKey, userData []byte, received time.Time) *state.Profile {
	return &state.Profile{Key: k, UserData: userData, Received: received, KeepUntil: T0.Add(48 * time.Hour)}
}

// T0 is the time the checks run at. It lies in the future so that DynamoDB's
// TTL never removes a test item early.
var T0 = time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)

// Options adapts the suite to a backend.
type Options struct {
	// Second returns another handle on the same data as first: what a second
	// S-CSCF instance sees.
	Second func(t *testing.T, first state.Store) state.Store
	// ListingWait is how long the listings may lag a write (DynamoDB global
	// secondary indexes are eventually consistent).
	ListingWait time.Duration
}

// Run runs every check against stores made by newStore, one per subtest.
func Run(t *testing.T, newStore func(t *testing.T) state.Store, o Options) {
	tests := []struct {
		name string
		fn   func(*testing.T, state.Store, state.Store, Options)
	}{
		{"SavedRegistrationReadsBackWithEveryField", testRegistrationRoundTrip},
		{"SavingARegistrationNeedsTheStoredVersion", testRegistrationVersion},
		{"OfTwoInstancesSavingOneRegistrationOnlyOneWins", testRegistrationRace},
		{"RegistrationsAreListedByIMPI", testRegistrationsOf},
		{"DeletingARegistrationNeedsTheStoredVersion", testRegistrationDelete},
		{"ExpiringRegistrationsAreListed", testExpiringRegistrations},
		{"ConcurrentSweepsHandleEveryExpiryOnce", testRegistrationSweep},
		{"InvalidItemsAreRefused", testInvalid},
		{"ReturnedValuesDoNotAliasTheStore", testNoAliasing},
		{"AChallengeStoredByOneInstanceIsFoundByAnother", testChallengeRoundTrip},
		{"AChallengeIsTakenOnceAcrossInstances", testChallengeTakenOnce},
		{"AnExpiredChallengeIsNotFound", testChallengeExpiry},
		{"SubscriptionsReadBackAndAreListedByIMPU", testSubscriptionRoundTrip},
		{"NotifyCountersNeverRepeatAcrossInstances", testNotifyCounters},
		{"NextNotifyInvalidatesEarlierReads", testNotifyVersion},
		{"ConcurrentSweepsEndEverySubscriptionOnce", testSubscriptionSweep},
		{"ASweepFromAStaleListingKeepsAFreshRegistration", testSweepFromAStaleListing},
		{"ASaveFromBeforeADeleteDoesNotOverwriteANewRegistration", testStaleSaveAfterRecreate},
		{"ASubscriptionDeletedAndCreatedAgainRefusesAnOldSave", testStaleSubscriptionSave},
		{"KeysNoItemCanHaveAreNotFound", testImpossibleKeys},
		{"ItemsOverTheSizeLimitAreRefusedByEveryBackend", testItemSize},
		{"BoundaryValuesAreTheSameEverywhere", testBoundaries},
		{"AFailedDeregistrationIsRetriedAfterTheLease", testSweepRetry},
		{"AClaimedSubscriptionKeepsItsGraceFromTheClaim", testTerminatedGrace},
		{"NotifyCountersStopAtTheirLimit", testCounterLimit},
		{"ProfilesAreKeptApartFromRegistrations", testProfiles},
		{"EachImplicitRegistrationSetHasItsOwnProfile", testProfilesPerSet},
		{"APPRForOneSetLeavesTheOtherSetsProfile", testPPRForOneSet},
		{"EveryIdentityOfASetPointsAtItsOneRecord", testIdentities},
		{"AProfileSaveNeverBringsKeepUntilCloser", testSaveProfileKeepsKeepUntil},
		{"AProfileIsNotFoundOnceItsKeepUntilHasCome", testProfileKeepUntil},
		{"KeepProfileOnlyMovesKeepUntilLater", testKeepProfile},
		{"AnUnregisteredUsersRecordLivesUntilItsStateEnds", testUnregisteredLifeCycle},
		{"ARegisterTurnsAnUnregisteredRecordIntoARegistration", testRegisterEndsUnregistered},
		{"AFailedEndOfAnUnregisteredStateIsRetriedAfterTheLease", testUnregisteredRetry},
		{"AConditionalProfileDeleteSparesAProfileSavedSince", testDeleteProfileIf},
		{"ASweepClaimsALiveRegistrationWhoseReassertIsDue", testReassertSweep},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := newStore(t)
			tc.fn(t, a, o.Second(t, a), o)
		})
	}
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

// must turns a (value, error) result into a check: must(f())(t) fails the test
// on an error and returns the value otherwise.
func must[T any](v T, err error) func(*testing.T) T {
	return func(t *testing.T) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

// eventually retries check until it holds or o.ListingWait has passed.
func eventually(t *testing.T, o Options, what string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(o.ListingWait)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Key1 is the key of IMPI1's set whose default identity is impu.
func Key1(impu string) state.SetKey { return state.SetKey{IMPI: IMPI1, IMPU: impu} }

// Registration returns a valid registration of the set of impi whose only
// identity, and so its default, is impu, with one contact per expiry, each
// relative to T0.
func Registration(impi, impu string, expiries ...time.Duration) *state.Registration {
	r := &state.Registration{Key: state.SetKey{IMPI: impi, IMPU: impu}, Incarnation: 1, Identities: []state.SetIdentity{{IMPU: impu}}}
	for i, e := range expiries {
		r.Contacts = append(r.Contacts, state.Contact{
			URI:        fmt.Sprintf("sip:ue%d@192.0.2.%d:5060;transport=tcp", i, 10+i),
			InstanceID: fmt.Sprintf("<urn:uuid:00000000-0000-0000-0000-00000000000%d>", i),
			RegID:      1,
			Path:       []string{"<sip:flow-token@pcscf.rcs.local;lr;ob>"},
			Expires:    T0.Add(e),
			FeatureTags: []string{
				`+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"`,
			},
			CallID:    fmt.Sprintf("call-%d", i),
			CSeq:      uint32(10 + i),
			FlowToken: "flow-token",
			KeepAlive: true,
		})
	}
	return r
}

func testRegistrationRoundTrip(t *testing.T, a, b state.Store, _ Options) {
	r := Registration(IMPI1, IMPU1, time.Hour, 2*time.Hour)
	r.Contacts[1].Q = 500
	saved := must(a.SaveRegistration(ctx(t), r))(t)
	if saved.Version == 0 {
		t.Error("a saved registration has version 0")
	}
	r.Version = saved.Version
	for _, s := range []state.Store{a, b} {
		got := must(s.Registration(ctx(t), Key1(IMPU1)))(t)
		if !reflect.DeepEqual(got, r) {
			t.Errorf("read %+v, want %+v", got, r)
		}
	}
	again := Registration(IMPI1, IMPU1, time.Hour)
	_, err := b.SaveRegistration(ctx(t), again)
	wantErr(t, err, state.ErrExists)
	_, err = a.Registration(ctx(t), Key1(IMPU2))
	wantErr(t, err, state.ErrNotFound)
}

func testRegistrationVersion(t *testing.T, a, b state.Store, _ Options) {
	v1 := must(a.SaveRegistration(ctx(t), Registration(IMPI1, IMPU1, time.Hour)))(t)
	next := v1.Clone()
	next.Contacts[0].CSeq++
	v2 := must(b.SaveRegistration(ctx(t), next))(t)
	if v2.Version == v1.Version {
		t.Error("an update kept the version")
	}
	_, err := a.SaveRegistration(ctx(t), v1)
	wantErr(t, err, state.ErrConflict)
	missing := Registration(IMPI1, IMPU2, time.Hour)
	missing.Version = 3
	_, err = a.SaveRegistration(ctx(t), missing)
	wantErr(t, err, state.ErrNotFound)
	if got := must(a.Registration(ctx(t), Key1(IMPU1)))(t); got.Contacts[0].CSeq != next.Contacts[0].CSeq {
		t.Error("a refused save changed the registration")
	}
}

func testRegistrationRace(t *testing.T, a, b state.Store, _ Options) {
	read := must(a.SaveRegistration(ctx(t), Registration(IMPI1, IMPU1, time.Hour)))(t)
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i, s := range []state.Store{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			next := read.Clone()
			next.Contacts[0].CSeq = uint32(100 + i)
			_, results[i] = s.SaveRegistration(ctx(t), next)
		}()
	}
	wg.Wait()
	won := 0
	for _, err := range results {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, state.ErrConflict):
			t.Fatalf("unexpected error %v", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d saves based on the same version succeeded, want 1", won)
	}
}

func testRegistrationsOf(t *testing.T, a, b state.Store, o Options) {
	for _, impu := range []string{IMPU1, TEL1, IMPU2} {
		must(a.SaveRegistration(ctx(t), Registration(IMPI1, impu, time.Hour)))(t)
	}
	must(a.SaveRegistration(ctx(t), Registration(IMPI2, IMPU3, time.Hour)))(t)
	want := []string{IMPU1, IMPU2, TEL1}
	var got []string
	eventually(t, o, "listing every IMPU of IMPI1", func() bool {
		got = nil
		for _, r := range must(b.RegistrationsOf(ctx(t), IMPI1))(t) {
			got = append(got, r.Key.IMPU)
		}
		return slices.Equal(got, want)
	})
	if regs := must(b.RegistrationsOf(ctx(t), "nobody@"+Domain))(t); len(regs) != 0 {
		t.Errorf("an unknown IMPI lists %d registrations", len(regs))
	}
}

func testRegistrationDelete(t *testing.T, a, b state.Store, _ Options) {
	v1 := must(a.SaveRegistration(ctx(t), Registration(IMPI1, IMPU1, time.Hour)))(t)
	v2 := must(a.SaveRegistration(ctx(t), v1))(t)
	wantErr(t, b.DeleteRegistration(ctx(t), v1), state.ErrConflict)
	if err := b.DeleteRegistration(ctx(t), v2); err != nil {
		t.Fatal(err)
	}
	_, err := a.Registration(ctx(t), Key1(IMPU1))
	wantErr(t, err, state.ErrNotFound)
	wantErr(t, a.DeleteRegistration(ctx(t), v2), state.ErrNotFound)
}

func testExpiringRegistrations(t *testing.T, a, b state.Store, o Options) {
	must(a.SaveRegistration(ctx(t), Registration(IMPI1, IMPU1, -time.Minute, time.Hour)))(t)
	must(a.SaveRegistration(ctx(t), Registration(IMPI1, IMPU2, -2*time.Minute)))(t)
	must(a.SaveRegistration(ctx(t), Registration(IMPI1, TEL1, time.Hour)))(t)
	empty := Registration(IMPI2, IMPU3)
	must(a.SaveRegistration(ctx(t), empty))(t)
	want := []string{IMPU1, IMPU2, IMPU3}
	eventually(t, o, "listing the expired and empty registrations", func() bool {
		var got []string
		for _, r := range must(b.ExpiringRegistrations(ctx(t), T0, 10))(t) {
			got = append(got, r.Key.IMPU)
		}
		slices.Sort(got)
		return slices.Equal(got, want)
	})
	if got := must(b.ExpiringRegistrations(ctx(t), T0, 2))(t); len(got) != 2 {
		t.Errorf("listed %d registrations with limit 2", len(got))
	}
	if got := must(b.ExpiringRegistrations(ctx(t), T0.Add(-time.Hour), 10))(t); len(got) != 1 {
		t.Errorf("an hour earlier, %d registrations are expiring, want only the empty one", len(got))
	}
}

func testRegistrationSweep(t *testing.T, a, b state.Store, o Options) {
	must(a.SaveRegistration(ctx(t), Registration(IMPI1, IMPU1, -time.Minute, time.Hour)))(t)
	must(a.SaveRegistration(ctx(t), Registration(IMPI1, IMPU2, -time.Minute)))(t)
	must(a.SaveRegistration(ctx(t), Registration(IMPI1, IMPU3, -time.Second, -time.Hour)))(t)
	eventually(t, o, "the index to list the three", func() bool {
		return len(must(b.ExpiringRegistrations(ctx(t), T0, 10))(t)) == 3
	})
	var mu sync.Mutex
	handled := map[string]int{}
	left := map[string]int{}
	var wg sync.WaitGroup
	for range 4 {
		for _, s := range []state.Store{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := state.SweepRegistrations(ctx(t), s, T0, 10, func(before, after *state.Registration) error {
					mu.Lock()
					defer mu.Unlock()
					handled[before.Key.IMPU]++
					left[before.Key.IMPU] = len(after.Contacts)
					return nil
				})
				if err != nil {
					t.Error(err)
				}
			}()
		}
	}
	wg.Wait()
	want := map[string]int{IMPU1: 1, IMPU2: 1, IMPU3: 1}
	if !reflect.DeepEqual(handled, want) {
		t.Fatalf("handled %v, want each registration once", handled)
	}
	if !reflect.DeepEqual(left, map[string]int{IMPU1: 1, IMPU2: 0, IMPU3: 0}) {
		t.Errorf("contacts left %v", left)
	}
	if got := must(a.Registration(ctx(t), Key1(IMPU1)))(t); len(got.Contacts) != 1 || got.Contacts[0].Expired(T0) {
		t.Errorf("the registration with a live contact kept %+v", got.Contacts)
	}
	for _, impu := range []string{IMPU2, IMPU3} {
		_, err := a.Registration(ctx(t), Key1(impu))
		wantErr(t, err, state.ErrNotFound)
	}
}

func testInvalid(t *testing.T, a, _ state.Store, _ Options) {
	nonCanonical := Registration(IMPI1, "sip:+15550100001@IMS.MNC001.MCC001.3GPPNETWORK.ORG", time.Hour)
	tooMany := Registration(IMPI1, IMPU1)
	for range state.MaxContacts + 1 {
		tooMany.Contacts = append(tooMany.Contacts, Registration(IMPI1, IMPU1, time.Hour).Contacts[0])
	}
	badIMPI := Registration("not an impi", IMPU1, time.Hour)
	noDefault := Registration(IMPI1, IMPU1, time.Hour)
	noDefault.Identities = []state.SetIdentity{{IMPU: IMPU2}}
	noIncarnation := Registration(IMPI1, IMPU1, time.Hour)
	noIncarnation.Incarnation = 0
	tooManyIdentities := Registration(IMPI1, IMPU1, time.Hour)
	for i := range state.MaxIdentities {
		tooManyIdentities.Identities = append(tooManyIdentities.Identities, state.SetIdentity{IMPU: fmt.Sprintf("sip:id%d@%s", i, Domain)})
	}
	before1970 := Registration(IMPI1, IMPU1)
	before1970.Unregistered = time.Date(1969, 12, 31, 0, 0, 0, 0, time.UTC)
	after9999 := Registration(IMPI1, IMPU1)
	after9999.Unregistered = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, r := range []*state.Registration{nonCanonical, tooMany, badIMPI, noDefault, noIncarnation, tooManyIdentities, before1970, after9999} {
		_, err := a.SaveRegistration(ctx(t), r)
		wantErr(t, err, state.ErrInvalid)
	}
	resyncDigest := &state.Challenge{
		IMPI: IMPI1, Nonce: "n", IMPU: IMPU1, Issued: T0, Expires: T0.Add(time.Minute), Resynchronised: true,
		Digest: &state.DigestChallenge{Realm: Domain, Algorithm: "MD5", QoP: "auth", HA1: "0123456789abcdef0123456789abcdef"},
	}
	wantErr(t, a.AddChallenge(ctx(t), resyncDigest), state.ErrInvalid)
	both := Challenge(IMPI1, "n", time.Minute)
	both.Digest = &state.DigestChallenge{Realm: Domain, HA1: "00"}
	wantErr(t, a.AddChallenge(ctx(t), both), state.ErrInvalid)
	noDialog := Subscription("s1", IMPU1, time.Hour)
	noDialog.Dialog.CallID = ""
	_, err := a.SaveSubscription(ctx(t), noDialog)
	wantErr(t, err, state.ErrInvalid)
}

func testNoAliasing(t *testing.T, a, _ state.Store, _ Options) {
	r := Registration(IMPI1, IMPU1, time.Hour)
	saved := must(a.SaveRegistration(ctx(t), r))(t)
	r.Contacts[0].Path[0] = "changed"
	saved.Contacts[0].Path[0] = "changed"
	read := must(a.Registration(ctx(t), Key1(IMPU1)))(t)
	read.Contacts[0].Path[0] = "changed"
	if got := must(a.Registration(ctx(t), Key1(IMPU1)))(t); got.Contacts[0].Path[0] == "changed" {
		t.Error("a caller's change reached the stored registration")
	}
}

// Challenge returns an AKA challenge of impi expiring after ttl.
func Challenge(impi, nonce string, ttl time.Duration) *state.Challenge {
	return &state.Challenge{
		IMPI: impi, Nonce: nonce, IMPU: IMPU1, Issued: T0.Add(ttl - time.Minute), Expires: T0.Add(ttl),
		AKA: &state.AKAVector{
			RAND: []byte("0123456789abcdef"), AUTN: []byte("fedcba9876543210"),
			XRES: []byte("xres0123"), CK: []byte("ck-0123456789abc"), IK: []byte("ik-0123456789abc"),
		},
	}
}

func testChallengeRoundTrip(t *testing.T, a, b state.Store, _ Options) {
	aka := Challenge(IMPI1, "nonce-aka", time.Minute)
	if err := a.AddChallenge(ctx(t), aka); err != nil {
		t.Fatal(err)
	}
	digest := &state.Challenge{
		IMPI: IMPI1, Nonce: "nonce-digest", IMPU: IMPU1, Issued: T0, Expires: T0.Add(time.Minute),
		Digest: &state.DigestChallenge{Realm: Domain, Algorithm: "MD5", QoP: "auth", Opaque: "op", HA1: "0123456789abcdef0123456789abcdef"},
	}
	if err := a.AddChallenge(ctx(t), digest); err != nil {
		t.Fatal(err)
	}
	resync := Challenge(IMPI1, "nonce-resync", time.Minute)
	resync.Resynchronised = true
	if err := a.AddChallenge(ctx(t), resync); err != nil {
		t.Fatal(err)
	}
	wantErr(t, b.AddChallenge(ctx(t), Challenge(IMPI1, "nonce-aka", time.Minute)), state.ErrExists)
	for _, want := range []*state.Challenge{aka, digest, resync} {
		got := must(b.TakeChallenge(ctx(t), want.IMPI, want.Nonce, T0))(t)
		if !sameChallenge(got, want) {
			t.Errorf("the second instance took %#v, want %#v", got, want)
		}
	}
	_, err := b.TakeChallenge(ctx(t), IMPI2, "nonce-aka", T0)
	wantErr(t, err, state.ErrNotFound)
}

func testChallengeTakenOnce(t *testing.T, a, b state.Store, _ Options) {
	c := Challenge(IMPI1, "nonce", time.Minute)
	if err := a.AddChallenge(ctx(t), c); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	taken := 0
	var wg sync.WaitGroup
	for range 4 {
		for _, s := range []state.Store{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, err := s.TakeChallenge(ctx(t), IMPI1, "nonce", T0)
				if errors.Is(err, state.ErrNotFound) {
					return
				}
				if err != nil {
					t.Error(err)
					return
				}
				if !sameChallenge(got, c) {
					t.Errorf("took %#v, want %#v", got, c)
				}
				mu.Lock()
				taken++
				mu.Unlock()
			}()
		}
	}
	wg.Wait()
	if taken != 1 {
		t.Fatalf("the challenge was taken %d times, want once", taken)
	}
	_, err := a.TakeChallenge(ctx(t), IMPI1, "nonce", T0)
	wantErr(t, err, state.ErrNotFound)
}

func testChallengeExpiry(t *testing.T, a, b state.Store, _ Options) {
	if err := a.AddChallenge(ctx(t), Challenge(IMPI1, "nonce", time.Minute)); err != nil {
		t.Fatal(err)
	}
	_, err := b.TakeChallenge(ctx(t), IMPI1, "nonce", T0.Add(time.Minute))
	wantErr(t, err, state.ErrNotFound)
}

// Subscription returns a reg event subscription to impu expiring after ttl.
func Subscription(id, impu string, ttl time.Duration) *state.Subscription {
	return &state.Subscription{
		ID: id, IMPU: impu, Subscriber: "sip:pcscf.rcs.local", Expires: T0.Add(ttl),
		Dialog: state.Dialog{
			CallID: "dialog-" + id, LocalTag: "local", RemoteTag: "remote",
			LocalURI: impu, RemoteURI: "sip:pcscf.rcs.local", RemoteTarget: "sip:pcscf@192.0.2.20:5060",
			RouteSet: []string{"<sip:pcscf.rcs.local;lr>"},
		},
	}
}

func testSubscriptionRoundTrip(t *testing.T, a, b state.Store, o Options) {
	s := Subscription("s1", IMPU1, time.Hour)
	saved := must(a.SaveSubscription(ctx(t), s))(t)
	s.Version = saved.Version
	if !reflect.DeepEqual(saved, s) {
		t.Errorf("saved %+v, want %+v", saved, s)
	}
	if got := must(b.Subscription(ctx(t), "s1"))(t); !reflect.DeepEqual(got, s) {
		t.Errorf("read %+v, want %+v", got, s)
	}
	_, err := b.SaveSubscription(ctx(t), Subscription("s1", IMPU1, time.Hour))
	wantErr(t, err, state.ErrExists)
	must(a.SaveSubscription(ctx(t), Subscription("s2", IMPU1, time.Hour)))(t)
	must(a.SaveSubscription(ctx(t), Subscription("s3", IMPU2, time.Hour)))(t)
	eventually(t, o, "listing the subscriptions of IMPU1", func() bool {
		var ids []string
		for _, s := range must(b.SubscriptionsOf(ctx(t), IMPU1))(t) {
			ids = append(ids, s.ID)
		}
		return slices.Equal(ids, []string{"s1", "s2"})
	})
	if err := b.DeleteSubscription(ctx(t), s); err != nil {
		t.Fatal(err)
	}
	_, err = a.Subscription(ctx(t), "s1")
	wantErr(t, err, state.ErrNotFound)
	_, _, err = a.NextNotify(ctx(t), "s1")
	wantErr(t, err, state.ErrNotFound)
}

func testNotifyCounters(t *testing.T, a, b state.Store, _ Options) {
	start := Subscription("s1", IMPU1, time.Hour)
	start.CSeq, start.ReginfoVersion = 7, 0
	must(a.SaveSubscription(ctx(t), start))(t)
	const each = 10
	var mu sync.Mutex
	var cseqs, versions []uint32
	var wg sync.WaitGroup
	for range 2 {
		for _, s := range []state.Store{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range each {
					c, v, err := s.NextNotify(ctx(t), "s1")
					if err != nil {
						t.Error(err)
						return
					}
					mu.Lock()
					cseqs = append(cseqs, c)
					versions = append(versions, v)
					mu.Unlock()
				}
			}()
		}
	}
	wg.Wait()
	slices.Sort(cseqs)
	slices.Sort(versions)
	for i := range cseqs {
		if cseqs[i] != 8+uint32(i) || versions[i] != 1+uint32(i) {
			t.Fatalf("CSeqs %v and versions %v are not each used once in sequence", cseqs, versions)
		}
	}
	got := must(a.Subscription(ctx(t), "s1"))(t)
	if got.CSeq != 7+4*each || got.ReginfoVersion != 4*each {
		t.Errorf("stored counters %d and %d", got.CSeq, got.ReginfoVersion)
	}
}

func testNotifyVersion(t *testing.T, a, b state.Store, _ Options) {
	read := must(a.SaveSubscription(ctx(t), Subscription("s1", IMPU1, time.Hour)))(t)
	if _, _, err := b.NextNotify(ctx(t), "s1"); err != nil {
		t.Fatal(err)
	}
	refresh := read.Clone()
	refresh.Expires = T0.Add(2 * time.Hour)
	_, err := a.SaveSubscription(ctx(t), refresh)
	wantErr(t, err, state.ErrConflict)
	fresh := must(a.Subscription(ctx(t), "s1"))(t)
	fresh.Expires = T0.Add(2 * time.Hour)
	must(a.SaveSubscription(ctx(t), fresh))(t)
	if c, v, err := b.NextNotify(ctx(t), "s1"); err != nil || c != 2 || v != 2 {
		t.Errorf("after a refresh NextNotify = %d, %d, %v; want the counters kept", c, v, err)
	}
}

func testSubscriptionSweep(t *testing.T, a, b state.Store, o Options) {
	must(a.SaveSubscription(ctx(t), Subscription("s1", IMPU1, -time.Minute)))(t)
	must(a.SaveSubscription(ctx(t), Subscription("s2", IMPU1, -time.Second)))(t)
	must(a.SaveSubscription(ctx(t), Subscription("s3", IMPU1, time.Hour)))(t)
	eventually(t, o, "the index to list the expired two", func() bool {
		return len(must(b.ExpiringSubscriptions(ctx(t), T0, 10))(t)) == 2
	})
	var mu sync.Mutex
	handled := map[string]int{}
	var wg sync.WaitGroup
	for range 4 {
		for _, s := range []state.Store{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := state.SweepSubscriptions(ctx(t), s, T0, 10, func(sub *state.Subscription) {
					// The final NOTIFY takes the next CSeq.
					if _, _, err := s.NextNotify(ctx(t), sub.ID); err != nil {
						t.Error(err)
					}
					mu.Lock()
					handled[sub.ID]++
					mu.Unlock()
				})
				if err != nil {
					t.Error(err)
				}
			}()
		}
	}
	wg.Wait()
	if !reflect.DeepEqual(handled, map[string]int{"s1": 1, "s2": 1}) {
		t.Fatalf("handled %v, want each expired subscription once", handled)
	}
	for _, id := range []string{"s1", "s2"} {
		_, err := a.Subscription(ctx(t), id)
		wantErr(t, err, state.ErrNotFound)
	}
	must(a.Subscription(ctx(t), "s3"))(t)
}
