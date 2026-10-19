// Package storetest checks a store.Store implementation against the
// behaviour the HSS relies on. The memory backend runs it in every unit test
// run and the DynamoDB backend against DynamoDB Local (make
// test-integration), so the two cannot drift apart.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/hss/keyring"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

// Test identities: MCC 001 / MNC 01 and the fictional +1 555 0100 range, as
// .github/allowed-test-identifiers.txt requires.
const (
	Domain = "ims.mnc001.mcc001.3gppnetwork.org"
	IMSI1  = "001010000000001"
	IMPI1  = IMSI1 + "@" + Domain
	IMPI2  = "001010000000002@" + Domain
	IMPU1  = "sip:+15550100001@" + Domain
	TEL1   = "tel:+15550100001"
	IMPU2  = "sip:+15550100002@" + Domain
	IMPU3  = "sip:+15550100003@" + Domain
)

// Profile returns a small valid service profile.
func Profile(id string) *store.ServiceProfile {
	return &store.ServiceProfile{
		ID: id,
		Criteria: []ifc.FilterCriteria{{
			Priority: 10,
			TriggerPoint: &ifc.TriggerPoint{SPTs: []ifc.SPT{
				{Groups: []int{0}, Condition: ifc.Method("MESSAGE")},
			}},
			ApplicationServer: ifc.ApplicationServer{ServerName: "sip:rcs-as.rcs.local", DefaultHandling: ifc.SessionTerminated},
		}},
		MandatoryCapabilities: []uint32{1},
		OptionalCapabilities:  []uint32{2, 3},
	}
}

// Subscription returns a valid subscription of impi with the IMPUs, using
// profile.
func Subscription(impi, profile string, impus ...string) *store.Subscription {
	s := &store.Subscription{IMPI: impi, Profile: profile}
	for _, impu := range impus {
		s.PublicIdentities = append(s.PublicIdentities, store.PublicIdentity{IMPU: impu})
	}
	return s
}

// Options adapts the suite to a backend.
type Options struct {
	// ListingWait is how long SubscriptionsByProfile may lag a write
	// (DynamoDB global secondary indexes are eventually consistent).
	ListingWait time.Duration
}

// Run runs every check against stores made by newStore, one per subtest.
func Run(t *testing.T, newStore func(t *testing.T) store.Store, o Options) {
	tests := []struct {
		name string
		fn   func(*testing.T, store.Store, Options)
	}{
		{"CreatedSubscriptionReadsBackByIMPIAndEveryIMPU", testCreateAndRead},
		{"EveryFieldSurvivesTheStore", testEveryField},
		{"CreateRefusesTakenKeysAndMissingProfiles", testCreateRefusals},
		{"UpdateNeedsTheStoredVersion", testUpdateVersion},
		{"UpdateMovesTheIMPUIndex", testUpdateIdentities},
		{"UpdateRefusesATakenIMPUAndChangesNothing", testUpdateTakenIdentity},
		{"DeleteFreesTheIMPUs", testDelete},
		{"ReturnedValuesDoNotAliasTheStore", testNoAliasing},
		{"ConcurrentWritersNeverLoseAnUpdate", testConcurrentUpdates},
		{"SubscriptionsAreListedByProfileInPages", testListByProfile},
		{"ProfilesHaveVersionsAndCannotBeDeletedInUse", testProfiles},
		{"OnlyOneFirstDataKeyIsStored", testDataKeys},
		{"StoredSubscriptionsAreSeen", testHasSubscriptions},
		{"AProfileCarryingItsCompiledSetIsNotCompiledAgain", testPrecompiledProfile},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, newStore(t), o) })
	}
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

// must turns a (value, error) result into a check: must(f())(t) fails the
// test on an error and returns the value otherwise.
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

func withProfile(t *testing.T, s store.Store, id string) {
	t.Helper()
	must(s.CreateProfile(ctx(t), Profile(id)))(t)
}

func testCreateAndRead(t *testing.T, s store.Store, _ Options) {
	withProfile(t, s, "p")
	created := must(s.CreateSubscription(ctx(t), Subscription(IMPI1, "p", IMPU1, TEL1)))(t)
	if created.Version != 1 {
		t.Errorf("version after create = %d, want 1", created.Version)
	}
	for _, read := range []func() (*store.Subscription, error){
		func() (*store.Subscription, error) { return s.Subscription(ctx(t), IMPI1) },
		func() (*store.Subscription, error) { return s.SubscriptionByIMPU(ctx(t), IMPU1) },
		func() (*store.Subscription, error) { return s.SubscriptionByIMPU(ctx(t), TEL1) },
	} {
		got := must(read())(t)
		if !reflect.DeepEqual(got, created) {
			t.Errorf("read %+v, want %+v", got, created)
		}
	}
	_, err := s.Subscription(ctx(t), IMPI2)
	wantErr(t, err, store.ErrNotFound)
	_, err = s.SubscriptionByIMPU(ctx(t), IMPU2)
	wantErr(t, err, store.ErrNotFound)
}

func testEveryField(t *testing.T, s store.Store, _ Options) {
	withProfile(t, s, "p")
	in := &store.Subscription{
		IMPI: IMPI1, IMSI: IMSI1, Profile: "p",
		PublicIdentities: []store.PublicIdentity{
			{IMPU: IMPU1, ImplicitSet: 1, State: store.Registered},
			{IMPU: TEL1, ImplicitSet: 1, State: store.Registered, Barred: true},
			{IMPU: IMPU2, ImplicitSet: 2, State: store.Unregistered},
		},
		AKA: &store.AKA{K: store.Sealed{1, 2}, OPc: store.Sealed{3, 4}, AMF: [2]byte{0x80, 0}, SQN: 1<<48 - 1},
		Digest: []store.DigestCredential{
			{Realm: Domain, HA1MD5: store.Sealed{5}, HA1SHA256: store.Sealed{6}},
			{Realm: "ft." + Domain, HA1MD5: store.Sealed{7}, HA1SHA256: store.Sealed{8}},
		},
		Charging: &store.ChargingInformation{
			PrimaryEventChargingFunctionName: "aaa://ecf1." + Domain, SecondaryEventChargingFunctionName: "aaa://ecf2." + Domain,
			PrimaryChargingCollectionFunctionName: "aaa://ccf1." + Domain, SecondaryChargingCollectionFunctionName: "aaa://ccf2." + Domain,
		},
		ACSManaged:  true,
		ServerName:  "sip:scscf.rcs.local",
		AuthPending: true,
	}
	created := must(s.CreateSubscription(ctx(t), in))(t)
	in.Version = 1
	if !reflect.DeepEqual(created, in) {
		t.Errorf("stored\n %+v\nwant\n %+v", created, in)
	}
	got := must(s.Subscription(ctx(t), IMPI1))(t)
	if !reflect.DeepEqual(got, in) {
		t.Errorf("read\n %+v\nwant\n %+v", got, in)
	}
}

func testCreateRefusals(t *testing.T, s store.Store, _ Options) {
	withProfile(t, s, "p")
	must(s.CreateSubscription(ctx(t), Subscription(IMPI1, "p", IMPU1)))(t)
	_, err := s.CreateSubscription(ctx(t), Subscription(IMPI1, "p", IMPU2))
	wantErr(t, err, store.ErrExists)
	_, err = s.CreateSubscription(ctx(t), Subscription(IMPI2, "p", IMPU2, IMPU1))
	wantErr(t, err, store.ErrIdentityInUse)
	_, err = s.CreateSubscription(ctx(t), Subscription(IMPI2, "missing", IMPU2))
	wantErr(t, err, store.ErrProfileMissing)
	// A refused create leaves nothing behind: IMPU2 is still free.
	_, err = s.SubscriptionByIMPU(ctx(t), IMPU2)
	wantErr(t, err, store.ErrNotFound)
	must(s.CreateSubscription(ctx(t), Subscription(IMPI2, "p", IMPU2)))(t)
	_, err = s.CreateSubscription(ctx(t), &store.Subscription{IMPI: "x", Profile: "p"})
	wantErr(t, err, store.ErrInvalid)
}

func testUpdateVersion(t *testing.T, s store.Store, _ Options) {
	withProfile(t, s, "p")
	v1 := must(s.CreateSubscription(ctx(t), Subscription(IMPI1, "p", IMPU1)))(t)
	next := *v1
	next.ServerName = "sip:scscf.rcs.local"
	v2 := must(s.UpdateSubscription(ctx(t), v1, &next))(t)
	if v2.Version != 2 || v2.ServerName != next.ServerName {
		t.Errorf("after update: %+v", v2)
	}
	stale := *v1
	stale.AuthPending = true
	_, err := s.UpdateSubscription(ctx(t), v1, &stale)
	wantErr(t, err, store.ErrConflict)
	got := must(s.Subscription(ctx(t), IMPI1))(t)
	if got.AuthPending || got.Version != 2 {
		t.Errorf("a stale update was applied: %+v", got)
	}
	gone := Subscription(IMPI2, "p", IMPU2)
	gone.Version = 1
	_, err = s.UpdateSubscription(ctx(t), gone, gone)
	wantErr(t, err, store.ErrNotFound)
	missing := *v2
	missing.Profile = "missing"
	_, err = s.UpdateSubscription(ctx(t), v2, &missing)
	wantErr(t, err, store.ErrProfileMissing)
}

func testUpdateIdentities(t *testing.T, s store.Store, _ Options) {
	withProfile(t, s, "p")
	v1 := must(s.CreateSubscription(ctx(t), Subscription(IMPI1, "p", IMPU1, IMPU2)))(t)
	next := Subscription(IMPI1, "p", IMPU2, IMPU3)
	must(s.UpdateSubscription(ctx(t), v1, next))(t)
	_, err := s.SubscriptionByIMPU(ctx(t), IMPU1)
	wantErr(t, err, store.ErrNotFound)
	for _, impu := range []string{IMPU2, IMPU3} {
		if got := must(s.SubscriptionByIMPU(ctx(t), impu))(t); got.IMPI != IMPI1 {
			t.Errorf("%s belongs to %s", impu, got.IMPI)
		}
	}
	// The removed identity is free for another subscription.
	must(s.CreateSubscription(ctx(t), Subscription(IMPI2, "p", IMPU1)))(t)
}

func testUpdateTakenIdentity(t *testing.T, s store.Store, _ Options) {
	withProfile(t, s, "p")
	v1 := must(s.CreateSubscription(ctx(t), Subscription(IMPI1, "p", IMPU1)))(t)
	must(s.CreateSubscription(ctx(t), Subscription(IMPI2, "p", IMPU2)))(t)
	_, err := s.UpdateSubscription(ctx(t), v1, Subscription(IMPI1, "p", IMPU3, IMPU2))
	wantErr(t, err, store.ErrIdentityInUse)
	got := must(s.Subscription(ctx(t), IMPI1))(t)
	if got.Version != 1 || len(got.PublicIdentities) != 1 {
		t.Errorf("a refused update changed the subscription: %+v", got)
	}
	_, err = s.SubscriptionByIMPU(ctx(t), IMPU3)
	wantErr(t, err, store.ErrNotFound)
}

func testDelete(t *testing.T, s store.Store, _ Options) {
	withProfile(t, s, "p")
	v1 := must(s.CreateSubscription(ctx(t), Subscription(IMPI1, "p", IMPU1, TEL1)))(t)
	next := *v1
	next.ServerName = "sip:scscf.rcs.local"
	must(s.UpdateSubscription(ctx(t), v1, &next))(t)
	wantErr(t, s.DeleteSubscription(ctx(t), v1), store.ErrConflict)
	cur := must(s.Subscription(ctx(t), IMPI1))(t)
	if err := s.DeleteSubscription(ctx(t), cur); err != nil {
		t.Fatal(err)
	}
	_, err := s.Subscription(ctx(t), IMPI1)
	wantErr(t, err, store.ErrNotFound)
	_, err = s.SubscriptionByIMPU(ctx(t), TEL1)
	wantErr(t, err, store.ErrNotFound)
	wantErr(t, s.DeleteSubscription(ctx(t), cur), store.ErrNotFound)
	must(s.CreateSubscription(ctx(t), Subscription(IMPI2, "p", IMPU1, TEL1)))(t)
}

func testNoAliasing(t *testing.T, s store.Store, _ Options) {
	withProfile(t, s, "p")
	in := Subscription(IMPI1, "p", IMPU1)
	in.AKA = &store.AKA{K: store.Sealed{1}, OPc: store.Sealed{2}}
	created := must(s.CreateSubscription(ctx(t), in))(t)
	in.PublicIdentities[0].Barred = true
	in.AKA.K[0] = 9
	created.PublicIdentities[0].State = store.Registered
	created.AKA.OPc[0] = 9
	got := must(s.Subscription(ctx(t), IMPI1))(t)
	if got.PublicIdentities[0].Barred || got.PublicIdentities[0].State != store.NotRegistered || got.AKA.K[0] != 1 || got.AKA.OPc[0] != 2 {
		t.Errorf("stored value changed through an alias: %+v", got)
	}
	p := must(s.Profile(ctx(t), "p"))(t)
	p.Criteria[0].Priority = 99
	if again := must(s.Profile(ctx(t), "p"))(t); again.Criteria[0].Priority != 10 {
		t.Error("stored profile changed through an alias")
	}
}

// testConcurrentUpdates is the property SQN allocation rests on: writers
// that retry on ErrConflict each see their increment applied exactly once.
func testConcurrentUpdates(t *testing.T, s store.Store, _ Options) {
	withProfile(t, s, "p")
	in := Subscription(IMPI1, "p", IMPU1)
	in.AKA = &store.AKA{K: store.Sealed{1}, OPc: store.Sealed{2}}
	must(s.CreateSubscription(ctx(t), in))(t)
	const writers, each = 8, 5
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				for attempt := 0; ; attempt++ {
					cur, err := s.Subscription(ctx(t), IMPI1)
					if err != nil {
						errs <- err
						return
					}
					next := *cur
					aka := *cur.AKA
					aka.SQN++
					next.AKA = &aka
					_, err = s.UpdateSubscription(ctx(t), cur, &next)
					if err == nil {
						break
					}
					if !errors.Is(err, store.ErrConflict) || attempt > 1000 {
						errs <- err
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	got := must(s.Subscription(ctx(t), IMPI1))(t)
	if got.AKA.SQN != writers*each || got.Version != 1+writers*each {
		t.Errorf("SQN = %d, version = %d; want %d, %d", got.AKA.SQN, got.Version, writers*each, 1+writers*each)
	}
}

func testListByProfile(t *testing.T, s store.Store, o Options) {
	withProfile(t, s, "p")
	withProfile(t, s, "other")
	want := map[string]bool{}
	for i := range 7 {
		impi := fmt.Sprintf("user%d@%s", i, Domain)
		must(s.CreateSubscription(ctx(t), Subscription(impi, "p", fmt.Sprintf("sip:user%d@%s", i, Domain))))(t)
		want[impi] = true
	}
	must(s.CreateSubscription(ctx(t), Subscription(IMPI2, "other", IMPU2)))(t)
	deadline := time.Now().Add(o.ListingWait)
	for {
		got, pages := map[string]bool{}, 0
		cursor := ""
		for {
			page := must(s.SubscriptionsByProfile(ctx(t), "p", cursor, 3))(t)
			pages++
			if len(page.IMPIs) > 3 {
				t.Fatalf("page of %d, limit 3", len(page.IMPIs))
			}
			for _, impi := range page.IMPIs {
				if got[impi] {
					t.Fatalf("%s listed twice", impi)
				}
				got[impi] = true
			}
			if page.Next == "" {
				break
			}
			if pages > 10 {
				t.Fatal("the listing does not end")
			}
			cursor = page.Next
		}
		if reflect.DeepEqual(got, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("listed %v, want %v", got, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func testProfiles(t *testing.T, s store.Store, o Options) {
	v1 := must(s.CreateProfile(ctx(t), Profile("p")))(t)
	if v1.Version != 1 || !reflect.DeepEqual(v1.Criteria, Profile("p").Criteria) {
		t.Errorf("created %+v", v1)
	}
	_, err := s.CreateProfile(ctx(t), Profile("p"))
	wantErr(t, err, store.ErrExists)
	next := *v1
	next.OptionalCapabilities = nil
	v2 := must(s.UpdateProfile(ctx(t), &next))(t)
	if v2.Version != 2 || len(v2.OptionalCapabilities) != 0 {
		t.Errorf("updated %+v", v2)
	}
	_, err = s.UpdateProfile(ctx(t), v1)
	wantErr(t, err, store.ErrConflict)
	_, err = s.UpdateProfile(ctx(t), Profile("missing"))
	wantErr(t, err, store.ErrNotFound)
	_, err = s.Profile(ctx(t), "missing")
	wantErr(t, err, store.ErrNotFound)
	bad := Profile("bad")
	bad.Criteria = append(bad.Criteria, bad.Criteria[0]) // duplicate priority
	_, err = s.CreateProfile(ctx(t), bad)
	wantErr(t, err, store.ErrInvalid)

	sub := must(s.CreateSubscription(ctx(t), Subscription(IMPI1, "p", IMPU1)))(t)
	// DeleteProfile sees the subscription once the listing does.
	deadline := time.Now().Add(o.ListingWait)
	for {
		page := must(s.SubscriptionsByProfile(ctx(t), "p", "", 1))(t)
		if len(page.IMPIs) == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	wantErr(t, s.DeleteProfile(ctx(t), v2), store.ErrProfileInUse)
	if err := s.DeleteSubscription(ctx(t), sub); err != nil {
		t.Fatal(err)
	}
	wantErr(t, s.DeleteProfile(ctx(t), v1), store.ErrConflict)
	for {
		err = s.DeleteProfile(ctx(t), v2)
		if !errors.Is(err, store.ErrProfileInUse) || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Profile(ctx(t), "p")
	wantErr(t, err, store.ErrNotFound)
	wantErr(t, s.DeleteProfile(ctx(t), v2), store.ErrNotFound)
}

func testDataKeys(t *testing.T, s store.Store, o Options) {
	if keys := must(s.DataKeys(ctx(t)))(t); len(keys) != 0 {
		t.Fatalf("new store has keys: %v", keys)
	}
	if err := s.AddFirstDataKey(ctx(t), keyring.WrappedKey{ID: "1760000000000", Ciphertext: []byte("one")}); err != nil {
		t.Fatal(err)
	}
	// Another task's first key loses: there is one first key.
	wantErr(t, s.AddFirstDataKey(ctx(t), keyring.WrappedKey{ID: "1760000000001", Ciphertext: []byte("other")}), keyring.ErrExists)
	keys := must(s.DataKeys(ctx(t)))(t)
	if len(keys) != 1 || keys[0].ID != "1760000000000" || string(keys[0].Ciphertext) != "one" {
		t.Errorf("keys = %+v", keys)
	}
}

func testHasSubscriptions(t *testing.T, s store.Store, o Options) {
	if must(s.HasSubscriptions(ctx(t)))(t) {
		t.Fatal("an empty store has subscriptions")
	}
	withProfile(t, s, "p")
	must(s.CreateSubscription(ctx(t), Subscription(IMPI1, "p", IMPU1)))(t)
	deadline := time.Now().Add(o.ListingWait)
	for !must(s.HasSubscriptions(ctx(t)))(t) {
		if time.Now().After(deadline) {
			t.Fatal("a subscription is not seen")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// testPrecompiledProfile writes a profile whose Compiled set the HSS API
// built when it validated the request, as the API passes it: the store must
// take that set rather than compile the criteria again on each write (#125).
// Criteria that do not compile are stored when the set says they did, so a
// store that compiles them refuses the write (QA of #125, #142).
func testPrecompiledProfile(t *testing.T, s store.Store, _ Options) {
	set, err := ifc.Compile(Profile("compiled").Criteria)
	if err != nil {
		t.Fatal(err)
	}
	p := &store.ServiceProfile{ID: "p", Compiled: set, Criteria: []ifc.FilterCriteria{{
		Priority:          1,
		TriggerPoint:      &ifc.TriggerPoint{SPTs: []ifc.SPT{{Groups: []int{0}, Condition: ifc.RequestURI("(unclosed")}}},
		ApplicationServer: ifc.ApplicationServer{ServerName: "sip:as.example.net", DefaultHandling: ifc.SessionContinued},
	}}}
	saved, err := s.CreateProfile(ctx(t), p)
	if err != nil {
		t.Fatalf("CreateProfile compiled again: %v", err)
	}
	p.Version = saved.Version
	if _, err := s.UpdateProfile(ctx(t), p); err != nil {
		t.Fatalf("UpdateProfile compiled again: %v", err)
	}
}
