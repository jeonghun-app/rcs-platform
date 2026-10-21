package dynamostore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state/statetest"
)

var (
	testKey  = ChallengeKey{ID: "k1", Key: bytes.Repeat([]byte{0x42}, KeySize)}
	otherKey = ChallengeKey{ID: "k2", Key: bytes.Repeat([]byte{0x43}, KeySize)}
)

// newTestStore returns a store over f that seals with the first key given, or
// testKey.
func newTestStore(t *testing.T, f *fakeDynamo, keys ...ChallengeKey) *Dynamo {
	t.Helper()
	if len(keys) == 0 {
		keys = []ChallengeKey{testKey}
	}
	return newSealing(t, f, keys[0].ID, keys...)
}

func newSealing(t *testing.T, f *fakeDynamo, seal string, keys ...ChallengeKey) *Dynamo {
	t.Helper()
	d, err := New(f, Config{ChallengeKeys: keys, SealKeyID: seal})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func newFake(t *testing.T) *fakeDynamo {
	return newFakeDynamo(t, DefaultRegistrationsTable, DefaultChallengesTable, DefaultSubscriptionsTable)
}

func TestDynamoStoreMeetsTheContractOnTheFake(t *testing.T) {
	statetest.Run(t, func(t *testing.T) state.Store { return newTestStore(t, newFake(t)) }, statetest.Options{
		Second: func(t *testing.T, first state.Store) state.Store {
			return newTestStore(t, first.(*Dynamo).api.(*fakeDynamo))
		},
	})
}

func bg() context.Context { return context.Background() }

// TestAResentWriteIsRecognisedByItsToken has the SDK resend writes whose
// response was lost: the resend fails its condition, and the store must see
// its own token rather than report a conflict or an existing item.
func TestAResentWriteIsRecognisedByItsToken(t *testing.T) {
	f := newFake(t)
	d := newTestStore(t, f)
	f.resendNext = true
	v1, err := d.SaveRegistration(bg(), statetest.Registration(statetest.IMPI1, statetest.IMPU1, time.Hour))
	if err != nil {
		t.Fatalf("resent create: %v", err)
	}
	f.resendNext = true
	if _, err := d.SaveRegistration(bg(), v1); err != nil {
		t.Fatalf("resent update: %v", err)
	}
	f.resendNext = true
	if err := d.AddChallenge(bg(), statetest.Challenge(statetest.IMPI1, "n", time.Minute)); err != nil {
		t.Fatalf("resent challenge: %v", err)
	}
	f.resendNext = true
	if _, err := d.SaveSubscription(bg(), statetest.Subscription("s1", statetest.IMPU1, time.Hour)); err != nil {
		t.Fatalf("resent subscription: %v", err)
	}
}

func TestAWriteWithoutRandomnessFailsSafeAsAConflict(t *testing.T) {
	f := newFake(t)
	d := newTestStore(t, f)
	v1, err := d.SaveRegistration(bg(), statetest.Registration(statetest.IMPI1, statetest.IMPU1, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	d.rand = strings.NewReader("")
	f.resendNext = true
	_, err = d.SaveRegistration(bg(), v1)
	if !errors.Is(err, state.ErrConflict) {
		t.Fatalf("error = %v, want a conflict: an empty token must not match", err)
	}
}

func TestAResentNextNotifyReturnsTheFirstAttemptsValues(t *testing.T) {
	f := newFake(t)
	d := newTestStore(t, f)
	if _, err := d.SaveSubscription(bg(), statetest.Subscription("s1", statetest.IMPU1, time.Hour)); err != nil {
		t.Fatal(err)
	}
	f.resendNext = true
	c, v, err := d.NextNotify(bg(), "s1", 0)
	if err != nil || c != 1 || v != 1 {
		t.Fatalf("NextNotify = %d, %d, %v; want 1, 1", c, v, err)
	}
	if c, v, _ := d.NextNotify(bg(), "s1", 0); c != 2 || v != 2 {
		t.Errorf("next NextNotify = %d, %d; the resend counted twice", c, v)
	}
}

func TestAResentKeepProfileSucceeds(t *testing.T) {
	f := newFake(t)
	d := newTestStore(t, f)
	if err := d.SaveProfile(bg(), statetest.Profile(statetest.Set1, []byte("x"), statetest.T0)); err != nil {
		t.Fatal(err)
	}
	until := statetest.T0.Add(72 * time.Hour)
	f.resendNext = true
	if err := d.KeepProfile(bg(), statetest.Set1, until, statetest.T0); err != nil {
		t.Fatalf("resent KeepProfile: %v", err)
	}
	if p, err := d.Profile(bg(), statetest.Set1, statetest.T0); err != nil || !p.KeepUntil.Equal(until) {
		t.Fatalf("after the resend: %v, %v", p, err)
	}
}

// TestAKeepProfileThatRacesASaveStillExtendsTheProfile: the profile is
// already kept as long, so the update's condition fails; before the read
// back, another instance deletes it and a third saves it anew with an earlier
// KeepUntil. The second attempt extends the new profile, and nothing reports
// a conflict.
func TestAKeepProfileThatRacesASaveStillExtendsTheProfile(t *testing.T) {
	f := newFake(t)
	d := newTestStore(t, f)
	p := statetest.Profile(statetest.Set1, []byte("x"), statetest.T0)
	p.KeepUntil = statetest.T0.Add(30 * time.Hour)
	if err := d.SaveProfile(bg(), p); err != nil {
		t.Fatal(err)
	}
	until := statetest.T0.Add(25 * time.Hour)
	saved := false
	f.afterUpdate = func() {
		if saved {
			return
		}
		saved = true
		// Deleted, by a deregistration, and saved again by a new
		// registration, with an earlier KeepUntil.
		if err := d.DeleteProfile(bg(), statetest.Set1); err != nil {
			t.Error(err)
		}
		q := statetest.Profile(statetest.Set1, []byte("y"), statetest.T0.Add(time.Second))
		q.KeepUntil = statetest.T0.Add(time.Hour)
		if err := d.SaveProfile(bg(), q); err != nil {
			t.Error(err)
		}
	}
	if err := d.KeepProfile(bg(), statetest.Set1, until, statetest.T0); err != nil {
		t.Fatalf("KeepProfile: %v", err)
	}
	got, err := d.Profile(bg(), statetest.Set1, statetest.T0)
	if err != nil || !got.KeepUntil.Equal(until) || string(got.UserData) != "y" {
		t.Fatalf("after the race: %+v, %v; want the saved profile kept until %v", got, err, until)
	}
}

// TestASaveProfileReadsAgainWhenAKeepProfileLandsBeforeItsPut: another
// instance's KeepProfile between SaveProfile's read and its put fails the
// put's condition. A PPR's save that gave up there would read as "a newer
// profile is stored" to the registrar, which drops it, so the save reads again
// and puts, keeping the later KeepUntil; only a set changed under every one of
// its attempts reports ErrContended (#184 QA).
func TestASaveProfileReadsAgainWhenAKeepProfileLandsBeforeItsPut(t *testing.T) {
	for _, tc := range []struct {
		raced int
		want  error
	}{
		{0, nil},
		{1, nil},
		{saveProfileAttempts - 1, nil},
		{saveProfileAttempts, state.ErrContended},
	} {
		f := newFake(t)
		d := newTestStore(t, f)
		p := statetest.Profile(statetest.Set1, []byte("old"), statetest.T0)
		p.KeepUntil = statetest.T0.Add(time.Hour)
		if err := d.SaveProfile(bg(), p); err != nil {
			t.Fatal(err)
		}
		gets, raced, inside := 0, 0, false
		f.afterGet = func() {
			if inside {
				return
			}
			gets++
			if raced == tc.raced {
				return
			}
			raced++
			inside = true
			defer func() { inside = false }()
			if err := d.KeepProfile(bg(), statetest.Set1, statetest.T0.Add(time.Duration(raced+1)*time.Hour), statetest.T0); err != nil {
				t.Error(err)
			}
		}
		ppr := statetest.Profile(statetest.Set1, []byte("ppr"), statetest.T0.Add(time.Second))
		ppr.KeepUntil = statetest.T0.Add(30 * time.Minute)
		err := d.SaveProfile(bg(), ppr)
		f.afterGet = nil
		if !errors.Is(err, tc.want) || (tc.want == nil) != (err == nil) {
			t.Fatalf("raced %d times: %v, want %v", tc.raced, err, tc.want)
		}
		if gets != min(tc.raced+1, saveProfileAttempts) {
			t.Errorf("raced %d times: read %d times", tc.raced, gets)
		}
		got, err := d.Profile(bg(), statetest.Set1, statetest.T0)
		if err != nil {
			t.Fatal(err)
		}
		wantData, wantKeep := "ppr", statetest.T0.Add(time.Duration(tc.raced+1)*time.Hour)
		if tc.want != nil {
			wantData = "old"
		}
		if string(got.UserData) != wantData || !got.KeepUntil.Equal(wantKeep) {
			t.Errorf("raced %d times: %q kept until %v, want %q kept until %v", tc.raced, got.UserData, got.KeepUntil, wantData, wantKeep)
		}
	}
}

// TestOnlyProfilesCarryTheTTLAttribute: DynamoDB deletes items by the table's
// TTL attribute, ttl, in Unix seconds. A profile has it, so one a failed
// deregistration left behind goes; a registration, unregistered or not, must
// not, since only a sweep sends the SAR that tells the HSS.
func TestOnlyProfilesCarryTheTTLAttribute(t *testing.T) {
	f := newFake(t)
	d := newTestStore(t, f)
	for _, r := range []*state.Registration{
		statetest.Registration(statetest.IMPI1, statetest.IMPU1, time.Hour),
		statetest.Unregistered(statetest.IMPI1, statetest.IMPU2, statetest.T0.Add(time.Hour)),
	} {
		if _, err := d.SaveRegistration(bg(), r); err != nil {
			t.Fatal(err)
		}
	}
	p := statetest.Profile(statetest.Set1, []byte("x"), statetest.T0)
	if err := d.SaveProfile(bg(), p); err != nil {
		t.Fatal(err)
	}
	tbl := f.tables[DefaultRegistrationsTable]
	for _, impu := range []string{statetest.IMPU1, statetest.IMPU2} {
		if _, ok := tbl[itemKey(key(impu))][attrTTL]; ok {
			t.Errorf("the registration of %s has a TTL", impu)
		}
	}
	item := tbl[itemKey(profileKey(statetest.Set1))]
	if got := number(item[attrTTL]); got != p.KeepUntil.Unix() {
		t.Errorf("profile ttl %d, want KeepUntil in Unix seconds %d", got, p.KeepUntil.Unix())
	}
	later := p.KeepUntil.Add(time.Hour)
	if err := d.KeepProfile(bg(), statetest.Set1, later, statetest.T0); err != nil {
		t.Fatal(err)
	}
	if got := number(tbl[itemKey(profileKey(statetest.Set1))][attrTTL]); got != later.Unix() {
		t.Errorf("after KeepProfile ttl %d, want %d", got, later.Unix())
	}
}

// TestAResentTakeLosesTheChallenge documents the one write that is not
// idempotent: the challenge is gone after the first attempt, so the caller
// sees ErrNotFound and challenges the client again. A response is never
// checked twice.
func TestAResentTakeLosesTheChallenge(t *testing.T) {
	f := newFake(t)
	d := newTestStore(t, f)
	if err := d.AddChallenge(bg(), statetest.Challenge(statetest.IMPI1, "n", time.Minute)); err != nil {
		t.Fatal(err)
	}
	f.resendNext = true
	if _, err := d.TakeChallenge(bg(), statetest.IMPI1, "n", statetest.T0); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

func TestChallengesAreSealedAndBoundToTheirKey(t *testing.T) {
	f := newFake(t)
	d := newTestStore(t, f)
	c := statetest.Challenge(statetest.IMPI1, "n1", time.Minute)
	c.AKA.XRES = []byte("XRES-IN-CLEAR")
	if err := d.AddChallenge(bg(), c); err != nil {
		t.Fatal(err)
	}
	tbl := f.tables[DefaultChallengesTable]
	item := tbl[itemKey(challengeKey(statetest.IMPI1, "n1"))]
	if bytes.Contains(item[attrDoc].(*types.AttributeValueMemberB).Value, []byte("XRES-IN-CLEAR")) {
		t.Fatal("the challenge is stored in clear")
	}
	// The same sealed document under another nonce does not open.
	moved := challengeKey(statetest.IMPI1, "n2")
	moved[attrDoc], moved[attrExpires] = item[attrDoc], item[attrExpires]
	tbl[itemKey(moved)] = moved
	if _, err := d.TakeChallenge(bg(), statetest.IMPI1, "n2", statetest.T0); !errors.Is(err, state.ErrInvalid) {
		t.Errorf("a moved challenge: error = %v, want ErrInvalid", err)
	}
	// A key with the same ID but other bytes does not open it either.
	other := newTestStore(t, f, ChallengeKey{ID: testKey.ID, Key: otherKey.Key})
	if _, err := other.TakeChallenge(bg(), statetest.IMPI1, "n1", statetest.T0); !errors.Is(err, state.ErrInvalid) {
		t.Errorf("another key: error = %v, want ErrInvalid", err)
	}
}

// TestEachStepOfAKeyRotationOpensWhatTheOthersSeal runs the documented
// rotation with instances one step apart, in both directions: whichever
// instance seals a challenge, whichever takes it opens it.
func TestEachStepOfAKeyRotationOpensWhatTheOthersSeal(t *testing.T) {
	f := newFake(t)
	steps := []*Dynamo{
		newSealing(t, f, "k1", testKey),           // before
		newSealing(t, f, "k1", testKey, otherKey), // 1: the new key added
		newSealing(t, f, "k2", testKey, otherKey), // 2: sealing with it
		newSealing(t, f, "k2", otherKey),          // 3: the old key dropped
	}
	n := 0
	for i := 0; i+1 < len(steps); i++ {
		for _, pair := range [][2]*Dynamo{{steps[i], steps[i+1]}, {steps[i+1], steps[i]}} {
			n++
			nonce := fmt.Sprint("n", n)
			if err := pair[0].AddChallenge(bg(), statetest.Challenge(statetest.IMPI1, nonce, time.Minute)); err != nil {
				t.Fatal(err)
			}
			if _, err := pair[1].TakeChallenge(bg(), statetest.IMPI1, nonce, statetest.T0); err != nil {
				t.Errorf("steps %d and %d: %v", i, i+1, err)
			}
		}
	}
}

func TestNewRefusesBadChallengeKeys(t *testing.T) {
	short := ChallengeKey{ID: "k", Key: make([]byte, 16)}
	for name, c := range map[string]Config{
		"no key":              {},
		"a short key":         {ChallengeKeys: []ChallengeKey{short}},
		"no ID":               {ChallengeKeys: []ChallengeKey{{Key: testKey.Key}}},
		"two with one ID":     {ChallengeKeys: []ChallengeKey{testKey, {ID: "k1", Key: otherKey.Key}}, SealKeyID: "k1"},
		"no seal key":         {ChallengeKeys: []ChallengeKey{testKey, otherKey}},
		"an unknown seal key": {ChallengeKeys: []ChallengeKey{testKey}, SealKeyID: "k9"},
	} {
		if _, err := New(newFake(t), c); err == nil {
			t.Errorf("New accepted %s", name)
		}
	}
}

func TestACorruptItemIsReportedWithoutHidingTheOthers(t *testing.T) {
	f := newFake(t)
	d := newTestStore(t, f)
	for _, impu := range []string{statetest.IMPU1, statetest.IMPU2} {
		if _, err := d.SaveRegistration(bg(), statetest.Registration(statetest.IMPI1, impu, -time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	f.tables[DefaultRegistrationsTable][itemKey(key(setPK(statetest.Key1(statetest.IMPU2))))][attrDoc] = bin([]byte("{"))
	if _, err := d.Registration(bg(), statetest.Key1(statetest.IMPU2)); !errors.Is(err, state.ErrInvalid) {
		t.Errorf("error = %v, want ErrInvalid", err)
	}
	regs, err := d.ExpiringRegistrations(bg(), statetest.T0, 10)
	if !errors.Is(err, state.ErrInvalid) || len(regs) != 1 {
		t.Fatalf("listed %d with error %v; want the good one and ErrInvalid", len(regs), err)
	}
	n, err := state.SweepRegistrations(bg(), d, statetest.T0, 10, func(_, _ *state.Registration) error { return nil })
	if n != 1 || !errors.Is(err, state.ErrInvalid) {
		t.Errorf("sweep handled %d with error %v; want 1 and ErrInvalid", n, err)
	}
	regs, err = d.RegistrationsOf(bg(), statetest.IMPI1)
	if !errors.Is(err, state.ErrInvalid) || len(regs) != 0 {
		t.Errorf("RegistrationsOf listed %d with error %v", len(regs), err)
	}
}

func TestSDKErrorsCarryNoKey(t *testing.T) {
	f := newFake(t)
	d := newTestStore(t, f)
	f.fail = &types.ProvisionedThroughputExceededException{Message: aws.String("throttled " + statetest.IMPU1)}
	checks := []error{
		func() error { _, err := d.Registration(bg(), statetest.Key1(statetest.IMPU1)); return err }(),
		func() error {
			_, err := d.SaveRegistration(bg(), statetest.Registration(statetest.IMPI1, statetest.IMPU1, time.Hour))
			return err
		}(),
		func() error { _, err := d.ExpiringRegistrations(bg(), statetest.T0, 1); return err }(),
		d.AddChallenge(bg(), statetest.Challenge(statetest.IMPI1, "n", time.Minute)),
		func() error { _, err := d.TakeChallenge(bg(), statetest.IMPI1, "n", statetest.T0); return err }(),
		func() error { _, _, err := d.NextNotify(bg(), "s1", 0); return err }(),
		d.Ready(bg()),
	}
	for _, err := range checks {
		if err == nil || strings.Contains(err.Error(), "15550100001") {
			t.Errorf("error %v", err)
		}
	}
	f.fail = context.DeadlineExceeded
	if _, err := d.Registration(bg(), statetest.Key1(statetest.IMPU1)); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a deadline is reported as %v", err)
	}
}

func TestReadyNeedsEveryTable(t *testing.T) {
	d := newTestStore(t, newFake(t))
	if err := d.Ready(bg()); err != nil {
		t.Fatal(err)
	}
	missing := newTestStore(t, newFakeDynamo(t, DefaultRegistrationsTable))
	if err := missing.Ready(bg()); err == nil {
		t.Error("Ready without two tables")
	}
}

func TestListingsReadEveryPage(t *testing.T) {
	f := newFake(t)
	d := newTestStore(t, f)
	impus := []string{}
	for i := range 3 * shards {
		impu := "sip:user" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "@" + statetest.Domain
		impus = append(impus, impu)
		if _, err := d.SaveRegistration(bg(), statetest.Registration(statetest.IMPI1, impu, -time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	regs, err := d.ExpiringRegistrations(bg(), statetest.T0, len(impus))
	if err != nil || len(regs) != len(impus) {
		t.Fatalf("listed %d of %d expiring: %v", len(regs), len(impus), err)
	}
	all, err := d.RegistrationsOf(bg(), statetest.IMPI1)
	if err != nil || len(all) != len(impus) {
		t.Fatalf("listed %d of %d by IMPI: %v", len(all), len(impus), err)
	}
}

func TestMalformedItemsAreInvalid(t *testing.T) {
	f := newFake(t)
	d := newTestStore(t, f)
	if _, err := d.SaveSubscription(bg(), statetest.Subscription("s1", statetest.IMPU1, -time.Minute)); err != nil {
		t.Fatal(err)
	}
	good := f.tables[DefaultSubscriptionsTable][itemKey(key("s1"))]
	breakers := map[string]func(map[string]types.AttributeValue){
		"no doc":           func(i map[string]types.AttributeValue) { delete(i, attrDoc) },
		"no version":       func(i map[string]types.AttributeValue) { delete(i, attrVersion) },
		"a bad version":    func(i map[string]types.AttributeValue) { i[attrVersion] = &types.AttributeValueMemberN{Value: "x"} },
		"no CSeq":          func(i map[string]types.AttributeValue) { delete(i, attrCSeq) },
		"a negative rver":  func(i map[string]types.AttributeValue) { i[attrRver] = num(-1) },
		"a doc not binary": func(i map[string]types.AttributeValue) { i[attrDoc] = str("{}") },
	}
	for name, breakIt := range breakers {
		t.Run(name, func(t *testing.T) {
			item := maps.Clone(good)
			breakIt(item)
			f.tables[DefaultSubscriptionsTable][itemKey(key("s1"))] = item
			if _, err := d.Subscription(bg(), "s1"); !errors.Is(err, state.ErrInvalid) {
				t.Errorf("Subscription: %v", err)
			}
			if _, err := d.SubscriptionsOf(bg(), statetest.IMPU1); !errors.Is(err, state.ErrInvalid) {
				t.Errorf("SubscriptionsOf: %v", err)
			}
			if _, err := d.ExpiringSubscriptions(bg(), statetest.T0, 10); !errors.Is(err, state.ErrInvalid) {
				t.Errorf("ExpiringSubscriptions: %v", err)
			}
		})
	}
	f.tables[DefaultRegistrationsTable][itemKey(key(setPK(statetest.Key1(statetest.IMPU1))))] = map[string]types.AttributeValue{
		attrPK: str(statetest.IMPU1), attrDoc: bin([]byte("{}")),
	}
	if _, err := d.Registration(bg(), statetest.Key1(statetest.IMPU1)); !errors.Is(err, state.ErrInvalid) {
		t.Errorf("a registration without a version: %v", err)
	}
}

func TestTransportErrorsAreReducedToTheirCause(t *testing.T) {
	f := newFake(t)
	d := newTestStore(t, f)
	f.fail = &url.Error{Op: "Post", URL: "https://dynamodb.example/" + statetest.IMPU1, Err: errors.New("connection refused")}
	_, err := d.Registration(bg(), statetest.Key1(statetest.IMPU1))
	if err == nil || strings.Contains(err.Error(), "15550100001") || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error %v", err)
	}
	f.fail = errors.New("something " + statetest.IMPU1)
	if _, err := d.Registration(bg(), statetest.Key1(statetest.IMPU1)); err == nil || strings.Contains(err.Error(), "15550100001") {
		t.Errorf("error %v", err)
	}
}

func TestTheDefaultTableNamesAreTheArchitecturesOwn(t *testing.T) {
	d := newTestStore(t, newFake(t))
	if d.registrations != "registrations" || d.challenges != "auth-challenges" || d.subscriptions != "reg-subscriptions" {
		t.Errorf("tables %q %q %q", d.registrations, d.challenges, d.subscriptions)
	}
}
