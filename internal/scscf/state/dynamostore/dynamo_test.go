package dynamostore

import (
	"bytes"
	"context"
	"errors"
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

var testKey = bytes.Repeat([]byte{0x42}, KeySize)

func newTestStore(t *testing.T, f *fakeDynamo, keys ...[]byte) *Dynamo {
	t.Helper()
	if len(keys) == 0 {
		keys = [][]byte{testKey}
	}
	d, err := New(f, Config{ChallengeKeys: keys})
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
	c, v, err := d.NextNotify(bg(), "s1")
	if err != nil || c != 1 || v != 1 {
		t.Fatalf("NextNotify = %d, %d, %v; want 1, 1", c, v, err)
	}
	if c, v, _ := d.NextNotify(bg(), "s1"); c != 2 || v != 2 {
		t.Errorf("next NextNotify = %d, %d; the resend counted twice", c, v)
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
	if _, err := d.Challenge(bg(), statetest.IMPI1, "n2", statetest.T0); !errors.Is(err, state.ErrInvalid) {
		t.Errorf("a moved challenge: error = %v, want ErrInvalid", err)
	}
	other := newTestStore(t, f, bytes.Repeat([]byte{0x43}, KeySize))
	if _, err := other.Challenge(bg(), statetest.IMPI1, "n1", statetest.T0); !errors.Is(err, state.ErrInvalid) {
		t.Errorf("another key: error = %v, want ErrInvalid", err)
	}
}

func TestAChallengeKeyRotatesWithoutLosingChallenges(t *testing.T) {
	f := newFake(t)
	oldKey, newKey := testKey, bytes.Repeat([]byte{0x43}, KeySize)
	before := newTestStore(t, f, oldKey)
	if err := before.AddChallenge(bg(), statetest.Challenge(statetest.IMPI1, "n", time.Minute)); err != nil {
		t.Fatal(err)
	}
	after := newTestStore(t, f, newKey, oldKey)
	if _, err := after.TakeChallenge(bg(), statetest.IMPI1, "n", statetest.T0); err != nil {
		t.Fatalf("a challenge sealed with the old key: %v", err)
	}
}

func TestNewRefusesBadChallengeKeys(t *testing.T) {
	for _, keys := range [][][]byte{nil, {make([]byte, 16)}} {
		if _, err := New(newFake(t), Config{ChallengeKeys: keys}); err == nil {
			t.Errorf("New accepted %d keys of %d bytes", len(keys), len(keys[0:min(1, len(keys))]))
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
	f.tables[DefaultRegistrationsTable][itemKey(key(statetest.IMPU2))][attrDoc] = bin([]byte("{"))
	if _, err := d.Registration(bg(), statetest.IMPU2); !errors.Is(err, state.ErrInvalid) {
		t.Errorf("error = %v, want ErrInvalid", err)
	}
	regs, err := d.ExpiringRegistrations(bg(), statetest.T0, 10)
	if !errors.Is(err, state.ErrInvalid) || len(regs) != 1 {
		t.Fatalf("listed %d with error %v; want the good one and ErrInvalid", len(regs), err)
	}
	n, err := state.SweepRegistrations(bg(), d, statetest.T0, 10, func(_, _ *state.Registration) {})
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
		func() error { _, err := d.Registration(bg(), statetest.IMPU1); return err }(),
		func() error {
			_, err := d.SaveRegistration(bg(), statetest.Registration(statetest.IMPI1, statetest.IMPU1, time.Hour))
			return err
		}(),
		func() error { _, err := d.ExpiringRegistrations(bg(), statetest.T0, 1); return err }(),
		d.AddChallenge(bg(), statetest.Challenge(statetest.IMPI1, "n", time.Minute)),
		func() error { _, err := d.TakeChallenge(bg(), statetest.IMPI1, "n", statetest.T0); return err }(),
		func() error { _, _, err := d.NextNotify(bg(), "s1"); return err }(),
		d.Ready(bg()),
	}
	for _, err := range checks {
		if err == nil || strings.Contains(err.Error(), "15550100001") {
			t.Errorf("error %v", err)
		}
	}
	f.fail = context.DeadlineExceeded
	if _, err := d.Registration(bg(), statetest.IMPU1); !errors.Is(err, context.DeadlineExceeded) {
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
	f.tables[DefaultRegistrationsTable][itemKey(key(statetest.IMPU1))] = map[string]types.AttributeValue{
		attrPK: str(statetest.IMPU1), attrDoc: bin([]byte("{}")),
	}
	if _, err := d.Registration(bg(), statetest.IMPU1); !errors.Is(err, state.ErrInvalid) {
		t.Errorf("a registration without a version: %v", err)
	}
}

func TestTransportErrorsAreReducedToTheirCause(t *testing.T) {
	f := newFake(t)
	d := newTestStore(t, f)
	f.fail = &url.Error{Op: "Post", URL: "https://dynamodb.example/" + statetest.IMPU1, Err: errors.New("connection refused")}
	_, err := d.Registration(bg(), statetest.IMPU1)
	if err == nil || strings.Contains(err.Error(), "15550100001") || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error %v", err)
	}
	f.fail = errors.New("something " + statetest.IMPU1)
	if _, err := d.Registration(bg(), statetest.IMPU1); err == nil || strings.Contains(err.Error(), "15550100001") {
		t.Errorf("error %v", err)
	}
}

func TestTheDefaultTableNamesAreTheArchitecturesOwn(t *testing.T) {
	d := newTestStore(t, newFake(t))
	if d.registrations != "registrations" || d.challenges != "auth-challenges" || d.subscriptions != "reg-subscriptions" {
		t.Errorf("tables %q %q %q", d.registrations, d.challenges, d.subscriptions)
	}
}
