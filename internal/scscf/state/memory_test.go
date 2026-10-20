package state_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state/statetest"
)

func TestMemoryStoreMeetsTheContract(t *testing.T) {
	statetest.Run(t, func(*testing.T) state.Store { return state.NewMemory() }, statetest.Options{
		// Two instances sharing DynamoDB are two handles on one store here.
		Second: func(_ *testing.T, first state.Store) state.Store { return first },
	})
}

func TestPruneRemovesOnlyExpiredContacts(t *testing.T) {
	r := statetest.Registration(statetest.IMPI1, statetest.IMPU1, -time.Minute, time.Hour, 0)
	expired := r.Prune(statetest.T0)
	if len(expired) != 2 || len(r.Contacts) != 1 || r.Contacts[0].Expires != statetest.T0.Add(time.Hour) {
		t.Fatalf("expired %d, left %+v", len(expired), r.Contacts)
	}
	if got := r.NextExpiry(); got != statetest.T0.Add(time.Hour) {
		t.Errorf("NextExpiry = %v", got)
	}
	if got := (&state.Registration{}).NextExpiry(); !got.IsZero() {
		t.Errorf("NextExpiry without contacts = %v, want zero", got)
	}
}

func TestCredentialsAreNotPrintedOrLogged(t *testing.T) {
	c := statetest.Challenge(statetest.IMPI1, "n", time.Minute)
	c.AKA.XRES = []byte("SECRET-XRES")
	d := &state.DigestChallenge{Realm: "r", Algorithm: "MD5", HA1: "SECRET-HA1"}
	digest := statetest.Challenge(statetest.IMPI1, "m", time.Minute)
	digest.AKA, digest.Digest = nil, d
	var out bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&out, nil))
	log.Info("x", "challenge", c, "ptr", &c, "aka", c.AKA, "akaValue", *c.AKA, "digest", d, "digestValue", *d, "dc", digest)
	b, _ := json.Marshal(map[string]any{"c": c, "d": digest})
	printed := []string{out.String(), string(b), fmt.Sprint(c.AKA), fmt.Sprintf("%v %+v %#v", *c.AKA, *c.AKA, *c.AKA),
		fmt.Sprintf("%v %+v %#v", *d, *d, *d), fmt.Sprintf("%v %+v %#v", *c, *c, *c)}
	for _, s := range printed {
		for _, secret := range []string{"SECRET", "U0VDUkVU", statetest.IMPI1} {
			if strings.Contains(s, secret) {
				t.Errorf("printed or logged a credential or identity: %s", s)
			}
		}
	}
}

func TestMemoryForgetsExpiredChallengesNobodyTook(t *testing.T) {
	m := state.NewMemory()
	for i := range 1023 {
		if err := m.AddChallenge(context.Background(), statetest.Challenge(statetest.IMPI1, fmt.Sprint("old", i), time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	// The next one is issued after all of those expired.
	late := statetest.Challenge(statetest.IMPI1, "late", 10*time.Minute)
	late.Issued = statetest.T0.Add(5 * time.Minute)
	if err := m.AddChallenge(context.Background(), late); err != nil {
		t.Fatal(err)
	}
	if n := m.HeldChallenges(); n != 1 {
		t.Errorf("%d challenges held after the purge, want 1", n)
	}
}

func TestAProfileOrIdentityIsKeptAgainOnceTheNewExpiryPassesItsMargin(t *testing.T) {
	p := &state.Profile{KeepUntil: statetest.T0.Add(state.ProfileGrace)}
	for _, tc := range []struct {
		lastExpiry time.Time
		want       bool
	}{
		{statetest.T0, false},
		{statetest.T0.Add(state.ProfileKeepMargin), false},
		{statetest.T0.Add(state.ProfileKeepMargin + time.Second), true},
		// A registration longer than ProfileGrace is due whatever the time
		// left on KeepUntil.
		{statetest.T0.Add(48 * time.Hour), true},
	} {
		if got := p.KeepDue(tc.lastExpiry); got != tc.want {
			t.Errorf("KeepDue(KeepUntil - %v) = %v, want %v", p.KeepUntil.Sub(tc.lastExpiry), got, tc.want)
		}
		if got := (&state.Identity{KeepUntil: p.KeepUntil}).KeepDue(tc.lastExpiry); got != tc.want {
			t.Errorf("identity KeepDue(KeepUntil - %v) = %v, want %v", p.KeepUntil.Sub(tc.lastExpiry), got, tc.want)
		}
	}
}

// TestAProfileIsFoundWhileItsSetIsRegisteredWhateverTheExpiry follows the
// rule a registrar applies (KeepUntil = last binding expiry + ProfileGrace
// at SAR, then KeepProfile on a re-registration when KeepDue) with a UE that
// refreshes 600 s before expiry (TS 24.229 §5.1.1.4.1), and checks the
// profile every hour of 30 days. From QA's review of #184: with the time
// left as the measure, registrations over a day lost their profile for
// hours.
func TestAProfileIsFoundWhileItsSetIsRegisteredWhateverTheExpiry(t *testing.T) {
	for _, x := range []time.Duration{time.Hour, 2 * time.Hour, 13 * time.Hour, 24 * time.Hour, 25 * time.Hour, 36 * time.Hour, 48 * time.Hour, 600000 * time.Second} {
		t.Run(x.String(), func(t *testing.T) {
			ctx := context.Background()
			m := state.NewMemory()
			now := statetest.T0
			expiry := now.Add(x)
			p := statetest.Profile(statetest.Set1, []byte("<IMSSubscription/>"), now)
			p.KeepUntil = expiry.Add(state.ProfileGrace)
			if err := m.SaveProfile(ctx, p); err != nil {
				t.Fatal(err)
			}
			end := statetest.T0.Add(30 * 24 * time.Hour)
			keeps := 0
			for now.Before(end) {
				refresh := expiry.Add(-600 * time.Second)
				for c := now; c.Before(expiry); c = c.Add(time.Hour) {
					if _, err := m.Profile(ctx, statetest.Set1, c); err != nil {
						t.Fatalf("not found at %v while registered until %v: %v", c.Sub(statetest.T0), expiry.Sub(statetest.T0), err)
					}
				}
				now = refresh
				cur, err := m.Profile(ctx, statetest.Set1, now)
				if err != nil {
					t.Fatalf("gone at the re-registration at %v: %v", now.Sub(statetest.T0), err)
				}
				expiry = now.Add(x)
				if cur.KeepDue(expiry) {
					keeps++
					if err := m.KeepProfile(ctx, statetest.Set1, expiry.Add(state.ProfileGrace), now); err != nil {
						t.Fatal(err)
					}
				}
			}
			// The point of KeepDue: hourly registrations write the profile
			// about twice a day, not at every re-registration.
			if days := 30; keeps > 3*days {
				t.Errorf("%d writes of KeepUntil in %d days", keeps, days)
			}
		})
	}
}
