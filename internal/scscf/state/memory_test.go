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

func TestAProfileIsKeptAgainOnlyWithinTheMarginOfItsKeepUntil(t *testing.T) {
	p := &state.Profile{KeepUntil: statetest.T0.Add(state.ProfileGrace)}
	for _, tc := range []struct {
		now  time.Time
		want bool
	}{
		{statetest.T0, false},
		{p.KeepUntil.Add(-state.ProfileKeepMargin), false},
		{p.KeepUntil.Add(-state.ProfileKeepMargin + time.Second), true},
		{p.KeepUntil.Add(time.Hour), true},
	} {
		if got := p.KeepDue(tc.now); got != tc.want {
			t.Errorf("KeepDue %v before KeepUntil = %v, want %v", p.KeepUntil.Sub(tc.now), got, tc.want)
		}
	}
}
