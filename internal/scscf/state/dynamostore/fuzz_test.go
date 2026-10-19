package dynamostore

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state/statetest"
)

// FuzzDecodeDocuments feeds arbitrary bytes to the decoders of the three
// documents, which read what any instance, of any version, wrote. Whatever
// they accept must pass the state package's validation and encode back to a
// document that decodes to the same value; whatever they refuse must be
// refused with ErrInvalid.
func FuzzDecodeDocuments(f *testing.F) {
	r := statetest.Registration(statetest.IMPI1, statetest.IMPU1, time.Hour, time.Minute)
	r.Contacts[0].Q = 700
	r.Deregistering = statetest.T0
	reg, _ := encodeRegistration(r)
	ch, _ := encodeChallenge(statetest.Challenge(statetest.IMPI1, "n", time.Minute))
	sub, _ := encodeSubscription(statetest.Subscription("s1", statetest.IMPU1, time.Hour))
	for _, seed := range [][]byte{reg, ch, sub, []byte("{}"), []byte(`{"contacts":[{}]}`), []byte("null"),
		[]byte(`{"impu":"sip:a@example.com","impi":"a@example.com","user_data":"","contacts":[{"uri":"sip:x","expires":"2031-01-01T00:00:00+09:00","path":[],"feature_tags":[]}]}`)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if r, err := decodeRegistration(b, 1); err == nil {
			again, err := encodeRegistration(r)
			if err != nil {
				t.Fatal(err)
			}
			back, err := decodeRegistration(again, 1)
			if err != nil || !reflect.DeepEqual(normal(back), normal(r)) {
				t.Fatalf("registration does not round-trip: %v", err)
			}
		} else if !errors.Is(err, state.ErrInvalid) {
			t.Fatalf("registration refused with %v", err)
		}
		if c, err := decodeChallenge(b, statetest.IMPI1, "n"); err == nil {
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
		} else if !errors.Is(err, state.ErrInvalid) {
			t.Fatalf("challenge refused with %v", err)
		}
		if s, err := decodeSubscription(b, 1, 2, 3); err == nil {
			again, err := encodeSubscription(s)
			if err != nil {
				t.Fatal(err)
			}
			if back, err := decodeSubscription(again, 1, 2, 3); err != nil || back.ID != s.ID || back.IMPU != s.IMPU {
				t.Fatalf("subscription does not round-trip: %v", err)
			}
		} else if !errors.Is(err, state.ErrInvalid) {
			t.Fatalf("subscription refused with %v", err)
		}
	})
}

// normal makes times comparable: JSON keeps the instant, not the location.
func normal(r *state.Registration) *state.Registration {
	c := r.Clone()
	c.Deregistering = c.Deregistering.UTC()
	for i := range c.Contacts {
		c.Contacts[i].Expires = c.Contacts[i].Expires.UTC()
	}
	return c
}

// FuzzOpenSealed checks that a sealed challenge opens only unchanged: any other
// bytes are refused with ErrInvalid, never a panic.
func FuzzOpenSealed(f *testing.F) {
	s, err := newSealer([]ChallengeKey{testKey}, "")
	if err != nil {
		f.Fatal(err)
	}
	// A fixed nonce keeps the seed corpus the same on every run.
	sealed, err := s.seal(bytes.NewReader(make([]byte, 64)), []byte(`{"expires":"2031-01-01T00:00:00Z"}`), []byte("aad"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sealed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		plain, err := s.open(b, []byte("aad"))
		if err != nil {
			if !errors.Is(err, state.ErrInvalid) {
				t.Fatalf("refused with %v", err)
			}
			return
		}
		if !bytes.Equal(b, sealed) {
			t.Fatalf("forged document opened to %q", plain)
		}
	})
}
