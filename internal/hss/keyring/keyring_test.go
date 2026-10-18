package keyring

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeKMS wraps keys by XOR with a fixed pad, which is enough to tell a
// wrapped key from its plaintext and to fail on a key it did not wrap.
type fakeKMS struct {
	mu        sync.Mutex
	generated int
	unwrapped int
	failGen   error
	failOpen  error
}

var pad = bytes.Repeat([]byte{0x5c}, DataKeySize)

func xor(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ pad[i%len(pad)]
	}
	return out
}

func (f *fakeKMS) GenerateDataKey(context.Context) ([]byte, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failGen != nil {
		return nil, nil, f.failGen
	}
	f.generated++
	key := make([]byte, DataKeySize)
	_, _ = rand.Read(key)
	return key, append([]byte("wrapped:"), xor(key)...), nil
}

func (f *fakeKMS) Unwrap(_ context.Context, wrapped []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOpen != nil {
		return nil, f.failOpen
	}
	f.unwrapped++
	rest, ok := bytes.CutPrefix(wrapped, []byte("wrapped:"))
	if !ok {
		return nil, errors.New("not wrapped by this key")
	}
	return xor(rest), nil
}

type memStore struct {
	mu   sync.Mutex
	keys []WrappedKey
	// beforeAdd runs before AddFirstDataKey stores, to simulate another
	// task.
	beforeAdd func()
	failLoad  error
}

func (s *memStore) DataKeys(context.Context) ([]WrappedKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failLoad != nil {
		return nil, s.failLoad
	}
	return append([]WrappedKey(nil), s.keys...), nil
}

func (s *memStore) AddFirstDataKey(_ context.Context, k WrappedKey) error {
	if s.beforeAdd != nil {
		s.beforeAdd()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.keys) > 0 {
		return fmt.Errorf("add: %w", ErrExists)
	}
	s.keys = append(s.keys, k)
	return nil
}

func create() OpenOptions { return OpenOptions{Rand: rand.Reader, Create: true} }

func localKeyring(t *testing.T) *Keyring {
	t.Helper()
	k, err := NewLocal(bytes.Repeat([]byte{7}, DataKeySize), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealedValueOpensWithTheSameAdditionalData(t *testing.T) {
	k := localKeyring(t)
	secret := []byte("0123456789abcdef")
	sealed, err := k.Seal(secret, []byte("k|impi-a"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("sealed value contains the plaintext")
	}
	got, err := k.Open(sealed, []byte("k|impi-a"))
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Open = %x, %v", got, err)
	}
}

func TestSealedValueMovedToAnotherRecordDoesNotOpen(t *testing.T) {
	k := localKeyring(t)
	sealed, err := k.Seal([]byte("secret"), []byte("k|impi-a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Open(sealed, []byte("k|impi-b")); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Open with other aad = %v, want ErrCorrupt", err)
	}
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 1
	if _, err := k.Open(tampered, []byte("k|impi-a")); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Open of tampered value = %v, want ErrCorrupt", err)
	}
}

func TestMalformedSealedValuesAreRefused(t *testing.T) {
	k := localKeyring(t)
	sealed, _ := k.Seal([]byte("secret"), nil)
	for name, v := range map[string][]byte{
		"empty":          nil,
		"wrong format":   append([]byte{9}, sealed[1:]...),
		"truncated":      sealed[:10],
		"id beyond data": {format, 200, 'x'},
	} {
		if _, err := k.Open(v, nil); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: Open = %v, want ErrCorrupt", name, err)
		}
	}
	relabelled := bytes.Clone(sealed)
	copy(relabelled[2:], "LOCAL")
	if _, err := k.Open(relabelled, nil); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("Open with unknown key id = %v, want ErrUnknownKey", err)
	}
}

func TestLocalKeyMustBe256Bits(t *testing.T) {
	if _, err := NewLocal(make([]byte, 16), rand.Reader); err == nil {
		t.Error("NewLocal accepted a 128-bit key")
	}
}

func TestOpenCreatesTheFirstDataKeyOnceAndReusesIt(t *testing.T) {
	kms, st := &fakeKMS{}, &memStore{}
	first, err := Open(context.Background(), kms, st, create())
	if err != nil {
		t.Fatal(err)
	}
	if kms.generated != 1 || len(st.keys) != 1 {
		t.Fatalf("generated %d, stored %+v", kms.generated, st.keys)
	}
	sealed, err := first.Seal([]byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(context.Background(), kms, st, create())
	if err != nil {
		t.Fatal(err)
	}
	if kms.generated != 1 {
		t.Errorf("a second task generated another key")
	}
	if got, err := second.Open(sealed, []byte("aad")); err != nil || string(got) != "secret" {
		t.Errorf("second task cannot open the first task's value: %q, %v", got, err)
	}
}

func TestOpenUsesTheKeyAnotherTaskStoredFirst(t *testing.T) {
	kms, st := &fakeKMS{}, &memStore{}
	var other *Keyring
	st.beforeAdd = func() {
		st.beforeAdd = nil
		var err error
		other, err = Open(context.Background(), kms, st, create())
		if err != nil {
			t.Error(err)
		}
	}
	mine, err := Open(context.Background(), kms, st, create())
	if err != nil {
		t.Fatal(err)
	}
	if len(st.keys) != 1 || kms.generated != 2 {
		t.Fatalf("stored keys = %d, generated %d; want 1 stored of 2", len(st.keys), kms.generated)
	}
	sealed, err := other.Seal([]byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mine.Open(sealed, nil); err != nil {
		t.Errorf("the losing task does not use the winner's key: %v", err)
	}
}

func TestTheHighestKeySealsAndEveryKeyOpens(t *testing.T) {
	kms := &fakeKMS{}
	old, wrappedOld, _ := kms.GenerateDataKey(context.Background())
	_, wrappedNew, _ := kms.GenerateDataKey(context.Background())
	st := &memStore{keys: []WrappedKey{{ID: "10", Ciphertext: wrappedNew}, {ID: "9", Ciphertext: wrappedOld}}}
	k, err := Open(context.Background(), kms, st, create())
	if err != nil {
		t.Fatal(err)
	}
	if k.CurrentKeyID() != "10" {
		t.Errorf("current key = %s, want 10 (numeric order, not text)", k.CurrentKeyID())
	}
	legacy, _ := NewLocal(old, rand.Reader)
	legacy.current = "9"
	legacy.aeads["9"] = legacy.aeads[LocalKeyID]
	sealed, _ := legacy.Seal([]byte("old secret"), nil)
	if got, err := k.Open(sealed, nil); err != nil || string(got) != "old secret" {
		t.Errorf("value under the older key = %q, %v", got, err)
	}
}

func TestOpenFailsClosed(t *testing.T) {
	boom := errors.New("boom")
	for name, tc := range map[string]struct {
		kms *fakeKMS
		st  *memStore
	}{
		"store unreadable":   {&fakeKMS{}, &memStore{failLoad: boom}},
		"kms cannot create":  {&fakeKMS{failGen: boom}, &memStore{}},
		"kms cannot unwrap":  {&fakeKMS{failOpen: boom}, &memStore{keys: []WrappedKey{{ID: "1", Ciphertext: []byte("wrapped:x")}}}},
		"wrong key size":     {&fakeKMS{}, &memStore{keys: []WrappedKey{{ID: "1", Ciphertext: []byte("wrapped:short")}}}},
		"invalid identifier": {&fakeKMS{}, &memStore{keys: []WrappedKey{{ID: "01", Ciphertext: []byte("wrapped:")}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if k, err := Open(context.Background(), tc.kms, tc.st, create()); err == nil {
				t.Errorf("Open = %v, want an error", k)
			}
		})
	}
}

func TestSealFailsWhenRandomnessFails(t *testing.T) {
	k, err := NewLocal(make([]byte, DataKeySize), strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Seal([]byte("x"), nil); err == nil {
		t.Error("Seal succeeded without a nonce")
	}
}

func TestKeyringNeverPrintsItsKeys(t *testing.T) {
	k := localKeyring(t)
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", slog.Any("keyring", k))
	j, _ := json.Marshal(struct{ K *Keyring }{k})
	for _, s := range []string{fmt.Sprint(k), fmt.Sprintf("%#v", k), fmt.Sprintf("%x", k), k.String(), buf.String(), string(j)} {
		if strings.Contains(s, "0707") || strings.Contains(s, "aead") {
			t.Errorf("keyring printed its contents: %s", s)
		}
	}
}

// A store without a key either is new or has lost its key. Creating one
// for a store that holds secrets would seal new values under a key nothing
// old opens with, so the caller must allow it.
func TestOpenCreatesAKeyOnlyWhenAllowed(t *testing.T) {
	kms, st := &fakeKMS{}, &memStore{}
	if _, err := Open(context.Background(), kms, st, OpenOptions{Rand: rand.Reader}); !errors.Is(err, ErrNoDataKey) {
		t.Fatalf("Open without Create = %v, want ErrNoDataKey", err)
	}
	if kms.generated != 0 || len(st.keys) != 0 {
		t.Fatal("a key was created without permission")
	}
	var created string
	at := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	k, err := Open(context.Background(), kms, st, OpenOptions{
		Rand: rand.Reader, Create: true, Now: func() time.Time { return at },
		Created: func(id string) { created = id },
	})
	if err != nil {
		t.Fatal(err)
	}
	// The ID is the creation time, so a replacement key never reuses the
	// ID of the key it replaces.
	want := strconv.FormatInt(at.UnixMilli(), 10)
	if created != want || k.CurrentKeyID() != want {
		t.Errorf("created %q, current %q; want %q", created, k.CurrentKeyID(), want)
	}
}
