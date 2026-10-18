package msrp

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"testing/iotest"
)

func TestSessionIDsCarryAtLeast128RandomBitsInBase32(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		id, err := NewSessionID(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := idEncoding.DecodeString(id)
		if err != nil {
			t.Fatalf("%q is not base32: %v", id, err)
		}
		if len(raw)*8 < 128 {
			t.Fatalf("%q carries %d bits; ADR 0004 needs at least 128", id, len(raw)*8)
		}
		if !validSessionID(id) {
			t.Fatalf("%q is not a valid session-id", id)
		}
		if seen[id] {
			t.Fatalf("%q repeated", id)
		}
		seen[id] = true
	}
}

func TestGeneratedIdentifiersFollowTheIdentGrammar(t *testing.T) {
	src := bytes.NewReader(bytes.Repeat([]byte{0xff, 0x00, 0x5a}, 100))
	for name, gen := range map[string]func() (string, error){
		"transaction": func() (string, error) { return NewTransactionID(src) },
		"message":     func() (string, error) { return NewMessageID(src) },
	} {
		id, err := gen()
		if err != nil {
			t.Fatal(err)
		}
		if !validIdent(id) {
			t.Errorf("%s id %q is not an ident", name, id)
		}
	}
}

func TestTransactionIDsCarryAtLeast64RandomBits(t *testing.T) {
	if transactionIDBytes*8 < 64 {
		t.Fatalf("transaction ids carry %d bits; §7.1 needs 64", transactionIDBytes*8)
	}
}

func TestIdentifierGenerationFailsWithoutRandomness(t *testing.T) {
	broken := iotest.ErrReader(errors.New("entropy gone"))
	if _, err := NewSessionID(broken); err == nil {
		t.Fatal("NewSessionID succeeded without randomness")
	}
	if _, err := NewMessageID(bytes.NewReader([]byte{1, 2})); err == nil {
		t.Fatal("NewMessageID succeeded on a short read")
	}
}

func TestIdentValidationFollowsTheGrammar(t *testing.T) {
	tests := map[string]bool{
		"abcd":                              true,
		"a1.-+%=":                           true,
		"0bcdefghijklmnopqrstuvwxyz123456":  true,
		"abc":                               false, // at least four characters
		"0bcdefghijklmnopqrstuvwxyz1234567": false, // at most 32
		".abc":                              false, // starts with a letter or digit
		"ab cd":                             false,
		"ab/cd":                             false,
		"":                                  false,
	}
	for in, want := range tests {
		if got := validIdent(in); got != want {
			t.Errorf("validIdent(%q) = %v, want %v", in, got, want)
		}
	}
}
