package keyring

import (
	"bytes"
	"testing"
)

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// FuzzOpen feeds arbitrary bytes to Open, which parses the sealed format
// read from the store. Nothing may panic, and a value that opens must have
// been sealed with the same additional data.
func FuzzOpen(f *testing.F) {
	// A fixed nonce, so that every fuzz worker process seals the seed to the
	// same bytes as the coordinator did.
	k, err := NewLocal(bytes.Repeat([]byte{1}, DataKeySize), zeros{})
	if err != nil {
		f.Fatal(err)
	}
	sealed, err := k.Seal([]byte("secret"), []byte("aad"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sealed, []byte("aad"))
	f.Add([]byte{format, 0}, []byte(nil))
	f.Add([]byte{format, 5, 'l', 'o', 'c', 'a', 'l'}, []byte("aad"))
	f.Fuzz(func(t *testing.T, data, aad []byte) {
		plain, err := k.Open(data, aad)
		if err != nil {
			return
		}
		if !bytes.Equal(data, sealed) || !bytes.Equal(aad, []byte("aad")) || string(plain) != "secret" {
			t.Fatalf("forged value opened: %x", data)
		}
	})
}
