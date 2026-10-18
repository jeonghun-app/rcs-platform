// Package keyring encrypts the subscriber secrets the HSS stores (K, OPc,
// Digest HA1) so that a copy of the subscribers table, a backup or a console
// read reveals nothing usable (docs/architecture.md §7).
//
// Secrets are sealed with AES-256-GCM under a data key. In staging and prod
// the data key is envelope-encrypted by AWS KMS: the wrapped key is stored
// next to the subscribers, and every HSS task asks KMS to unwrap it once at
// start-up, so KMS sees one request per task start rather than one per
// authentication. In dev and test a local key from the environment is used
// directly (NewLocal); the HSS refuses that in production.
//
// Every sealed value names the data key that sealed it, so a later key can
// be added without re-encrypting what exists, and is bound by the caller's
// additional data to the record and field it belongs to: a ciphertext copied
// to another subscriber or another field does not open.
package keyring

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
)

// DataKeySize is the size of a data key: AES-256.
const DataKeySize = 32

// LocalKeyID names the key of a keyring built with NewLocal.
const LocalKeyID = "local"

// format is the first byte of every sealed value, so the layout can change
// later without guessing.
const format = 1

const nonceSize = 12

var (
	// ErrExists is returned by Store.AddDataKey when another task added a
	// key with the same identifier first.
	ErrExists = errors.New("keyring: data key exists")
	// ErrUnknownKey means a value was sealed with a data key this keyring
	// does not hold.
	ErrUnknownKey = errors.New("keyring: sealed with an unknown data key")
	// ErrCorrupt means a value is not a sealed value, or does not open with
	// its key and additional data: it was altered, truncated or moved.
	ErrCorrupt = errors.New("keyring: sealed value does not open")
)

// WrappedKey is a data key encrypted under the master key, as stored.
type WrappedKey struct {
	// ID is a decimal number; the highest one seals new values.
	ID         string
	Ciphertext []byte
}

// Wrapper is the master key: AWS KMS in production (internal/hss/awsstore).
type Wrapper interface {
	// GenerateDataKey returns a new DataKeySize-byte key in plaintext and
	// wrapped under the master key.
	GenerateDataKey(ctx context.Context) (plaintext, wrapped []byte, err error)
	// Unwrap returns the plaintext of a wrapped data key in a new slice,
	// which the keyring clears once it has made its cipher.
	Unwrap(ctx context.Context, wrapped []byte) ([]byte, error)
}

// Store keeps the wrapped data keys.
type Store interface {
	// DataKeys returns every stored wrapped key.
	DataKeys(ctx context.Context) ([]WrappedKey, error)
	// AddDataKey stores a key, or fails with an error wrapping ErrExists
	// when a key with its ID is already stored.
	AddDataKey(ctx context.Context, k WrappedKey) error
}

// Keyring seals and opens values. It is safe for concurrent use and formats
// as a placeholder, because it holds the data keys.
type Keyring struct {
	current string
	aeads   map[string]cipher.AEAD
	rand    io.Reader
}

// NewLocal returns a keyring holding key alone, for dev and test. rand
// supplies nonces (crypto/rand.Reader).
func NewLocal(key []byte, rand io.Reader) (*Keyring, error) {
	k := &Keyring{aeads: map[string]cipher.AEAD{}, rand: rand}
	if err := k.add(LocalKeyID, key); err != nil {
		return nil, err
	}
	k.current = LocalKeyID
	return k, nil
}

// Open loads the wrapped data keys from s and unwraps each with w. When s
// holds none, it generates the first one and stores it; when another task
// stores one at the same time, it uses that task's key instead, so every
// task seals with the same key.
func Open(ctx context.Context, w Wrapper, s Store, rand io.Reader) (*Keyring, error) {
	wrapped, err := s.DataKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("keyring: loading data keys: %w", err)
	}
	if len(wrapped) == 0 {
		if wrapped, err = createFirst(ctx, w, s); err != nil {
			return nil, err
		}
	}
	k := &Keyring{aeads: map[string]cipher.AEAD{}, rand: rand}
	highest := -1
	for _, wk := range wrapped {
		n, err := strconv.Atoi(wk.ID)
		if err != nil || n < 0 || strconv.Itoa(n) != wk.ID {
			return nil, errors.New("keyring: a stored data key has an invalid identifier")
		}
		plain, err := w.Unwrap(ctx, wk.Ciphertext)
		if err != nil {
			return nil, fmt.Errorf("keyring: unwrapping data key %s: %w", wk.ID, err)
		}
		err = k.add(wk.ID, plain)
		clear(plain)
		if err != nil {
			return nil, err
		}
		if n > highest {
			highest, k.current = n, wk.ID
		}
	}
	return k, nil
}

func createFirst(ctx context.Context, w Wrapper, s Store) ([]WrappedKey, error) {
	plain, ct, err := w.GenerateDataKey(ctx)
	clear(plain) // reloaded through Unwrap like every other key
	if err != nil {
		return nil, fmt.Errorf("keyring: generating a data key: %w", err)
	}
	err = s.AddDataKey(ctx, WrappedKey{ID: "1", Ciphertext: ct})
	if err != nil && !errors.Is(err, ErrExists) {
		return nil, fmt.Errorf("keyring: storing the data key: %w", err)
	}
	wrapped, err := s.DataKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("keyring: loading data keys: %w", err)
	}
	if len(wrapped) == 0 {
		return nil, errors.New("keyring: the stored data key cannot be read back")
	}
	return wrapped, nil
}

func (k *Keyring) add(id string, key []byte) error {
	if len(key) != DataKeySize {
		return fmt.Errorf("keyring: data key %s is %d bytes, want %d", id, len(key), DataKeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	k.aeads[id] = aead
	return nil
}

// Seal encrypts plaintext under the current data key, bound to aad. Nonces
// are random: the HSS seals only when secrets are provisioned, which stays
// far below the number of messages a random 96-bit GCM nonce allows per key.
func (k *Keyring) Seal(plaintext, aad []byte) ([]byte, error) {
	id := k.current
	header := make([]byte, 0, 2+len(id)+nonceSize)
	header = append(header, format, byte(len(id)))
	header = append(header, id...)
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(k.rand, nonce); err != nil {
		return nil, fmt.Errorf("keyring: reading a nonce: %w", err)
	}
	header = append(header, nonce...)
	return k.aeads[id].Seal(header, nonce, plaintext, additional(header[:2+len(id)], aad)), nil
}

// Open decrypts a value Seal returned for the same aad.
func (k *Keyring) Open(sealed, aad []byte) ([]byte, error) {
	if len(sealed) < 2 || sealed[0] != format {
		return nil, ErrCorrupt
	}
	idLen := int(sealed[1])
	if len(sealed) < 2+idLen+nonceSize {
		return nil, ErrCorrupt
	}
	id := string(sealed[2 : 2+idLen])
	aead, ok := k.aeads[id]
	if !ok {
		return nil, ErrUnknownKey
	}
	nonce := sealed[2+idLen : 2+idLen+nonceSize]
	plain, err := aead.Open(nil, nonce, sealed[2+idLen+nonceSize:], additional(sealed[:2+idLen], aad))
	if err != nil {
		return nil, ErrCorrupt
	}
	return plain, nil
}

// additional authenticates the key identifier together with the caller's
// data, so a value cannot be relabelled with another key's identifier.
func additional(header, aad []byte) []byte {
	out := make([]byte, 0, len(header)+len(aad))
	return append(append(out, header...), aad...)
}

// CurrentKeyID is the identifier of the key that seals new values.
func (k *Keyring) CurrentKeyID() string { return k.current }

const placeholder = "keyring[redacted]"

// String returns a placeholder: the keyring holds data keys.
func (k *Keyring) String() string { return placeholder }

// GoString returns the placeholder too.
func (k *Keyring) GoString() string { return placeholder }

// Format makes every fmt verb print the placeholder.
func (k *Keyring) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, placeholder) }

// LogValue keeps slog from walking the fields.
func (k *Keyring) LogValue() slog.Value { return slog.StringValue(placeholder) }
