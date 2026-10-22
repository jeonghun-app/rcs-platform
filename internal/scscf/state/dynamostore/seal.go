package dynamostore

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

// KeySize is the length of a challenge key (AES-256).
const KeySize = 32

// maxKeyID bounds a key's identifier, which every sealed challenge carries.
const maxKeyID = 64

// ChallengeKey is one key that challenges are sealed or opened with, named by
// an identifier the instances agree on (the Secrets Manager version, say).
type ChallengeKey struct {
	ID string
	// Key is the AES-256 key, which no output reaches (internal/secret).
	Key secret.Key
}

// redacted is what a ChallengeKey prints as: its ID, never its key.
func (k ChallengeKey) redacted() string { return "ChallengeKey{ID:" + k.ID + " Key:[redacted]}" }

// String, GoString, Format, LogValue and MarshalJSON print the key's ID
// alone, under every valid verb of fmt, as routing.DialogKey's do, so that
// a Config logged or printed does not give the key away (#439 security
// review). An invalid verb, %p on a struct say, calls none of them and
// prints the fields, where Key, a secret.Key, shows no byte (#455).
func (k ChallengeKey) String() string               { return k.redacted() }
func (k ChallengeKey) GoString() string             { return k.redacted() }
func (k ChallengeKey) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, k.redacted()) }
func (k ChallengeKey) LogValue() slog.Value         { return slog.StringValue(k.redacted()) }
func (k ChallengeKey) MarshalJSON() ([]byte, error) { return json.Marshal(k.redacted()) }

// sealer seals challenge documents with AES-256-GCM under the seal key and
// opens them with any key it knows. A sealed document is the length of the
// key's identifier, the identifier, the nonce and the ciphertext, so the key a
// document needs is found by name, whatever order the keys are configured in.
type sealer struct {
	sealWith *sealKey
	keys     map[string]*sealKey
}

type sealKey struct {
	id   string
	aead cipher.AEAD
}

func newSealer(keys []ChallengeKey, sealID string) (*sealer, error) {
	if len(keys) == 0 {
		return nil, errors.New("dynamostore: at least one challenge key is needed")
	}
	s := &sealer{keys: map[string]*sealKey{}}
	for _, k := range keys {
		if k.ID == "" || len(k.ID) > maxKeyID {
			return nil, fmt.Errorf("dynamostore: a challenge key needs an ID of 1 to %d bytes", maxKeyID)
		}
		if _, dup := s.keys[k.ID]; dup {
			return nil, errors.New("dynamostore: two challenge keys share an ID")
		}
		if k.Key.Len() != KeySize {
			return nil, fmt.Errorf("dynamostore: a challenge key must be %d bytes", KeySize)
		}
		block, err := aes.NewCipher(k.Key.Reveal())
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		s.keys[k.ID] = &sealKey{id: k.ID, aead: aead}
	}
	if sealID == "" && len(keys) == 1 {
		sealID = keys[0].ID
	}
	s.sealWith = s.keys[sealID]
	if s.sealWith == nil {
		return nil, errors.New("dynamostore: the seal key is not among the challenge keys")
	}
	return s, nil
}

// seal encrypts plain with the seal key. aad binds it to its item, so a sealed
// document copied into another item does not open.
func (s *sealer) seal(rand io.Reader, plain, aad []byte) ([]byte, error) {
	k := s.sealWith
	head := 1 + len(k.id)
	ns := k.aead.NonceSize()
	out := make([]byte, head+ns, head+ns+len(plain)+k.aead.Overhead())
	out[0] = byte(len(k.id))
	copy(out[1:], k.id)
	if _, err := io.ReadFull(rand, out[head:]); err != nil {
		return nil, fmt.Errorf("dynamostore: drawing a nonce: %w", err)
	}
	return k.aead.Seal(out, out[head:], plain, aad), nil
}

// open decrypts a sealed document with the key it names.
func (s *sealer) open(sealed, aad []byte) ([]byte, error) {
	if len(sealed) < 1 || len(sealed) < 1+int(sealed[0]) {
		return nil, fmt.Errorf("%w: sealed challenge too short", state.ErrInvalid)
	}
	head := 1 + int(sealed[0])
	k := s.keys[string(sealed[1:head])]
	if k == nil {
		return nil, fmt.Errorf("%w: challenge sealed with an unknown key", state.ErrInvalid)
	}
	ns := k.aead.NonceSize()
	if len(sealed) < head+ns+k.aead.Overhead() {
		return nil, fmt.Errorf("%w: sealed challenge too short", state.ErrInvalid)
	}
	plain, err := k.aead.Open(nil, sealed[head:head+ns], sealed[head+ns:], aad)
	if err != nil {
		return nil, fmt.Errorf("%w: challenge does not open", state.ErrInvalid)
	}
	return plain, nil
}
