package dynamostore

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// KeySize is the length of a challenge key (AES-256).
const KeySize = 32

// maxKeyID bounds a key's identifier, which every sealed challenge carries.
const maxKeyID = 64

// ChallengeKey is one key that challenges are sealed or opened with, named by
// an identifier the instances agree on (the Secrets Manager version, say).
type ChallengeKey struct {
	ID  string
	Key []byte
}

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
		if len(k.Key) != KeySize {
			return nil, fmt.Errorf("dynamostore: a challenge key must be %d bytes", KeySize)
		}
		block, err := aes.NewCipher(k.Key)
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
