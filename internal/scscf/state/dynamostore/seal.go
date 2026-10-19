package dynamostore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// KeySize is the length of a challenge key (AES-256).
const KeySize = 32

// keyIDSize is the length of the key identifier a sealed document starts with.
const keyIDSize = 4

// sealer seals challenge documents with AES-256-GCM. A sealed document is the
// sealing key's identifier, the nonce and the ciphertext. The identifier is a
// hash of the key rather than its position in Config.ChallengeKeys, which
// changes when a key rotates in.
type sealer struct {
	keys []sealKey
}

type sealKey struct {
	id   []byte
	aead cipher.AEAD
}

func newSealer(keys [][]byte) (*sealer, error) {
	if len(keys) == 0 {
		return nil, errors.New("dynamostore: at least one challenge key is needed")
	}
	s := &sealer{}
	for _, k := range keys {
		if len(k) != KeySize {
			return nil, fmt.Errorf("dynamostore: a challenge key must be %d bytes", KeySize)
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(append([]byte("scscf challenge key id\x00"), k...))
		s.keys = append(s.keys, sealKey{id: sum[:keyIDSize], aead: aead})
	}
	return s, nil
}

// seal encrypts plain with the first key. aad binds it to its item, so a
// sealed document copied into another item does not open.
func (s *sealer) seal(rand io.Reader, plain, aad []byte) ([]byte, error) {
	k := s.keys[0]
	ns := k.aead.NonceSize()
	out := make([]byte, keyIDSize+ns, keyIDSize+ns+len(plain)+k.aead.Overhead())
	copy(out, k.id)
	if _, err := io.ReadFull(rand, out[keyIDSize:]); err != nil {
		return nil, fmt.Errorf("dynamostore: drawing a nonce: %w", err)
	}
	return k.aead.Seal(out, out[keyIDSize:], plain, aad), nil
}

// open decrypts a sealed document with the key it names.
func (s *sealer) open(sealed, aad []byte) ([]byte, error) {
	if len(sealed) < keyIDSize {
		return nil, fmt.Errorf("%w: sealed challenge too short", state.ErrInvalid)
	}
	for _, k := range s.keys {
		if !bytes.Equal(k.id, sealed[:keyIDSize]) {
			continue
		}
		ns := k.aead.NonceSize()
		if len(sealed) < keyIDSize+ns+k.aead.Overhead() {
			return nil, fmt.Errorf("%w: sealed challenge too short", state.ErrInvalid)
		}
		plain, err := k.aead.Open(nil, sealed[keyIDSize:keyIDSize+ns], sealed[keyIDSize+ns:], aad)
		if err != nil {
			return nil, fmt.Errorf("%w: challenge does not open", state.ErrInvalid)
		}
		return plain, nil
	}
	return nil, fmt.Errorf("%w: challenge sealed with an unknown key", state.ErrInvalid)
}
