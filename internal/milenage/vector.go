package milenage

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

// ErrMACFailure means a MAC-A in AUTN or a MAC-S in AUTS did not verify: the
// value was not produced with this subscriber's K and OPc for this RAND.
var ErrMACFailure = errors.New("milenage: MAC verification failed")

// resyncAMF is the dummy AMF that MAC-S is computed over (TS 33.102 §6.3.3):
// the card does not know the AMF the network will use next, so both sides use
// zero.
var resyncAMF = [AMFSize]byte{}

// Vector is one authentication vector (TS 33.102 §6.3.2): what hss returns to
// scscf in a Cx Multimedia-Auth-Answer.
//
// XRES, CK and IK are secrets, and RAND and AUTN must not be logged either, so
// the parts are sealed, read through methods, and the type formats as a fixed
// placeholder. The zero Vector holds all zeros.
type Vector struct {
	p secret.Sealed[vectorParts]
}

type vectorParts struct {
	rand [RANDSize]byte
	xres [RESSize]byte
	ck   [CKSize]byte
	ik   [IKSize]byte
	autn [AUTNSize]byte
}

func (v Vector) parts() vectorParts {
	if v.p == nil {
		return vectorParts{}
	}
	return *v.p()
}

// RAND returns the challenge.
func (v Vector) RAND() [RANDSize]byte { return v.parts().rand }

// XRES returns the expected response. Secret.
func (v Vector) XRES() [RESSize]byte { return v.parts().xres }

// CK returns the cipher key. Secret.
func (v Vector) CK() [CKSize]byte { return v.parts().ck }

// IK returns the integrity key. Secret.
func (v Vector) IK() [IKSize]byte { return v.parts().ik }

// AUTN returns the network authentication token.
func (v Vector) AUTN() [AUTNSize]byte { return v.parts().autn }

// Vector builds the authentication vector for rand, sqn and amf. rand must
// come from a cryptographically secure source (crypto/rand); it is a parameter
// so that the caller owns randomness and tests stay deterministic.
func (m Milenage) Vector(rand [RANDSize]byte, sqn SQN, amf [AMFSize]byte) Vector {
	sqnBytes := sqn.Bytes()
	temp := m.temp(rand)
	out1 := m.out1(temp, sqnBytes, amf)
	out2 := m.out(temp, r2, c2)

	p := &vectorParts{
		rand: rand,
		xres: [RESSize]byte(out2[8:16]),
		ck:   m.out(temp, r3, c3),
		ik:   m.out(temp, r4, c4),
	}
	// AUTN = SQN ⊕ AK ‖ AMF ‖ MAC-A (TS 33.102 §6.3.2).
	for i := range SQNSize {
		p.autn[i] = sqnBytes[i] ^ out2[i]
	}
	copy(p.autn[SQNSize:SQNSize+AMFSize], amf[:])
	copy(p.autn[SQNSize+AMFSize:], out1[:MACSize])
	return Vector{p: secret.Seal(p)}
}

// CheckAUTN does the card's half of TS 33.102 §6.3.3: it recovers SQN from
// AUTN with AK and verifies MAC-A. It returns ErrMACFailure if AUTN was not
// made with this subscriber's keys. It does not judge whether SQN is fresh:
// the caller compares it with its own state using Fresh, and answers with
// AUTS when it is not.
func (m Milenage) CheckAUTN(rand [RANDSize]byte, autn [AUTNSize]byte) (SQN, error) {
	temp := m.temp(rand)
	out2 := m.out(temp, r2, c2)
	var sqnBytes [SQNSize]byte
	for i := range SQNSize {
		sqnBytes[i] = autn[i] ^ out2[i]
	}
	amf := [AMFSize]byte(autn[SQNSize : SQNSize+AMFSize])
	out1 := m.out1(temp, sqnBytes, amf)
	if subtle.ConstantTimeCompare(out1[:MACSize], autn[SQNSize+AMFSize:]) != 1 {
		return 0, ErrMACFailure
	}
	return SQNFromBytes(sqnBytes), nil
}

// AUTS builds the resynchronisation token the card returns when AUTN carried
// a sequence number it will not accept (TS 33.102 §6.3.3):
// AUTS = SQN_MS ⊕ AK* ‖ MAC-S, with MAC-S over the dummy AMF.
func (m Milenage) AUTS(rand [RANDSize]byte, sqnMS SQN) [AUTSSize]byte {
	sqnBytes := sqnMS.Bytes()
	temp := m.temp(rand)
	out1 := m.out1(temp, sqnBytes, resyncAMF)
	out5 := m.out(temp, r5, c5)
	var auts [AUTSSize]byte
	for i := range SQNSize {
		auts[i] = sqnBytes[i] ^ out5[i]
	}
	copy(auts[SQNSize:], out1[MACSize:])
	return auts
}

// VerifyAUTS does the network's half of resynchronisation (TS 33.102 §6.3.5):
// it recovers SQN_MS from AUTS with AK* and verifies MAC-S. rand is the RAND
// of the challenge the card rejected. Pass the result to Resynchronise.
func (m Milenage) VerifyAUTS(rand [RANDSize]byte, auts [AUTSSize]byte) (SQN, error) {
	temp := m.temp(rand)
	out5 := m.out(temp, r5, c5)
	var sqnBytes [SQNSize]byte
	for i := range SQNSize {
		sqnBytes[i] = auts[i] ^ out5[i]
	}
	out1 := m.out1(temp, sqnBytes, resyncAMF)
	if subtle.ConstantTimeCompare(out1[MACSize:], auts[SQNSize:]) != 1 {
		return 0, ErrMACFailure
	}
	return SQNFromBytes(sqnBytes), nil
}

const redactedVector = "milenage.Vector{redacted}"

// String returns a fixed placeholder: no part of a vector may reach a log.
func (v Vector) String() string { return redactedVector }

// GoString returns the same placeholder as String.
func (v Vector) GoString() string { return redactedVector }

// Format makes every fmt verb produce the placeholder.
func (v Vector) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedVector) }

// LogValue keeps log/slog handlers from serialising the fields.
func (v Vector) LogValue() slog.Value { return slog.StringValue(redactedVector) }

// MarshalJSON emits the placeholder, because a vector nested in another value
// reaches a JSON log handler through encoding/json, which ignores LogValue.
// Code that stores a vector copies its parts into its own record type.
func (v Vector) MarshalJSON() ([]byte, error) { return json.Marshal(redactedVector) }
