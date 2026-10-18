package milenage

import (
	"errors"
	"fmt"
)

// SQN is a 48-bit AKA sequence number, held in the low 48 bits of a uint64.
//
// The package follows the profile for sequence numbers that are not time
// based (TS 33.102 Annex C.3.2):
//
//   - SQN = SEQ ‖ IND, with IND the low INDBits bits and SEQ the high 43 bits.
//   - The network increments SEQ by one for every vector it issues and keeps
//     IND fixed. IND names the consumer of the vectors; this platform has one,
//     scscf, so hss uses a single IND value.
//   - The card accepts a SEQ that is greater than the highest SEQ it has
//     accepted and not more than Delta above it (the wrap-around limit of
//     Annex C). The optional age limit L is not used: it only matters when
//     several IND values are in use.
//
// That profile is stricter than what a card with a full IND array accepts, so
// a vector this package calls fresh is accepted by any conforming card.
type SQN uint64

const (
	// INDBits is the length of IND in bits.
	INDBits = 5
	// SEQBits is the length of SEQ in bits.
	SEQBits = 48 - INDBits
	// MaxSEQ is the largest SEQ a 48-bit SQN can carry.
	MaxSEQ = 1<<SEQBits - 1
	// MaxIND is the largest IND value.
	MaxIND = 1<<INDBits - 1
	// Delta is the wrap-around limit: the largest step in SEQ a card accepts.
	Delta = 1 << 28

	sqnMask = 1<<48 - 1
)

// ErrSQNExhausted means SEQ has reached MaxSEQ, so no further fresh vector
// can be generated for the subscriber without re-keying the card.
var ErrSQNExhausted = errors.New("milenage: SEQ exhausted")

// NewSQN joins seq and ind into an SQN. It fails if either does not fit.
func NewSQN(seq uint64, ind uint8) (SQN, error) {
	if seq > MaxSEQ {
		return 0, fmt.Errorf("milenage: SEQ does not fit in %d bits", SEQBits)
	}
	if ind > MaxIND {
		return 0, fmt.Errorf("milenage: IND does not fit in %d bits", INDBits)
	}
	return SQN(seq<<INDBits | uint64(ind)), nil
}

// SQNFromBytes reads the 6-byte big-endian form used inside AUTN and AUTS.
func SQNFromBytes(b [SQNSize]byte) SQN {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return SQN(v)
}

// Bytes returns the 6-byte big-endian form. Bits above the 48th are ignored.
func (s SQN) Bytes() [SQNSize]byte {
	var b [SQNSize]byte
	v := uint64(s) & sqnMask
	for i := SQNSize - 1; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b
}

// SEQ returns the counter part of s.
func (s SQN) SEQ() uint64 { return (uint64(s) & sqnMask) >> INDBits }

// IND returns the index part of s.
func (s SQN) IND() uint8 { return uint8(uint64(s) & MaxIND) }

// Next returns the SQN for the next vector: SEQ plus one, IND unchanged.
func (s SQN) Next() (SQN, error) {
	if s.SEQ() >= MaxSEQ {
		return 0, ErrSQNExhausted
	}
	return NewSQN(s.SEQ()+1, s.IND())
}

// Fresh reports whether a card whose highest accepted sequence number is
// highest would accept sqn. tools/rcs-sim uses it as the card's check;
// Resynchronise uses it to decide whether the network's counter is still in
// range.
func Fresh(sqn, highest SQN) bool {
	seq, ms := sqn.SEQ(), highest.SEQ()
	return seq > ms && seq-ms <= Delta
}

// Resynchronise returns the SQN_HE the network continues from after a card
// reported SQN_MS in a verified AUTS (TS 33.102 §6.3.5): the current he if the
// next vector made from it would be accepted, otherwise SQN_MS's SEQ with he's
// IND. The caller stores the result and generates the next vector from
// result.Next().
func Resynchronise(he, ms SQN) SQN {
	if next, err := he.Next(); err == nil && Fresh(next, ms) {
		return he
	}
	// NewSQN cannot fail: both parts come from valid SQNs.
	sqn, _ := NewSQN(ms.SEQ(), he.IND())
	return sqn
}
