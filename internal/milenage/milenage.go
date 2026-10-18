// Package milenage implements the 3GPP MILENAGE algorithm set (TS 35.205,
// TS 35.206): the functions f1, f1*, f2, f3, f4, f5 and f5* that turn a
// subscriber key K and the operator variant OPc into authentication vectors.
//
// It exists because both ends of IMS AKA run here: hss builds vectors for
// scscf, and tools/rcs-sim plays the ISIM that answers them. Beyond the bare
// functions the package carries the framing from TS 33.102 §6.3 (AUTN, AUTS
// and resynchronisation) and a sequence number profile from TS 33.102 Annex C,
// so callers never assemble those byte layouts themselves.
//
// K, OPc, RES, CK and IK are secrets. Every type that holds one formats as a
// fixed redacted string under fmt and log/slog, and no error carries one.
package milenage

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"log/slog"
)

// Sizes in bytes of the MILENAGE inputs and outputs (TS 35.206 §4).
const (
	KeySize  = 16 // K, OP and OPc
	RANDSize = 16
	SQNSize  = 6
	AMFSize  = 2
	MACSize  = 8 // MAC-A (f1) and MAC-S (f1*)
	RESSize  = 8 // f2 output; MILENAGE always produces 64 bits
	CKSize   = 16
	IKSize   = 16
	AKSize   = 6 // f5 and f5* output
	AUTNSize = SQNSize + AMFSize + MACSize
	AUTSSize = SQNSize + MACSize
)

// Rotation amounts (in bits) and constants c1..c5 are the default values of
// TS 35.206 §4. Every rotation is a whole number of bytes, so rotate works on
// bytes. Each constant is zero except for its last byte.
const (
	r1, r2, r3, r4, r5 = 64, 0, 32, 64, 96
	c1, c2, c3, c4, c5 = 0x00, 0x01, 0x02, 0x04, 0x08
)

// Milenage computes the MILENAGE functions for one subscriber, that is for one
// (K, OPc) pair. It is an immutable value and safe for concurrent use. The zero
// value is not usable; build one with New or NewWithOP.
type Milenage struct {
	block cipher.Block // AES-128 keyed with K: the kernel function E_K of TS 35.206 §4
	opc   [KeySize]byte
}

// New returns the functions for subscriber key k and operator variant opc.
// HSS stores OPc rather than OP (TS 35.206 allows either), so this is the
// constructor production code uses.
func New(k, opc [KeySize]byte) Milenage {
	return Milenage{block: kernel(k), opc: opc}
}

// NewWithOP returns the functions for subscriber key k and operator variant
// op, deriving OPc first.
func NewWithOP(k, op [KeySize]byte) Milenage {
	return New(k, DeriveOPc(k, op))
}

// DeriveOPc computes OPc = OP ⊕ E_K(OP) (TS 35.206 §4). Operators provision
// OPc into the HSS and the card so that OP itself never has to leave the
// operator.
func DeriveOPc(k, op [KeySize]byte) [KeySize]byte {
	var opc [KeySize]byte
	kernel(k).Encrypt(opc[:], op[:])
	xorInto(&opc, &op)
	return opc
}

// kernel returns E_K, AES-128 under k. aes.NewCipher fails only for a key
// length other than 16, 24 or 32 bytes, which the array type rules out.
func kernel(k [KeySize]byte) cipher.Block {
	block, err := aes.NewCipher(k[:])
	if err != nil {
		panic("milenage: AES-128 with a 16-byte key failed: " + err.Error())
	}
	return block
}

// F1 computes the network authentication code MAC-A that goes into AUTN.
func (m Milenage) F1(rand [RANDSize]byte, sqn [SQNSize]byte, amf [AMFSize]byte) [MACSize]byte {
	out := m.out1(m.temp(rand), sqn, amf)
	return [MACSize]byte(out[:MACSize])
}

// F1Star computes the resynchronisation code MAC-S that goes into AUTS.
func (m Milenage) F1Star(rand [RANDSize]byte, sqn [SQNSize]byte, amf [AMFSize]byte) [MACSize]byte {
	out := m.out1(m.temp(rand), sqn, amf)
	return [MACSize]byte(out[MACSize:])
}

// F2 computes the response RES (XRES on the network side).
func (m Milenage) F2(rand [RANDSize]byte) [RESSize]byte {
	out := m.out(m.temp(rand), r2, c2)
	return [RESSize]byte(out[8:16])
}

// F3 computes the cipher key CK.
func (m Milenage) F3(rand [RANDSize]byte) [CKSize]byte {
	return m.out(m.temp(rand), r3, c3)
}

// F4 computes the integrity key IK.
func (m Milenage) F4(rand [RANDSize]byte) [IKSize]byte {
	return m.out(m.temp(rand), r4, c4)
}

// F5 computes the anonymity key AK that conceals SQN inside AUTN.
func (m Milenage) F5(rand [RANDSize]byte) [AKSize]byte {
	out := m.out(m.temp(rand), r2, c2)
	return [AKSize]byte(out[:AKSize])
}

// F5Star computes the anonymity key AK* that conceals SQN_MS inside AUTS.
func (m Milenage) F5Star(rand [RANDSize]byte) [AKSize]byte {
	out := m.out(m.temp(rand), r5, c5)
	return [AKSize]byte(out[:AKSize])
}

// temp computes TEMP = E_K(RAND ⊕ OPc), the value shared by every function
// (TS 35.206 §4).
func (m Milenage) temp(rand [RANDSize]byte) [16]byte {
	x := rand
	xorInto(&x, &m.opc)
	var t [16]byte
	m.block.Encrypt(t[:], x[:])
	return t
}

// out1 computes OUT1 (TS 35.206 §4). IN1 repeats SQN‖AMF twice, and the
// rotation is applied to IN1 ⊕ OPc rather than to TEMP, unlike OUT2..OUT5.
func (m Milenage) out1(temp [16]byte, sqn [SQNSize]byte, amf [AMFSize]byte) [16]byte {
	var in1 [16]byte
	copy(in1[0:6], sqn[:])
	copy(in1[6:8], amf[:])
	copy(in1[8:14], sqn[:])
	copy(in1[14:16], amf[:])
	xorInto(&in1, &m.opc)
	x := rotate(in1, r1)
	xorInto(&x, &temp)
	x[15] ^= c1
	return m.finish(x)
}

// out computes OUT2..OUT5 from TEMP with rotation r and constant c
// (TS 35.206 §4).
func (m Milenage) out(temp [16]byte, r int, c byte) [16]byte {
	x := temp
	xorInto(&x, &m.opc)
	x = rotate(x, r)
	x[15] ^= c
	return m.finish(x)
}

// finish applies the final E_K and ⊕ OPc common to every OUTi.
func (m Milenage) finish(x [16]byte) [16]byte {
	var y [16]byte
	m.block.Encrypt(y[:], x[:])
	xorInto(&y, &m.opc)
	return y
}

// rotate cyclically rotates x left by bits, which TS 35.206 §4 only ever
// asks for in whole bytes.
func rotate(x [16]byte, bits int) [16]byte {
	n := bits / 8
	var y [16]byte
	for i := range y {
		y[i] = x[(i+n)%16]
	}
	return y
}

func xorInto(dst, src *[16]byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

const redactedMilenage = "milenage.Milenage{K:redacted, OPc:redacted}"

// String returns a fixed placeholder: K and OPc must never reach a log.
func (m Milenage) String() string { return redactedMilenage }

// GoString returns the same placeholder as String, so %#v cannot leak K.
func (m Milenage) GoString() string { return redactedMilenage }

// Format makes every fmt verb (including %x and %d, which would otherwise
// print the fields) produce the placeholder.
func (m Milenage) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedMilenage) }

// LogValue keeps log/slog handlers from serialising the fields.
func (m Milenage) LogValue() slog.Value { return slog.StringValue(redactedMilenage) }
