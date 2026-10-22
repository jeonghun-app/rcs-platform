package msrp

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"unsafe"
)

// Body is a message body: chat content, which no fmt verb, slog record or
// JSON encoding may show (#530). It is the []byte it was made from, held
// as a pointer to its first byte and its length and capacity, and so
// aliases it as the []byte did: BodyOf copies nothing, and neither does
// Bytes, so the relay's path allocates no more than before.
//
// A pointer is what keeps the octets out of the invalid verbs: under %p
// and %w fmt prints its argument field by field and calls no method, not
// even a nested field's Format, but prints a pointer below the top level
// as its address. A Body's own String, Format, LogValue and MarshalJSON
// cover the valid verbs and the other encoders.
//
// This file is the package's only use of unsafe. It relies on two rules
// of the unsafe package: unsafe.SliceData returns the address of a
// slice's first element (nil for a nil slice), and unsafe.Slice(p, n),
// then a reslice to its capacity, rebuilds a slice from that address,
// which keeps the backing array reachable for the garbage collector as
// any interior pointer does. No address goes through a uintptr.
type Body struct {
	p    *byte
	n, c int
}

// BodyOf is a Body of b, sharing b's array. An empty b, nil or not, is the
// zero Body, whose Bytes is nil.
func BodyOf(b []byte) Body {
	if len(b) == 0 {
		return Body{}
	}
	return Body{p: unsafe.SliceData(b), n: len(b), c: cap(b)}
}

// Bytes is the body, nil for the zero Body. It shares the Body's array.
func (b Body) Bytes() []byte {
	if b.p == nil {
		return nil
	}
	return unsafe.Slice(b.p, b.c)[:b.n]
}

// Len is the body's length in octets.
func (b Body) Len() int { return b.n }

const redactedBody = "[redacted body]"

func (Body) String() string                 { return redactedBody }
func (Body) GoString() string               { return redactedBody }
func (Body) Format(f fmt.State, _ rune)     { _, _ = io.WriteString(f, redactedBody) }
func (b Body) LogValue() slog.Value         { return slog.IntValue(b.n) }
func (b Body) MarshalJSON() ([]byte, error) { return json.Marshal(map[string]int{"octets": b.n}) }
