package content

import (
	"testing"
)

// A Body is the slice it was made from: the same array, length and
// capacity, so that relaying copies nothing; an empty one, nil or not, is
// the zero Body, whose Bytes is nil.
func TestABodyIsItsSlice(t *testing.T) {
	b := make([]byte, 5, 9)
	copy(b, "hello")
	body := BodyOf(b)
	got := body.Bytes()
	if string(got) != "hello" || body.Len() != 5 || cap(got) != 9 || &got[0] != &b[0] {
		t.Fatalf("Bytes = %q len %d cap %d, want b itself", got, body.Len(), cap(got))
	}
	for _, empty := range [][]byte{nil, {}, b[:0]} {
		if e := BodyOf(empty); e.p != nil || e.Bytes() != nil || e.Len() != 0 {
			t.Errorf("BodyOf(%#v) = a non-zero Body", empty)
		}
	}
	var zero Body
	if zero.Bytes() != nil || zero.Len() != 0 {
		t.Error("the zero Body is not empty")
	}
}

// Neither BodyOf nor Bytes allocates: the relay's path must allocate no
// more than it did with a []byte (#530).
func TestABodyAllocatesNothing(t *testing.T) {
	b := make([]byte, 4096)
	var sink Body
	var out []byte
	if n := testing.AllocsPerRun(100, func() {
		sink = BodyOf(b)
		out = sink.Bytes()
	}); n != 0 {
		t.Fatalf("BodyOf and Bytes allocate %v times, want 0", n)
	}
	if len(out) != len(b) {
		t.Fatal("Bytes lost the body")
	}
}
