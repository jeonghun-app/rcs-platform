package msrp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// chat is content no verb may show: as text, as the bytes %d and %v of a
// []byte write, and in hex.
const chat = "meet me at the usual place"

func chatForms() []string {
	return []string{chat[:12], strings.Trim(fmt.Sprint([]byte(chat[:6])), "[]"), hex.EncodeToString([]byte(chat[:6]))}
}

// No fmt verb, valid or not, slog record or JSON encoding shows a message
// body (#530): %p and %w print their argument field by field and call no
// method, so the body is behind a pointer, which they print as an address.
func TestABodyIsPrintedNowhere(t *testing.T) {
	m := Message{TransactionID: "t1", Method: MethodSend, ContentType: "text/plain", Body: BodyOf([]byte(chat))}
	out := Outgoing{ContentType: "text/plain", Body: BodyOf([]byte(chat))}
	holder := struct {
		M   Message
		O   Outgoing
		B   Body
		Ptr *Message
	}{m, out, m.Body, &m}
	var outs []string
	for _, v := range []any{m, &m, out, &out, m.Body, &m.Body, holder, &holder, []Message{m}, map[string]Body{"b": m.Body}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%o", "%b", "%t", "%p", "%w", "%c", "%U", "%e"} {
			outs = append(outs, fmt.Sprintf(verb, v))
		}
		j, _ := json.Marshal(v)
		var logged bytes.Buffer
		slog.New(slog.NewJSONHandler(&logged, nil)).Info("m", "v", v)
		slog.New(slog.NewTextHandler(&logged, nil)).Info("m", "v", v)
		outs = append(outs, string(j), logged.String())
	}
	for _, o := range outs {
		for _, f := range chatForms() {
			if strings.Contains(o, f) {
				t.Errorf("%q shows the body (%q)", o, f)
			}
		}
	}
}

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
	b := bodyOf(4096)
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
