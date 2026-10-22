package secret

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// key is made up for the tests, and printable, so that %s would show it.
var key = []byte("0123456789abcdefFEDCBA9876543210")

// forms are what would show key: as text, as %d and %x write its bytes,
// and in base64.
func forms() []string {
	return []string{string(key[:8]), strings.Trim(fmt.Sprint(key[:8]), "[]"), hex.EncodeToString(key[:8]), base64.StdEncoding.EncodeToString(key)[:10]}
}

// holder nests a Key in an unexported field, where fmt calls no method.
type holder struct {
	ID  string
	key Key
}

// TestAKeyIsPrintedNowhere: on its own, nested in an unexported field, or
// in a pointer, under every verb fmt has, valid or not, and under slog and
// encoding/json, no form of the key's bytes appears (#455).
func TestAKeyIsPrintedNowhere(t *testing.T) {
	k := NewKey(key)
	h := holder{ID: "k1", key: k}
	var outs []string
	for _, v := range []any{k, h, &h, []Key{k}, map[string]Key{"k": k}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%o", "%b", "%t", "%p", "%w", "%c", "%U", "%e"} {
			outs = append(outs, fmt.Sprintf(verb, v))
		}
		j, _ := json.Marshal(v)
		var logged bytes.Buffer
		slog.New(slog.NewJSONHandler(&logged, nil)).Info("m", "v", v)
		outs = append(outs, string(j), logged.String())
	}
	for _, out := range outs {
		for _, f := range forms() {
			if strings.Contains(out, f) {
				t.Errorf("%q shows the key (%q)", out, f)
			}
		}
	}
}

// TestAKeyKeepsItsBytes: a Key holds a copy of what it was made of, which
// a change to the caller's slice does not reach.
func TestAKeyKeepsItsBytes(t *testing.T) {
	b := bytes.Clone(key)
	k := NewKey(b)
	b[0] = 'X'
	if !bytes.Equal(k.Reveal(), key) || k.Len() != len(key) || !k.Equal(NewKey(key)) || k.Equal(NewKey(b)) {
		t.Error("the key changed with the caller's slice, or does not compare by its bytes")
	}
	var zero Key
	if zero.Reveal() != nil || zero.Len() != 0 || zero.String() != redacted {
		t.Error("the zero Key is not empty")
	}
}
