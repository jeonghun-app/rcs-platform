// Package contenttest checks that a value holding chat content shows none
// of it, for the tests of every package that holds such content (#547).
package contenttest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// Verbs are the fmt verbs a value is printed under: the valid ones, and
// the invalid ones that print a struct field by field without calling a
// method (%p, %w), which a []byte field would show through.
var Verbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%o", "%b", "%t", "%p", "%w", "%c", "%U", "%e"}

// ValidVerbs are Verbs without %p and %w, which go vet refuses on a value
// that is not a pointer or an error (HiddenFromValidVerbs).
var ValidVerbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%o", "%b", "%t", "%c", "%U", "%e"}

// Hidden fails t if any of vs, printed under every verb in Verbs,
// encoded by encoding/json or logged by slog's text and JSON handlers,
// shows chat: as text, as the decimal octets %d and %v write for a
// []byte, or in hex. chat must be at least 12 octets.
func Hidden(t testing.TB, chat string, vs ...any) {
	t.Helper()
	hidden(t, chat, Verbs, vs)
}

// HiddenFromValidVerbs is Hidden under ValidVerbs only, for content held
// in a []byte with methods, as sip.Body (#573): under %p and %w fmt calls
// no method, so for those it is go vet's printf check that keeps them off
// such a value.
func HiddenFromValidVerbs(t testing.TB, chat string, vs ...any) {
	t.Helper()
	hidden(t, chat, ValidVerbs, vs)
}

func hidden(t testing.TB, chat string, verbs []string, vs []any) {
	t.Helper()
	if len(chat) < 12 {
		t.Fatalf("contenttest: chat %d octets, want 12 or more", len(chat))
	}
	forms := []string{chat[:12], strings.Trim(fmt.Sprint([]byte(chat[:6])), "[]"), hex.EncodeToString([]byte(chat[:6]))}
	for i, v := range vs {
		var outs []string
		for _, verb := range verbs {
			outs = append(outs, fmt.Sprintf(verb, v))
		}
		j, _ := json.Marshal(v)
		var logged bytes.Buffer
		slog.New(slog.NewJSONHandler(&logged, nil)).Info("m", "v", v)
		slog.New(slog.NewTextHandler(&logged, nil)).Info("m", "v", v)
		outs = append(outs, string(j), logged.String())
		for _, o := range outs {
			for _, f := range forms {
				if strings.Contains(o, f) {
					t.Errorf("value %d (%T): %q shows the content (%q)", i, v, o, f)
				}
			}
		}
	}
}
