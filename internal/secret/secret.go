// Package secret holds key bytes where no output can reach them.
//
// A key type's Format, String, LogValue and MarshalJSON cover a key that
// fmt, slog or encoding/json is handed directly. They do not cover every
// path: fmt calls none of them for a verb that does not fit the value, %p
// or %w on a struct say, and then prints the fields by reflection, and for
// a mismatched verb such as %s or %q it prints a nested pointer's target in
// full (#455). A func value is the one kind fmt prints only as an address,
// under every verb and at every depth, so a Key reaches its bytes through a
// closure, as internal/sip/digest's sealed state does.
package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
)

// Key is key bytes that print as a placeholder. The zero Key has none.
type Key struct {
	b func() []byte
}

// redacted is what a Key prints as.
const redacted = "[redacted]"

// NewKey is a Key of a copy of b, so that the caller's slice changing
// afterwards does not change the key.
func NewKey(b []byte) Key {
	c := bytes.Clone(b)
	return Key{b: func() []byte { return c }}
}

// Reveal returns the key's bytes, for the HMAC or cipher that uses them. It
// is the key itself, not a copy: the caller must not change it, nor keep it
// where it could be printed.
func (k Key) Reveal() []byte {
	if k.b == nil {
		return nil
	}
	return k.b()
}

// Len is how many bytes the key has.
func (k Key) Len() int { return len(k.Reveal()) }

// Equal reports whether k and o hold the same bytes.
func (k Key) Equal(o Key) bool { return bytes.Equal(k.Reveal(), o.Reveal()) }

// String, GoString, Format, LogValue and MarshalJSON print the placeholder,
// under every valid verb of fmt; an invalid one prints the closure's address.
func (k Key) String() string               { return redacted }
func (k Key) GoString() string             { return redacted }
func (k Key) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, redacted) }
func (k Key) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (k Key) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }
