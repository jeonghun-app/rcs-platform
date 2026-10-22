// Package secret holds key bytes where no output can reach them.
//
// A key type's Format, String, LogValue and MarshalJSON cover a key that
// fmt, slog or encoding/json is handed directly. They do not cover every
// path: fmt calls none of them for a verb that does not fit the value, %p
// or %w on a struct say, and then prints the fields by reflection, and for
// a mismatched verb such as %s or %q it prints a nested pointer's target in
// full (#455). A func value is the one kind fmt prints only as an address,
// under every verb and at every depth, so a Key reaches its bytes through a
// closure, and Sealed is the same for any secret state, which milenage and
// digest keep their state in.
package secret

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
)

// Sealed holds a pointer to secret state where fmt cannot reach it: a func
// value, which fmt prints only as an address, under every verb and at
// every depth. A struct holding secret state keeps it in a Sealed field
// and reaches it by calling the field.
type Sealed[T any] func() *T

// Seal is v, sealed.
func Seal[T any](v *T) Sealed[T] { return func() *T { return v } }

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

// NewString is a Key of s's bytes, for a secret that is text, such as a
// token or a password.
func NewString(s string) Key { return NewKey([]byte(s)) }

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

// RevealString returns the key's bytes as text, for a secret that is
// text; the caller must not keep it where it could be printed.
func (k Key) RevealString() string { return string(k.Reveal()) }

// IsZero reports whether the key has no bytes.
func (k Key) IsZero() bool { return k.Len() == 0 }

// Equal reports whether k and o hold the same bytes, in a time that
// depends on their lengths only, so that it can compare a secret a
// request carries with a configured one (#496 security review).
func (k Key) Equal(o Key) bool { return subtle.ConstantTimeCompare(k.Reveal(), o.Reveal()) == 1 }

// String, GoString, Format, LogValue and MarshalJSON print the placeholder,
// under every valid verb of fmt; an invalid one prints the closure's address.
func (k Key) String() string               { return redacted }
func (k Key) GoString() string             { return redacted }
func (k Key) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, redacted) }
func (k Key) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (k Key) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }
