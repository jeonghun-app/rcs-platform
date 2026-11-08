package chatbot

import (
	"bytes"
	"cmp"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Bounds of a JSON envelope (ADR 0009 §9): the request and event bodies of
// the chatbot, operator and internal APIs, as opposed to the content one
// carries in a string field.
const (
	MaxEnvelopeDepth = 4
	MaxEnvelopeArray = 8
)

// Errors of [DecodeEnvelope]: ErrBodyTooLarge is 413, ErrInvalidEnvelope
// 400.
var (
	ErrBodyTooLarge    = errors.New("chatbot: body over its limit")
	ErrInvalidEnvelope = errors.New("chatbot: invalid JSON envelope")
)

// DecodeEnvelope reads at most maxBytes from r and decodes them into v, a
// pointer to a struct, as strict JSON (ADR 0009 §9): UTF-8, one value and
// nothing after it, at most MaxEnvelopeDepth deep with arrays of at most
// MaxEnvelopeArray elements, keys that name a field exactly, never twice and
// never two that differ only in case, null only for a pointer or slice field
// (never as an array element), and no \u escape of half a surrogate pair, which encoding/json would turn into
// U+FFFD and so change a body without a word. encoding/json alone matches
// keys without regard to case and lets the last of two keys win.
//
// Every string field, or slice of strings, needs a tag maxbytes:"n"
// bounding each string in bytes once decoded; a struct field holds only
// bools, numbers, strings, structs, and pointers (one level) to and slices
// of them. No two fields share a JSON name, even in another case; no field
// is embedded or tagged ",string"; and no type decodes itself (a
// json.Unmarshaler or encoding.TextUnmarshaler, such as time.Time), since
// the walker would then check what the decoder does not read. DecodeEnvelope
// panics on a type that breaks this, a programming error that any test of
// the envelope finds.
//
// When v has a method Validate() error, as every wire type of this package
// does, DecodeEnvelope returns what it returns, so that no handler can
// decode a body and forget its field rules. Such a method's errors should
// wrap ErrInvalidEnvelope, as this package's do, to answer 400.
func DecodeEnvelope(r io.Reader, maxBytes int64, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() || rv.Elem().Kind() != reflect.Struct {
		panic("chatbot: DecodeEnvelope needs a non-nil pointer to a struct")
	}
	checkType(rv.Elem().Type(), map[reflect.Type]bool{})
	limit := maxBytes
	if limit < math.MaxInt64 {
		limit++ // one byte over the limit is what tells it was passed
	}
	data, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return fmt.Errorf("chatbot: reading the body: %w", err)
	}
	switch {
	case int64(len(data)) > maxBytes:
		return ErrBodyTooLarge
	case !utf8.Valid(data):
		return refuse(ErrInvalidEnvelope, "not UTF-8")
	}
	w := walker{kind: ErrInvalidEnvelope, maxDepth: MaxEnvelopeDepth, maxArray: MaxEnvelopeArray}
	if err := walkJSON(data, w, rv.Elem().Type()); err != nil {
		return err
	}
	if loneSurrogate(data) {
		return refuse(ErrInvalidEnvelope, "an escape of half a surrogate pair")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil {
		// The decoder's error quotes the value; this one names no part of it.
		return refuse(ErrInvalidEnvelope, "a value of the wrong type for its field")
	}
	if val, ok := v.(interface{ Validate() error }); ok {
		return val.Validate()
	}
	return nil
}

// field is a struct field as an envelope key names it.
type field struct {
	typ    reflect.Type
	maxLen int
}

// fieldsOf maps the JSON names of t's fields to their types and string
// bounds, as encoding/json names them: the json tag's name, or the Go name;
// a field tagged "-" is never decoded. checkType has refused embedded fields,
// so there are no promoted ones.
func fieldsOf(t reflect.Type) map[string]field {
	fields := map[string]field{}
	for i := range t.NumField() {
		if f := t.Field(i); f.IsExported() {
			if name, _, ok := jsonName(f); ok {
				maxLen, _ := strconv.Atoi(f.Tag.Get("maxbytes"))
				fields[name] = field{f.Type, maxLen}
			}
		}
	}
	return fields
}

// jsonName returns the key and the options encoding/json reads f by, or
// false for a field it skips.
func jsonName(f reflect.StructField) (string, []string, bool) {
	tag := f.Tag.Get("json")
	if tag == "-" {
		return "", nil, false
	}
	name, opts, _ := strings.Cut(tag, ",")
	return cmp.Or(name, f.Name), strings.Split(opts, ","), true
}

var (
	jsonUnmarshaler = reflect.TypeFor[json.Unmarshaler]()
	textUnmarshaler = reflect.TypeFor[encoding.TextUnmarshaler]()
)

// decodesItself reports whether encoding/json hands t's JSON to a method of
// t rather than decoding it field by field.
func decodesItself(t reflect.Type) bool {
	p := reflect.PointerTo(t)
	return t.Implements(jsonUnmarshaler) || p.Implements(jsonUnmarshaler) ||
		t.Implements(textUnmarshaler) || p.Implements(textUnmarshaler)
}

// checkType panics unless struct type t and every type reachable from it
// follow DecodeEnvelope's rules.
func checkType(t reflect.Type, seen map[reflect.Type]bool) {
	if seen[t] {
		return
	}
	seen[t] = true
	bad := func(name, why string) {
		panic(fmt.Sprintf("chatbot: envelope field %s.%s %s", t, name, why))
	}
	if decodesItself(t) {
		panic(fmt.Sprintf("chatbot: envelope type %s decodes itself", t))
	}
	names := map[string]bool{}
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Anonymous {
			bad(f.Name, "is embedded")
		}
		name, opts, ok := jsonName(f)
		if !f.IsExported() || !ok {
			continue
		}
		if slices.Contains(opts, "string") {
			bad(f.Name, `is tagged ",string"`)
		}
		if k := foldKey(name); names[k] {
			bad(f.Name, "shares its JSON name with another field")
		} else {
			names[k] = true
		}
		maxLen, _ := strconv.Atoi(f.Tag.Get("maxbytes"))
		ft := f.Type
		for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice {
			switch {
			case ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.Uint8:
				// encoding/json reads []byte from a base64 string, which
				// no maxbytes bound would cover.
				bad(f.Name, "is a []byte")
			case ft.Kind() == reflect.Pointer && ft.Elem().Kind() == reflect.Pointer:
				bad(f.Name, "is a pointer to a pointer") // the walker unwraps one level
			case decodesItself(ft):
				bad(f.Name, "decodes itself")
			}
			ft = ft.Elem()
		}
		if decodesItself(ft) {
			bad(f.Name, "decodes itself")
		}
		switch k := ft.Kind(); {
		case k == reflect.Struct:
			checkType(ft, seen)
		case k == reflect.String:
			if maxLen <= 0 {
				bad(f.Name, "needs a maxbytes tag")
			}
		case reflect.Bool <= k && k <= reflect.Float64:
		default:
			bad(f.Name, "has an unsupported type")
		}
	}
}

// foldKey returns s with each rune replaced by the smallest rune of its
// case-folding orbit, so that two keys that strings.EqualFold matches, and
// encoding/json would read as one field, fold to the same string.
func foldKey(s string) string {
	return strings.Map(func(r rune) rune {
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			least = min(least, f)
		}
		return least
	}, s)
}

// loneSurrogate reports whether data, which is valid JSON, has a \u escape
// of a high surrogate not followed by one of a low surrogate, or of a low
// surrogate not preceded by a high one. Outside strings JSON has no
// backslash, so every backslash starts an escape.
func loneSurrogate(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		r, ok := escapedRune(data[i:])
		switch {
		case !ok:
			i++ // a one-character escape such as \" or \\
		case 0xDC00 <= r && r <= 0xDFFF:
			return true
		case 0xD800 <= r && r <= 0xDBFF:
			if low, ok := escapedRune(data[i+6:]); !ok || low < 0xDC00 || low > 0xDFFF {
				return true
			}
			i += 11
		default:
			i += 5
		}
	}
	return false
}

// escapedRune decodes the \uXXXX escape at the start of b.
func escapedRune(b []byte) (rune, bool) {
	if len(b) < 6 || b[0] != '\\' || b[1] != 'u' {
		return 0, false
	}
	n, err := strconv.ParseUint(string(b[2:6]), 16, 16)
	return rune(n), err == nil
}
