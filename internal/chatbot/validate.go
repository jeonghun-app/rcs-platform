package chatbot

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxJSONDepth and MaxJSONArray bound content of a JSON type (ADR 0009 §5).
// Its schema is not checked: the bounds keep what a client parses small and
// shallow.
const (
	MaxJSONDepth = 32
	MaxJSONArray = 1000
)

// ErrInvalidContent is wrapped by every error of [ValidateContent].
var ErrInvalidContent = errors.New("chatbot: invalid content")

// ValidateContent checks content of the given type against ADR 0009 §5: it
// is UTF-8 with no C0 control but tab, CR and LF, and content of a JSON type
// (application/json or a +json suffix, RFC 6839 §3.1) is one JSON value with
// no duplicate key, at most MaxJSONDepth deep, with arrays of at most
// MaxJSONArray elements and only numbers a float64 holds. In JSON the C0
// rule holds for every string and key once its escapes are decoded, since
// that is what a client's parser shows, and an escape of half a surrogate
// pair, which parsers decode each their own way, is refused. It does not
// check the size, which is the caller's to bound, or the type, which is the
// caller's to match with [MatchContentType].
func ValidateContent(contentType string, body []byte) error {
	if !utf8.Valid(body) {
		return refuse(ErrInvalidContent, "not UTF-8")
	}
	for _, c := range body {
		if c < 0x20 && c != '\t' && c != '\r' && c != '\n' {
			return refuse(ErrInvalidContent, "a control character other than tab, CR or LF")
		}
	}
	base, _, _ := strings.Cut(contentType, ";")
	if base = strings.ToLower(strings.TrimSpace(base)); base != "application/json" && !strings.HasSuffix(base, "+json") {
		return nil
	}
	w := walker{kind: ErrInvalidContent, maxDepth: MaxJSONDepth, maxArray: MaxJSONArray, decodedControls: true}
	if err := walkJSON(body, w, nil); err != nil {
		return err
	}
	if loneSurrogate(body) {
		return refuse(ErrInvalidContent, "an escape of half a surrogate pair")
	}
	return nil
}

// hasControl reports whether s holds a C0 control other than tab, CR or LF.
func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 && r != '\t' && r != '\r' && r != '\n' })
}

// walker reads one JSON value token by token and refuses it as kind when it
// breaks a bound. With a type (envelopes), objects must be structs of that
// type, keys must name their fields exactly, and keys that differ only in
// case are refused; without one (content), any value is walked.
// decodedControls refuses decoded strings and keys that hold a C0 control
// other than tab, CR or LF.
type walker struct {
	kind               error
	dec                *json.Decoder
	maxDepth, maxArray int
	decodedControls    bool
}

// walkJSON walks data as one JSON value of type t, or of any type when t is
// nil, and refuses anything after it.
func walkJSON(data []byte, w walker, t reflect.Type) error {
	w.dec = json.NewDecoder(bytes.NewReader(data))
	w.dec.UseNumber()
	if err := w.value(0, t, 0, false); err != nil {
		return err
	}
	if _, err := w.dec.Token(); err != io.EOF {
		return refuse(w.kind, "data after the JSON value")
	}
	return nil
}

// value walks the next value, inside depth containers. maxLen bounds a
// string of type t, from its field's tag; element says the value is an
// array element.
func (w *walker) value(depth int, t reflect.Type, maxLen int, element bool) error {
	tok, err := w.dec.Token()
	if err != nil {
		return refuse(w.kind, "not JSON")
	}
	if t != nil && tok == nil {
		switch {
		case element:
			// An element cannot be absent, and a nil one would reach the
			// handler.
			return refuse(w.kind, "null as an array element")
		case t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice:
			return nil // absent, as encoding/json writes a nil pointer or slice
		}
		return refuse(w.kind, "null for a field that is not optional")
	}
	if t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch v := tok.(type) {
	case json.Delim:
		if depth == w.maxDepth {
			return refuse(w.kind, "nested deeper than "+strconv.Itoa(w.maxDepth))
		}
		if v == '{' {
			return w.object(depth+1, t)
		}
		return w.array(depth+1, t, maxLen)
	case json.Number:
		if f, _ := strconv.ParseFloat(string(v), 64); math.IsInf(f, 0) {
			return refuse(w.kind, "a number beyond the range of a float64")
		}
	case string:
		if t != nil && t.Kind() == reflect.String && len(v) > maxLen {
			return refuse(w.kind, "a string longer than its field allows")
		}
		if w.decodedControls && hasControl(v) {
			return refuse(w.kind, "an escaped control character other than tab, CR or LF")
		}
	}
	return nil
}

func (w *walker) object(depth int, t reflect.Type) error {
	var fields map[string]field
	if t != nil {
		if t.Kind() != reflect.Struct {
			return refuse(w.kind, "an object where its field holds another type")
		}
		fields = fieldsOf(t)
	}
	seen, folded := map[string]bool{}, map[string]bool{}
	for w.dec.More() {
		tok, err := w.dec.Token()
		if err != nil {
			return refuse(w.kind, "not JSON")
		}
		key := tok.(string)
		if seen[key] {
			return refuse(w.kind, "a duplicate key")
		}
		seen[key] = true
		if w.decodedControls && hasControl(key) {
			return refuse(w.kind, "an escaped control character other than tab, CR or LF")
		}
		var f field
		if t != nil {
			k := foldKey(key)
			if folded[k] {
				return refuse(w.kind, "keys that differ only in case")
			}
			folded[k] = true
			var ok bool
			if f, ok = fields[key]; !ok {
				return refuse(w.kind, "an unknown field")
			}
		}
		if err := w.value(depth, f.typ, f.maxLen, false); err != nil {
			return err
		}
	}
	return w.end()
}

func (w *walker) array(depth int, t reflect.Type, maxLen int) error {
	var elem reflect.Type
	if t != nil {
		if t.Kind() != reflect.Slice {
			return refuse(w.kind, "an array where its field holds another type")
		}
		elem = t.Elem()
	}
	for n := 1; w.dec.More(); n++ {
		if n > w.maxArray {
			return refuse(w.kind, "an array of more than "+strconv.Itoa(w.maxArray)+" elements")
		}
		if err := w.value(depth, elem, maxLen, true); err != nil {
			return err
		}
	}
	return w.end()
}

// end reads the "}" or "]" that closes a container.
func (w *walker) end() error {
	if _, err := w.dec.Token(); err != nil {
		return refuse(w.kind, "not JSON")
	}
	return nil
}
