package chatbot

import (
	"errors"
	"strings"
	"testing"
)

type testItem struct {
	Kind string `json:"kind" maxbytes:"16"`
}

type testNest struct {
	Next *testNest `json:"next"`
}

type testEnvelope struct {
	Body  string     `json:"body" maxbytes:"64"`
	Count int        `json:"count"`
	Tags  []string   `json:"tags" maxbytes:"8"`
	Item  *testItem  `json:"item"`
	Items []testItem `json:"items"`
	Nest  *testNest  `json:"nest"`
}

func decode(data string) (testEnvelope, error) {
	var e testEnvelope
	err := DecodeEnvelope(strings.NewReader(data), 256, &e)
	return e, err
}

func TestAStrictEnvelopeDecodes(t *testing.T) {
	e, err := decode(`{"body":"hi 😀 \\ud800","count":3,"tags":["a","b","c","d","e","f","g","h"],
		"item":null,"items":[{"kind":"x"}],"nest":{"next":{"next":{}}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if e.Body != `hi 😀 \ud800` || e.Count != 3 || len(e.Tags) != 8 || e.Item != nil || e.Items[0].Kind != "x" || e.Nest.Next.Next == nil {
		t.Errorf("decoded %+v", e)
	}
}

func TestAnEnvelopeBreakingARuleIsRefusedWithItsReason(t *testing.T) {
	tests := map[string]struct{ data, reason string }{
		"unknown field":         {`{"body":"secret","extra":1}`, "an unknown field"},
		"field in another case": {`{"Body":"secret"}`, "an unknown field"},
		"keys only in case":     {`{"body":"secret","Body":"secret"}`, "keys that differ only in case"},
		"Kelvin sign":           {`{"items":[{"kind":"secret","\u212aind":"secret"}]}`, "keys that differ only in case"},
		"duplicate key":         {`{"body":"secret","body":"secret"}`, "a duplicate key"},
		"trailing data":         {`{"body":"secret"}{}`, "data after the JSON value"},
		"too deep":              {`{"nest":{"next":{"next":{"next":{}}}}}`, "nested deeper than 4"},
		"nine elements":         {`{"tags":["a","b","c","d","e","f","g","h","i"]}`, "an array of more than 8 elements"},
		"long string":           {`{"body":"` + strings.Repeat("s", 65) + `"}`, "a string longer than its field allows"},
		"long string in a list": {`{"tags":["secret-long"]}`, "a string longer than its field allows"},
		"long in bytes":         {`{"item":{"kind":"` + strings.Repeat(`é`, 9) + `"}}`, "a string longer than its field allows"},
		"null for a value":      {`{"count":null}`, "null for a field that is not optional"},
		"wrong type":            {`{"count":"secret"}`, "a value of the wrong type for its field"},
		"object for a string":   {`{"body":{"secret":1}}`, "an object where its field holds another type"},
		"array for a struct":    {`{"item":["secret"]}`, "an array where its field holds another type"},
		"not an object":         {`["secret"]`, "an array where its field holds another type"},
		"high surrogate alone":  {`{"body":"secret\ud800"}`, "an escape of half a surrogate pair"},
		"low surrogate alone":   {`{"body":"secret\udc00x"}`, "an escape of half a surrogate pair"},
		"not UTF-8":             {"{\"body\":\"secret\xff\"}", "not UTF-8"},
		"empty":                 {"", "not JSON"},
	}
	for name, tc := range tests {
		_, err := decode(tc.data)
		if !errors.Is(err, ErrInvalidEnvelope) || reasonOf(err) != tc.reason {
			t.Errorf("%s: %v, want %q", name, err, tc.reason)
		} else if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "extra") {
			t.Errorf("%s: the error %q repeats the body", name, err)
		}
	}
}

func TestABodyOverItsLimitIsRefusedUnparsed(t *testing.T) {
	body := `{"body":"` + strings.Repeat("s", 256-11) + `"}`
	var e testEnvelope
	if err := DecodeEnvelope(strings.NewReader(body), int64(len(body)), &e); !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("at the limit: %v, want the string bound to refuse it", err)
	}
	if err := DecodeEnvelope(strings.NewReader(body+" "), int64(len(body)), &e); !errors.Is(err, ErrBodyTooLarge) {
		t.Errorf("one byte over: %v, want ErrBodyTooLarge", err)
	}
}

func TestAnEnvelopeTypeWithoutBoundsPanics(t *testing.T) {
	tests := map[string]any{
		"string without maxbytes": &struct {
			S string `json:"s"`
		}{},
		"nested without maxbytes": &struct {
			I []struct{ S *string } `json:"i"`
		}{},
		"map":       &struct{ M map[string]int }{},
		"any":       &struct{ A any }{},
		"[]byte":    &struct{ B []byte }{},
		"no struct": new(string),
		"nil":       (*testEnvelope)(nil),
	}
	for name, v := range tests {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			_ = DecodeEnvelope(strings.NewReader("{}"), 16, v)
		}()
	}
}
