package resourcelists

import (
	"errors"
	"testing"
	"unicode/utf8"
)

// FuzzParse: Parse never panics, keeps to its limit, and returns entries
// with a uri and valid text, or a typed error.
func FuzzParse(f *testing.F) {
	f.Add([]byte(rcsjtaList), 2)
	f.Add([]byte(`<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list><list><entry uri="x"/></list></list></resource-lists>`), 1)
	f.Fuzz(func(t *testing.T, data []byte, limit int) {
		if limit < 0 || limit > 1000 {
			return
		}
		got, err := Parse(data, limit)
		if err != nil {
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrDTD) && !errors.Is(err, ErrTooLarge) && !errors.Is(err, ErrTooMany) {
				t.Fatalf("untyped error %v", err)
			}
			return
		}
		if len(got) > limit {
			t.Fatalf("%d entries past the limit %d", len(got), limit)
		}
		for _, e := range got {
			if e.URI == "" || !utf8.ValidString(e.URI) || !utf8.ValidString(e.DisplayName) || len(e.DisplayName) > maxNameBytes {
				t.Fatalf("entry %+v", e)
			}
		}
	})
}
