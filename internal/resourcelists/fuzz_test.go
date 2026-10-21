package resourcelists

import (
	"errors"
	"strings"
	"testing"
	"unicode"
)

// FuzzParse: Parse never panics, keeps to its limit, skipped entries
// included, and returns entries with a uri a client means and valid text,
// or a typed error.
func FuzzParse(f *testing.F) {
	f.Add([]byte(rcsjtaList), 2)
	f.Add([]byte(`<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list><list><entry uri="x"/></list></list></resource-lists>`), 1)
	f.Fuzz(func(t *testing.T, data []byte, limit int) {
		if limit < 0 || limit > 1000 {
			return
		}
		got, skipped, err := Parse(data, limit)
		if err != nil {
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrDTD) && !errors.Is(err, ErrTooLarge) && !errors.Is(err, ErrTooMany) {
				t.Fatalf("untyped error %v", err)
			}
			return
		}
		if len(got)+skipped > limit {
			t.Fatalf("%d entries and %d skipped past the limit %d", len(got), skipped, limit)
		}
		for _, e := range got {
			if e.URI == "" || !isText(e.URI) || strings.ContainsFunc(e.URI, unicode.IsSpace) || strings.ContainsFunc(e.URI, unicode.IsControl) ||
				!isText(e.DisplayName) || len(e.DisplayName) > maxNameBytes {
				t.Fatalf("entry %+v", e)
			}
		}
	})
}
