package ftserver

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestParseRangeFollowsRFC9110(t *testing.T) {
	const size = 1000
	for _, c := range []struct {
		v      string
		size   int64
		result rangeResult
		start  int64
		length int64
	}{
		{"bytes=0-499", size, rangeSatisfiable, 0, 500},
		{"bytes=500-999", size, rangeSatisfiable, 500, 500},
		{"bytes=999-999", size, rangeSatisfiable, 999, 1},
		{"bytes=900-", size, rangeSatisfiable, 900, 100},
		{"bytes=900-5000", size, rangeSatisfiable, 900, 100},
		{"bytes=0-99999999999999999999", size, rangeSatisfiable, 0, size},
		{"bytes=-1", size, rangeSatisfiable, 999, 1},
		{"bytes=-1000", size, rangeSatisfiable, 0, size},
		{"bytes=-5000", size, rangeSatisfiable, 0, size},
		{"bytes=-99999999999999999999", size, rangeSatisfiable, 0, size},
		{"BYTES=0-0", size, rangeSatisfiable, 0, 1},
		{"bytes= 0-0 ", size, rangeSatisfiable, 0, 1},
		{"bytes=1000-", size, rangeUnsatisfiable, 0, 0},
		{"bytes=1000-2000", size, rangeUnsatisfiable, 0, 0},
		{"bytes=99999999999999999999-", size, rangeUnsatisfiable, 0, 0},
		{"bytes=99999999999999999999-99999999999999999999", size, rangeUnsatisfiable, 0, 0},
		{"bytes=-0", size, rangeUnsatisfiable, 0, 0},
		{"", size, rangeIgnored, 0, 0},
		{"bytes", size, rangeIgnored, 0, 0},
		{"bytes=", size, rangeIgnored, 0, 0},
		{"bytes=-", size, rangeIgnored, 0, 0},
		{"bytes=5", size, rangeIgnored, 0, 0},
		{"bytes=5-1", size, rangeIgnored, 0, 0},
		{"bytes=99999999999999999999-5", size, rangeIgnored, 0, 0},
		{"bytes=0-0,5-6", size, rangeIgnored, 0, 0},
		{"bytes=+1-2", size, rangeIgnored, 0, 0},
		{"bytes=0x1-2", size, rangeIgnored, 0, 0},
		{"bytes=1 -2", size, rangeIgnored, 0, 0},
		{"items=0-1", size, rangeIgnored, 0, 0},
		{"bytes=0-0", 0, rangeIgnored, 0, 0},
		{"bytes=-1", 0, rangeIgnored, 0, 0},
		{"bytes=" + strings.Repeat("0", maxRangeField) + "-1", size, rangeIgnored, 0, 0},
	} {
		r, result := parseRange(c.v, c.size)
		if result != c.result || result == rangeSatisfiable && (r.start != c.start || r.length != c.length) {
			t.Errorf("parseRange(%q, %d) = %+v %v, want %d+%d %v", c.v, c.size, r, result, c.start, c.length, c.result)
		}
	}
}

func TestParseContentRangeNeedsACompleteLength(t *testing.T) {
	for v, want := range map[string]*contentRange{
		"bytes 0-9/10":  {0, 9, 10},
		"bytes 5-9/10":  {5, 9, 10},
		"Bytes 0-0/1":   {0, 0, 1},
		"bytes 0-9/*":   nil,
		"bytes */10":    nil,
		"bytes 5-4/10":  nil,
		"bytes 0-10/10": nil,
		"bytes 0-9/9":   nil,
		"bytes 0-9":     nil,
		"bytes 09":      nil,
		"bytes 0-9/1x":  nil,
		"items 0-9/10":  nil,
		"bytes=0-9/10":  nil,
		"bytes -1-9/10": nil,
		"bytes 0-99999999999999999999/99999999999999999999": nil,
		"": nil,
		"bytes 0-1/" + strings.Repeat("9", maxRangeField): nil,
	} {
		got, ok := parseContentRange(v)
		if ok != (want != nil) || ok && got != *want {
			t.Errorf("parseContentRange(%q) = %+v %v, want %+v", v, got, ok, want)
		}
	}
}

func TestDownloadIDsAreRecognised(t *testing.T) {
	id := strings.Repeat("A", 23) + "_"
	for v, want := range map[string]struct {
		id        string
		thumbnail bool
		ok        bool
	}{
		id:                      {id, false, true},
		id + ".t":               {id, true, true},
		id + ".x":               {"", false, false},
		id + "A":                {"", false, false},
		id[:23]:                 {"", false, false},
		strings.Repeat("=", 24): {"", false, false},
		"":                      {"", false, false},
	} {
		got, thumb, ok := parseDownloadID(v)
		if got != want.id || thumb != want.thumbnail || ok != want.ok {
			t.Errorf("parseDownloadID(%q) = %q %v %v", v, got, thumb, ok)
		}
	}
}

func TestNewIDsAreLongAndURLSafe(t *testing.T) {
	id, err := newID(bytes.NewReader(bytes.Repeat([]byte{0xfb}, idBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if got, _, ok := parseDownloadID(id); !ok || got != id || len(id) != idLength {
		t.Fatalf("id %q does not parse back", id)
	}
	if _, err := newID(errReader{errors.New("no entropy")}); err == nil {
		t.Fatal("an id was made without randomness")
	}
}

func TestTransactionIDsAreUnreservedCharacters(t *testing.T) {
	for v, want := range map[string]bool{
		"f81d4fae-7dec-11d0-a765-00a0c91e6bf6": true,
		"a.b~c_d":                              true,
		"...":                                  true,
		strings.Repeat("a", 128):               true,
		"":                                     false,
		".":                                    false,
		"..":                                   false,
		strings.Repeat("a", 129):               false,
		"a/b":                                  false,
		"a b":                                  false,
		"a%2F":                                 false,
		"ä":                                    false,
	} {
		if got := validTID(v); got != want {
			t.Errorf("validTID(%q) = %v", v, got)
		}
	}
}
