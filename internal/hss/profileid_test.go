package hss

import (
	"strings"
	"testing"
)

func TestProfileIDsAreLowerCaseLabels(t *testing.T) {
	for id, want := range map[string]bool{
		"rcs-default": true, "a.b_c-1": true, "": false, "Upper": false, "a b": false, "a/b": false,
		strings.Repeat("a", 64): true, strings.Repeat("a", 65): false,
	} {
		if got := ValidProfileID(id) == nil; got != want {
			t.Errorf("ValidProfileID(%q) = %t, want %t", id, got, want)
		}
	}
}
