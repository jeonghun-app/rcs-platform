package sdp

import (
	"errors"
	"reflect"
	"testing"
)

func attrs(pairs ...string) Attributes {
	var as Attributes
	for i := 0; i < len(pairs); i += 2 {
		as = append(as, Attribute{Name: pairs[i], Value: pairs[i+1]})
	}
	return as
}

func TestAttributeLookupIgnoresCase(t *testing.T) {
	as := attrs("Path", "msrp://a.example.com/1;tcp", "x", "1", "X", "2")
	if v, ok := as.Get("path"); !ok || v != "msrp://a.example.com/1;tcp" {
		t.Errorf("Get(path) = %q, %v", v, ok)
	}
	if got := as.Values("x"); !reflect.DeepEqual(got, []string{"1", "2"}) {
		t.Errorf("Values(x) = %q", got)
	}
	if as.Has("missing") {
		t.Error("Has(missing) = true")
	}
	if _, ok := as.Get("missing"); ok {
		t.Error("Get(missing) reported a value")
	}
}

func TestSetReplacesTheFirstOccurrenceInPlaceAndDropsTheRest(t *testing.T) {
	as := attrs("a", "1", "setup", "active", "b", "2", "SETUP", "passive", "c", "3")
	as.Set("setup", "actpass")
	want := attrs("a", "1", "setup", "actpass", "b", "2", "c", "3")
	if !reflect.DeepEqual(as, want) {
		t.Errorf("got %+v, want %+v", as, want)
	}
}

func TestSetAppendsWhenTheAttributeIsAbsent(t *testing.T) {
	as := attrs("a", "1")
	as.Set("setup", "passive")
	if want := attrs("a", "1", "setup", "passive"); !reflect.DeepEqual(as, want) {
		t.Errorf("got %+v, want %+v", as, want)
	}
}

func TestAddKeepsExistingAttributesAndRemoveDropsEveryMatch(t *testing.T) {
	as := attrs("x", "1")
	as.Add("x", "2")
	as.Add("y", "")
	if got := as.Values("x"); len(got) != 2 {
		t.Fatalf("after Add, Values(x) = %q", got)
	}
	as.Remove("X")
	if want := attrs("y", ""); !reflect.DeepEqual(as, want) {
		t.Errorf("after Remove, got %+v, want %+v", as, want)
	}
}

func TestSingleValuedAttributeMustOccurOnceWithAValue(t *testing.T) {
	tests := []struct {
		name    string
		as      Attributes
		wantErr string
		noAttr  bool
	}{
		{"absent", nil, "sdp: attribute not present: a=max-size", true},
		{"twice", attrs("max-size", "1", "max-size", "2"), "sdp: a=max-size: more than one line", false},
		{"no value", attrs("max-size", ""), "sdp: a=max-size: value missing", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.as.singleValue("max-size")
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("got %v, want %q", err, tt.wantErr)
			}
			if errors.Is(err, ErrNoAttribute) != tt.noAttr {
				t.Errorf("errors.Is(err, ErrNoAttribute) = %v, want %v", !tt.noAttr, tt.noAttr)
			}
		})
	}
}
