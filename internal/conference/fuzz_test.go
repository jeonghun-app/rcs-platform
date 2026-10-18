package conference

import (
	"reflect"
	"testing"
)

// FuzzParse checks that Parse never panics and that any document it accepts
// marshals to one that parses to the same Info.
func FuzzParse(f *testing.F) {
	f.Add([]byte(fullDoc))
	f.Add([]byte(partial(`<users state="partial"><user entity="` + alice + `" state="partial"><endpoint entity="e" state="deleted"/></user></users>`)))
	f.Add([]byte(`<!DOCTYPE c [<!ENTITY a "b">]><conference-info/>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := Parse(data)
		if err != nil {
			return
		}
		out, err := c.Marshal()
		if err != nil {
			t.Fatalf("Marshal of a parsed document failed: %v\n%+v", err, c)
		}
		back, err := Parse(out)
		if err != nil || !reflect.DeepEqual(back, c) {
			t.Fatalf("round trip changed the document:\n%+v\n%+v, %v", c, back, err)
		}
	})
}

// FuzzMerge checks that merging any two accepted documents leaves the inputs
// untouched and, when it succeeds, yields a state that marshals and parses
// back unchanged.
func FuzzMerge(f *testing.F) {
	f.Add([]byte(fullDoc), []byte(partial(`<users state="partial"><user entity="`+bob+`" state="deleted"/></users>`)))
	f.Add([]byte(fullDoc), []byte(root(`state="deleted" version="3"`, "")))
	f.Fuzz(func(t *testing.T, first, second []byte) {
		a, errA := Parse(first)
		b, errB := Parse(second)
		if errA != nil || errB != nil {
			return
		}
		local, err := Merge(nil, a)
		if err != nil {
			return
		}
		before, _ := Parse(second)
		snapshot := local.clone()
		got, err := Merge(local, b)
		if !reflect.DeepEqual(local, snapshot) || !reflect.DeepEqual(b, before) {
			t.Fatal("Merge modified its inputs")
		}
		if err != nil {
			return
		}
		out, err := got.Marshal()
		if err != nil {
			t.Fatalf("Marshal of a merged state failed: %v\n%+v", err, got)
		}
		back, err := Parse(out)
		if err != nil || !reflect.DeepEqual(back, got) {
			t.Fatalf("merged state does not round-trip:\n%+v\n%+v, %v", got, back, err)
		}
	})
}
