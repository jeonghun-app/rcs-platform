package reginfo

import (
	"reflect"
	"testing"
)

// FuzzParse checks that Parse never panics and that any document it accepts
// marshals to one that parses to the same Info.
func FuzzParse(f *testing.F) {
	f.Add([]byte(fullDoc))
	f.Add([]byte(doc(reg(`<contact id="c" state="active" event="shortened" expires="5"><uri>` + contact + `</uri></contact>`))))
	f.Add([]byte(`<!DOCTYPE r [<!ENTITY a "b">]><reginfo/>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := Parse(data)
		if err != nil {
			return
		}
		out, err := r.Marshal()
		if err != nil {
			t.Fatalf("Marshal of a parsed document failed: %v\n%+v", err, r)
		}
		back, err := Parse(out)
		if err != nil || !reflect.DeepEqual(back, r) {
			t.Fatalf("round trip changed the document:\n%+v\n%+v, %v", r, back, err)
		}
	})
}
