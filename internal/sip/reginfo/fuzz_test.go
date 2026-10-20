package reginfo

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// FuzzParse checks that Parse never panics and that any document it accepts
// marshals to one that parses to the same Info, unless Marshal refuses it
// only as a sender may not write it (ErrNotWritable) or as too large once
// escaped (ErrTooLarge): Parse is lenient where Marshal is strict.
func FuzzParse(f *testing.F) {
	f.Add([]byte(fullDoc))
	f.Add([]byte(doc(reg(`<contact id="c" state="active" event="shortened" expires="5"><uri>` + contact + `</uri></contact>`))))
	f.Add([]byte(`<!DOCTYPE r [<!ENTITY a "b">]><reginfo/>`))
	// Read, and not to be written: review of #233.
	f.Add([]byte(doc(reg(`<contact id="c" state="active" event="expired"><uri>` + contact + `</uri></contact>`))))
	f.Add([]byte(doc(reg(`<contact id="c" state="terminated" event="unregistered" expires="0"><uri>` + contact + `</uri></contact>`))))
	f.Add([]byte(doc(`<registration aor="` + alice + `" id="a" state="init"><contact id="c" state="active" event="registered"><uri>` + contact + `</uri></contact></registration>`)))
	f.Add([]byte(doc(reg(`<contact id="c" state="active" event="registered"><uri>` + contact + `</uri><display-name>` + strings.Repeat(`"`, 60000) + `</display-name></contact>`))))
	// QA's crasher of #233.
	f.Add([]byte(`<reginfo xmlns="urn:ietf:params:xml:ns:reginfo"version="0"state="full"><registration aor="sip:A"id=""state="active"><contact id=""state="active"event="expired"><uri>sip:0.0.0.0</uri></contact></registration></reginfo>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := Parse(data)
		if err != nil {
			return
		}
		out, err := r.Marshal()
		if errors.Is(err, ErrNotWritable) || errors.Is(err, ErrTooLarge) {
			return
		}
		if err != nil {
			t.Fatalf("Marshal of a parsed document failed: %v\n%+v", err, r)
		}
		back, err := Parse(out)
		if err != nil || !reflect.DeepEqual(back, r) {
			t.Fatalf("round trip changed the document:\n%+v\n%+v, %v", r, back, err)
		}
	})
}
