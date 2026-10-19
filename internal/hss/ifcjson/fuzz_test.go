package ifcjson

import (
	"reflect"
	"testing"
)

// FuzzDecode checks that whatever Decode accepts encodes and decodes back to
// the same criteria, and that nothing panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	seed, err := Encode(every())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"priority":0,"application_server":{"server_name":"sip:a","default_handling":"SESSION_CONTINUED"}}]`))
	f.Add([]byte(`[{"priority":1,"trigger_point":{"condition_type_cnf":true,"spt":[{"group":[0],"sip_header":{"header":"From"}}]},` +
		`"application_server":{"server_name":"sip:a","default_handling":"SESSION_TERMINATED"}}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		criteria, err := Decode(data)
		if err != nil {
			return
		}
		out, err := Encode(criteria)
		if err != nil {
			t.Fatalf("decoded criteria do not encode: %v", err)
		}
		back, err := Decode(out)
		if err != nil {
			t.Fatalf("encoded criteria do not decode: %v\n%s", err, out)
		}
		if len(criteria) == 0 && len(back) == 0 {
			return
		}
		if !reflect.DeepEqual(back, criteria) {
			t.Fatalf("round trip changed the criteria:\n%+v\n%+v", criteria, back)
		}
	})
}
