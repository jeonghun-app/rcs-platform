package sipua

import (
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// FuzzParseRegInfo reads whatever a notifier might send: it never panics,
// and what it accepts has a valid state, and each contact whose URI is one
// can be looked up by it.
func FuzzParseRegInfo(f *testing.F) {
	f.Add([]byte(reginfo(0, "full", "active", "registered", "sip:a@192.0.2.1")))
	f.Add([]byte(`<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="18446744073709551615" state="partial"><registration aor="x"><contact><uri> </uri></contact></registration></reginfo>`))
	f.Add([]byte(`<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="-1" state="full"/>`))
	f.Fuzz(func(t *testing.T, body []byte) {
		r, err := ParseRegInfo(body)
		if err != nil {
			return
		}
		if r.State != "full" && r.State != "partial" {
			t.Fatalf("accepted state %q", r.State)
		}
		for _, reg := range r.Registrations {
			for _, c := range reg.Contacts {
				if _, err := sip.ParseURI(c.URI); err != nil {
					continue
				}
				if _, ok := r.Contact(reg.AOR, c.URI); !ok {
					t.Fatalf("contact %q of %q not found", c.URI, reg.AOR)
				}
			}
		}
	})
}
