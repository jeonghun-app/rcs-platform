package icscf

import (
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// ParseSCSCFs either refuses its input or returns a list New accepts.
func FuzzParseSCSCFs(f *testing.F) {
	for _, s := range []string{
		`[{"uri":"sip:scscf.rcs.local:5060;transport=tcp","mandatory":[1],"optional":[2,3]}]`,
		`[{"uri":"sips:a.rcs.local"},{"uri":"sip:b.rcs.local","optional":[4294967295]}]`,
		`[]`, `null`, `[{"uri":"tel:+15550100001"}]`, `[{"uri":"sip:a.rcs.local"}] x`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		list, err := ParseSCSCFs(data)
		if err != nil {
			return
		}
		if _, err := New(Config{HSS: &stubHSS{}, SCSCFs: list, HomeDomain: home}); err != nil {
			t.Fatalf("ParseSCSCFs returned a list New refuses: %v", err)
		}
	})
}

// telForm returns its input or a tel URI for the same number, and never a
// URI that cannot be written.
func FuzzTelForm(f *testing.F) {
	for _, s := range []string{
		"sip:+15550100001@" + home + ";user=phone",
		"sip:%2B1-555-010-0001;npdi@" + home + ";user=phone",
		"sip:+15550100001@" + home + ";user=phone;gr",
		"sip:user1@" + home, tel1, "sip:+1;%3D@" + home + ";user=phone",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, err := sip.ParseURI(s)
		if err != nil {
			return
		}
		got := telForm(u)
		if got.Scheme == u.Scheme {
			if got.String() != u.String() {
				t.Fatalf("telForm(%s) = %s, changed but kept the scheme", s, got.String())
			}
			return
		}
		if got.Scheme != "tel" || !u.IsSIP() {
			t.Fatalf("telForm(%s) = %s", s, got.String())
		}
		want, ok := u.E164()
		if e, eok := got.E164(); ok != eok || e != want {
			t.Fatalf("telForm(%s) = %s names %q, the SIP URI %q", s, got.String(), e, want)
		}
		if strings.ContainsRune(got.String(), 0) {
			t.Fatalf("telForm(%s) cannot be written", s)
		}
	})
}
