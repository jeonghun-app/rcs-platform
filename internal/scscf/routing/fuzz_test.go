package routing

import (
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// FuzzCallerPreferences: any Accept-Contact and Reject-Contact against any
// feature tags a binding stored keeps a subset of the bindings, in order,
// and never panics.
func FuzzCallerPreferences(f *testing.F) {
	f.Add(`*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session";require;explicit`, `*;+g.oma.sip-im`, `+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"`)
	f.Add(`*;+a="!x,y";require`, `*;audio`, `+a="y,z";audio`)
	f.Add(`sip:x`, `*;;;`, `"`)
	f.Add(`*;+g.3gpp.icsi-ref="URN%3aX";require;explicit`, `*;+a="!b"`, `+g.3gpp.icsi-ref="urn%3Ax"`)
	f.Add(`*;+sip.description="<a,b>";require;explicit`, `*;+x="#>=4"`, `+sip.description="<a,b>";+x="#=4"`)
	f.Add(`*;+x="#1:5,#-2.5:-1.";require`, `*;+x="#<=+3."`, `+x="#=3"`)
	f.Add(`*;audio;require;explicit`, `*;video`, ``)
	f.Fuzz(func(t *testing.T, accept, reject, tags string) {
		if strings.ContainsAny(accept+reject, "\r\n") {
			return
		}
		extra := []string{"Accept-Contact: " + accept, "Reject-Contact: " + reject}
		r, ok := tryRequest(extra)
		if !ok {
			return
		}
		cs := []state.Contact{binding(1, 0, time.Hour, strings.Split(tags, ";")...), binding(2, 0, time.Hour)}
		got := accepted(cs, r)
		for i, c := range got {
			if i > 0 && c.URI == got[i-1].URI || c.URI != cs[0].URI && c.URI != cs[1].URI {
				t.Fatalf("kept %v", got)
			}
		}
	})
}
