package routing

import (
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
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

// FuzzODI: a position comes back from its signed form as it was signed for
// the Call-ID, and any other value of the parameter is refused, without a
// panic.
func FuzzODI(f *testing.F) {
	rt := (&env{t: f, store: state.NewMemory(), clock: &clock{now: t0}, metrics: &counts{}, hss: &fakeRegistrar{}}).router(nil)
	f.Add("AAAAAAAAAAA.BBBB", "term-call-1", impu1, int32(10), uint8(0), true, false)
	f.Add("", "", tel1, int32(-1), uint8(2), false, true)
	f.Add("..", "x", "", int32(1<<30), uint8(255), true, true)
	f.Fuzz(func(t *testing.T, v, callID, served string, priority int32, scase uint8, registered, kept bool) {
		if _, err := rt.openODI(v, callID, t0); err == nil {
			t.Fatalf("a value the router did not sign opened: %q", v)
		}
		pos := position{served: served, scase: ifc.SessionCase(scase), registered: registered, kept: kept, priority: int(priority)}
		signed := rt.signODI(pos, callID, t0.Add(time.Minute))
		got, err := rt.openODI(signed, callID, t0)
		pos.expires = t0.Add(time.Minute)
		if err != nil || got != pos {
			t.Fatalf("signed %+v, opened %+v, %v", pos, got, err)
		}
		if _, err := rt.openODI(signed, callID+"x", t0); err == nil {
			t.Fatal("opened for another Call-ID")
		}
		if _, err := rt.openODI(signed, callID, t0.Add(time.Minute+time.Second)); err == nil {
			t.Fatal("opened after it expired")
		}
	})
}

// FuzzIFCView: any header field value is presented to iFC as one or more
// values of its full name, never none, and an SDP body as its lines,
// without their ends.
func FuzzIFCView(f *testing.F) {
	f.Add("Accept-Contact", `*;+g.oma.sip-im, *;explicit;require`, "v=0\r\nm=message 9 TCP/MSRP *")
	f.Add("Subject", `a, b`, "")
	f.Add("k", `"a,b", c`, "\n\n")
	f.Fuzz(func(t *testing.T, name, value, sdp string) {
		if !isToken(name) || strings.ContainsAny(value, "\r\n") {
			return
		}
		r, ok := tryRequest([]string{name + ": " + value, "Content-Type: application/sdp"})
		if !ok {
			return
		}
		r.Body = []byte(sdp)
		v := view{req: r}
		n := 0
		for _, h := range v.HeaderFields() {
			if strings.EqualFold(h.Name, name) || strings.EqualFold(h.Name, sip.CanonicalName(name)) {
				n++
			}
		}
		if n == 0 {
			t.Fatalf("%s: %q is not presented", name, value)
		}
		for _, l := range v.SDPLines() {
			if l == "" || strings.Contains(l, "\n") || strings.HasSuffix(l, "\r") {
				t.Fatalf("SDP line %q", l)
			}
		}
	})
}

// isToken reports whether s is an RFC 3261 §25.1 token, as a header
// field name is.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("-.!%*_+`'~", c) >= 0) {
			return false
		}
	}
	return true
}

// FuzzDialogSignature: a dlg value signs the hops it was made for, for its
// Call-ID, and any other value signs nothing, without a panic.
func FuzzDialogSignature(f *testing.F) {
	e := &env{t: f, store: state.NewMemory(), clock: &clock{now: t0}, metrics: &counts{}, hss: &fakeRegistrar{}}
	rt := e.router(nil)
	f.Add("k2.AAAAAAAAAAAAAAAAAAAAAA", "dialog-1", "sip:a@198.51.100.5:5070;tcp", "sip:@10.0.131.7:5060;tcp")
	f.Add("k2..", "", "", "")
	f.Add(".", "x", "y", "z")
	f.Fuzz(func(t *testing.T, v, callID, hopA, hopB string) {
		if rt.signedHop(v, callID, hopA) {
			t.Fatalf("a value the router did not make signs %q", hopA)
		}
		signed, _ := rt.signedRR(callID, hopA, hopB).URI.Param(dlgParam)
		if !rt.signedHop(signed, callID, hopA) || !rt.signedHop(signed, callID, hopB) {
			t.Fatal("a signed hop does not verify")
		}
		if other := hopA + "x"; other != hopB && rt.signedHop(signed, callID, other) || rt.signedHop(signed, callID+"x", hopA) {
			t.Fatal("verified for another hop or dialog")
		}
	})
}
