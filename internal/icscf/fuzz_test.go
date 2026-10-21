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

// A request with a Route, or inside a dialog, is forwarded only to a
// configured S-CSCF, and never while its Route names this I-CSCF; anything
// else is refused 403 or 482 (#337).
func FuzzRoutedNextHop(f *testing.F) {
	const self = "sip:icscf.rcs.local:5060;lr"
	for _, tc := range [][2]string{
		{"<" + scscfURI + ";lr>", "sip:+15550100001@" + home},
		{"<sip:SCSCF.rcs.local:5060;transport=TCP;lr>, <sip:as.rcs.local;lr>", "sip:+15550100001@" + home},
		{"<sip:192.0.2.66;lr>", "sip:+15550100001@" + home},
		{"<" + scscfURI + ";lr>, <" + self + ">", "sip:+15550100001@" + home},
		{"<sips:scscf.rcs.local:5060;transport=tcp;lr>", "tel:+15550100001"},
		{"", scscfURI},
		{"", "sip:icscf.rcs.local"},
		{"<sip:[::ffff:192.0.2.1]:5060;lr>", "sip:x@[::1]"},
	} {
		f.Add(tc[0], tc[1])
	}
	f.Fuzz(func(t *testing.T, route, ruri string) {
		if strings.ContainsAny(route+ruri, "\r\n") {
			return
		}
		text := "MESSAGE " + ruri + " SIP/2.0\r\n" +
			"Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKfuzz\r\n" +
			"Max-Forwards: 70\r\nTo: <" + impu1 + ">;tag=t1\r\nFrom: <sip:+15550100002@" + home + ">;tag=f1\r\n" +
			"Call-ID: fuzz@192.0.2.10\r\nCSeq: 1 MESSAGE\r\n"
		if route != "" {
			text += "Route: " + route + "\r\n"
		}
		msg, err := sip.ParseMessage([]byte(text + "Content-Length: 0\r\n\r\n"))
		if err != nil {
			return
		}
		req, ok := msg.(*sip.Request)
		if !ok {
			return
		}
		g := newRig(t, func(c *Config) { c.Self = []sip.URI{mustURI(self)} })
		d := g.route(req)
		if len(d.Targets) == 0 {
			if d.Status != 403 && d.Status != 482 {
				t.Fatalf("Route %q to %q: decision %+v, want a forward, 403 or 482", route, ruri, d)
			}
			return
		}
		routes, err := req.Header.Route()
		if err != nil {
			t.Fatalf("forwarded a request whose Route does not parse: %v", err)
		}
		next := req.URI
		if len(routes) > 0 {
			next = routes[0].URI
		}
		if !g.r.scscfHop(next) {
			t.Fatalf("forwarded to %s, not a configured S-CSCF", next.String())
		}
		for _, a := range routes {
			if g.r.self(a.URI) {
				t.Fatalf("forwarded a request whose Route names this I-CSCF: %s", a.URI.String())
			}
		}
	})
}
