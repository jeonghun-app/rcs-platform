package icscf

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
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
		{"<" + scscfURI + ";maddr=192.0.2.66;lr>", "sip:+15550100001@" + home},
		{"<" + scscfURI + ";lr>, <sip:[::ffff:192.0.2.31]:5060;lr>", "sip:icscf.rcs.local."},
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
		g := newRig(t, func(c *Config) { c.Self = []sip.URI{mustURI(self), mustURI("sip:" + fuzzSelf.String() + ";lr")} })
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
		// The oracle is the proxy's resolver, not the Router's own checks
		// (review of #350): where the request would really go, against where
		// the configured S-CSCF and this I-CSCF are.
		next := req.URI
		if len(routes) > 0 {
			next = routes[0].URI
		}
		if _, ok := next.Param("maddr"); ok {
			t.Fatalf("forwarded to %s, whose maddr a resolver may follow", next.String())
		}
		if got, ok := fuzzDestination(next); !ok || got != fuzzSCSCF {
			t.Fatalf("forwarded to %s, which is %+v, not the S-CSCF at %+v", next.String(), got, fuzzSCSCF)
		}
		for _, u := range append([]sip.URI{req.URI}, uris(routes)...) {
			if got, ok := fuzzDestination(u); ok && got.Addr == fuzzSelf {
				t.Fatalf("forwarded a request that names this I-CSCF: %s", u.String())
			}
		}
	})
}

// The addresses FuzzRoutedNextHop's names stand for: the Router's S-CSCF
// (scscfURI) and the Self it is given.
var (
	fuzzSCSCF = transport.Destination{Network: transport.TCP, Addr: netip.MustParseAddrPort("192.0.2.30:5060")}
	fuzzSelf  = netip.MustParseAddrPort("192.0.2.31:5060")
)

// fuzzDestination is where the proxy's NumericResolver sends u once its host
// name is looked up as DNS would: without case or a trailing dot.
func fuzzDestination(u sip.URI) (transport.Destination, bool) {
	switch strings.TrimSuffix(strings.ToLower(u.Host), ".") {
	case "scscf.rcs.local":
		u.Host = fuzzSCSCF.Addr.Addr().String()
	case "icscf.rcs.local":
		u.Host = fuzzSelf.Addr().String()
	}
	d, err := proxy.NumericResolver{}.Resolve(context.Background(), u)
	return transport.Destination{Network: d.Network, Addr: d.Addr}, err == nil
}

func uris(as []sip.Address) []sip.URI {
	us := make([]sip.URI, len(as))
	for i, a := range as {
		us[i] = a.URI
	}
	return us
}
