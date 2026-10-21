package icscf

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

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
// configured S-CSCF, and never while its Route or Request-URI names this
// I-CSCF; anything else is refused 403 or 482 (#337). It is checked twice:
// through a proxy, whose own Route handling runs before and after the
// Router's, and at the Router alone, with the Route as it arrived.
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
		// QA of #350: this I-CSCF as the Request-URI, behind a loose or a
		// strict S-CSCF, or put back from the end of the Route (§16.4).
		{"<" + scscfURI + ";lr>", "sip:icscf.rcs.local"},
		{"<" + scscfURI + ">", "sip:icscf.rcs.local:5060"},
		{"<" + scscfURI + ";lr>, <sip:icscf.rcs.local:5060>", "sip:icscf.rcs.local:5060;lr"},
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
		selfURIs := []sip.URI{mustURI(self), mustURI("sip:" + fuzzSelf.String() + ";lr")}
		g := newRig(t, func(c *Config) { c.Self = selfURIs })
		throughProxy(t, g.r, selfURIs, req)
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
	d, err := fuzzResolver{}.Resolve(context.Background(), u)
	return transport.Destination{Network: d.Network, Addr: d.Addr}, err == nil
}

// fuzzResolver is fuzzDestination as the proxy's Resolver.
type fuzzResolver struct{}

func (fuzzResolver) Resolve(ctx context.Context, u sip.URI) (transport.Destination, error) {
	switch strings.TrimSuffix(strings.ToLower(u.Host), ".") {
	case "scscf.rcs.local":
		u.Host = fuzzSCSCF.Addr.Addr().String()
	case "icscf.rcs.local":
		u.Host = fuzzSelf.Addr().String()
	}
	return proxy.NumericResolver{}.Resolve(ctx, u)
}

// throughProxy hands req to a proxy built as Run builds it, on r and self,
// and checks what leaves it: a final response, or the request on its way to
// the S-CSCF with nothing in its Request-URI or Route that names this
// I-CSCF. The proxy removes this I-CSCF's own Route entries before the
// Router sees them and rewrites the Route for a strict next hop after, so
// a loop either side of the Router shows here.
func throughProxy(t *testing.T, r *Router, self []sip.URI, req *sip.Request) {
	t.Helper()
	if req.Validate() != nil {
		return
	}
	out := &recordingSender{done: make(chan sentMessage, 1)}
	p, err := proxy.New(out, proxy.Config{Self: self, Router: r, Resolver: fuzzResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.Receive(transport.Inbound{Message: req.Clone(), Source: transport.Source{
		Flow: "f1", Network: transport.TCP, Addr: netip.MustParseAddrPort("192.0.2.10:5060"), Listener: "core",
	}})
	var sent sentMessage
	select {
	case sent = <-out.done:
	case <-time.After(10 * time.Second):
		t.Fatalf("the proxy neither answered nor forwarded %s", req.URI.String())
	}
	if sent.res != nil {
		if sent.res.StatusCode < 300 {
			t.Fatalf("the proxy answered %d itself", sent.res.StatusCode)
		}
		return
	}
	if sent.dst.Network != fuzzSCSCF.Network || sent.dst.Addr != fuzzSCSCF.Addr {
		t.Fatalf("the proxy sent %s to %+v, not the S-CSCF at %+v", req.URI.String(), sent.dst, fuzzSCSCF)
	}
	routes, err := sent.req.Header.Route()
	if err != nil {
		t.Fatalf("the proxy sent a Route that does not parse: %v", err)
	}
	for _, u := range append([]sip.URI{sent.req.URI}, uris(routes)...) {
		if got, ok := fuzzDestination(u); ok && got.Addr == fuzzSelf {
			t.Fatalf("the proxy sent the S-CSCF a request that names this I-CSCF: %s", u.String())
		}
	}
}

// sentMessage is the first thing a proxy sent: a request and where it went,
// or a final response.
type sentMessage struct {
	req *sip.Request
	dst transport.Destination
	res *sip.Response
}

// recordingSender is the transport under throughProxy's proxy.
type recordingSender struct{ done chan sentMessage }

func (s *recordingSender) SendRequest(req *sip.Request, dst transport.Destination, _ ...transport.SendOption) (transport.Network, error) {
	s.record(sentMessage{req: req.Clone(), dst: dst})
	return dst.Network, nil
}

func (s *recordingSender) SendResponse(res *sip.Response, _ transport.Source, _ ...transport.SendOption) error {
	if res.StatusCode >= 200 {
		s.record(sentMessage{res: res})
	}
	return nil
}

func (s *recordingSender) record(m sentMessage) {
	select {
	case s.done <- m:
	default:
	}
}

func uris(as []sip.Address) []sip.URI {
	us := make([]sip.URI, len(as))
	for i, a := range as {
		us[i] = a.URI
	}
	return us
}
