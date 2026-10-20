package sipas

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

func TestTheResolverLooksUpOnlyNamesInTheNamespaceAndUsesPrivateAddresses(t *testing.T) {
	lookups := 0
	r := Resolver{Namespace: "rcs.internal", Lookup: func(_ context.Context, _, host string) ([]netip.Addr, error) {
		lookups++
		switch host {
		case "scscf.rcs.internal":
			return []netip.Addr{netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("10.0.1.5")}, nil
		case "public.rcs.internal":
			return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
		}
		return nil, errors.New("no such host")
	}}
	resolve := func(s string) (transport.Destination, error) {
		u, err := sip.ParseURI(s)
		if err != nil {
			t.Fatal(err)
		}
		return r.Resolve(t.Context(), u)
	}
	for in, want := range map[string]transport.Destination{
		"sip:scscf.rcs.internal;transport=tcp;lr":   {Network: transport.TCP, Addr: netip.MustParseAddrPort("10.0.1.5:5060")},
		"sip:scscf.rcs.internal:5070;transport=tcp": {Network: transport.TCP, Addr: netip.MustParseAddrPort("10.0.1.5:5070")},
		"sips:scscf.rcs.internal":                   {Network: transport.TLS, Addr: netip.MustParseAddrPort("10.0.1.5:5061"), ServerName: "scscf.rcs.internal"},
		"sip:10.0.2.7:5080;transport=tcp":           {Network: transport.TCP, Addr: netip.MustParseAddrPort("10.0.2.7:5080")},
		"sip:127.0.0.1:5080;transport=tcp":          {Network: transport.TCP, Addr: netip.MustParseAddrPort("127.0.0.1:5080")},
	} {
		got, err := resolve(in)
		if err != nil || got != want {
			t.Errorf("%s: %+v, %v, want %+v", in, got, err, want)
		}
	}
	before := lookups
	for _, in := range []string{
		"sip:scscf.example.org;transport=tcp", // outside the namespace: not looked up
		"tel:+15550100002",
		// Addresses outside the platform (security review on #242).
		"sip:203.0.113.9;transport=tcp",
		"sip:169.254.169.254;transport=tcp",
		"sip:[2001:db8::1];transport=tcp",
	} {
		if _, err := resolve(in); !errors.Is(err, proxy.ErrUnresolvable) {
			t.Errorf("%s: %v", in, err)
		}
	}
	if lookups != before {
		t.Errorf("%d lookups for names it must not look up", lookups-before)
	}
	for _, in := range []string{"sip:public.rcs.internal;transport=tcp", "sip:gone.rcs.internal;transport=tcp"} {
		if _, err := resolve(in); !errors.Is(err, proxy.ErrUnresolvable) {
			t.Errorf("%s: %v", in, err)
		}
	}
}
