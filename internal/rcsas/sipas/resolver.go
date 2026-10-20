package sipas

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// Resolver finds the next hop of a SIP URI inside the platform: a host that
// is a private or loopback address goes as proxy.NumericResolver says, any
// other address is refused, and a name is looked up
// only inside Namespace (the Cloud Map namespace, ADR 0007 §5), its private
// addresses only, one of them at random, so that requests spread over the
// tasks behind it. It looks the name up at every call; the core has a
// handful of names and the VPC resolver caches.
type Resolver struct {
	Namespace string
	// Lookup resolves a name; nil is net.DefaultResolver.LookupNetIP.
	Lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Resolve implements proxy.Resolver.
func (r Resolver) Resolve(ctx context.Context, u sip.URI) (transport.Destination, error) {
	host := strings.TrimSuffix(strings.TrimPrefix(u.Host, "["), "]")
	if a, err := netip.ParseAddr(host); err == nil {
		// An address is used as it is if it is inside the platform too: a
		// Route that names another, should one ever survive the core, does
		// not take rcs-as out of the VPC (ADR 0007 §5). Loopback stays on
		// the task, as in a local stack.
		if a = a.Unmap(); !runtime.IsPrivateAddr(a) && !a.IsLoopback() {
			return transport.Destination{}, fmt.Errorf("%w: not a private address", proxy.ErrUnresolvable)
		}
		return proxy.NumericResolver{}.Resolve(ctx, u)
	}
	if !u.IsSIP() || !runtime.InServiceNamespace(host, r.Namespace) {
		return transport.Destination{}, fmt.Errorf("%w: not a name in the service namespace", proxy.ErrUnresolvable)
	}
	lookup := r.Lookup
	if lookup == nil {
		lookup = net.DefaultResolver.LookupNetIP
	}
	addrs, err := lookup(ctx, "ip", host)
	if err != nil {
		return transport.Destination{}, fmt.Errorf("%w: lookup failed", proxy.ErrUnresolvable)
	}
	var private []netip.Addr
	for _, a := range addrs {
		if a = a.Unmap(); runtime.IsPrivateAddr(a) {
			private = append(private, a)
		}
	}
	if len(private) == 0 {
		return transport.Destination{}, fmt.Errorf("%w: no private address", proxy.ErrUnresolvable)
	}
	// The numeric resolution of the chosen address settles the transport
	// and the port the URI names, exactly as for an address host.
	numeric := u
	a := private[rand.N(len(private))]
	numeric.Host = a.String()
	if a.Is6() {
		numeric.Host = "[" + numeric.Host + "]"
	}
	dst, err := proxy.NumericResolver{}.Resolve(ctx, numeric)
	if err != nil {
		return transport.Destination{}, err
	}
	if dst.Network == transport.TLS {
		dst.ServerName = host
	}
	return dst, nil
}
