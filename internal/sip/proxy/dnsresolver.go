package proxy

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// DefaultDNSTTL is how long a DNSResolver reuses an answer by default: the
// TTL the platform gives its Cloud Map records.
const DefaultDNSTTL = 10 * time.Second

// maxDNSNames bounds the names a DNSResolver keeps answers for: the core has
// a handful, and a URI a client wrote may name any.
const maxDNSNames = 256

// DNSResolver resolves SIP and SIPS URIs to the private addresses of their
// host, for services that reach one another by name inside the VPC, such as
// pcscf, icscf and scscf through Cloud Map (icscf.<namespace>). It looks up
// A and AAAA records, uses only the answers that are private addresses
// (runtime.IsPrivateAddr, ADR 0007 §5), keeps them for TTL and picks one at
// random for each branch, so requests spread over the instances; a host that
// is already an address is checked the same way. The transport and port
// follow the URI as for NumericResolver; TLS verifies the host name.
//
// A Cloud Map answer holds at most eight records, chosen at random when
// more instances are registered: each answer then spreads over a different
// eight, which suits CSCF fleets of that size. The TTL stands in for the
// record TTL, which Go's resolver does not report; keep it no longer than
// the namespace's.
type DNSResolver struct {
	// Lookup resolves a host name; nil is net.DefaultResolver.LookupNetIP.
	Lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)
	// TTL is how long an answer is reused; zero is DefaultDNSTTL.
	TTL time.Duration
	// Allow says which addresses may be used; nil is runtime.IsPrivateAddr.
	// A test or dev stack on one host may add loopback.
	Allow func(netip.Addr) bool
	// Now and Pick are for tests: the clock, and the choice among n
	// addresses (rand.IntN by default).
	Now  func() time.Time
	Pick func(n int) int

	mu    sync.Mutex
	names map[string]dnsAnswer
}

type dnsAnswer struct {
	addrs   []netip.Addr
	expires time.Time
}

// Resolve implements Resolver.
func (r *DNSResolver) Resolve(ctx context.Context, u sip.URI) (transport.Destination, error) {
	d, err := NumericResolver{}.withAddr(u, netip.IPv6Unspecified())
	if err != nil {
		return transport.Destination{}, err
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(u.Host, "["), "]"))
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a.Unmap()}
	} else if addrs, err = r.lookup(ctx, host); err != nil {
		return transport.Destination{}, err
	}
	allow := runtime.IsPrivateAddr
	if r.Allow != nil {
		allow = r.Allow
	}
	var private []netip.Addr
	for _, a := range addrs {
		if allow(a) {
			private = append(private, a)
		}
	}
	if len(private) == 0 {
		return transport.Destination{}, fmt.Errorf("%w: no private address", ErrUnresolvable)
	}
	pick := rand.IntN
	if r.Pick != nil {
		pick = r.Pick
	}
	d.Addr = netip.AddrPortFrom(private[pick(len(private))], d.Addr.Port())
	if d.Network == transport.TLS && net.ParseIP(host) == nil {
		d.ServerName = host
	}
	return d, nil
}

// lookup returns the addresses of host, from a kept answer if it is fresh.
func (r *DNSResolver) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	t := now()
	r.mu.Lock()
	if a, ok := r.names[host]; ok && t.Before(a.expires) {
		r.mu.Unlock()
		return a.addrs, nil
	}
	r.mu.Unlock()
	lookup := net.DefaultResolver.LookupNetIP
	if r.Lookup != nil {
		lookup = r.Lookup
	}
	addrs, err := lookup(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("%w: lookup failed", ErrUnresolvable)
	}
	for i, a := range addrs {
		addrs[i] = a.Unmap()
	}
	ttl := r.TTL
	if ttl <= 0 {
		ttl = DefaultDNSTTL
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.names == nil {
		r.names = map[string]dnsAnswer{}
	}
	if _, ok := r.names[host]; !ok && len(r.names) >= maxDNSNames {
		// Drop the expired answers, or else any one.
		for name, a := range r.names {
			if !t.Before(a.expires) {
				delete(r.names, name)
			}
		}
		for name := range r.names {
			if len(r.names) < maxDNSNames {
				break
			}
			delete(r.names, name)
		}
	}
	r.names[host] = dnsAnswer{addrs: addrs, expires: t.Add(ttl)}
	return addrs, nil
}
