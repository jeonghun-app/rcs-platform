package runtime

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// The rule for plain-http internal APIs (ADR 0007 §5) is applied in one place
// so that every client of an internal API (ft-server and acs calling the HSS,
// pcscf calling msrp-relay's control API, msrp-relay checking where it may
// connect) draws the line the same way.

// IsPrivateHost reports whether host may be reached over plain http inside
// the VPC (ADR 0007 §5): an RFC 1918 address, an IPv6 unique local address
// (fc00::/7, RFC 4193), or a name inside namespace, the Cloud Map namespace
// from RCS_SERVICE_NAMESPACE. Loopback, link-local (including the task
// metadata address), other IPv6 addresses (GUAs, refused so that a dual-stack
// VPC fails safe) and public addresses are not private. An IPv4-mapped IPv6
// address is judged as the IPv4 address it carries.
func IsPrivateHost(host, namespace string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return IsPrivateAddr(ip)
	}
	return InServiceNamespace(host, namespace)
}

// IsPrivateAddr reports whether an internal client may connect to ip
// (ADR 0007 §5): an RFC 1918 or unique local address without a zone, an
// IPv4-mapped address judged as the IPv4 address it carries.
func IsPrivateAddr(ip netip.Addr) bool {
	return ip.Zone() == "" && ip.Unmap().IsPrivate()
}

// ErrAddressNotPrivate is the error of an [InternalDialer] asked to reach a
// host none of whose addresses is private.
var ErrAddressNotPrivate = errors.New("runtime: the internal API host has no private address (ADR 0007 §5)")

// InternalDialer connects the HTTP client of an internal API only to private
// addresses ([IsPrivateAddr]), checked after the host name resolves. A name
// is allowed by [IsPrivateInternalURL] because it lies in the Cloud Map
// namespace, but whoever can write to the namespace's hosted zone could
// point it at the task metadata address, a loopback or a public address,
// and the client would send its bearer token there (#87). Checking at dial
// time covers https too, before any byte is sent, where the URL check only
// covers http.
//
// Its zero value resolves with net.DefaultResolver and dials with a
// net.Dialer. Use DialContext as an http.Transport's DialContext in staging
// and prod; dev runs internal APIs on loopback.
type InternalDialer struct {
	// Timeout bounds each connection attempt; 0 means none beyond ctx.
	Timeout time.Duration
	// Lookup resolves a host name, for tests; nil means
	// net.DefaultResolver.LookupNetIP.
	Lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)
	// Dial connects to an address already checked, for tests; nil means a
	// net.Dialer with Timeout.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// DialContext resolves address's host and connects to its private
// addresses in order, skipping the others. It fails with
// ErrAddressNotPrivate when there is none; the error names no address.
func (d InternalDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		lookup := d.Lookup
		if lookup == nil {
			lookup = net.DefaultResolver.LookupNetIP
		}
		if addrs, err = lookup(ctx, "ip", host); err != nil {
			return nil, err
		}
	}
	dial := d.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: d.Timeout}).DialContext
	}
	err = ErrAddressNotPrivate
	for _, ip := range addrs {
		if !IsPrivateAddr(ip) {
			continue
		}
		conn, dialErr := dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if dialErr == nil {
			return conn, nil
		}
		if errors.Is(err, ErrAddressNotPrivate) {
			err = dialErr // the first real failure says the most
		}
	}
	return nil, err
}

// InServiceNamespace reports whether the DNS name host lies inside
// namespace. Whole labels are compared, so "hss.evil-rcs.local" is not inside
// "rcs.local", and the namespace itself is not inside itself: Cloud Map
// registers services below it. The labels before the namespace must form a
// DNS name, so ".rcs.local", "a..b.rcs.local" and "*.rcs.local" are not
// inside it. Case and a trailing dot do not matter. An empty namespace
// contains nothing.
func InServiceNamespace(host, namespace string) bool {
	namespace = strings.TrimSuffix(strings.ToLower(namespace), ".")
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	name, inside := strings.CutSuffix(host, "."+namespace)
	return namespace != "" && inside && validDNSName(name)
}

// IsPrivateInternalURL reports whether u is an http or https URL whose host
// is private by [IsPrivateHost]. A service uses it to refuse, in staging and
// prod, a plain-http internal API outside the VPC:
//
//	s.ForbidInProduction(u.Scheme == "http" && !runtime.IsPrivateInternalURL(u, s.ServiceNamespace()), "...")
func IsPrivateInternalURL(u *url.URL, namespace string) bool {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return IsPrivateHost(u.Hostname(), namespace)
}

// RefuseRedirects is the CheckRedirect of every internal HTTP client: a
// redirect would carry the caller's bearer token to wherever the answer
// points (ADR 0007 §5). The redirect response itself is returned to the
// caller, which treats it as a failure.
func RefuseRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// validDNSName reports whether v is a DNS name of letters, digits and
// hyphens (RFC 1123 §2.1): labels of 1 to 63 characters not starting or
// ending with a hyphen, 253 characters at most. It is the rule of
// identity.IsDomainName, restated so that the runtime, which every service
// imports, does not depend on the IMS packages.
func validDNSName(v string) bool {
	if v == "" || len(v) > 253 {
		return false
	}
	for _, label := range strings.Split(v, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			if c := label[i]; !isAlnum(c) && c != '-' {
				return false
			}
		}
	}
	return true
}

// validServiceNamespace reports whether v may be the Cloud Map namespace: a
// DNS name whose last label is not all digits, which would make it an IPv4
// address rather than a name (RFC 1123 §2.1). loadShared also requires two
// labels or more in staging and prod.
func validServiceNamespace(v string) bool {
	last := v[strings.LastIndexByte(v, '.')+1:]
	return validDNSName(v) && strings.Trim(last, "0123456789") != ""
}
