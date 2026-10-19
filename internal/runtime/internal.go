package runtime

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"
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
		return ip.Zone() == "" && ip.Unmap().IsPrivate()
	}
	return InServiceNamespace(host, namespace)
}

// InServiceNamespace reports whether the DNS name host lies inside
// namespace. Whole labels are compared, so "hss.evil-rcs.local" is not inside
// "rcs.local", and the namespace itself is not inside itself: Cloud Map
// registers services below it. Case and a trailing dot do not matter. An
// empty namespace contains nothing.
func InServiceNamespace(host, namespace string) bool {
	namespace = strings.TrimSuffix(strings.ToLower(namespace), ".")
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return namespace != "" && strings.HasSuffix(host, "."+namespace)
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
// hyphens (RFC 1123 §2.1), as Cloud Map namespaces are: labels of 1 to 63
// characters not starting or ending with a hyphen, 253 characters at most.
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
