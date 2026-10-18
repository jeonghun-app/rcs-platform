package diameter

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Application is a Diameter application this node supports. A non-zero
// VendorID advertises it inside Vendor-Specific-Application-Id, which is how
// 3GPP applications such as Cx (vendor 10415) are announced (TS 29.229 §6).
// Only authentication applications are supported; Cx and Sh are both of that
// kind.
type Application struct {
	ID       uint32
	VendorID uint32
}

// PeerRule says which inbound peers a responder accepts. A peer is accepted
// when every non-empty field of at least one rule matches its CER.
//
// Under ADR 0005 every `scscf` task has its own Origin-Host
// (`scscf-<task id>.<namespace>`), so a rule usually names a HostPattern or a
// Realm rather than each host. Origin-Host and Origin-Realm are whatever the
// peer claims: without TLS only the source address is evidence, so a rule
// that relies on a pattern or realm should also list Networks.
type PeerRule struct {
	// Host is an exact Origin-Host, compared without regard to case.
	Host string
	// HostPattern is an Origin-Host pattern in which `*` matches any run of
	// characters within one label, never a dot: `scscf-*.rcs.local`
	// matches `scscf-1a2b.rcs.local` but not `scscf-x.evil.rcs.local`.
	HostPattern string
	// Realm is an exact Origin-Realm, compared without regard to case.
	Realm string
	// Networks, when not empty, restricts the TCP source address.
	Networks []netip.Prefix
}

func (r PeerRule) validate() error {
	if r.Host == "" && r.HostPattern == "" && r.Realm == "" {
		return errors.New("diameter: peer rule must name a Host, a HostPattern or a Realm")
	}
	if r.HostPattern != "" {
		for _, c := range []byte(r.HostPattern) {
			if c != '*' && !validIdentity([]byte{c}) {
				return fmt.Errorf("diameter: peer rule host pattern %q has an invalid character", r.HostPattern)
			}
		}
	}
	for _, p := range r.Networks {
		if !p.IsValid() {
			return errors.New("diameter: peer rule has an invalid network")
		}
	}
	return nil
}

func (r PeerRule) matches(host, realm string, src netip.Addr) bool {
	if r.Host != "" && !strings.EqualFold(r.Host, host) {
		return false
	}
	if r.HostPattern != "" && !matchHostPattern(r.HostPattern, host) {
		return false
	}
	if r.Realm != "" && !strings.EqualFold(r.Realm, realm) {
		return false
	}
	if len(r.Networks) > 0 {
		if !src.IsValid() {
			return false
		}
		if !slices.ContainsFunc(r.Networks, func(p netip.Prefix) bool { return p.Contains(src) }) {
			return false
		}
	}
	return true
}

// matchHostPattern matches label by label so that a wildcard can never span
// a dot and widen the pattern to other domains.
func matchHostPattern(pattern, host string) bool {
	pl := strings.Split(strings.ToLower(pattern), ".")
	hl := strings.Split(strings.ToLower(host), ".")
	if len(pl) != len(hl) {
		return false
	}
	for i := range pl {
		if !matchLabel(pl[i], hl[i]) {
			return false
		}
	}
	return true
}

// matchLabel is a glob match where `*` matches any run of characters,
// including none. With `*` as the only wildcard, backtracking to the most
// recent star is enough, which bounds the work by len(p)*len(s).
func matchLabel(p, s string) bool {
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case pi < len(p) && p[pi] == s[si]:
			pi++
			si++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// capabilities is what a CER or CEA says about its sender (RFC 6733 §5.3.1,
// §5.3.2).
type capabilities struct {
	host, realm    string
	authApps       []uint32 // from Auth-Application-Id and Vendor-Specific-Application-Id
	inbandSecurity []uint32
	originStateID  uint32
}

// parseCapabilities reads a CER or CEA. The AVPs RFC 6733 §5.3.1 makes
// required are checked, so a CER missing one is answered with
// DIAMETER_MISSING_AVP.
func parseCapabilities(m *Message, dict *Dictionary) (capabilities, *Error) {
	var c capabilities
	for _, req := range []uint32{AVPOriginHost, AVPOriginRealm, AVPHostIPAddress, AVPVendorID, AVPProductName} {
		if m.Find(req, 0) == nil {
			def, _ := dict.Lookup(req, 0)
			return c, missingAVP(def)
		}
	}
	var err error
	if c.host, err = m.Find(AVPOriginHost, 0).DiameterIdentity(); err != nil {
		return c, invalidAVP(m.Find(AVPOriginHost, 0), "Origin-Host")
	}
	if c.realm, err = m.Find(AVPOriginRealm, 0).DiameterIdentity(); err != nil {
		return c, invalidAVP(m.Find(AVPOriginRealm, 0), "Origin-Realm")
	}
	if a := m.Find(AVPOriginStateID, 0); a != nil {
		c.originStateID, _ = a.Unsigned32()
	}
	for _, a := range m.AVPs {
		if a.VendorID != 0 {
			continue
		}
		switch a.Code {
		case AVPAuthApplicationID:
			id, err := a.Unsigned32()
			if err != nil {
				return c, invalidAVP(a, "Auth-Application-Id")
			}
			c.authApps = append(c.authApps, id)
		case AVPInbandSecurityID:
			id, err := a.Unsigned32()
			if err != nil {
				return c, invalidAVP(a, "Inband-Security-Id")
			}
			c.inbandSecurity = append(c.inbandSecurity, id)
		case AVPVendorSpecificApplicationID:
			children, err := a.Grouped()
			if err != nil {
				return c, invalidAVP(a, "Vendor-Specific-Application-Id")
			}
			for _, ch := range children {
				if ch.Code == AVPAuthApplicationID && ch.VendorID == 0 {
					id, err := ch.Unsigned32()
					if err != nil {
						return c, invalidAVP(a, "Vendor-Specific-Application-Id")
					}
					c.authApps = append(c.authApps, id)
				}
			}
		}
	}
	return c, nil
}

// commonApplications returns the local application ids the remote also
// supports. A remote that advertises the relay application accepts every
// application (RFC 6733 §5.3).
func commonApplications(local []Application, remote []uint32) []uint32 {
	relay := slices.Contains(remote, AppRelay)
	var out []uint32
	for _, app := range local {
		if (relay || slices.Contains(remote, app.ID)) && !slices.Contains(out, app.ID) {
			out = append(out, app.ID)
		}
	}
	return out
}

// securityAcceptable reports whether the remote accepts NO_INBAND_SECURITY,
// the only option this node offers. No Inband-Security-Id at all means the
// default, NO_INBAND_SECURITY (RFC 6733 §6.10).
func securityAcceptable(remote []uint32) bool {
	return len(remote) == 0 || slices.Contains(remote, InbandSecurityNone)
}

// capabilityAVPs are the AVPs a CER and a successful CEA share, in the order
// of the RFC 6733 §5.3.1 ABNF.
func (n *Node) capabilityAVPs(local netip.Addr) []*AVP {
	avps := []*AVP{
		NewAVP(AVPOriginHost, FlagMandatory, 0, []byte(n.cfg.OriginHost)),
		NewAVP(AVPOriginRealm, FlagMandatory, 0, []byte(n.cfg.OriginRealm)),
	}
	addrs := n.cfg.HostIPAddresses
	if len(addrs) == 0 && local.IsValid() {
		addrs = []netip.Addr{local}
	}
	for _, a := range addrs {
		avps = append(avps, NewAVP(AVPHostIPAddress, FlagMandatory, 0, Address(a)))
	}
	avps = append(avps,
		NewAVP(AVPVendorID, FlagMandatory, 0, Unsigned32(n.cfg.VendorID)),
		NewAVP(AVPProductName, 0, 0, []byte(n.cfg.ProductName)),
		NewAVP(AVPOriginStateID, FlagMandatory, 0, Unsigned32(n.cfg.OriginStateID)),
	)
	for _, v := range n.cfg.SupportedVendorIDs {
		avps = append(avps, NewAVP(AVPSupportedVendorID, FlagMandatory, 0, Unsigned32(v)))
	}
	for _, app := range n.cfg.Applications {
		if app.VendorID == 0 {
			avps = append(avps, NewAVP(AVPAuthApplicationID, FlagMandatory, 0, Unsigned32(app.ID)))
		}
	}
	for _, app := range n.cfg.Applications {
		if app.VendorID != 0 {
			avps = append(avps, NewGrouped(AVPVendorSpecificApplicationID, FlagMandatory, 0,
				NewAVP(AVPVendorID, FlagMandatory, 0, Unsigned32(app.VendorID)),
				NewAVP(AVPAuthApplicationID, FlagMandatory, 0, Unsigned32(app.ID)),
			))
		}
	}
	if n.cfg.FirmwareRevision != 0 {
		avps = append(avps, NewAVP(AVPFirmwareRevision, 0, 0, Unsigned32(n.cfg.FirmwareRevision)))
	}
	return avps
}
