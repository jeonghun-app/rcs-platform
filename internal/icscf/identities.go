package icscf

import (
	"net/url"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// publicIdentity is the IMPU a REGISTER registers, its To URI, in the form
// the HSS matches (identity.CanonicalIMPU).
func publicIdentity(m *sip.Request) (string, bool) {
	to, err := m.Header.To()
	if err != nil {
		return "", false
	}
	return identity.CanonicalIMPU(to.URI.String())
}

// privateIdentity is the User-Name of a REGISTER's UAR: the username of its
// Digest credentials for realm, the home network's, or, without any, the
// IMPU without its scheme, which is what TS 24.229 §5.3.1.2 derives (impu is
// canonical, so port and parameters are already gone). Credentials for
// another realm are not for this network (RFC 3261 §22.4), and scscf passes
// them over the same way. A username that is not an IMPI is refused, as the
// HSS would refuse it.
func privateIdentity(m *sip.Request, impu, realm string) (string, bool) {
	if creds, err := m.Header.Authorization(); err == nil {
		for _, c := range creds {
			if !strings.EqualFold(c.Scheme, "Digest") {
				continue
			}
			if v, _ := c.Param("realm"); v != realm {
				continue
			}
			if user, ok := c.Param("username"); ok && user != "" {
				return user, identity.ValidIMPI(user) == nil
			}
		}
	}
	_, impi, _ := strings.Cut(impu, ":")
	return impi, true
}

// visitedNetwork is the UAR's Visited-Network-Identifier: the first
// P-Visited-Network-ID, which the P-CSCF inserted (TS 24.229 §5.2.2), or
// the home domain without one.
func (r *Router) visitedNetwork(m *sip.Request) []byte {
	if ids, err := m.Header.PVisitedNetworkID(); err == nil && len(ids) > 0 && ids[0].Name != "" {
		return []byte(ids[0].Name)
	}
	return r.home
}

// authorizationType is the UAR's User-Authorization-Type (TS 29.228 §6.1.1):
// DE_REGISTRATION when the REGISTER sets the expiry of every binding it
// names to zero, REGISTRATION otherwise, a query without Contact included.
// An expiry that does not parse counts as non-zero; the S-CSCF refuses the
// request.
func authorizationType(m *sip.Request) cx.UserAuthorizationType {
	contacts, err := m.Header.Contact()
	if err != nil || len(contacts) == 0 {
		return cx.AuthorizeRegistration
	}
	expires, err := m.Header.Expires()
	zeroDefault := m.Header.Has("Expires") && err == nil && expires == 0
	for _, c := range contacts {
		if c.Star {
			if !zeroDefault {
				return cx.AuthorizeRegistration
			}
			continue
		}
		e, present, err := c.Expires()
		switch {
		case err != nil:
			return cx.AuthorizeRegistration
		case present && e != 0, !present && !zeroDefault:
			return cx.AuthorizeRegistration
		}
	}
	return cx.AuthorizeDeregistration
}

// telForm applies TS 24.229 §5.3.2.1 step 1 b): a SIP URI for a global
// telephone number (user=phone, RFC 3261 §19.1.6) becomes the tel URI of the
// number, with the number's parameters, unless it is a GRUU. A GRUU stays as
// it is, as step 1 c) wants: its identity is looked up without the gr
// parameter, which identity.CanonicalIMPU drops. A user part that does not
// make a valid tel URI is left alone, and the HSS decides.
func telForm(u sip.URI) sip.URI {
	if !u.IsSIP() || !u.IsGlobalNumber() {
		return u
	}
	if _, gruu := u.Param("gr"); gruu {
		return u
	}
	user, err := url.PathUnescape(u.User)
	if err != nil {
		return u
	}
	tel, err := sip.ParseURI("tel:" + user)
	if err != nil {
		return u
	}
	return tel
}
