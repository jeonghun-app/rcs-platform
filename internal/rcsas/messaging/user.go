package messaging

import (
	"slices"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// UserOf returns the one form in which rcs-as names the user uri names, or
// false when it names none. A global telephone number is "tel:+" and its
// digits (sip.URI.E164), whether written as a tel URI, as a SIP URI with
// user=phone (RFC 3261 §19.1.6), or as a SIP URI at homeDomain whose user
// part is the number: the platform gives each subscriber
// sip:+<E.164>@<home domain> and tel:+<E.164> as one implicit registration
// set (architecture §4), pcscf asserts either, and rcsjta addresses a peer
// either way. Anything else is identity.CanonicalIMPU's form.
//
// The engine keys queues, a sender's share of them and sent-message records
// by this string, so the same person arriving in any of these forms holds
// one share, and its notifications find the messages sent to it; the SIP
// layer names users so (Origin), and the engine compares the addresses a
// client writes for itself the same way (Config.HomeDomain). It is rcs-as's
// key only: scscf keeps the SIP and tel URIs as two identities.
func UserOf(uri, homeDomain string) (string, bool) {
	u, err := sip.ParseURI(uri)
	if err != nil {
		return "", false
	}
	if e164, ok := u.E164(); ok {
		return "tel:" + e164, true
	}
	// A user parameter that is not phone says the user part is no number.
	if u.IsSIP() && homeDomain != "" && strings.EqualFold(u.Host, homeDomain) && !u.Params.Has("user") {
		phone := u
		phone.Params = slices.Clone(u.Params)
		phone.Params.Set("user", "phone")
		if e164, ok := phone.E164(); ok {
			return "tel:" + e164, true
		}
	}
	return identity.CanonicalIMPU(uri)
}
