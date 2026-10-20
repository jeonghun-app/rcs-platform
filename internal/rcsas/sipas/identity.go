package sipas

import (
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// UserOf returns the one form in which rcs-as names the user uri names, or
// false when it names none: a global telephone number, written as a tel URI
// or as a SIP URI with user=phone, is "tel:+" and its digits (RFC 3261
// §19.1.6, sip.URI.E164); anything else is identity.CanonicalIMPU's form.
// The engine keys queues, a sender's share of them and sent-message records
// by this string, so the same person arriving as tel:+1-555-0100 and as
// sip:+15550100@host;user=phone holds one share, not two.
func UserOf(uri string) (string, bool) {
	u, err := sip.ParseURI(uri)
	if err != nil {
		return "", false
	}
	if e164, ok := u.E164(); ok {
		return "tel:" + e164, true
	}
	return identity.CanonicalIMPU(uri)
}
