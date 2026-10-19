package group

import (
	"strings"
	"unicode/utf8"

	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
)

// Every identity, name and subject a request carries is checked, and
// every identity put in canonical form, before anything is stored. The
// roster documents (RFC 4575) are built from what is stored, so a value
// internal/conference cannot write would otherwise be stored first and
// make every later Roster call, and every change, fail for good.

// Bounds on what a client names: they are stored once per participant,
// the group's item must stay well inside DynamoDB's 400 KB, and the roster
// document inside conference.MaxDocumentSize (rosterBound). A name of 100
// bytes, each escaping to five in XML, lets a default group of 100 keep 100
// former participants as well.
const (
	MaxDisplayNameLength = 100
	MaxSubjectLength     = 256
)

// canonical returns id in the one form the group stores and compares
// identities in, identity.CanonicalIMPU's: the form the HSS provisions and
// the CSCFs assert. A SIP URI keeps its user part and loses its
// parameters, its host is lower case; a tel URI is a global number without
// visual separators. It is false for anything else, such as a URI without
// a user, a local number or a value that is no URI at all. The SIP layer
// names users in the same form (docs/rcs-as.md), so the identities a
// client adds match the asserted ones that later join.
func canonical(id string) (string, bool) {
	if len(id) > messaging.MaxIdentityLength {
		return "", false
	}
	c, ok := identity.CanonicalIMPU(id)
	// An identity is written into the roster twice, as XML attributes; one
	// that XML would escape could take five times its length there, which
	// rosterBound does not allow for. No real IMPU has these.
	if !ok || strings.ContainsAny(c, "&'") {
		return "", false
	}
	return c, true
}

// validText reports whether s may be a display name or a subject: at most
// max bytes of UTF-8 that XML 1.0 can carry, without control characters
// (C0, DEL, C1), which no name needs and which would break the CPIM and
// SIP headers names are copied into.
func validText(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || 0x7f <= r && r < 0xa0 || r == 0xfffe || r == 0xffff {
			return false
		}
	}
	return true
}
