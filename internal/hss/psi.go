package hss

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

// chatbotRange is the stored wildcarded PSI with its ERE compiled: the
// chatbot URIs that a Location-Info-Answer routes to the AS name (ADR 0009
// §3, TS 29.228 §6.1.4.1).
type chatbotRange struct {
	psi    string
	domain chatbot.Domain
	user   *ifc.WholePattern
}

// parseChatbotRange checks a wildcarded PSI as an operator writes it,
// sip:!<ERE>!@<RCS_CHATBOT_DOMAIN> (TS 23.003 §13.5): at most
// store.MaxPSILength bytes of printable ASCII without white space, the
// host exactly the chatbot domain as configured, and an ERE that does not
// hold the delimiter "!" and compiles as an ifc.WholePattern, under
// internal/ifc's rules and budget. With the domain unset there is no
// chatbot range. The error names the rule broken, never the value.
func parseChatbotRange(psi string, domain chatbot.Domain) (*chatbotRange, error) {
	if domain.Name() == "" {
		return nil, errors.New("RCS_CHATBOT_DOMAIN is unset, so there is no chatbot range")
	}
	if len(psi) > store.MaxPSILength {
		return nil, fmt.Errorf("longer than %d bytes", store.MaxPSILength)
	}
	for i := 0; i < len(psi); i++ {
		if c := psi[i]; c <= ' ' || c > '~' {
			return nil, errors.New("white space or a character outside printable ASCII")
		}
	}
	ere, ok := strings.CutPrefix(psi, "sip:!")
	if ok {
		ere, ok = strings.CutSuffix(ere, "!@"+domain.Name())
	}
	switch {
	case !ok:
		return nil, errors.New("not of the form sip:!<ERE>!@<RCS_CHATBOT_DOMAIN>")
	case ere == "":
		return nil, errors.New("an empty ERE")
	case strings.Contains(ere, "!"):
		// The delimiter would make the PSI read differently by whoever
		// splits it at another "!".
		return nil, errors.New(`an ERE holding "!", the delimiter`)
	}
	user, err := ifc.CompileWholePattern("the ERE", ere)
	if err != nil {
		return nil, err
	}
	return &chatbotRange{psi: psi, domain: domain, user: user}, nil
}

// contains reports whether uri is in the range: a chatbot URI in the normal
// form of internal/chatbot, exactly, whose user part matches the ERE. A
// URI that normalises to another string is not, so the range never holds
// more than the normal forms, whatever the ERE. An error is a match the
// work budget could not pay for, which the caller must not take for "no".
func (r *chatbotRange) contains(uri string) (bool, error) {
	if normal, err := r.domain.Normalise(uri); err != nil || normal != uri {
		return false, nil
	}
	return r.userMatches(strings.TrimSuffix(strings.TrimPrefix(uri, "sip:"), "@"+r.domain.Name()))
}

// userMatches matches a user part against the ERE as the ERE is meant
// (chatbot.UserPartERE): the whole user part and with regard to case.
// internal/ifc's trigger patterns, by default, match anywhere in a value,
// and a Request-URI pattern ignores case; read so, the ERE would also take
// upper-case user parts and three labels (#679, from the review of #686).
func (r *chatbotRange) userMatches(user string) (bool, error) {
	return r.user.Match(user)
}
