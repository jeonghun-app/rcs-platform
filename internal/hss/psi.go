package hss

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
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

// containsInRange is chatbotRange.contains; a variable so that a test can
// make a match fail, which the work budget never lets a stored PSI do.
var containsInRange = (*chatbotRange).contains

// atChatbotHost reports whether impu, in the canonical form the IMPU lookup
// uses (identity.CanonicalIMPU: the host in lower case), is a SIP or SIPS
// URI at domain, with or without a trailing dot; never with domain unset.
// A tel URI has no "@", so its whole text is the "host" and never matches.
// The host is the wildcarded PSI's alone (ADR 0009 §3 as amended in #679,
// threat model T14): no IMPU may be provisioned there, and Cx registers
// none and answers an LIR there from the PSI only.
func atChatbotHost(domain chatbot.Domain, impu string) bool {
	host := impu[strings.LastIndexByte(impu, '@')+1:]
	return domain.Name() != "" && strings.TrimSuffix(host, ".") == domain.Name()
}

// storedAtChatbotHost is atChatbotHost for an identity as stored, put in
// canonical form first: the store keeps IMPUs canonical, but a record
// written past the API, as a migration might, need not be.
func storedAtChatbotHost(domain chatbot.Domain, impu string) bool {
	if c, ok := identity.CanonicalIMPU(impu); ok {
		impu = c
	}
	return atChatbotHost(domain, impu)
}

// holdsChatbotHost reports whether the implicit set holds an identity at
// the chatbot host, and onlyChatbotHost whether it holds nothing else.
func (h *HSS) holdsChatbotHost(s *store.Subscription, set int) bool {
	return slices.ContainsFunc(members(s, set), func(id store.PublicIdentity) bool { return storedAtChatbotHost(h.chatbot, id.IMPU) })
}

func (h *HSS) onlyChatbotHost(s *store.Subscription, set int) bool {
	m := members(s, set)
	return len(m) > 0 && !slices.ContainsFunc(m, func(id store.PublicIdentity) bool { return !storedAtChatbotHost(h.chatbot, id.IMPU) })
}

// chatbotRange returns the range of the stored PSI, or nil when there is
// none: no PSI is stored, it is not active, or it does not hold under the
// current RCS_CHATBOT_DOMAIN. Every call reads the item, so a new version
// is seen at once; the compiled range is kept per version, PSI and
// activation, so a stored PSI is checked and compiled once per task. Any
// other than the cached one replaces it, a lower version too: a table
// restored or recreated starts its versions again, and its PSI, active or
// not, must take effect at once, even at the version number the task has
// cached (the tester on #695). A read that another request's newer read
// overtook may so put an older PSI back for a moment; the next read, which
// sees the newer item, corrects it. A
// PSI that does not hold, such as one written for a domain since changed,
// is counted on every LIR it leaves without a range, so an alarm can see
// it, and logged once per stored PSI, naming the rule and not the PSI.
func (h *HSS) chatbotRange(ctx context.Context) (*chatbotRange, error) {
	p, err := h.store.WildcardedPSI(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	h.rangeMu.Lock()
	defer h.rangeMu.Unlock()
	if !h.rangeRead || p.Version != h.rangeVersion || p.PSI != h.rangePSI || p.Active != h.rangeActive {
		r, err := parseChatbotRange(p.PSI, h.chatbot)
		invalid := err != nil
		if invalid {
			h.log.Warn("the stored chatbot PSI does not hold under RCS_CHATBOT_DOMAIN, so there is no chatbot range",
				slog.Int64("psi_version", p.Version), slog.String("reason", err.Error()))
		}
		if invalid || !p.Active {
			r = nil
		}
		h.rangeRead, h.rangeVersion, h.rangePSI, h.rangeActive = true, p.Version, p.PSI, p.Active
		h.rangeOf, h.rangeInvalid = r, invalid
	}
	if h.rangeInvalid {
		h.metrics.Count("chatbot.psi_invalid", 1)
	}
	return h.rangeOf, nil
}
