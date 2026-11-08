package chatbot

import (
	"errors"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// UserPartERE is the user part of a chatbot URI in normal form as a POSIX
// extended regular expression: at most two labels joined by ".", each 1–63
// of lower-case letters, digits and "-" (ADR 0009 §2, a strict subset of
// RCC.07 v13.0 §2.5.4.1.2). hss stores it in the wildcarded PSI
// sip:!<UserPartERE>!@<RCS_CHATBOT_DOMAIN> (TS 23.003 §13.5), matched
// against the whole user part; it is what [Domain.Normalise] accepts.
const UserPartERE = `[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})?`

// MaxURIBytes bounds a chatbot URI in normal form, which rcs-as writes into
// the CPIM it reserves room for (ADR 0009 §5). [NewDomain] refuses a domain
// that a normal form of the longest user part would take past it.
const MaxURIBytes = 256

// maxLabel and maxUser bound the user part: two labels of 63 and the dot.
const (
	maxLabel = 63
	maxUser  = 2*maxLabel + 1
)

// MaxDomainBytes is the longest RCS_CHATBOT_DOMAIN: "sip:", the longest
// user part, "@" and the domain fit in MaxURIBytes.
const MaxDomainBytes = MaxURIBytes - len("sip:") - maxUser - len("@")

// Errors of [Domain.Normalise]. ErrNotChatbot says the URI is not at the
// chatbot domain, or the domain is unset, and the caller treats it as it
// treats any other URI. ErrNotNormal says the URI is at the chatbot domain
// but not in normal form: every service answers it 404 (ADR 0009 §2).
var (
	ErrNotChatbot = errors.New("chatbot: not a chatbot URI")
	ErrNotNormal  = errors.New("chatbot: a URI at the chatbot domain not in normal form")
)

// refusal is an error of a kind (one of the package's sentinel errors) with
// a reason that names a rule, never the refused value.
type refusal struct {
	kind   error
	reason string
}

func (r *refusal) Error() string { return r.kind.Error() + ": " + r.reason }
func (r *refusal) Unwrap() error { return r.kind }

func refuse(kind error, reason string) error { return &refusal{kind, reason} }

// Domain is RCS_CHATBOT_DOMAIN, the host of every chatbot URI. The zero
// Domain is unset: there is no chatbot path, and every service behaves as
// if there were no chatbots.
type Domain struct{ name string }

// NewDomain checks a value of RCS_CHATBOT_DOMAIN against the IMS domain:
// a lower-case DNS name of at most MaxDomainBytes, without a trailing dot,
// that differs from imsDomain without regard to case, since the chatbot
// range and the IMPUs must not meet in hss (ADR 0009 §2, §3). An empty
// name is the zero Domain. The error names the rule, not the value.
func NewDomain(name, imsDomain string) (Domain, error) {
	switch {
	case name == "":
		return Domain{}, nil
	case !identity.IsDomainName(name) || strings.ToLower(name) != name:
		return Domain{}, errors.New("not a lower-case DNS name")
	case len(name) > MaxDomainBytes:
		return Domain{}, errors.New("longer than the chatbot URI bound allows")
	case strings.EqualFold(strings.TrimSuffix(imsDomain, "."), name):
		return Domain{}, errors.New("the same as RCS_IMS_DOMAIN")
	}
	return Domain{name: name}, nil
}

// LoadDomain reads RCS_CHATBOT_DOMAIN from the shared RCS_ settings and
// records a problem there, so that the service refuses to start, when
// [NewDomain] refuses it.
func LoadDomain(shared *runtime.Env, imsDomain string) Domain {
	d, err := NewDomain(shared.String("CHATBOT_DOMAIN", ""), imsDomain)
	if err != nil {
		shared.Invalid("CHATBOT_DOMAIN", err.Error())
	}
	return d
}

// Name returns the domain, or "" when it is unset.
func (d Domain) Name() string { return d.name }

// Normalise returns a chatbot URI in normal form, sip:<user>@<domain>, or an
// error: ErrNotChatbot for a URI elsewhere, and a tel URI, which is never a
// chatbot; ErrNotNormal for one at the chatbot domain that is not in normal
// form. It accepts sip: only (the scheme and the host without regard to
// case, RFC 3261 §19.1.4), with no password, port, URI header or escape,
// and no parameter but tk=on or tk=off (RCC.07 v13.0 §2.5.4.3), which it
// drops: the client ignores added parameters when it compares chatbot URIs
// (§2.5.4.4), so tk does not name another chatbot. The user part must match
// [UserPartERE].
func (d Domain) Normalise(uri string) (string, error) {
	if d.name == "" || !d.atDomain(uri) {
		return "", ErrNotChatbot
	}
	u, err := sip.ParseURI(uri)
	switch {
	case err != nil:
		return "", refuse(ErrNotNormal, "not a valid SIP URI")
	case u.Scheme != "sip":
		return "", refuse(ErrNotNormal, "not a sip: URI")
	case u.Password != "" || u.User != "" && userinfo(uri) != u.User:
		// The parser reads "sip:a:@host" as user a with no password.
		return "", refuse(ErrNotNormal, "a password")
	case u.Port != 0:
		return "", refuse(ErrNotNormal, "a port")
	case len(u.Headers) > 0:
		return "", refuse(ErrNotNormal, "URI headers")
	case !strings.EqualFold(u.Host, d.name):
		return "", refuse(ErrNotNormal, "a host that is not the chatbot domain as written")
	}
	for _, p := range u.Params {
		if !strings.EqualFold(p.Name, "tk") || !strings.EqualFold(p.Value, "on") && !strings.EqualFold(p.Value, "off") {
			return "", refuse(ErrNotNormal, "a parameter other than tk=on or tk=off")
		}
	}
	if reason := userPartProblem(u.User); reason != "" {
		return "", refuse(ErrNotNormal, reason)
	}
	return "sip:" + u.User + "@" + d.name, nil
}

// atDomain reports whether uri is a sip: or sips: URI whose host, read
// loosely, is the chatbot domain: after the first or the last "@", up to a
// port, parameter or header, without regard to case and with one trailing
// dot dropped. It must hold for every URI the strict parse reads as at the
// domain, and also for malformed ones, so that a URI meant for a chatbot
// that another parser might read differently is 404 here, not sent on.
func (d Domain) atDomain(uri string) bool {
	scheme, rest, ok := strings.Cut(uri, ":")
	if !ok || !strings.EqualFold(scheme, "sip") && !strings.EqualFold(scheme, "sips") {
		return false
	}
	first, last := rest, rest
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		first, last = rest[i+1:], rest[strings.LastIndexByte(rest, '@')+1:]
	}
	for _, host := range []string{first, last} {
		if end := strings.IndexAny(host, ":;?"); end >= 0 {
			host = host[:end]
		}
		if strings.EqualFold(strings.TrimSuffix(host, "."), d.name) {
			return true
		}
	}
	return false
}

// userinfo returns what uri, a sip: or sips: URI, has between the scheme
// and the first "@".
func userinfo(uri string) string {
	_, rest, _ := strings.Cut(uri, ":")
	info, _, _ := strings.Cut(rest, "@")
	return info
}

// userPartProblem names what keeps user from matching UserPartERE, or
// returns "" when it does.
func userPartProblem(user string) string {
	switch {
	case user == "":
		return "no user part"
	case strings.Contains(user, "%"):
		return "an escape in the user part"
	case strings.Count(user, ".") > 1:
		return "more than two labels in the user part"
	}
	for label := range strings.SplitSeq(user, ".") {
		if label == "" || len(label) > maxLabel {
			return "a label of the user part that is empty or longer than 63 bytes"
		}
		for i := 0; i < len(label); i++ {
			if c := label[i]; !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
				return "a character of the user part outside a-z, 0-9 and -"
			}
		}
	}
	return ""
}
