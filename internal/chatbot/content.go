package chatbot

import (
	"mime"
	"strings"
)

// Bounds of ADR 0009 §5 and §7.
const (
	// MaxContentBytes bounds a chatbot's content, chip list included:
	// 248 KiB, above the payload size RCC.07 v13.0 §3.6.10.1 suggests for
	// JSON, and 8 KiB below rcs-as's smallest RCSAS_MAX_MESSAGE_SIZE with
	// the chatbot API on, room for the CPIM rcs-as writes around it.
	MaxContentBytes = 248 << 10
	// MaxDisplayNameBytes bounds a chatbot's display name before escaping.
	MaxDisplayNameBytes = 128
	// MaxOutOfServiceTextBytes bounds the text/plain a suspended chatbot's
	// subscribers get (§11).
	MaxOutOfServiceTextBytes = 512
)

// The content types of RCC.07 v13.0 §3.6.10.2.
const (
	RichCardType           = "application/vnd.gsma.botmessage.v1.0+json"
	ChipListType           = "application/vnd.gsma.botsuggestion.v1.0+json"
	SuggestionResponseType = "application/vnd.gsma.botsuggestion.response.v1.0+json"
	SharedClientDataType   = "application/vnd.gsma.botsharedclientdata.v1.0+json"
)

// ContentTypes are the content types a service accepts each way; anything
// else is 415 (ADR 0009 §5). They are operator configuration: a service
// starts from [DefaultContentTypes] and its settings replace them.
type ContentTypes struct {
	// FromChatbots are the types of a chatbot's message, each of which may
	// carry one chip list of type ChipList as the second part of a
	// multipart CPIM (§3.6.10.1). An empty ChipList allows none.
	FromChatbots []string
	ChipList     string
	// FromSubscribers are the types a subscriber may send a chatbot.
	FromSubscribers []string
}

// DefaultContentTypes returns the content types of RCC.07 v13.0 §3.6.10.2,
// newly allocated so that a service may change its copy.
func DefaultContentTypes() ContentTypes {
	return ContentTypes{
		FromChatbots:    []string{"text/plain;charset=utf-8", RichCardType},
		ChipList:        ChipListType,
		FromSubscribers: []string{"text/plain", SuggestionResponseType, SharedClientDataType},
	}
}

// MatchContentType returns the entry of allowed that contentType matches,
// the shared rule rcs-as and maap both apply before answering 415 (ADR 0009
// §5). Callers write the entry it returns into CPIM, SIP or JSON, never the
// sender's text.
//
// Types, subtypes and parameter names compare without regard to case
// (RFC 2045 §5.1), and so does a charset value (RFC 2046 §4.1.2). Every
// parameter of the entry must be present with its value. The types of
// RCC.07 v13.0 §3.6.10.2 carry no parameter, so the only one a sender may
// add is charset=utf-8, the only charset content may have (§5). A control
// character anywhere, even the CR, LF or tab mime.ParseMediaType would trim,
// and an RFC 2231 parameter name ("charset*="), which clients read in
// different ways, match nothing; so does an entry that does not parse.
func MatchContentType(contentType string, allowed []string) (string, bool) {
	if strings.ContainsFunc(contentType, func(r rune) bool { return r < 0x20 || r == 0x7f }) || extendedParam(contentType) {
		return "", false
	}
	got, gotParams, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", false
	}
	for _, entry := range allowed {
		want, wantParams, err := mime.ParseMediaType(entry)
		if err == nil && got == want && sameParams(gotParams, wantParams) {
			return entry, true
		}
	}
	return "", false
}

// extendedParam reports whether a parameter name of the media type s, as
// written, holds "*", the mark of RFC 2231's extended and continued
// parameters. Quoted values are skipped, so a "*" inside one is no mark.
func extendedParam(s string) bool {
	_, rest, _ := strings.Cut(s, ";")
	for rest != "" {
		name, value, _ := strings.Cut(rest, "=")
		if strings.Contains(name, "*") {
			return true
		}
		if value = strings.TrimLeft(value, " "); strings.HasPrefix(value, `"`) {
			i := 1
			for ; i < len(value) && value[i] != '"'; i++ {
				if value[i] == '\\' {
					i++
				}
			}
			value = value[min(i+1, len(value)):]
		}
		_, rest, _ = strings.Cut(value, ";")
	}
	return false
}

func sameParams(got, want map[string]string) bool {
	for name, v := range want {
		if !paramEqual(name, got[name], v) {
			return false
		}
	}
	for name, v := range got {
		if _, ok := want[name]; !ok && !(name == "charset" && strings.EqualFold(v, "utf-8")) {
			return false
		}
	}
	return true
}

func paramEqual(name, a, b string) bool {
	if name == "charset" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
