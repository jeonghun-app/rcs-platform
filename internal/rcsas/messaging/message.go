package messaging

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
)

// AnonymousURI is what RCS clients put in the CPIM From and To of 1-to-1
// chat messages and their notifications, leaving the identities to SIP
// (RCC.07 1-to-1 chat; rcsjta ChatUtils.ANONYMOUS_URI). The engine accepts
// it as From in place of one of the sender's identities.
const AnonymousURI = "sip:anonymous@anonymous.invalid"

// Message is a CPIM message as rcs-as reads it: the body to forward and
// what the engine needs from its headers.
type Message struct {
	// Raw is the message/cpim body as received, which is what gets
	// forwarded.
	Raw  []byte
	CPIM *cpim.Message
	From cpim.Address
	// Request is what the sender asked for; zero Dispositions when nothing,
	// which is always the case for a notification.
	Request imdn.Request
	// IncompleteRequest is set when the message asks for notifications
	// without the Message-ID and DateTime needed to answer it. The message
	// is still delivered, without notifications.
	IncompleteRequest bool
	// Notification is set when the message is a disposition notification.
	Notification *imdn.Notification
}

var (
	errLongMessageID   = errors.New("messaging: Message-ID longer than " + strconv.Itoa(MaxMessageIDLength) + " bytes")
	errAmbiguousSender = errors.New("messaging: more than one header that could be read as From or To")
)

// ParseMessage reads a message/cpim body of at most maxSize bytes. Its
// errors are *Rejection.
func ParseMessage(raw []byte, maxSize int) (*Message, error) {
	if len(raw) > maxSize {
		return nil, reject(ReasonTooLarge, nil)
	}
	c, err := cpim.Limits{MaxSize: maxSize}.Parse(raw)
	if err != nil {
		return nil, reject(ReasonMalformed, err)
	}
	from, err := c.From()
	if err != nil {
		return nil, reject(ReasonMalformed, err)
	}
	if !singleAddresses(c) {
		return nil, reject(ReasonMalformed, errAmbiguousSender)
	}
	m := &Message{Raw: raw, CPIM: c, From: from}
	if imdn.IsNotification(c) {
		n, err := imdn.ParseNotificationMessage(c)
		if err != nil {
			return nil, reject(ReasonIMDNMalformed, err)
		}
		if len(n.MessageID) > MaxMessageIDLength {
			return nil, reject(ReasonIMDNMalformed, errLongMessageID)
		}
		m.Notification = &n
		return m, nil
	}
	m.Request, err = imdn.ParseRequest(c)
	switch {
	case errors.Is(err, imdn.ErrIncompleteRequest):
		m.Request, m.IncompleteRequest = imdn.Request{}, true
	case err != nil:
		return nil, reject(ReasonMalformed, err)
	case len(m.Request.MessageID) > MaxMessageIDLength:
		// RFC 5438 §6.3 sets no bound; the ID becomes a store key, and a
		// real one is a few dozen characters.
		return nil, reject(ReasonMalformed, errLongMessageID)
	}
	return m, nil
}

// namesSender reports whether uri, written by a client to name itself (a
// CPIM From, an IMDN recipient-uri), is the anonymous URI or one of the
// sender's identities: equal, or equal in canonical form
// (identity.CanonicalIMPU) where both have one. A client writes its
// provisioned public URI as it was given, ;user=phone and a host's case
// included, and the group path names senders in canonical form; neither
// is a reason to refuse its own address.
func namesSender(uri, sender string, identities []string) bool {
	if uri == AnonymousURI {
		return true
	}
	c, canon := identity.CanonicalIMPU(uri)
	for _, id := range append([]string{sender}, identities...) {
		if id == uri {
			return true
		}
		if canon {
			if cid, ok := identity.CanonicalIMPU(id); ok && cid == c {
				return true
			}
		}
	}
	return false
}

// addressHeader returns cpim.HeaderFrom or cpim.HeaderTo when a header
// called name could be taken for one by some receiver, whatever its case,
// namespace prefix or namespace, and "" otherwise. RFC 3862 §2.2 makes
// header names case-sensitive and §3.4 puts a prefixed name in the
// namespace its NS header binds, but a receiver that compares names
// loosely, or reads a prefix bound to the core namespace under another
// spelling of its URN, would find a From or To there all the same.
func addressHeader(name string) string {
	local := name[strings.LastIndexByte(name, '.')+1:]
	switch {
	case strings.EqualFold(local, cpim.HeaderFrom):
		return cpim.HeaderFrom
	case strings.EqualFold(local, cpim.HeaderTo):
		return cpim.HeaderTo
	}
	return ""
}

// singleAddresses reports whether c names its sender once and its
// recipient at most once: the only header that addressHeader takes for a
// From is the core From, the only one it takes for a To, if any, the core
// To, and no content header looks like either. The engine checks the core
// From against the sender's identities and forwards a 1-to-1 message as it
// came (RFC 3862 §2.2), so a second From that a receiver might read
// instead would let a sender write as someone else. RFC 3862 §4.2 allows
// several To headers; RCS clients write one.
func singleAddresses(c *cpim.Message) bool {
	var from, to int
	for _, h := range c.Headers {
		switch addressHeader(h.Name) {
		case cpim.HeaderFrom:
			from++
		case cpim.HeaderTo:
			to++
		}
	}
	for _, f := range c.ContentHeaders {
		if addressHeader(f.Name) != "" {
			return false
		}
	}
	return from == 1 && to <= 1 && len(c.All(cpim.CoreNamespace, cpim.HeaderFrom)) == 1 &&
		len(c.All(cpim.CoreNamespace, cpim.HeaderTo)) == to
}

// EscapeDisplayName makes a CPIM formal name safe to copy into another
// protocol's header, such as a SIP display name. cpim.Address.Name has its
// escapes decoded (RFC 3862 §2.3), so it may hold CR, LF or other control
// characters that would end or corrupt a header line; each becomes a \uXXXX
// escape, as do quote, backslash and the Unicode line and paragraph
// separators, so the result can sit inside a quoted string (RFC 3261 §25.1)
// as it is. So do the bidirectional controls and zero-width characters
// (U+061C, U+200B-U+200F, U+202A-U+202E, U+2066-U+2069), with which a name
// can be made to display as another. Invalid UTF-8 becomes U+FFFD.
func EscapeDisplayName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r < 0x20, r == 0x7f, 0x80 <= r && r < 0xa0, r == '"', r == '\\', r == 0x2028, r == 0x2029,
			r == 0x061c, 0x200b <= r && r <= 0x200f, 0x202a <= r && r <= 0x202e, 0x2066 <= r && r <= 0x2069:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			// range yields utf8.RuneError for invalid bytes, which
			// WriteRune writes as U+FFFD.
			b.WriteRune(r)
		}
	}
	return b.String()
}
