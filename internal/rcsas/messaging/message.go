package messaging

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
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
	m := &Message{Raw: raw, CPIM: c, From: from}
	if imdn.IsNotification(c) {
		n, err := imdn.ParseNotificationMessage(c)
		if err != nil {
			return nil, reject(ReasonIMDNMalformed, err)
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
	}
	return m, nil
}

// EscapeDisplayName makes a CPIM formal name safe to copy into another
// protocol's header, such as a SIP display name. cpim.Address.Name has its
// escapes decoded (RFC 3862 §2.3), so it may hold CR, LF or other control
// characters that would end or corrupt a header line; each becomes a \uXXXX
// escape, as do quote, backslash and the Unicode line and paragraph
// separators, so the result can sit inside a quoted string (RFC 3261 §25.1)
// as it is. Invalid UTF-8 becomes U+FFFD.
func EscapeDisplayName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r < 0x20, r == 0x7f, 0x80 <= r && r < 0xa0, r == '"', r == '\\', r == 0x2028, r == 0x2029:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			// range yields utf8.RuneError for invalid bytes, which
			// WriteRune writes as U+FFFD.
			b.WriteRune(r)
		}
	}
	return b.String()
}
