package sipas

import (
	"bytes"
	"errors"
	"mime"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/resourcelists"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

var errBodyUnreadable = errors.New("sipas: body rcs-as cannot take apart")

// inviteBody splits the body of a client's INVITE for a 1-to-1 session
// into its session description and, for a chat INVITE that carries the
// chat's first message, that message (RFC 5621; RCC.07 §3.2, rcsjta's
// OriginatingOneToOneChatSession), as inviteParts reads them. A resource
// list, which only a group chat's INVITE carries, is errBodyUnreadable.
func inviteBody(h *sip.Header, body []byte) (desc, first []byte, err error) {
	p, err := inviteParts(h, body)
	if err != nil || p.list != nil {
		return nil, nil, errBodyUnreadable
	}
	return p.desc, p.first, nil
}

// groupBody splits the body of a client's INVITE to a group chat into its
// session description and resource list: an INVITE to the conference
// factory has both (RFC 5366; rcsjta's OriginatingAdhocGroupChatSession),
// one to a conference URI, which joins the group, only the description. A
// first message is not taken: it could only be stored once the group is,
// and refused after the group was made.
func groupBody(h *sip.Header, body []byte, factory bool) (desc, list []byte, err error) {
	p, err := inviteParts(h, body)
	if err != nil || p.first != nil || factory != (p.list != nil) {
		return nil, nil, errBodyUnreadable
	}
	return p.desc, p.list, nil
}

// bodyParts are the parts of a client's INVITE body rcs-as takes.
type bodyParts struct {
	desc, first, list []byte
}

// inviteParts splits a client's INVITE body: the whole body when it is
// application/sdp, or the one application/sdp part, at most one
// message/cpim part and at most one resource list of a multipart/mixed
// body. It reads the parts as pcscf does (findSDPPart, #136), so that both
// find the same description. A body with no description, two of a kind, a
// part of another type, a nested multipart, or one it cannot split, is
// errBodyUnreadable.
func inviteParts(h *sip.Header, body []byte) (out bodyParts, err error) {
	if len(body) == 0 {
		return out, errBodyUnreadable
	}
	mt, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil {
		return out, errBodyUnreadable
	}
	switch mt {
	case sdpType:
		return bodyParts{desc: body}, nil
	case "multipart/mixed":
	default:
		return out, errBodyUnreadable
	}
	boundary := params["boundary"]
	if boundary == "" || len(boundary) > 70 {
		return bodyParts{}, errBodyUnreadable
	}
	delim := []byte("\r\n--" + boundary)
	// The first delimiter may open the body, with no CRLF before it.
	i := bytes.Index(append([]byte("\r\n"), body...), delim)
	if i < 0 {
		return bodyParts{}, errBodyUnreadable
	}
	pos := i - 2 + len(delim)
	for {
		if pos+2 <= len(body) && string(body[pos:pos+2]) == "--" {
			break // the close delimiter
		}
		eol := bytes.Index(body[pos:], []byte("\r\n"))
		if eol < 0 {
			return bodyParts{}, errBodyUnreadable
		}
		start := pos + eol + 2
		next := bytes.Index(body[start:], delim)
		if next < 0 {
			return bodyParts{}, errBodyUnreadable
		}
		end := start + next
		seg := body[start:end]
		var header []byte
		content := seg
		if bytes.HasPrefix(seg, []byte("\r\n")) {
			content = seg[2:] // no header fields
		} else {
			h, rest, ok := bytes.Cut(seg, []byte("\r\n\r\n"))
			if !ok {
				return bodyParts{}, errBodyUnreadable
			}
			header, content = h, rest
		}
		pt, ok := partType(header)
		switch {
		case !ok:
			return bodyParts{}, errBodyUnreadable
		case pt == sdpType && out.desc == nil:
			out.desc = content
		case pt == cpim.ContentType && out.first == nil:
			out.first = content
		case pt == resourcelists.ContentType && out.list == nil:
			out.list = content
		default:
			return bodyParts{}, errBodyUnreadable
		}
		pos = end + len(delim)
	}
	if out.desc == nil {
		return bodyParts{}, errBodyUnreadable
	}
	return out, nil
}

// partType is the media type of a part with header, text/plain without a
// Content-Type (RFC 2046 §5.1), and false for a header rcs-as does not
// take: an unreadable type, or a Content-Transfer-Encoding that is not the
// identity, which SIP bodies do not use (RFC 3261 §7.4).
func partType(header []byte) (string, bool) {
	mt := "text/plain"
	for _, line := range strings.Split(string(header), "\r\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return "", false
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "content-type":
			t, _, err := mime.ParseMediaType(value)
			if err != nil {
				return "", false
			}
			mt = t
		case "content-transfer-encoding":
			switch strings.ToLower(value) {
			case "7bit", "8bit", "binary":
			default:
				return "", false
			}
		}
	}
	return mt, true
}
