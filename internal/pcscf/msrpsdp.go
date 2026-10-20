package pcscf

import (
	"bytes"
	"errors"
	"fmt"
	"mime"
	"net/netip"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/sdp"
)

// The SDP side of MSRP anchoring (ADR 0004, #136): finding the session
// description of a SIP body, the MSRP lines in it, and writing the relay's
// path into them. Everything else in the body is left byte for byte.

// errBodyUnreadable says a body may carry a session description pcscf cannot
// read. Such an offer is refused rather than forwarded, since forwarding it
// would leave its MSRP lines unanchored, end to end.
var errBodyUnreadable = errors.New("pcscf: the body's session description cannot be read")

// maxSDP bounds a session description: a chat or file transfer offer is
// well under 2 KiB.
const maxSDP = 16 << 10

// sdpPart is where a body holds its session description: the bytes of the
// description within the body, so that a rewritten one replaces them alone.
type sdpPart struct {
	body       []byte
	start, end int
}

// description returns the description's bytes.
func (p sdpPart) description() []byte { return p.body[p.start:p.end] }

// with returns the body with the description replaced by d.
func (p sdpPart) with(d []byte) []byte {
	out := make([]byte, 0, len(p.body)-(p.end-p.start)+len(d))
	out = append(out, p.body[:p.start]...)
	out = append(out, d...)
	return append(out, p.body[p.end:]...)
}

// findSDP finds the session description of a body of contentType: the
// whole body for application/sdp, or the one application/sdp part of a
// multipart/mixed body (RFC 5621), as an RCS chat INVITE carries with its
// first message. ok is false when the body has no description. A
// description pcscf cannot locate for sure, in a multipart body it cannot
// split, two descriptions, or a multipart within a part, is
// errBodyUnreadable.
func findSDP(contentType string, body []byte) (part sdpPart, ok bool, err error) {
	if len(body) == 0 {
		return sdpPart{}, false, nil
	}
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return sdpPart{}, false, errBodyUnreadable
	}
	switch {
	case mt == "application/sdp":
		return sdpPart{body: body, start: 0, end: len(body)}, true, nil
	case strings.HasPrefix(mt, "multipart/"):
		return findSDPPart(body, params["boundary"])
	}
	return sdpPart{}, false, nil
}

// findSDPPart finds the application/sdp part of a multipart body (RFC 2046
// §5.1.1): the parts lie between delimiter lines "--boundary", each its
// header fields, an empty line and its content; the content ends at the
// CRLF before the next delimiter.
func findSDPPart(body []byte, boundary string) (sdpPart, bool, error) {
	if boundary == "" || len(boundary) > 70 {
		return sdpPart{}, false, errBodyUnreadable
	}
	delim := []byte("\r\n--" + boundary)
	// The first delimiter may open the body, with no CRLF before it.
	i := bytes.Index(append([]byte("\r\n"), body...), delim)
	if i < 0 {
		return sdpPart{}, false, errBodyUnreadable
	}
	pos := i - 2 + len(delim) // just past the first "--boundary"
	var found sdpPart
	seen := false
	for {
		if pos+2 <= len(body) && string(body[pos:pos+2]) == "--" {
			break // the close delimiter
		}
		eol := bytes.Index(body[pos:], []byte("\r\n"))
		if eol < 0 {
			return sdpPart{}, false, errBodyUnreadable
		}
		start := pos + eol + 2
		next := bytes.Index(body[start:], delim)
		if next < 0 {
			return sdpPart{}, false, errBodyUnreadable
		}
		end := start + next
		seg := body[start:end]
		var header []byte
		contentStart := start + 2 // a part with no header fields starts with the empty line
		if !bytes.HasPrefix(seg, []byte("\r\n")) {
			h, _, ok := bytes.Cut(seg, []byte("\r\n\r\n"))
			if !ok {
				return sdpPart{}, false, errBodyUnreadable
			}
			header, contentStart = h, start+len(h)+4
		}
		mt := partType(header)
		switch {
		case mt == "application/sdp":
			if seen {
				return sdpPart{}, false, errBodyUnreadable
			}
			found, seen = sdpPart{body: body, start: contentStart, end: end}, true
		case strings.HasPrefix(mt, "multipart/"):
			return sdpPart{}, false, errBodyUnreadable
		}
		pos = end + len(delim)
	}
	return found, seen, nil
}

// partType is the media type of a body part from its header fields, in
// lower case; text/plain without one (RFC 2046 §5.1).
func partType(header []byte) string {
	for _, line := range strings.Split(string(header), "\r\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "Content-Type") {
			continue
		}
		mt, _, err := mime.ParseMediaType(strings.TrimSpace(value))
		if err != nil {
			return "invalid"
		}
		return mt
	}
	return "text/plain"
}

// msrpLine is an MSRP media line to anchor: its index, the endpoint's
// a=path and the a=setup role that applies to it.
type msrpLine struct {
	index int
	path  []string
	setup sdp.Setup
}

// msrpLines parses a description and finds its MSRP lines with a port
// other than 0; one with port 0 is declined and has nothing to anchor. A
// line without a=setup takes the RFC 4145 §4 default: active in an offer,
// passive in an answer (ADR 0004).
func msrpLines(d []byte, offer bool) (*sdp.Session, []msrpLine, error) {
	s, err := sdp.Parser{MaxSize: maxSDP}.Parse(d)
	if err != nil {
		return nil, nil, err
	}
	var lines []msrpLine
	for i := range s.Media {
		m := &s.Media[i]
		if !m.IsMSRP() || m.Port == 0 {
			continue
		}
		path, err := m.Path()
		if err != nil {
			return nil, nil, err
		}
		setup, err := s.MediaSetup(i)
		switch {
		case errors.Is(err, sdp.ErrNoAttribute) && offer:
			setup = sdp.SetupActive
		case errors.Is(err, sdp.ErrNoAttribute):
			setup = sdp.SetupPassive
		case err != nil:
			return nil, nil, err
		}
		lines = append(lines, msrpLine{index: i, path: path, setup: setup})
	}
	return s, lines, nil
}

// anchorLine writes the relay's path into line i of s with role setup: the
// relay's URI as a=path, its host as c= and its port on the m= line (RFC
// 4975 §8.1), and the transport its scheme calls for.
func anchorLine(s *sdp.Session, i int, path string, setup sdp.Setup, answer bool) error {
	u, err := msrp.ParseURI(path)
	if err != nil {
		return fmt.Errorf("pcscf: relay path: %w", err)
	}
	conn := sdp.Connection{NetType: "IN", AddrType: "IP4", Address: u.Host}
	if a, err := netip.ParseAddr(u.Host); err == nil && a.Is6() {
		conn.AddrType = "IP6"
	}
	return s.RewriteMSRP(i, sdp.MSRPRewrite{Connection: conn, Port: u.Port, Path: []string{path}, Setup: setup, Answer: answer})
}
