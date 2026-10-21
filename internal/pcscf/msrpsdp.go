package pcscf

import (
	"bytes"
	"errors"
	"fmt"
	"mime"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/sdp"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// The SDP side of MSRP anchoring (ADR 0004, #136): finding the session
// description of a SIP body, the MSRP lines in it, and writing the relay's
// path into them. The other parts of a multipart body are left byte for
// byte. A description pcscf rewrites is written again whole
// (sdp.Session.Marshal): an offer's other lines keep their meaning, not
// their spelling, and get CRLF line ends; an answer toward the client keeps
// only its anchored lines (towardClient).

// errBodyUnreadable says a body may carry a session description pcscf cannot
// read. Such an offer is refused rather than forwarded, since forwarding it
// would leave its MSRP lines unanchored, end to end.
var errBodyUnreadable = errors.New("pcscf: the body's session description cannot be read")

// maxSDP bounds a session description: a chat or file transfer offer is
// well under 2 KiB.
const maxSDP = 16 << 10

// sdpPart is where a body holds its session description: the bytes of the
// description within the body, so that a rewritten one replaces them alone,
// and the value of its part's Content-Length, if it has one, to rewrite
// with it (lenStart < 0 without).
type sdpPart struct {
	body             []byte
	start, end       int
	lenStart, lenEnd int
}

// description returns the description's bytes.
func (p sdpPart) description() []byte { return p.body[p.start:p.end] }

// with returns the body with the description replaced by d, and its part's
// Content-Length, if any, made d's.
func (p sdpPart) with(d []byte) []byte {
	out := make([]byte, 0, len(p.body)-(p.end-p.start)+len(d)+8)
	if p.lenStart >= 0 {
		out = append(out, p.body[:p.lenStart]...)
		out = strconv.AppendInt(out, int64(len(d)), 10)
		out = append(out, p.body[p.lenEnd:p.start]...)
	} else {
		out = append(out, p.body[:p.start]...)
	}
	out = append(out, d...)
	return append(out, p.body[p.end:]...)
}

// messageSDP is findSDP for the body of a SIP message with header h. A
// message with more than one Content-Type field, or one that does not
// parse, has a body pcscf cannot read: another reader might take the field
// pcscf did not, and find a description in it (QA of #248).
func messageSDP(h *sip.Header, body []byte) (sdpPart, bool, error) {
	if len(body) == 0 {
		return sdpPart{}, false, nil
	}
	if _, err := h.ContentType(); err != nil {
		return sdpPart{}, false, errBodyUnreadable
	}
	return findSDP(h.Get("Content-Type"), body)
}

// findSDP finds the session description of a body of contentType: the
// whole body for application/sdp, or the one application/sdp part of a
// multipart body (RFC 5621), as an RCS chat INVITE carries with its first
// message. ok is false when the body has no description. Whatever pcscf
// cannot read in one way only, so that another reader might find a
// description it did not, is errBodyUnreadable: it fails closed (findSDPPart).
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
		return sdpPart{body: body, start: 0, end: len(body), lenStart: -1}, true, nil
	case strings.HasPrefix(mt, "multipart/"):
		return findSDPPart(body, params["boundary"])
	}
	return sdpPart{}, false, nil
}

// delimiter is a delimiter line of a multipart body: where it starts, where
// the next line does, and whether it closes the body.
type delimiter struct {
	at, next int
	close    bool
}

// findSDPPart finds the application/sdp part of a multipart body (RFC 2046
// §5.1.1) strictly, and refuses what it cannot split in one way only:
//   - a boundary outside RFC 2046's grammar;
//   - a line beginning with "--boundary" that is not a delimiter line, that
//     is "--boundary" or "--boundary--", white space after, then CRLF (or the
//     end, for the close delimiter), or that ends in a bare LF;
//   - no close delimiter, or a line beginning with "--boundary" after it;
//   - a part's header fields folded, with a bare CR or LF, without a colon,
//     or with a Content-Type twice or one that does not parse;
//   - a part that is multipart itself, two application/sdp parts, or the
//     description in a transfer encoding other than an identity one, or
//     with a Content-Length other than its length.
//
// The content of a part ends at the CRLF before the next delimiter, which
// belongs to it.
func findSDPPart(body []byte, boundary string) (sdpPart, bool, error) {
	if !validBoundary(boundary) {
		return sdpPart{}, false, errBodyUnreadable
	}
	dash := []byte("--" + boundary)
	var delims []delimiter
	for from := 0; ; {
		k := bytes.Index(body[from:], dash)
		if k < 0 {
			break
		}
		at := from + k
		from = at + 1
		if at > 0 && body[at-1] != '\n' {
			continue // within a line: content
		}
		if at > 0 && (at < 2 || body[at-2] != '\r') || len(delims) > 0 && delims[len(delims)-1].close {
			// A bare LF before it, or a line like one in the epilogue,
			// which a reader that does not stop at the close delimiter
			// would take for one.
			return sdpPart{}, false, errBodyUnreadable
		}
		rest := at + len(dash)
		closing := bytes.HasPrefix(body[rest:], []byte("--"))
		if closing {
			rest += 2
		}
		for rest < len(body) && (body[rest] == ' ' || body[rest] == '\t') {
			rest++
		}
		switch {
		case bytes.HasPrefix(body[rest:], []byte("\r\n")):
			rest += 2
		case closing && rest == len(body):
		default:
			return sdpPart{}, false, errBodyUnreadable
		}
		delims = append(delims, delimiter{at: at, next: rest, close: closing})
	}
	if len(delims) < 2 || delims[0].close || !delims[len(delims)-1].close {
		return sdpPart{}, false, errBodyUnreadable
	}
	var found sdpPart
	seen := false
	for k := 0; k+1 < len(delims); k++ {
		start, end := delims[k].next, delims[k+1].at-2
		if end < start {
			return sdpPart{}, false, errBodyUnreadable
		}
		h, err := partHeader(body, start, end)
		if err != nil {
			return sdpPart{}, false, err
		}
		switch {
		case h.mediaType == "application/sdp":
			if seen || !identityEncoding(h.encoding) {
				return sdpPart{}, false, errBodyUnreadable
			}
			// A Content-Length that is not the content's says the part is
			// something else than it seems.
			if h.lenStart >= 0 && string(body[h.lenStart:h.lenEnd]) != strconv.Itoa(end-h.content) {
				return sdpPart{}, false, errBodyUnreadable
			}
			found, seen = sdpPart{body: body, start: h.content, end: end, lenStart: h.lenStart, lenEnd: h.lenEnd}, true
		case strings.HasPrefix(h.mediaType, "multipart/"):
			return sdpPart{}, false, errBodyUnreadable
		}
	}
	return found, seen, nil
}

// partHeaders is what findSDPPart reads of a part's header fields.
type partHeaders struct {
	mediaType, encoding string
	// content is where the part's content starts, and lenStart and lenEnd
	// span its Content-Length's value, -1 without one.
	content, lenStart, lenEnd int
}

// partHeader reads the header fields of the part in body[start:end]: lines
// "name: value" ending in CRLF up to an empty line. A part with none
// starts with the empty line; its type is then text/plain (RFC 2046 §5.1).
func partHeader(body []byte, start, end int) (partHeaders, error) {
	h := partHeaders{mediaType: "text/plain", lenStart: -1, lenEnd: -1}
	seg := body[start:end]
	stop := bytes.Index(seg, []byte("\r\n\r\n"))
	if bytes.HasPrefix(seg, []byte("\r\n")) {
		stop = -2
	} else if stop < 0 {
		return h, errBodyUnreadable
	}
	h.content = start + stop + 4
	if stop < 0 {
		return h, nil
	}
	types := 0
	for off := 0; off < stop; {
		eol := bytes.Index(seg[off:stop+2], []byte("\r\n"))
		line := seg[off : off+eol]
		lineStart := start + off
		off += eol + 2
		if len(line) == 0 || line[0] == ' ' || line[0] == '\t' || bytes.ContainsAny(line, "\r\n") {
			return h, errBodyUnreadable
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || bytes.ContainsAny(line[:colon], " \t") {
			return h, errBodyUnreadable
		}
		name, value := string(line[:colon]), strings.TrimSpace(string(line[colon+1:]))
		switch {
		case strings.EqualFold(name, "Content-Type"):
			mt, _, err := mime.ParseMediaType(value)
			if types++; err != nil || types > 1 {
				return h, errBodyUnreadable
			}
			h.mediaType = mt
		case strings.EqualFold(name, "Content-Transfer-Encoding"):
			h.encoding = strings.ToLower(value)
		case strings.EqualFold(name, "Content-Length"):
			if h.lenStart >= 0 {
				return h, errBodyUnreadable
			}
			// The value without the blanks around it; one of blanks only
			// is empty, and so not the content's length.
			v := line[colon+1:]
			trimmed := bytes.TrimLeft(v, " \t")
			h.lenStart = lineStart + colon + 1 + len(v) - len(trimmed)
			h.lenEnd = h.lenStart + len(bytes.TrimRight(trimmed, " \t"))
		}
	}
	return h, nil
}

// identityEncoding reports whether a Content-Transfer-Encoding leaves the
// content as it is (RFC 2045 §6.2).
func identityEncoding(e string) bool {
	return e == "" || e == "7bit" || e == "8bit" || e == "binary"
}

// validBoundary reports whether b is a multipart boundary (RFC 2046
// §5.1.1): 1 to 70 of its characters, not ending in a space.
func validBoundary(b string) bool {
	if b == "" || len(b) > 70 || b[len(b)-1] == ' ' {
		return false
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("'()+_,-./:=? ", c) >= 0) {
			return false
		}
	}
	return true
}

// msrpLine is an MSRP media line to anchor: its index, the endpoint's
// a=path and the a=setup role that applies to it; holdconn says the role
// written is holdconn, which applies as no role (RFC 6135 §4.2.1).
type msrpLine struct {
	index    int
	path     []string
	setup    sdp.Setup
	holdconn bool
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
		lines = append(lines, msrpLine{index: i, path: path, setup: setup, holdconn: holdconn(s, i)})
	}
	return s, lines, nil
}

// holdconn reports whether the a=setup that applies to line i of s, its own
// or the session's, is holdconn.
func holdconn(s *sdp.Session, i int) bool {
	r, err := s.Media[i].Setup()
	if errors.Is(err, sdp.ErrNoAttribute) {
		v, ok := s.Attributes.Get("setup")
		return ok && strings.EqualFold(strings.TrimSpace(v), string(sdp.SetupHoldConn))
	}
	return err == nil && r == sdp.SetupHoldConn
}

// relayTakesPath reports whether the relay takes path as a client's
// endpoint path, by its own rule (internal/msrprelay onePath): one URI,
// with no RFC 4976 relay before it, of MSRP over TCP, with a port and a
// session id (RFC 4975 §8.2). An offer it would not take is refused as one
// (488), before the relay is asked: a 503 would have the client try again
// in a second for nothing (#248 code review 2).
func relayTakesPath(path []string) bool {
	if len(path) != 1 {
		return false
	}
	u, err := msrp.ParseURI(path[0])
	return err == nil && strings.EqualFold(u.Transport, "tcp") && u.Port != 0 && u.SessionID != ""
}

// towardClient makes s, a description going to the client, show nothing of
// the core: each line in anchored gets the relay's client path it maps to,
// passive in an answer (RFC 6135 §4.2.2) and actpass in an offer (ADR 0004,
// second row), and every other line is declined (port 0, RFC 3264 §6)
// without its c=, b= and a= lines, since only MSRP goes through the relay
// and a declined line's address means nothing. The o= and the
// session-level c= get host, the relay's host or pcscf's own, in place of
// rcs-as's address (RFC 8866 §5.2 lets o= carry any host the originator
// chooses; ADR 0004).
func towardClient(s *sdp.Session, anchored map[int]string, host string, answer bool) error {
	addrType := "IP4"
	if a, err := netip.ParseAddr(host); err == nil && a.Is6() {
		addrType = "IP6"
	}
	for i := range s.Media {
		if _, ok := anchored[i]; ok {
			continue
		}
		m := &s.Media[i]
		m.Port, m.PortCount = 0, 0
		m.Connections, m.Bandwidths, m.Attributes, m.Key = nil, nil, nil, ""
	}
	s.Connection = &sdp.Connection{NetType: "IN", AddrType: addrType, Address: host}
	setup := sdp.SetupActPass
	if answer {
		setup = sdp.SetupPassive
	}
	for i, path := range anchored {
		if err := anchorLine(s, i, path, setup, answer); err != nil {
			return err
		}
	}
	s.Origin.AddrType, s.Origin.Address = addrType, host
	return nil
}

// towardCore writes into s, a description going to rcs-as, the relay's
// core-side path of each line in anchored, active: the relay connects to
// rcs-as, offer or answer (ADR 0004), on port 9 (RFC 4145 §4). A declined
// MSRP line keeps no path, so that rcs-as learns none of the client's
// (#315 code review 5).
func towardCore(s *sdp.Session, anchored map[int]string, answer bool) error {
	for i := range s.Media {
		if m := &s.Media[i]; m.IsMSRP() && m.Port == 0 {
			m.Attributes.Remove("path")
		}
	}
	for i, path := range anchored {
		if err := anchorLine(s, i, path, sdp.SetupActive, answer); err != nil {
			return err
		}
	}
	return nil
}

// declineAll returns d with every line declined, as towardClient writes it
// with host, or nil if d cannot be read: the client must not learn a path
// the relay does not serve, nor an address of the core.
func declineAll(d []byte, host string) []byte {
	s, err := sdp.Parser{MaxSize: maxSDP}.Parse(d)
	if err != nil || towardClient(s, nil, host, true) != nil {
		return nil
	}
	out, err := s.Marshal()
	if err != nil {
		return nil
	}
	return out
}

// declineMSRP returns d with its MSRP lines declined and their paths
// removed, or nil if d cannot be read: what rcs-as gets of a description
// pcscf cannot anchor, so that it learns no path of the client's.
func declineMSRP(d []byte) []byte {
	s, err := sdp.Parser{MaxSize: maxSDP}.Parse(d)
	if err != nil {
		return nil
	}
	for i := range s.Media {
		if m := &s.Media[i]; m.IsMSRP() {
			m.Port, m.PortCount = 0, 0
			m.Attributes.Remove("path")
		}
	}
	out, err := s.Marshal()
	if err != nil {
		return nil
	}
	return out
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
