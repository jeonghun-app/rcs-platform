package pcscf

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sdp"
)

// lines joins SDP or MIME lines with CRLF, the last one included.
func lines(ls ...string) string { return strings.Join(ls, "\r\n") + "\r\n" }

// clientChatOffer is a client's chat offer: an MSRP line over TLS, actpass,
// beside an audio line and attributes pcscf does not interpret.
var clientChatOffer = lines(
	"v=0",
	"o=- 3913000001 3913000001 IN IP4 192.0.2.10",
	"s=-",
	"c=IN IP4 192.0.2.10",
	"t=0 0",
	"m=audio 49170 RTP/AVP 0",
	"a=rtpmap:0 PCMU/8000",
	"m=message 9 TCP/TLS/MSRP *",
	"a=accept-types:message/cpim application/im-iscomposing+xml",
	"a=setup:actpass",
	"a=path:msrps://192.0.2.10:9/s7d2k8f;tcp",
	"a=sendrecv",
	"a=msrp-cema",
)

// The description is the body of application/sdp, or the one SDP part of a
// multipart body, which a chat INVITE carrying its first message has; the
// rest of the body is kept byte for byte when it is replaced.
func TestTheDescriptionIsFoundInTheBody(t *testing.T) {
	cpim := lines("From: <sip:anonymous@anonymous.invalid>", "", "Content-Type: text/plain", "", "hi")
	multipart := "preamble\r\n" + lines(
		"--b1",
		"Content-Type: application/sdp",
		"Content-Disposition: session",
		"",
	) + clientChatOffer + lines(
		"--b1",
		"Content-Type: message/cpim",
		"",
	) + cpim + "\r\n--b1--\r\n"
	for _, tt := range []struct {
		name, ct, body, want string
		found                bool
	}{
		{"sdp", "application/sdp", clientChatOffer, clientChatOffer, true},
		{"sdp with parameters", "Application/SDP; charset=utf-8", clientChatOffer, clientChatOffer, true},
		// The CRLF before a delimiter is the delimiter's (RFC 2046 §5.1.1).
		{"multipart", `multipart/mixed; boundary="b1"`, multipart, strings.TrimSuffix(clientChatOffer, "\r\n"), true},
		{"multipart opening with the delimiter", "multipart/mixed;boundary=b1", strings.TrimPrefix(multipart, "preamble\r\n"), strings.TrimSuffix(clientChatOffer, "\r\n"), true},
		{"a part without header fields", "multipart/mixed;boundary=b1", lines("--b1", "") + "plain\r\n--b1\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n\r\n--b1--", "v=0\r\n", true},
		{"multipart without SDP", "multipart/mixed;boundary=b1", lines("--b1", "Content-Type: message/cpim", "", "x", "--b1--"), "", false},
		{"multipart/related", `multipart/related;type="application/sdp";boundary=b1`, strings.TrimPrefix(multipart, "preamble\r\n"), strings.TrimSuffix(clientChatOffer, "\r\n"), true},
		{"multipart/alternative", "multipart/alternative;boundary=b1", strings.TrimPrefix(multipart, "preamble\r\n"), strings.TrimSuffix(clientChatOffer, "\r\n"), true},
		// Transport padding after a delimiter (RFC 2046 §5.1.1).
		{"padded delimiters", "multipart/mixed;boundary=b1", "--b1 \t\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b1-- \r\n", "v=0", true},
		{"the longest boundary", "multipart/mixed;boundary=" + strings.Repeat("b", 70),
			"--" + strings.Repeat("b", 70) + "\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--" + strings.Repeat("b", 70) + "--", "v=0", true},
		{"an identity encoding", "multipart/mixed;boundary=b1", "--b1\r\nContent-Type: application/sdp\r\nContent-Transfer-Encoding: 8bit\r\n\r\nv=0\r\n--b1--", "v=0", true},
		{"another type", "message/cpim", cpim, "", false},
		{"no body", "application/sdp", "", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			part, found, err := findSDP(tt.ct, []byte(tt.body))
			if err != nil || found != tt.found {
				t.Fatalf("found %v, %v", found, err)
			}
			if !found {
				return
			}
			if got := string(part.description()); got != tt.want {
				t.Errorf("description %q, want %q", got, tt.want)
			}
			if got := string(part.with(part.description())); got != tt.body {
				t.Errorf("body rebuilt as %q", got)
			}
			if got := string(part.with([]byte("X"))); got != strings.Replace(tt.body, tt.want, "X", 1) {
				t.Errorf("replaced: %q", got)
			}
		})
	}
}

// A body whose description pcscf cannot locate for sure is refused, never
// passed on unanchored.
func TestABodyPcscfCannotSplitIsRefused(t *testing.T) {
	sdpPart := lines("--b1", "Content-Type: application/sdp", "", "v=0")
	for name, tt := range map[string]struct{ ct, body string }{
		"a bad content type":    {"multipart/mixed; boundary=", sdpPart},
		"no boundary":           {"multipart/mixed", sdpPart},
		"no delimiter":          {"multipart/mixed;boundary=b2", sdpPart + "--b1--"},
		"no close delimiter":    {"multipart/mixed;boundary=b1", sdpPart},
		"two descriptions":      {"multipart/mixed;boundary=b1", sdpPart + sdpPart + "--b1--"},
		"a multipart inside":    {"multipart/mixed;boundary=b1", lines("--b1", "Content-Type: multipart/mixed;boundary=b2", "", "x", "--b1--")},
		"a part without an end": {"multipart/mixed;boundary=b1", "--b1"},
		"a part header unended": {"multipart/mixed;boundary=b1", "--b1\r\nContent-Type: application/sdp\r\n--b1--"},
		"a boundary too long": {"multipart/mixed;boundary=" + strings.Repeat("b", 71),
			"--" + strings.Repeat("b", 71) + "\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--" + strings.Repeat("b", 71) + "--"},
		"a folded header":                 {"multipart/mixed;boundary=b1", "--b1\r\nContent-Type:\r\n application/sdp\r\n\r\nv=0\r\n--b1--"},
		"a content type unreadable":       {"multipart/mixed;boundary=b1", "--b1\r\nContent-Type: application/sdp; charset\r\n\r\nv=0\r\n--b1--"},
		"two content types":               {"multipart/mixed;boundary=b1", "--b1\r\nContent-Type: text/plain\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b1--"},
		"a header line ending in LF":      {"multipart/mixed;boundary=b1", "--b1\r\nContent-Type: application/sdp\n\r\nv=0\r\n--b1--"},
		"a bare CR in a header":           {"multipart/mixed;boundary=b1", "--b1\r\nContent-Type: application/sdp\rX: y\r\n\r\nv=0\r\n--b1--"},
		"a header without a colon":        {"multipart/mixed;boundary=b1", "--b1\r\nContent-Type application/sdp\r\n\r\nv=0\r\n--b1--"},
		"a delimiter ending in LF":        {"multipart/mixed;boundary=b1", "--b1\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b1--"},
		"a delimiter preceded by LF":      {"multipart/mixed;boundary=b1", "--b1\r\nContent-Type: text/plain\r\n\r\nx\n--b1\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b1--"},
		"a line longer than a delimiter":  {"multipart/mixed;boundary=b1", "--b1\r\nContent-Type: text/plain\r\n\r\nx\r\n--b1x\r\n\r\n--b1--"},
		"a delimiter after the close":     {"multipart/mixed;boundary=b1", "--b1\r\nContent-Type: text/plain\r\n\r\nx\r\n--b1--\r\n\r\ny\r\n--b1\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b1--"},
		"an encoded description":          {"multipart/mixed;boundary=b1", "--b1\r\nContent-Type: application/sdp\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nv=3D0\r\n--b1--"},
		"a length that is not the part's": {"multipart/mixed;boundary=b1", "--b1\r\nContent-Type: application/sdp\r\nContent-Length: 4\r\n\r\nv=0\r\n--b1--"},
		"an empty length":                 {"multipart/mixed;boundary=b1", "--b1\r\nContent-Type: application/sdp\r\nContent-Length:\r\n\r\nv=0\r\n--b1--"},
		"two lengths":                     {"multipart/mixed;boundary=b1", "--b1\r\nContent-Type: application/sdp\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nv=0\r\n--b1--"},
	} {
		if _, _, err := findSDP(tt.ct, []byte(tt.body)); !errors.Is(err, errBodyUnreadable) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A rewritten description gets its part's Content-Length made its own, so
// a reader that splits parts by it reads the whole of it (#248 code review
// 7); the rest of the body is as it was.
func TestARewrittenPartHasItsOwnLength(t *testing.T) {
	body := "--b1\r\nContent-Type: application/sdp\r\ncontent-length:  3 \r\n\r\nv=0\r\n--b1\r\nContent-Type: message/cpim\r\nContent-Length: 2\r\n\r\nhi\r\n--b1--\r\n"
	part, found, err := findSDP("multipart/mixed;boundary=b1", []byte(body))
	if err != nil || !found {
		t.Fatal(found, err)
	}
	got := string(part.with([]byte("v=0\r\nlonger")))
	want := "--b1\r\nContent-Type: application/sdp\r\ncontent-length:  11 \r\n\r\nv=0\r\nlonger\r\n--b1\r\nContent-Type: message/cpim\r\nContent-Length: 2\r\n\r\nhi\r\n--b1--\r\n"
	if got != want {
		t.Errorf("rewritten:\n%q\nwant\n%q", got, want)
	}
}

// Only MSRP lines with a port are anchored, each with the role that applies:
// its own, the session's, or the RFC 4145 default, active in an offer and
// passive in an answer.
func TestTheMSRPLinesAndTheirRoles(t *testing.T) {
	d := lines(
		"v=0", "o=- 1 1 IN IP4 192.0.2.10", "s=-", "c=IN IP4 192.0.2.10", "t=0 0",
		"a=setup:active",
		"m=message 9 TCP/MSRP *", "a=path:msrp://192.0.2.10:9/a;tcp", "a=setup:passive",
		"m=message 9 TCP/MSRP *", "a=path:msrp://192.0.2.10:9/b;tcp",
		"m=message 0 TCP/MSRP *", "a=path:msrp://192.0.2.10:9/c;tcp",
		"m=audio 4000 RTP/AVP 0",
	)
	_, got, err := msrpLines([]byte(d), true)
	if err != nil || len(got) != 2 || got[0].index != 0 || got[0].setup != sdp.SetupPassive || got[1].index != 1 || got[1].setup != sdp.SetupActive ||
		got[0].path[0] != "msrp://192.0.2.10:9/a;tcp" {
		t.Fatalf("%+v, %v", got, err)
	}
	none := strings.Replace(strings.Replace(d, "a=setup:active\r\n", "", 1), "a=setup:passive\r\n", "", 1)
	for _, offer := range []bool{true, false} {
		want := sdp.SetupActive
		if !offer {
			want = sdp.SetupPassive
		}
		_, got, err := msrpLines([]byte(none), offer)
		if err != nil || got[0].setup != want || got[1].setup != want {
			t.Errorf("offer %v: %+v, %v", offer, got, err)
		}
	}
	if _, _, err := msrpLines([]byte(strings.Replace(d, "a=path:msrp://192.0.2.10:9/a;tcp\r\n", "", 1)), true); err == nil {
		t.Error("an MSRP line without a=path was read")
	}
	if _, _, err := msrpLines([]byte("v=1\r\n"), true); err == nil {
		t.Error("a malformed description was read")
	}
}

// Anchoring writes the relay's path, host, port and transport and the role
// into the MSRP line, and leaves every other line as it was.
func TestAnchoringRewritesTheMSRPLineAlone(t *testing.T) {
	s, ls, err := msrpLines([]byte(clientChatOffer), true)
	if err != nil || len(ls) != 1 {
		t.Fatal(ls, err)
	}
	if err := anchorLine(s, ls[0].index, testCoreLocal, sdp.SetupActive, false); err != nil {
		t.Fatal(err)
	}
	out, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := strings.NewReplacer(
		"m=message 9 TCP/TLS/MSRP *", "m=message 9 TCP/MSRP *\r\nc=IN IP4 10.0.2.9",
		"a=setup:actpass", "a=setup:active",
		"a=path:msrps://192.0.2.10:9/s7d2k8f;tcp", "a=path:"+testCoreLocal,
	).Replace(clientChatOffer)
	if string(out) != want {
		t.Errorf("rewritten:\n%s\nwant:\n%s", out, want)
	}

	// Toward the client: the relay's public name and TLS port.
	s, ls, _ = msrpLines([]byte(clientChatOffer), false)
	if err := anchorLine(s, ls[0].index, testClientPath, sdp.SetupPassive, true); err != nil {
		t.Fatal(err)
	}
	out, _ = s.Marshal()
	if !bytes.Contains(out, []byte("m=message 2856 TCP/TLS/MSRP *\r\nc=IN IP4 msrp.example.net\r\n")) || !bytes.Contains(out, []byte("a=setup:passive")) {
		t.Errorf("toward the client:\n%s", out)
	}
	// An offer never says passive (RFC 6135 §4.2.2), and an IPv6 relay is IP6.
	s, ls, _ = msrpLines([]byte(clientChatOffer), true)
	if err := anchorLine(s, ls[0].index, testClientPath, sdp.SetupPassive, false); err == nil {
		t.Error("an offer was made passive")
	}
	if err := anchorLine(s, ls[0].index, "msrp://[fd00::5]:9/x1;tcp", sdp.SetupActive, false); err != nil {
		t.Fatal(err)
	}
	if out, _ = s.Marshal(); !bytes.Contains(out, []byte("c=IN IP6 fd00::5")) {
		t.Errorf("IPv6:\n%s", out)
	}
	if err := anchorLine(s, ls[0].index, "sip:x", sdp.SetupActive, false); err == nil {
		t.Error("a path that is no MSRP URI was written")
	}
}
