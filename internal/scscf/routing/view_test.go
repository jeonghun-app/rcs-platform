package routing

import (
	"slices"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

// TestTheIFCViewPresentsEachValueOfAListOnItsOwn (TS 29.228 Annex F): list
// header fields split into their values, under their full names; other
// fields, whose values may hold commas, kept whole; the SDP of a session
// description body by line; and the hidden header left out.
func TestTheIFCViewPresentsEachValueOfAListOnItsOwn(t *testing.T) {
	r := request(t, "INVITE", impu1,
		`a: *;+g.oma.sip-im, *;audio`,
		`Subject: chat, later`,
		`P-Served-User: <`+impu1+`>;sescase=term`,
		"Content-Type: application/sdp").Message
	r.Body = []byte("v=0\r\n\r\nm=message 9 TCP/MSRP *\r\n")
	var got []ifc.HeaderField
	for _, h := range (view{req: r, hide: "P-Served-User"}).HeaderFields() {
		if h.Name == "Accept-Contact" || h.Name == "Subject" || h.Name == "P-Served-User" {
			got = append(got, h)
		}
	}
	want := []ifc.HeaderField{{Name: "Accept-Contact", Value: "*;+g.oma.sip-im"}, {Name: "Accept-Contact", Value: "*;audio"}, {Name: "Subject", Value: "chat, later"}}
	if !slices.Equal(got, want) {
		t.Errorf("fields %v", got)
	}
	if lines := (view{req: r}).SDPLines(); !slices.Equal(lines, []string{"v=0", "m=message 9 TCP/MSRP *"}) {
		t.Errorf("SDP %q", lines)
	}
	for _, ct := range []string{"text/plain", "application/xml"} {
		if err := r.Header.Set("Content-Type", ct); err != nil {
			t.Fatal(err)
		}
		if lines := (view{req: r}).SDPLines(); lines != nil {
			t.Errorf("a %s body read as SDP: %q", ct, lines)
		}
	}
	if v := (view{req: r}); v.Method() != "INVITE" || v.RequestURI() != impu1 {
		t.Errorf("%s %s", v.Method(), v.RequestURI())
	}
}

// TestTheIFCViewReadsTheSDPPartOfAMultipartBody (code review on #359):
// rcsjta's chat INVITE carries its SDP and its first message together.
func TestTheIFCViewReadsTheSDPPartOfAMultipartBody(t *testing.T) {
	r := request(t, "INVITE", impu1, "Content-Type: multipart/mixed;boundary=b1").Message
	r.Body = []byte("--b1\r\nContent-Type: message/cpim\r\n\r\nFrom: <sip:anonymous@anonymous.invalid>\r\n\r\nhi\r\n" +
		"--b1\r\nContent-Type: application/sdp\r\n\r\nv=0\r\nm=message 9 TCP/MSRP *\r\n--b1--\r\n")
	if lines := (view{req: r}).SDPLines(); !slices.Equal(lines, []string{"v=0", "m=message 9 TCP/MSRP *"}) {
		t.Errorf("SDP %q", lines)
	}
	for name, body := range map[string]string{
		"no SDP part":      "--b1\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b1--\r\n",
		"not multipart":    "garbage",
		"another boundary": "--b2\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b2--\r\n",
	} {
		r.Body = []byte(body)
		if lines := (view{req: r}).SDPLines(); lines != nil {
			t.Errorf("%s: SDP %q", name, lines)
		}
	}
	// An SDP part past the parts looked through is not read.
	var b strings.Builder
	for range maxParts {
		b.WriteString("--b1\r\nContent-Type: text/plain\r\n\r\nx\r\n")
	}
	b.WriteString("--b1\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b1--\r\n")
	r.Body = []byte(b.String())
	if lines := (view{req: r}).SDPLines(); lines != nil {
		t.Errorf("an SDP part past %d parts: %q", maxParts, lines)
	}
}
