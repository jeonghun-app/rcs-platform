package routing

import (
	"slices"
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
	r.Header.Set("Content-Type", "text/plain")
	if lines := (view{req: r}).SDPLines(); lines != nil {
		t.Errorf("a text body read as SDP: %q", lines)
	}
	if v := (view{req: r}); v.Method() != "INVITE" || v.RequestURI() != impu1 {
		t.Errorf("%s %s", v.Method(), v.RequestURI())
	}
}
