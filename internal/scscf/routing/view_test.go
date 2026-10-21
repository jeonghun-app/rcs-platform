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

// TestTheIFCViewSpellsFeatureTagsOneWay (#359 security review): names and
// quoted tokens in lower case, an escape's hex digits in upper case, the
// Contact's own URI and a string value kept.
func TestTheIFCViewSpellsFeatureTagsOneWay(t *testing.T) {
	r := request(t, "INVITE", impu1,
		`Accept-Contact: *;+G.3GPP.ICSI-REF="URN%3aURN-7%3a3GPP-SERVICE.IMS.ICSI.OMA.CPM.SESSION";REQUIRE`,
		`Contact: <sip:UE@192.0.2.10;Transport=TCP>;+SIP.Instance="<urn:uuid:ABC>";+G.OMA.SIP-IM`).Message
	want := map[string]string{
		"Accept-Contact": `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session";require`,
		"Contact":        `<sip:UE@192.0.2.10;Transport=TCP>;+sip.instance="<urn:uuid:ABC>";+g.oma.sip-im`,
	}
	for _, h := range (view{req: r}).HeaderFields() {
		if w, ok := want[h.Name]; ok && h.Value != w {
			t.Errorf("%s: %q, want %q", h.Name, h.Value, w)
		}
	}
}

// TestTheIFCViewNamesEachFeatureTag (#359 security review): an
// ifc.FeatureTagField for each feature-tag parameter of an Accept-Contact
// or Contact element, a flag by its name, a quoted one by each of its
// values, decoded, in lower case, after the request's own fields; none
// for a URI parameter, a display name, another parameter's value, a
// Reject-Contact or an element that does not parse.
func TestTheIFCViewNamesEachFeatureTag(t *testing.T) {
	r := request(t, "INVITE", impu1,
		`Accept-Contact: *;+G.3GPP.IARI-REF="x";require;explicit, *;audio;+g.example="+g.3gpp.icsi-ref"`,
		`Contact: "+g.3gpp.icsi-ref" <sip:ue1@192.0.2.11:5060;+g.3gpp.icsi-ref>;+g.3gpp.iari-ref="URN%3AURN-7%3AA,urn%3aurn-7%3ab";+g.oma.sip-im;expires=60`,
		`Reject-Contact: *;+g.3gpp.icsi-ref="y"`).Message
	var got []string
	fields := (view{req: r}).HeaderFields()
	for i, h := range fields {
		if h.Name == ifc.FeatureTagField {
			got = append(got, h.Value)
		} else if len(got) > 0 {
			t.Errorf("field %d, %s, after the feature tags", i, h.Name)
		}
	}
	if want := []string{"+g.3gpp.iari-ref=x", "audio", "+g.example=+g.3gpp.icsi-ref", "+g.3gpp.iari-ref=urn:urn-7:a", "+g.3gpp.iari-ref=urn:urn-7:b", "+g.oma.sip-im"}; !slices.Equal(got, want) {
		t.Errorf("feature tags %q, want %q", got, want)
	}
}
