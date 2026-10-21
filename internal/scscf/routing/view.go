package routing

import (
	"bytes"
	"io"
	"mime/multipart"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// listHeaders are the header fields of RFC 3261 §7.3.1 list syntax, and of
// the IMS extensions to it, that iFC triggers are written against: each of
// their values is matched on its own (TS 29.228 Annex F). Any other field
// is one value, as Subject, Date and the authentication fields, whose values
// hold commas of their own, must be.
var listHeaders = map[string]bool{
	"Accept": true, "Accept-Contact": true, "Accept-Encoding": true, "Accept-Language": true,
	"Allow": true, "Allow-Events": true, "Contact": true, "Content-Encoding": true,
	"P-Asserted-Identity": true, "P-Asserted-Service": true, "P-Associated-URI": true,
	"P-Preferred-Identity": true, "P-Preferred-Service": true, "Path": true,
	"Proxy-Require": true, "Record-Route": true, "Reject-Contact": true, "Require": true,
	"Route": true, "Service-Route": true, "Supported": true, "Unsupported": true, "Via": true,
}

// view presents a SIP request to iFC evaluation (ifc.Request): header names
// in their full form, list headers split into their values, and the SDP
// lines of a session description body. hide leaves a header out, as the
// P-Served-User the S-CSCF inserted itself toward an application server
// (TS 24.229 §5.4.3.2), which the request carries back.
type view struct {
	req  *sip.Request
	hide string
}

func (v view) Method() string     { return v.req.Method }
func (v view) RequestURI() string { return v.req.URI.String() }

func (v view) HeaderFields() []ifc.HeaderField {
	var out []ifc.HeaderField
	for _, f := range v.req.Header.Fields() {
		name := sip.CanonicalName(f.Name)
		if v.hide != "" && strings.EqualFold(name, v.hide) {
			continue
		}
		if listHeaders[name] {
			var one sip.Header
			if one.Add(name, f.Value) == nil {
				if els, err := one.Elements(name); err == nil {
					for _, e := range els {
						out = append(out, ifc.HeaderField{Name: name, Value: e})
					}
					continue
				}
			}
		}
		out = append(out, ifc.HeaderField{Name: name, Value: f.Value})
	}
	return out
}

func (v view) SDPLines() []string {
	ct, err := v.req.Header.ContentType()
	if err != nil {
		return nil
	}
	body := v.req.Body
	switch {
	case isSDP(ct):
	case strings.EqualFold(ct.Type, "multipart"):
		if body = sdpPart(ct, body); body == nil {
			return nil
		}
	default:
		return nil
	}
	var out []string
	for _, l := range bytes.Split(body, []byte("\n")) {
		if l = bytes.TrimRight(l, "\r"); len(l) > 0 {
			out = append(out, string(l))
		}
	}
	return out
}

func isSDP(ct sip.MediaType) bool {
	return strings.EqualFold(ct.Type, "application") && strings.EqualFold(ct.Subtype, "sdp")
}

// maxParts bounds the parts of a multipart body sdpPart looks through: an
// RCS INVITE carries two, its SDP and the first message (CPIM).
const maxParts = 8

// sdpPart is the first application/sdp part of a multipart body, as
// rcsjta's chat INVITE with its first message has (RFC 2046 §5.1), read up
// to what iFC examine of an SDP (ifc.MaxSDPBytes); nil without one, or if
// the body does not read.
func sdpPart(ct sip.MediaType, body []byte) []byte {
	boundary, ok := ct.Params.Get("boundary")
	if !ok || boundary == "" {
		return nil
	}
	r := multipart.NewReader(bytes.NewReader(body), boundary)
	for range maxParts {
		p, err := r.NextPart()
		if err != nil {
			return nil
		}
		var h sip.Header
		if h.Add("Content-Type", p.Header.Get("Content-Type")) != nil {
			continue
		}
		if pct, err := h.ContentType(); err != nil || !isSDP(pct) {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(p, ifc.MaxSDPBytes))
		if err != nil {
			return nil
		}
		return b
	}
	return nil
}
