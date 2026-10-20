package reginfo

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
)

// The wire types decode with namespace-qualified names, so an extension
// element sharing a local name is never mistaken for a reginfo one.
// Single-valued elements are slices so a duplicate is detected rather than
// silently overwritten. Attributes are collected whole and read with
// plainAttr.
type wireInfo struct {
	XMLName       xml.Name           `xml:"urn:ietf:params:xml:ns:reginfo reginfo"`
	Attrs         []xml.Attr         `xml:",any,attr"`
	Registrations []wireRegistration `xml:"urn:ietf:params:xml:ns:reginfo registration"`
}

type wireRegistration struct {
	Attrs    []xml.Attr    `xml:",any,attr"`
	Contacts []wireContact `xml:"urn:ietf:params:xml:ns:reginfo contact"`
}

type wireContact struct {
	Attrs        []xml.Attr `xml:",any,attr"`
	URI          []string   `xml:"urn:ietf:params:xml:ns:reginfo uri"`
	DisplayName  []wireText `xml:"urn:ietf:params:xml:ns:reginfo display-name"`
	UnknownParam []wireText `xml:"urn:ietf:params:xml:ns:reginfo unknown-param"`
}

type wireText struct {
	Attrs []xml.Attr `xml:",any,attr"`
	Text  string     `xml:",chardata"`
}

// xmlNamespace is the namespace of xml:lang (XML Namespaces §3).
const xmlNamespace = "http://www.w3.org/XML/1998/namespace"

// plainAttr returns the attribute called name in no namespace. RFC 3680
// attributes are unqualified (§5.4), and one of the same local name in
// another namespace is an extension to be ignored (§5.1).
func plainAttr(attrs []xml.Attr, name string) (string, bool) {
	for _, a := range attrs {
		if a.Name.Space == "" && a.Name.Local == name {
			return a.Value, true
		}
	}
	return "", false
}

func required(attrs []xml.Attr, element, name string) (string, error) {
	v, ok := plainAttr(attrs, name)
	if !ok {
		return "", fmt.Errorf("%w: %s without %s", ErrMalformed, element, name)
	}
	return v, nil
}

// unsignedLong reads an xs:unsignedLong attribute, if present. Its white
// space collapses (XML Schema Part 2 §3.3.21), so it is trimmed.
func unsignedLong(attrs []xml.Attr, name string) (*uint64, error) {
	v, ok := plainAttr(attrs, name)
	if !ok {
		return nil, nil
	}
	n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not an unsigned long", ErrMalformed, name)
	}
	return &n, nil
}

func (w *wireInfo) info() (*Info, error) {
	v, err := required(w.Attrs, "reginfo", "version")
	if err != nil {
		return nil, err
	}
	version, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: version is not a 32-bit unsigned integer", ErrMalformed)
	}
	// The enumerations are xs:string, whose white space is significant, so
	// " full" is not "full".
	state, err := required(w.Attrs, "reginfo", "state")
	if err != nil {
		return nil, err
	}
	r := &Info{Version: uint32(version), State: State(state)}
	for _, wr := range w.Registrations {
		reg, err := wr.registration()
		if err != nil {
			return nil, err
		}
		r.Registrations = append(r.Registrations, reg)
	}
	return r, nil
}

func (w *wireRegistration) registration() (Registration, error) {
	var reg Registration
	var err error
	if reg.AOR, err = required(w.Attrs, "registration", "aor"); err != nil {
		return Registration{}, err
	}
	// xs:anyURI collapses white space.
	reg.AOR = strings.TrimSpace(reg.AOR)
	if reg.ID, err = required(w.Attrs, "registration", "id"); err != nil {
		return Registration{}, err
	}
	state, err := required(w.Attrs, "registration", "state")
	if err != nil {
		return Registration{}, err
	}
	reg.State = RegistrationState(state)
	for _, wc := range w.Contacts {
		c, err := wc.contact()
		if err != nil {
			return Registration{}, err
		}
		reg.Contacts = append(reg.Contacts, c)
	}
	return reg, nil
}

func (w *wireContact) contact() (Contact, error) {
	var c Contact
	var err error
	if c.ID, err = required(w.Attrs, "contact", "id"); err != nil {
		return Contact{}, err
	}
	state, err := required(w.Attrs, "contact", "state")
	if err != nil {
		return Contact{}, err
	}
	event, err := required(w.Attrs, "contact", "event")
	if err != nil {
		return Contact{}, err
	}
	c.State, c.Event = ContactState(state), Event(event)
	for _, n := range []struct {
		name string
		to   **uint64
	}{{"duration-registered", &c.DurationRegistered}, {"expires", &c.Expires}, {"retry-after", &c.RetryAfter}, {"cseq", &c.CSeq}} {
		if *n.to, err = unsignedLong(w.Attrs, n.name); err != nil {
			return Contact{}, err
		}
	}
	c.Q, _ = plainAttr(w.Attrs, "q")
	c.CallID, _ = plainAttr(w.Attrs, "callid")
	if len(w.URI) != 1 {
		return Contact{}, fmt.Errorf("%w: contact without exactly one uri", ErrMalformed)
	}
	c.URI = strings.TrimSpace(w.URI[0])
	switch len(w.DisplayName) {
	case 0:
	case 1:
		c.DisplayName = w.DisplayName[0].Text
		for _, a := range w.DisplayName[0].Attrs {
			if a.Name.Space == xmlNamespace && a.Name.Local == "lang" {
				c.Language = a.Value
			}
		}
	default:
		return Contact{}, fmt.Errorf("%w: more than one display-name", ErrMalformed)
	}
	for _, p := range w.UnknownParam {
		name, err := required(p.Attrs, "unknown-param", "name")
		if err != nil {
			return Contact{}, err
		}
		c.Params = append(c.Params, Param{Name: name, Value: p.Text})
	}
	return c, nil
}
