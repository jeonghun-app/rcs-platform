// Package reginfo reads and writes registration information documents (RFC
// 3680 §5), the bodies of reg event NOTIFY requests: scscf writes them to
// tell a UE and its pcscf how the registrations of an implicit registration
// set change, and pcscf and clients read them to learn of a registration
// the network ended (TS 24.229 §5.2.5.2).
//
// The model is the RFC 3680 §5.4 schema: the document's version and state,
// and per registration its address-of-record, id and state with its
// contacts, each with its URI, id, state, the event that put it there and
// the optional attributes, display name and unknown parameters. Elements
// and attributes of other namespaces are skipped when parsing, as §5.1
// requires, and Marshal writes only the modelled ones.
//
// Documents are decoded with encoding/xml behind a size limit, a nesting
// limit and a refusal of any document type declaration, and checked
// against the schema and §5.1: the required attributes, the enumerations,
// the expires a shortened contact needs and the retry-after a contact on
// probation needs, and ids unique where a subscriber keys its tables on
// them (§5.2). ByAOR and ByURI find a subscriber's identity and contact
// in a document by URI comparison, never by text.
package reginfo

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// ContentType is the MIME type of a registration information document (RFC
// 3680 §8.2).
const ContentType = "application/reginfo+xml"

// Namespace is the XML namespace of registration information documents (RFC
// 3680 §8.3).
const Namespace = "urn:ietf:params:xml:ns:reginfo"

// maxRegistrations and maxContacts bound what one document may list: an
// implicit registration set has a few dozen identities, each with a handful
// of contacts, and a subscriber keeps a table entry for each.
const (
	maxRegistrations = 256
	maxContacts      = 64
)

// ErrMalformed reports a document outside RFC 3680.
var ErrMalformed = errors.New("reginfo: malformed document")

// State says whether a document carries the whole registration state of the
// subscription or only what changed (RFC 3680 §5.1).
type State string

// The document states RFC 3680 §5.4 defines.
const (
	Full    State = "full"
	Partial State = "partial"
)

// RegistrationState is the state of an address-of-record's registration
// (RFC 3680 §4.7.1, §5.1).
type RegistrationState string

// The registration states RFC 3680 §5.4 defines.
const (
	Init       RegistrationState = "init"
	Active     RegistrationState = "active"
	Terminated RegistrationState = "terminated"
)

// ContactState is the state of a contact (RFC 3680 §4.7.1, §5.1).
type ContactState string

// The contact states RFC 3680 §5.4 defines.
const (
	ContactActive     ContactState = "active"
	ContactTerminated ContactState = "terminated"
)

// Event is what put a contact in its state (RFC 3680 §4.7.2, §5.1).
type Event string

// The events RFC 3680 §5.4 defines: the first four leave a contact active,
// the others end it.
const (
	Registered   Event = "registered"
	Created      Event = "created"
	Refreshed    Event = "refreshed"
	Shortened    Event = "shortened"
	Expired      Event = "expired"
	Deactivated  Event = "deactivated"
	Probation    Event = "probation"
	Unregistered Event = "unregistered"
	Rejected     Event = "rejected"
)

var events = []Event{Registered, Created, Refreshed, Shortened, Expired, Deactivated, Probation, Unregistered, Rejected}

// Info is a <reginfo> document.
type Info struct {
	// Version orders the documents of one subscription (RFC 3680 §5.2).
	// The schema allows any non-negative integer; a notifier counts from 0
	// and RFC 3265-style counters are 32 bits, so a larger one is refused.
	Version       uint32
	State         State
	Registrations []Registration
}

// Registration is the registration of one address-of-record (RFC 3680
// §5.1).
type Registration struct {
	// AOR is the address-of-record, a SIP or tel URI.
	AOR string
	// ID names the registration within the subscription.
	ID       string
	State    RegistrationState
	Contacts []Contact
}

// Contact is one contact of a registration (RFC 3680 §5.1).
type Contact struct {
	// ID names the contact within the subscription. scscf makes one per
	// binding, from its +sip.instance and reg-id, or from the contact URI
	// and the flow without them, not one per URI: the same URI bound over
	// two flows (RFC 5626) is two contacts with two ids (#233).
	ID string
	// State says whether the contact is registered, and Event what put it
	// in that state. A document may pair them in a way RFC 3680 §4.7.1
	// does not, which Parse accepts and Marshal refuses; State decides, so
	// use Active rather than Event to tell whether it is registered.
	State ContactState
	Event Event
	// URI is the contact address.
	URI         string
	DisplayName string
	// Language is the display name's xml:lang, if any.
	Language string
	// Expires is the seconds left; a shortened contact must have it.
	// RetryAfter is when the owner should register again; a contact on
	// probation must have it. Both, and DurationRegistered, are nil when
	// absent.
	Expires, RetryAfter, DurationRegistered *uint64
	// Q, CallID and CSeq are the contact's priority and the Call-ID and
	// CSeq of the REGISTER that last changed it, if given.
	Q, CallID string
	CSeq      *uint64
	// Params are the contact's unknown parameters, such as +sip.instance.
	Params []Param
}

// Active reports whether c is registered: its state is active, whatever
// its event says (RFC 3680 §5.1, #233).
func (c Contact) Active() bool { return c.State == ContactActive }

// Param returns the value of the unknown parameter called name, its name
// compared without case as a contact parameter's is (RFC 3261 §7.3.1), and
// a quoted-string value unquoted, as +sip.instance's is (RFC 5626 §4.1):
// so `"<urn:uuid:…>"` is `<urn:uuid:…>`. A flag has the value "".
func (c Contact) Param(name string) (string, bool) {
	for _, p := range c.Params {
		if strings.EqualFold(p.Name, name) {
			return unquote(p.Value), true
		}
	}
	return "", false
}

// unquote returns the content of a quoted-string, its escapes undone
// (RFC 3261 §25.1), or v as it is when it is not one.
func unquote(v string) string {
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return v
	}
	var b strings.Builder
	in := v[1 : len(v)-1]
	for i := 0; i < len(in); i++ {
		if in[i] == '\\' && i+1 < len(in) {
			i++
		}
		b.WriteByte(in[i])
	}
	return b.String()
}

// Param is an <unknown-param>: a contact parameter RFC 3261 does not
// define, with its value, empty for a flag.
type Param struct {
	Name, Value string
}

// Parse reads a registration information document.
func Parse(data []byte) (*Info, error) {
	if err := checkDocument(data); err != nil {
		return nil, err
	}
	if err := checkElements(data); err != nil {
		return nil, err
	}
	var w wireInfo
	if err := xml.NewDecoder(bytes.NewReader(withoutBOM(data))).Decode(&w); err != nil {
		return nil, decodeError(err)
	}
	info, err := w.info()
	if err != nil {
		return nil, err
	}
	if err := info.validate(); err != nil {
		return nil, err
	}
	return info, nil
}

// Marshal serializes r in the element order of the RFC 3680 §5.4 schema.
// It refuses what Parse would, and also a contact whose state and event
// RFC 3680 §4.7.1 does not pair, an expires on one not active, and an
// active contact under a registration in init or terminated, so a
// notifier sends no document its subscribers could read two ways.
func (r *Info) Marshal() ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	if err := r.validateStrict(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(xml.Header)
	w := &xmlWriter{e: xml.NewEncoder(&b)}
	// The namespace is declared once on the root; encoding/xml would repeat
	// it on every element if the names carried it.
	w.start("reginfo",
		xml.Attr{Name: xml.Name{Local: "xmlns"}, Value: Namespace},
		attr("version", strconv.FormatUint(uint64(r.Version), 10)),
		attr("state", string(r.State)))
	for _, reg := range r.Registrations {
		w.start("registration", attr("aor", reg.AOR), attr("id", reg.ID), attr("state", string(reg.State)))
		for _, c := range reg.Contacts {
			writeContact(w, c)
		}
		w.end("registration")
	}
	w.end("reginfo")
	if err := w.close(); err != nil {
		return nil, err
	}
	// The counts allow more than MaxDocumentSize, which Parse refuses.
	if b.Len() > MaxDocumentSize {
		return nil, ErrTooLarge
	}
	return b.Bytes(), nil
}

func writeContact(w *xmlWriter, c Contact) {
	attrs := []xml.Attr{attr("id", c.ID), attr("state", string(c.State)), attr("event", string(c.Event))}
	for _, n := range []struct {
		name string
		v    *uint64
	}{{"duration-registered", c.DurationRegistered}, {"expires", c.Expires}, {"retry-after", c.RetryAfter}, {"cseq", c.CSeq}} {
		if n.v != nil {
			attrs = append(attrs, attr(n.name, strconv.FormatUint(*n.v, 10)))
		}
	}
	if c.Q != "" {
		attrs = append(attrs, attr("q", c.Q))
	}
	if c.CallID != "" {
		attrs = append(attrs, attr("callid", c.CallID))
	}
	w.start("contact", attrs...)
	w.text("uri", c.URI)
	if c.DisplayName != "" || c.Language != "" {
		var lang []xml.Attr
		if c.Language != "" {
			lang = []xml.Attr{{Name: xml.Name{Local: "xml:lang"}, Value: c.Language}}
		}
		w.start("display-name", lang...)
		w.chars(c.DisplayName)
		w.end("display-name")
	}
	for _, p := range c.Params {
		w.start("unknown-param", attr("name", p.Name))
		w.chars(p.Value)
		w.end("unknown-param")
	}
	w.end("contact")
}

func attr(name, value string) xml.Attr {
	return xml.Attr{Name: xml.Name{Local: name}, Value: value}
}

// validate checks r against the schema and §5.1, for Parse and Marshal
// alike, so that a document Marshal writes is one Parse reads. An
// address-of-record appears in one registration only (§5.1), compared as
// URIs, so no subscriber finds it both active and terminated.
func (r *Info) validate() error {
	if r.State != Full && r.State != Partial {
		return fmt.Errorf("%w: invalid reginfo state", ErrMalformed)
	}
	if len(r.Registrations) > maxRegistrations {
		return fmt.Errorf("%w: more than %d registrations", ErrMalformed, maxRegistrations)
	}
	var ids []string
	aors := make([]aorForm, 0, len(r.Registrations))
	// Contact ids are unique in the whole document, as RFC 3680 §5.1 has
	// them within a subscription, and so within each registration too.
	contacts := map[string]bool{}
	for _, reg := range r.Registrations {
		if err := reg.validate(); err != nil {
			return err
		}
		if slices.Contains(ids, reg.ID) {
			return fmt.Errorf("%w: repeated registration id", ErrMalformed)
		}
		ids = append(ids, reg.ID)
		u, _ := sip.ParseURI(reg.AOR) // validate parsed it
		aor := aorOf(u)
		if slices.ContainsFunc(aors, aor.same) {
			return fmt.Errorf("%w: repeated address-of-record", ErrMalformed)
		}
		aors = append(aors, aor)
		for _, c := range reg.Contacts {
			if contacts[c.ID] {
				return fmt.Errorf("%w: repeated contact id", ErrMalformed)
			}
			contacts[c.ID] = true
		}
	}
	return nil
}

// activeEvents are the events that leave a contact active; the others end
// it (RFC 3680 §4.7.1).
var activeEvents = []Event{Registered, Created, Refreshed, Shortened}

// validateStrict checks what only a sender is held to.
func (r *Info) validateStrict() error {
	for _, reg := range r.Registrations {
		for _, c := range reg.Contacts {
			if slices.Contains(activeEvents, c.Event) != c.Active() {
				return fmt.Errorf("%w: contact state and event disagree", ErrMalformed)
			}
			if c.Expires != nil && !c.Active() {
				return fmt.Errorf("%w: expires on a contact not active", ErrMalformed)
			}
			if c.Active() && reg.State != Active {
				return fmt.Errorf("%w: active contact under a registration not active", ErrMalformed)
			}
		}
	}
	return nil
}

func (reg Registration) validate() error {
	if !validURI(reg.AOR) {
		return fmt.Errorf("%w: aor is not a SIP or tel URI", ErrMalformed)
	}
	if !isXMLText(reg.ID) {
		return fmt.Errorf("%w: invalid registration id", ErrMalformed)
	}
	switch reg.State {
	case Init, Active, Terminated:
	default:
		return fmt.Errorf("%w: invalid registration state", ErrMalformed)
	}
	if len(reg.Contacts) > maxContacts {
		return fmt.Errorf("%w: more than %d contacts in a registration", ErrMalformed, maxContacts)
	}
	for _, c := range reg.Contacts {
		if err := c.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (c Contact) validate() error {
	if !isXMLText(c.ID) {
		return fmt.Errorf("%w: invalid contact id", ErrMalformed)
	}
	if c.State != ContactActive && c.State != ContactTerminated {
		return fmt.Errorf("%w: invalid contact state", ErrMalformed)
	}
	if !slices.Contains(events, c.Event) {
		return fmt.Errorf("%w: invalid contact event", ErrMalformed)
	}
	if c.Event == Shortened && c.Expires == nil {
		return fmt.Errorf("%w: shortened contact without expires", ErrMalformed)
	}
	if c.Event == Probation && c.RetryAfter == nil {
		return fmt.Errorf("%w: contact on probation without retry-after", ErrMalformed)
	}
	if !validURI(c.URI) {
		return fmt.Errorf("%w: contact uri is not a SIP or tel URI", ErrMalformed)
	}
	for _, s := range []string{c.DisplayName, c.Language, c.Q, c.CallID} {
		if !isXMLText(s) {
			return fmt.Errorf("%w: invalid contact text", ErrMalformed)
		}
	}
	for _, p := range c.Params {
		if p.Name == "" || !isXMLText(p.Name) || !isXMLText(p.Value) {
			return fmt.Errorf("%w: invalid unknown-param", ErrMalformed)
		}
	}
	return nil
}

// ByAOR is the registration whose address-of-record is aor, if there is
// one. Addresses-of-record compare in the form the HSS keeps a public
// identity in (identity.CanonicalIMPU: parameters dropped, escapes undone,
// the host in lower case, a tel URI's separators removed), since a
// notifier may write the identity otherwise than the subscriber knows it
// by; one that has no such form compares as a URI (RFC 3261 §19.1.4). A
// document Parse returned has at most one: it refuses an address-of-record
// repeated.
func (r *Info) ByAOR(aor sip.URI) (Registration, bool) {
	want := aorOf(aor)
	for _, reg := range r.Registrations {
		u, err := sip.ParseURI(reg.AOR)
		if err == nil && aorOf(u).same(want) {
			return reg, true
		}
	}
	return Registration{}, false
}

// aorForm is an address-of-record as it compares: its canonical form, or
// the URI when it has none.
type aorForm struct {
	canonical string
	uri       sip.URI
}

func aorOf(u sip.URI) aorForm {
	c, _ := identity.CanonicalIMPU(u.String())
	return aorForm{canonical: c, uri: u}
}

func (a aorForm) same(b aorForm) bool {
	if a.canonical != "" && b.canonical != "" {
		return a.canonical == b.canonical
	}
	return a.uri.Equal(b.uri)
}

// ByURI is the contacts of reg at uri, compared as URIs (RFC 3261 §19.1.4). There
// may be more than one: a contact URI can be bound once per flow (RFC 5626
// §6), the bindings told apart by their parameters.
func (reg Registration) ByURI(uri sip.URI) []Contact {
	var out []Contact
	for _, c := range reg.Contacts {
		if equalURI(c.URI, uri) {
			out = append(out, c)
		}
	}
	return out
}

// equalURI reports whether the URI text s is u.
func equalURI(s string, u sip.URI) bool {
	v, err := sip.ParseURI(s)
	return err == nil && v.Equal(u)
}

// validURI reports whether s is a SIP, SIPS or tel URI, which is what a
// subscriber compares with the identities and contacts it knows.
func validURI(s string) bool {
	u, err := sip.ParseURI(s)
	return err == nil && (u.IsSIP() || u.Scheme == "tel") && isXMLText(s)
}
