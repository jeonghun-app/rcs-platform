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
	"net/url"
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

// ErrNotWritable reports, from Marshal only, a document Parse would read
// but a sender must not write (validateStrict): it wraps ErrMalformed.
var ErrNotWritable = fmt.Errorf("%w: not to be sent", ErrMalformed)

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
	// ID names the contact within the subscription (RFC 3680 §5.1). scscf
	// makes one per binding and address-of-record, from the binding's
	// +sip.instance and reg-id, or its URI and flow without them, and the
	// AOR: the same URI bound over two flows (RFC 5626) is two contacts,
	// and one binding under the sip and tel identities of an implicit set
	// has two ids (#233). Marshal requires them unique in the document;
	// Parse, lenient, only within a registration, and subscribers match
	// bindings by their parameters and URI, never by id.
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
// compared without ASCII case as a contact parameter's is (RFC 3261
// §7.3.1), and a quoted-string value unquoted, as +sip.instance's is (RFC
// 5626 §4.1): so `"<urn:uuid:…>"` is `<urn:uuid:…>`. A flag has the value
// "". With the name twice, which Marshal refuses, the first counts.
func (c Contact) Param(name string) (string, bool) {
	for _, p := range c.Params {
		if asciiEqualFold(p.Name, name) {
			return unquote(p.Value), true
		}
	}
	return "", false
}

// asciiEqualFold reports whether a and b are equal but for the case of
// ASCII letters: a token's case, not Unicode's folding (RFC 3261 §7.3.1).
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
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
// aorKey and sameAOR, so no subscriber finds it both active and
// terminated. Contact
// ids are unique within a registration.
func (r *Info) validate() error {
	if r.State != Full && r.State != Partial {
		return fmt.Errorf("%w: invalid reginfo state", ErrMalformed)
	}
	if len(r.Registrations) > maxRegistrations {
		return fmt.Errorf("%w: more than %d registrations", ErrMalformed, maxRegistrations)
	}
	// One key each, looked up in a map, so the checks stay linear in the
	// document (docs/architecture.md §8).
	ids := make(map[string]bool, len(r.Registrations))
	aors := make(map[string][]aorEntry, len(r.Registrations))
	for _, reg := range r.Registrations {
		if err := reg.validate(); err != nil {
			return err
		}
		if ids[reg.ID] {
			return fmt.Errorf("%w: repeated registration id", ErrMalformed)
		}
		ids[reg.ID] = true
		u, _ := sip.ParseURI(reg.AOR) // validate parsed it
		key, e := aorKey(u), entryOf(u)
		if slices.ContainsFunc(aors[key], func(v aorEntry) bool { return sameAOR(key, e, v) }) {
			return fmt.Errorf("%w: repeated address-of-record", ErrMalformed)
		}
		aors[key] = append(aors[key], e)
	}
	return nil
}

// activeEvents are the events that leave a contact active; the others end
// it (RFC 3680 §4.7.1).
var activeEvents = []Event{Registered, Created, Refreshed, Shortened}

// validateStrict checks what only a sender is held to: besides the state
// machine, contact ids unique in the whole document (RFC 3680 §5.1) and a
// contact's parameter names unique, so Param has one reading.
func (r *Info) validateStrict() error {
	contacts := map[string]bool{}
	for _, reg := range r.Registrations {
		for _, c := range reg.Contacts {
			if contacts[c.ID] {
				return fmt.Errorf("%w: contact id repeated in the document", ErrNotWritable)
			}
			contacts[c.ID] = true
			for i, p := range c.Params {
				if slices.ContainsFunc(c.Params[:i], func(q Param) bool { return asciiEqualFold(q.Name, p.Name) }) {
					return fmt.Errorf("%w: contact parameter repeated", ErrNotWritable)
				}
			}
			if slices.Contains(activeEvents, c.Event) != c.Active() {
				return fmt.Errorf("%w: contact state and event disagree", ErrNotWritable)
			}
			if c.Expires != nil && !c.Active() {
				return fmt.Errorf("%w: expires on a contact not active", ErrNotWritable)
			}
			if c.Active() && reg.State != Active {
				return fmt.Errorf("%w: active contact under a registration not active", ErrNotWritable)
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
	// Contact ids are unique within a registration, whose table they key
	// (§5.2); the same binding under the identities of an implicit set
	// keeps its one id in each.
	ids := make(map[string]bool, len(reg.Contacts))
	for _, c := range reg.Contacts {
		if err := c.validate(); err != nil {
			return err
		}
		if ids[c.ID] {
			return fmt.Errorf("%w: repeated contact id", ErrMalformed)
		}
		ids[c.ID] = true
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
	want, e := aorKey(aor), entryOf(aor)
	for _, reg := range r.Registrations {
		u, err := sip.ParseURI(reg.AOR)
		if err == nil && aorKey(u) == want && sameAOR(want, entryOf(u), e) {
			return reg, true
		}
	}
	return Registration{}, false
}

// aorKey is the key an address-of-record is filed under: its canonical
// IMPU, which decides alone, or, for one without (a port, a password,
// headers, no user part, a local number), a key two URIs share whenever
// sip.URI.Equal says they are one (RFC 3261 §19.1.4, RFC 3966 §4): the
// scheme, the user with its escapes undone, the host in lower case and the
// port, and of the parameters only those §19.1.4 makes match, the rest
// being sameAOR's to compare. One key per AOR keeps the duplicate check
// linear (docs/architecture.md §8).
func aorKey(u sip.URI) string {
	if c, ok := identity.CanonicalIMPU(u.String()); ok {
		return "c\x00" + c
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "tel" {
		return "t\x00" + strings.ToLower(strings.Map(func(r rune) rune {
			if strings.ContainsRune("-.()", r) {
				return -1
			}
			return r
		}, u.User))
	}
	user := u.User
	if v, err := url.PathUnescape(user); err == nil {
		user = v
	}
	var ps []string
	for _, p := range u.Params {
		switch name := strings.ToLower(p.Name); name {
		case "user", "ttl", "method", "maddr", "transport":
			v := p.Value
			if d, err := url.PathUnescape(v); err == nil {
				v = d
			}
			ps = append(ps, name+"="+strings.ToLower(v))
		}
	}
	slices.Sort(ps)
	return "u\x00" + scheme + ":" + user + "@" + strings.ToLower(u.Host) + ":" + strconv.Itoa(u.Port) + ";" + strings.Join(ps, ";")
}

// aorEntry is an AOR with what sameAOR compares made ready once: the URI
// without its parameters, and the parameters by name, normalized as
// sip.URI.Equal normalizes them. So the URIs sharing a key compare in time
// linear in their parameters, not quadratic as Equal's would be.
type aorEntry struct {
	uri, bare sip.URI
	params    map[string]string
}

func entryOf(u sip.URI) aorEntry {
	e := aorEntry{uri: u, bare: u, params: make(map[string]string, len(u.Params))}
	e.bare.Params = nil
	for _, p := range u.Params {
		e.params[strings.ToLower(p.Name)] = strings.ToLower(normalizeEscapes(p.Value))
	}
	return e
}

// sameAOR reports whether a and b, filed under key, are one AOR: the
// canonical key decides alone; otherwise they are as sip.URI.Equal has
// them (RFC 3261 §19.1.4): the same without their parameters, and every
// parameter both carry the same, those that must be on both already in
// the key. A tel URI, whose parameters all count (RFC 3966 §4), is Equal's.
func sameAOR(key string, a, b aorEntry) bool {
	switch {
	case strings.HasPrefix(key, "c\x00"):
		return true
	case strings.HasPrefix(key, "t\x00"):
		return a.uri.Equal(b.uri)
	}
	if !a.bare.Equal(b.bare) {
		return false
	}
	if len(b.params) < len(a.params) {
		a, b = b, a
	}
	for name, v := range a.params {
		if w, ok := b.params[name]; ok && w != v {
			return false
		}
	}
	return true
}

// normalizeEscapes decodes every escape but those of "%" and the reserved
// characters, and upper-cases the hex digits of those, as sip.URI.Equal
// compares (RFC 3261 §19.1.4).
func normalizeEscapes(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' || i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
			b.WriteByte(s[i])
			continue
		}
		if c := unhex(s[i+1])<<4 | unhex(s[i+2]); c != '%' && strings.IndexByte(";/?:@&=+$,", c) < 0 {
			b.WriteByte(c)
		} else {
			b.WriteString(strings.ToUpper(s[i : i+3]))
		}
		i += 2
	}
	return b.String()
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c >= 'a':
		return c - 'a' + 10
	}
	return c - 'A' + 10
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
