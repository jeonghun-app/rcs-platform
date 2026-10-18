// Package conference reads, writes and merges conference-info documents
// (RFC 4575), which an RCS group chat focus sends in NOTIFY requests to tell
// participants who is in the chat and how each of them is connected.
//
// The model covers what group chat uses: the conference URI, version and
// state; the description's display text and subject; and per user the entity,
// display text, roles and endpoints with their status, joining method and
// disconnection method. Other elements are skipped when parsing, and Marshal
// writes only the modelled ones.
//
// A focus sends a full document first and partial ones afterwards. Merge
// applies a document to the local state with the RFC 4575 §4.6 procedure, so a
// client simulator can keep the same roster a real client would.
//
// Documents are decoded with encoding/xml behind a size limit, a nesting limit
// and a refusal of any document type declaration.
package conference

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// ContentType is the MIME type of a conference-info document (RFC 4575 §9.2).
const ContentType = "application/conference-info+xml"

// Namespace is the XML namespace of conference-info documents (RFC 4575
// §4.2).
const Namespace = "urn:ietf:params:xml:ns:conference-info"

// ErrMalformed reports a document outside RFC 4575.
var ErrMalformed = errors.New("conference: malformed document")

// State says whether an element carries everything about itself, only what
// changed, or that it was removed (RFC 4575 §4.4). An empty State means Full,
// the schema default.
type State string

// The states RFC 4575 §4.4 defines.
const (
	Full    State = "full"
	Partial State = "partial"
	Deleted State = "deleted"
)

func (s State) orFull() State {
	if s == "" {
		return Full
	}
	return s
}

func (s State) valid() bool {
	return s == "" || s == Full || s == Partial || s == Deleted
}

// EndpointStatus is the <status> of an endpoint (RFC 4575 §5.7.3).
type EndpointStatus string

// The endpoint statuses RFC 4575 §5.7.3 defines.
const (
	Pending       EndpointStatus = "pending"
	DialingOut    EndpointStatus = "dialing-out"
	DialingIn     EndpointStatus = "dialing-in"
	Alerting      EndpointStatus = "alerting"
	OnHold        EndpointStatus = "on-hold"
	Connected     EndpointStatus = "connected"
	MutedViaFocus EndpointStatus = "muted-via-focus"
	Disconnecting EndpointStatus = "disconnecting"
	Disconnected  EndpointStatus = "disconnected"
)

var endpointStatuses = []EndpointStatus{Pending, DialingOut, DialingIn, Alerting, OnHold, Connected, MutedViaFocus, Disconnecting, Disconnected}

// JoiningMethod is how an endpoint joined (RFC 4575 §5.7.4).
type JoiningMethod string

// The joining methods RFC 4575 §5.7.4 defines.
const (
	DialedIn   JoiningMethod = "dialed-in"
	DialedOut  JoiningMethod = "dialed-out"
	FocusOwner JoiningMethod = "focus-owner"
)

var joiningMethods = []JoiningMethod{DialedIn, DialedOut, FocusOwner}

// DisconnectionMethod is how an endpoint left (RFC 4575 §5.7.6); group chat
// tells a participant who left from one who was removed this way.
type DisconnectionMethod string

// The disconnection methods RFC 4575 §5.7.6 defines.
const (
	Departed DisconnectionMethod = "departed"
	Booted   DisconnectionMethod = "booted"
	Failed   DisconnectionMethod = "failed"
	Busy     DisconnectionMethod = "busy"
)

var disconnectionMethods = []DisconnectionMethod{Departed, Booted, Failed, Busy}

// Info is a <conference-info> document, or the merged state of a
// conference that Merge maintains.
type Info struct {
	// Entity is the conference URI (RFC 4575 §5.2).
	Entity string
	State  State
	// Version orders the documents of one subscription (RFC 4575 §4.3).
	Version uint32
	// Description is nil when the document has no <conference-description>.
	Description *Description
	// Users is nil when the document has no <users>.
	Users *Users
}

// Description is a <conference-description> (RFC 4575 §5.3). An empty field
// is an absent element.
type Description struct {
	DisplayText string
	Subject     string
}

// Users is the <users> element (RFC 4575 §5.6), which has a state of its
// own: in a partial document, <users> without state="partial" replaces the
// whole roster.
type Users struct {
	State State
	List  []User
}

// User is a <user> (RFC 4575 §5.6), keyed by Entity (§4.5). An empty
// DisplayText and an empty Roles are absent elements; RFC 4575 gives neither an
// empty meaning.
type User struct {
	Entity      string
	State       State
	DisplayText string
	// Roles are the <roles> entries, for example "participant".
	Roles     []string
	Endpoints []Endpoint
}

// Endpoint is an <endpoint> (RFC 4575 §5.7), keyed by Entity within its user
// (§4.5). An empty field is an absent element.
type Endpoint struct {
	Entity              string
	State               State
	DisplayText         string
	Status              EndpointStatus
	JoiningMethod       JoiningMethod
	DisconnectionMethod DisconnectionMethod
}

// Parse parses an application/conference-info+xml document. States are made
// explicit, so an element without a state attribute comes back as Full, and
// the content of a deleted element is dropped, as RFC 4575 §4.4 tells a
// subscriber to ignore it.
func Parse(data []byte) (*Info, error) {
	if err := checkDocument(data); err != nil {
		return nil, err
	}
	var w wireInfo
	if err := xml.NewDecoder(bytes.NewReader(data)).Decode(&w); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
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

// Marshal serializes c in the element order of the RFC 4575 §6 schema, with
// every state attribute written out.
func (c *Info) Marshal() ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(xml.Header)
	w := &xmlWriter{e: xml.NewEncoder(&b)}
	// The namespace is declared once on the root; encoding/xml would repeat
	// it on every element if the names carried it.
	w.start("conference-info",
		xml.Attr{Name: xml.Name{Local: "xmlns"}, Value: Namespace},
		attr("entity", c.Entity),
		attr("state", string(c.State.orFull())),
		attr("version", strconv.FormatUint(uint64(c.Version), 10)))
	if d := c.Description; d != nil {
		w.start("conference-description")
		optionalText(w, "display-text", d.DisplayText)
		optionalText(w, "subject", d.Subject)
		w.end("conference-description")
	}
	if c.Users != nil {
		w.start("users", attr("state", string(c.Users.State.orFull())))
		for _, u := range c.Users.List {
			writeUser(w, u)
		}
		w.end("users")
	}
	w.end("conference-info")
	if err := w.close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeUser(w *xmlWriter, u User) {
	w.start("user", attr("entity", u.Entity), attr("state", string(u.State.orFull())))
	optionalText(w, "display-text", u.DisplayText)
	if len(u.Roles) > 0 {
		w.start("roles")
		for _, r := range u.Roles {
			w.text("entry", r)
		}
		w.end("roles")
	}
	for _, e := range u.Endpoints {
		w.start("endpoint", attr("entity", e.Entity), attr("state", string(e.State.orFull())))
		optionalText(w, "display-text", e.DisplayText)
		optionalText(w, "status", string(e.Status))
		optionalText(w, "joining-method", string(e.JoiningMethod))
		optionalText(w, "disconnection-method", string(e.DisconnectionMethod))
		w.end("endpoint")
	}
	w.end("user")
}

func attr(name, value string) xml.Attr {
	return xml.Attr{Name: xml.Name{Local: name}, Value: value}
}

func optionalText(w *xmlWriter, name, value string) {
	if value != "" {
		w.text(name, value)
	}
}

// validate checks the rules Parse and Marshal share. Marshal is stricter than
// what Parse tolerates on input only in that a deleted element must be empty,
// which Parse guarantees by dropping the content.
func (c *Info) validate() error {
	if !isURIText(c.Entity) || c.Entity == "" {
		return fmt.Errorf("%w: conference entity missing or not a URI", ErrMalformed)
	}
	if !c.State.valid() {
		return fmt.Errorf("%w: invalid conference state", ErrMalformed)
	}
	switch c.State.orFull() {
	case Full:
		// §5.2: a full document has at least these two elements.
		if c.Description == nil || c.Users == nil {
			return fmt.Errorf("%w: full document without conference-description and users", ErrMalformed)
		}
	case Deleted:
		if c.Description != nil || c.Users != nil {
			return fmt.Errorf("%w: deleted conference with content", ErrMalformed)
		}
	}
	if d := c.Description; d != nil && (!isXMLText(d.DisplayText) || !isXMLText(d.Subject)) {
		return fmt.Errorf("%w: description contains characters XML cannot carry", ErrMalformed)
	}
	if c.Users != nil {
		return c.Users.validate(c.State.orFull())
	}
	return nil
}

// validate checks the users against their parent's state: below a full
// element everything is full (RFC 4575 §4.4).
func (us *Users) validate(parent State) error {
	if err := childState(parent, us.State); err != nil {
		return err
	}
	if us.State.orFull() == Deleted && len(us.List) > 0 {
		return fmt.Errorf("%w: deleted users element with content", ErrMalformed)
	}
	seen := make(map[string]bool, len(us.List))
	for _, u := range us.List {
		if seen[u.Entity] {
			return fmt.Errorf("%w: user entity repeated", ErrMalformed)
		}
		seen[u.Entity] = true
		if err := u.validate(us.State.orFull()); err != nil {
			return err
		}
	}
	return nil
}

func (u *User) validate(parent State) error {
	if !isURIText(u.Entity) || u.Entity == "" {
		return fmt.Errorf("%w: user entity missing or not a URI", ErrMalformed)
	}
	if err := childState(parent, u.State); err != nil {
		return err
	}
	if u.State.orFull() == Deleted && (u.DisplayText != "" || len(u.Roles) > 0 || len(u.Endpoints) > 0) {
		return fmt.Errorf("%w: deleted user with content", ErrMalformed)
	}
	if !isXMLText(u.DisplayText) {
		return fmt.Errorf("%w: user display text contains characters XML cannot carry", ErrMalformed)
	}
	for _, r := range u.Roles {
		if !isXMLText(r) {
			return fmt.Errorf("%w: role contains characters XML cannot carry", ErrMalformed)
		}
	}
	seen := make(map[string]bool, len(u.Endpoints))
	for _, e := range u.Endpoints {
		if seen[e.Entity] {
			return fmt.Errorf("%w: endpoint entity repeated within a user", ErrMalformed)
		}
		seen[e.Entity] = true
		if err := e.validate(u.State.orFull()); err != nil {
			return err
		}
	}
	return nil
}

func (e *Endpoint) validate(parent State) error {
	// The endpoint entity is an xs:string rather than a URI (RFC 4575 §6).
	if e.Entity == "" || !isXMLText(e.Entity) {
		return fmt.Errorf("%w: endpoint entity missing or invalid", ErrMalformed)
	}
	if err := childState(parent, e.State); err != nil {
		return err
	}
	if e.State.orFull() == Deleted && (e.DisplayText != "" || e.Status != "" || e.JoiningMethod != "" || e.DisconnectionMethod != "") {
		return fmt.Errorf("%w: deleted endpoint with content", ErrMalformed)
	}
	switch {
	case !isXMLText(e.DisplayText):
		return fmt.Errorf("%w: endpoint display text contains characters XML cannot carry", ErrMalformed)
	case e.Status != "" && !slices.Contains(endpointStatuses, e.Status):
		return fmt.Errorf("%w: unknown endpoint status", ErrMalformed)
	case e.JoiningMethod != "" && !slices.Contains(joiningMethods, e.JoiningMethod):
		return fmt.Errorf("%w: unknown joining method", ErrMalformed)
	case e.DisconnectionMethod != "" && !slices.Contains(disconnectionMethods, e.DisconnectionMethod):
		return fmt.Errorf("%w: unknown disconnection method", ErrMalformed)
	}
	return nil
}

// childState applies RFC 4575 §4.4: a child of a full element is full.
func childState(parent, child State) error {
	if !child.valid() {
		return fmt.Errorf("%w: invalid state", ErrMalformed)
	}
	if parent == Full && child.orFull() != Full {
		return fmt.Errorf("%w: %s element inside a full one", ErrMalformed, child)
	}
	return nil
}

// isURIText reports whether s can be an anyURI value that survives a round
// trip unchanged.
func isURIText(s string) bool {
	return isXMLText(s) && !strings.ContainsAny(s, " \t\r\n")
}
