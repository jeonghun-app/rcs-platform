package conference

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
)

// The wire types decode with namespace-qualified names, so an extension
// element sharing a local name is never mistaken for a conference-info one.
// Single-valued elements are slices so a duplicate is detected rather than
// silently overwritten, and required attributes are pointers so a missing one
// is told from an empty one.
type wireInfo struct {
	XMLName     xml.Name          `xml:"urn:ietf:params:xml:ns:conference-info conference-info"`
	Entity      *string           `xml:"entity,attr"`
	State       string            `xml:"state,attr"`
	Version     *string           `xml:"version,attr"`
	Description []wireDescription `xml:"urn:ietf:params:xml:ns:conference-info conference-description"`
	Users       []wireUsers       `xml:"urn:ietf:params:xml:ns:conference-info users"`
}

type wireDescription struct {
	DisplayText []string `xml:"urn:ietf:params:xml:ns:conference-info display-text"`
	Subject     []string `xml:"urn:ietf:params:xml:ns:conference-info subject"`
}

type wireUsers struct {
	State string     `xml:"state,attr"`
	User  []wireUser `xml:"urn:ietf:params:xml:ns:conference-info user"`
}

type wireUser struct {
	Entity      *string        `xml:"entity,attr"`
	State       string         `xml:"state,attr"`
	DisplayText []string       `xml:"urn:ietf:params:xml:ns:conference-info display-text"`
	Roles       []wireRoles    `xml:"urn:ietf:params:xml:ns:conference-info roles"`
	Endpoint    []wireEndpoint `xml:"urn:ietf:params:xml:ns:conference-info endpoint"`
}

type wireRoles struct {
	Entry []string `xml:"urn:ietf:params:xml:ns:conference-info entry"`
}

type wireEndpoint struct {
	Entity              *string  `xml:"entity,attr"`
	State               string   `xml:"state,attr"`
	DisplayText         []string `xml:"urn:ietf:params:xml:ns:conference-info display-text"`
	Status              []string `xml:"urn:ietf:params:xml:ns:conference-info status"`
	JoiningMethod       []string `xml:"urn:ietf:params:xml:ns:conference-info joining-method"`
	DisconnectionMethod []string `xml:"urn:ietf:params:xml:ns:conference-info disconnection-method"`
}

// parseState reads a state attribute. The enumeration is an xs:string, whose
// white space is significant, so " full" is not "full".
func parseState(s string) (State, error) {
	st := State(s)
	if !st.valid() {
		return "", fmt.Errorf("%w: invalid state attribute", ErrMalformed)
	}
	return st.orFull(), nil
}

func (w *wireInfo) info() (*Info, error) {
	if w.Entity == nil {
		return nil, fmt.Errorf("%w: conference-info without entity", ErrMalformed)
	}
	// §4.3: version is mandatory on the root even though the schema marks
	// it optional.
	if w.Version == nil {
		return nil, fmt.Errorf("%w: conference-info without version", ErrMalformed)
	}
	version, err := strconv.ParseUint(strings.TrimSpace(*w.Version), 10, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: version is not a 32-bit unsigned integer", ErrMalformed)
	}
	state, err := parseState(w.State)
	if err != nil {
		return nil, err
	}
	c := &Info{Entity: strings.TrimSpace(*w.Entity), State: state, Version: uint32(version)}
	if state == Deleted {
		return c, nil
	}

	switch len(w.Description) {
	case 0:
	case 1:
		d := &Description{}
		if d.DisplayText, err = one("display-text", w.Description[0].DisplayText); err != nil {
			return nil, err
		}
		if d.Subject, err = one("subject", w.Description[0].Subject); err != nil {
			return nil, err
		}
		c.Description = d
	default:
		return nil, fmt.Errorf("%w: more than one <conference-description>", ErrMalformed)
	}

	switch len(w.Users) {
	case 0:
	case 1:
		if c.Users, err = w.Users[0].users(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: more than one <users>", ErrMalformed)
	}
	return c, nil
}

func (w *wireUsers) users() (*Users, error) {
	state, err := parseState(w.State)
	if err != nil {
		return nil, err
	}
	us := &Users{State: state}
	if state == Deleted {
		return us, nil
	}
	for _, wu := range w.User {
		u, err := wu.user()
		if err != nil {
			return nil, err
		}
		us.List = append(us.List, u)
	}
	return us, nil
}

func (w *wireUser) user() (User, error) {
	if w.Entity == nil {
		return User{}, fmt.Errorf("%w: user without entity", ErrMalformed)
	}
	state, err := parseState(w.State)
	if err != nil {
		return User{}, err
	}
	u := User{Entity: strings.TrimSpace(*w.Entity), State: state}
	if state == Deleted {
		return u, nil
	}
	if u.DisplayText, err = one("display-text", w.DisplayText); err != nil {
		return User{}, err
	}
	switch len(w.Roles) {
	case 0:
	case 1:
		// user-roles-type needs at least one entry (RFC 4575 §6).
		if len(w.Roles[0].Entry) == 0 {
			return User{}, fmt.Errorf("%w: <roles> without an entry", ErrMalformed)
		}
		u.Roles = w.Roles[0].Entry
	default:
		return User{}, fmt.Errorf("%w: more than one <roles>", ErrMalformed)
	}
	for _, we := range w.Endpoint {
		e, err := we.endpoint()
		if err != nil {
			return User{}, err
		}
		u.Endpoints = append(u.Endpoints, e)
	}
	return u, nil
}

func (w *wireEndpoint) endpoint() (Endpoint, error) {
	if w.Entity == nil {
		return Endpoint{}, fmt.Errorf("%w: endpoint without entity", ErrMalformed)
	}
	state, err := parseState(w.State)
	if err != nil {
		return Endpoint{}, err
	}
	e := Endpoint{Entity: *w.Entity, State: state}
	if state == Deleted {
		return e, nil
	}
	var status, joining, disconnection string
	if e.DisplayText, err = one("display-text", w.DisplayText); err != nil {
		return Endpoint{}, err
	}
	if status, err = one("status", w.Status); err != nil {
		return Endpoint{}, err
	}
	if joining, err = one("joining-method", w.JoiningMethod); err != nil {
		return Endpoint{}, err
	}
	if disconnection, err = one("disconnection-method", w.DisconnectionMethod); err != nil {
		return Endpoint{}, err
	}
	e.Status = EndpointStatus(status)
	e.JoiningMethod = JoiningMethod(joining)
	e.DisconnectionMethod = DisconnectionMethod(disconnection)
	return e, nil
}

// one returns the value of an element that may appear at most once.
func one(name string, values []string) (string, error) {
	switch len(values) {
	case 0:
		return "", nil
	case 1:
		return values[0], nil
	}
	return "", fmt.Errorf("%w: more than one <%s>", ErrMalformed, name)
}
