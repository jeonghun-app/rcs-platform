package sdp

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Transport protocols of an MSRP media line (RFC 4975 §8.1). The TLS form goes
// with msrps: URIs in a=path.
const (
	ProtoMSRP  = "TCP/MSRP"
	ProtoMSRPS = "TCP/TLS/MSRP"
)

// IsMSRP reports whether m is an MSRP media line: m=message over TCP/MSRP or
// TCP/TLS/MSRP.
func (m *Media) IsMSRP() bool {
	return strings.EqualFold(m.Type, "message") &&
		(strings.EqualFold(m.Proto, ProtoMSRP) || strings.EqualFold(m.Proto, ProtoMSRPS))
}

// Path returns the URIs of a=path. RFC 4975 §8.2 makes the attribute
// mandatory and singular; the leftmost URI is the one the peer connects to
// (RFC 4975 §8.3). URIs are only checked for an msrp: or msrps: scheme here;
// internal/msrp parses them.
func (m *Media) Path() ([]string, error) {
	v, err := m.Attributes.singleValue("path")
	if err != nil {
		return nil, err
	}
	uris := strings.Split(v, " ")
	if err := validatePath(uris); err != nil {
		return nil, err
	}
	return uris, nil
}

// SetPath replaces a=path, or appends it when absent.
func (m *Media) SetPath(uris []string) error {
	if err := validatePath(uris); err != nil {
		return err
	}
	m.Attributes.Set("path", strings.Join(uris, " "))
	return nil
}

func validatePath(uris []string) error {
	if len(uris) == 0 {
		return errors.New("sdp: a=path: at least one URI is required")
	}
	for _, u := range uris {
		if _, ok := msrpScheme(u); !ok {
			return fmt.Errorf("sdp: a=path: %.64q is not an msrp: or msrps: URI", u)
		}
	}
	return nil
}

// msrpScheme reports whether uri is an msrp: or msrps: URI, and which.
func msrpScheme(uri string) (secure, ok bool) {
	if !isNonWS(uri) {
		return false, false
	}
	scheme, rest, found := strings.Cut(uri, "://")
	switch {
	case !found || rest == "":
		return false, false
	case strings.EqualFold(scheme, "msrp"):
		return false, true
	case strings.EqualFold(scheme, "msrps"):
		return true, true
	}
	return false, false
}

// AcceptTypes returns a=accept-types, which RFC 4975 §8.6 requires on every
// MSRP media line. Entries are media types, type/* ranges or "*".
func (m *Media) AcceptTypes() ([]string, error) {
	return mediaTypeList(m.Attributes, "accept-types")
}

// SetAcceptTypes replaces a=accept-types, or appends it when absent.
func (m *Media) SetAcceptTypes(types []string) error {
	if len(types) == 0 {
		return errors.New("sdp: a=accept-types: at least one type is required")
	}
	if err := validateMediaTypes("accept-types", types); err != nil {
		return err
	}
	m.Attributes.Set("accept-types", strings.Join(types, " "))
	return nil
}

// AcceptWrappedTypes returns a=accept-wrapped-types (RFC 4975 §8.6): the types
// accepted only inside a wrapper such as message/cpim.
func (m *Media) AcceptWrappedTypes() ([]string, error) {
	return mediaTypeList(m.Attributes, "accept-wrapped-types")
}

// SetAcceptWrappedTypes replaces a=accept-wrapped-types, or appends it when
// absent. An empty list removes the attribute.
func (m *Media) SetAcceptWrappedTypes(types []string) error {
	if len(types) == 0 {
		m.Attributes.Remove("accept-wrapped-types")
		return nil
	}
	if err := validateMediaTypes("accept-wrapped-types", types); err != nil {
		return err
	}
	m.Attributes.Set("accept-wrapped-types", strings.Join(types, " "))
	return nil
}

func mediaTypeList(as Attributes, name string) ([]string, error) {
	v, err := as.singleValue(name)
	if err != nil {
		return nil, err
	}
	types := strings.Split(v, " ")
	if err := validateMediaTypes(name, types); err != nil {
		return nil, err
	}
	return types, nil
}

func validateMediaTypes(name string, types []string) error {
	for _, t := range types {
		if !isMediaRange(t) {
			return fmt.Errorf("sdp: a=%s: %.64q is not a media type, type/* or *", name, t)
		}
	}
	return nil
}

// isMediaRange reports whether s is "*", type/* or type/subtype, the entries
// RFC 4975 §9 allows in accept-types. Parameters are not allowed there.
func isMediaRange(s string) bool {
	if s == "*" {
		return true
	}
	typ, sub, ok := strings.Cut(s, "/")
	return ok && isToken(typ) && isToken(sub)
}

// MaxSize returns a=max-size, the largest message the endpoint is willing to
// receive (RFC 4975 §8.6).
func (m *Media) MaxSize() (int64, error) {
	v, err := m.Attributes.singleValue("max-size")
	if err != nil {
		return 0, err
	}
	n, ok := parseInt64(v)
	if !ok {
		return 0, fmt.Errorf("sdp: a=max-size: %.32q is not a size in bytes", v)
	}
	return n, nil
}

// SetMaxSize replaces a=max-size, or appends it when absent.
func (m *Media) SetMaxSize(n int64) error {
	if n < 0 {
		return errors.New("sdp: a=max-size: size must not be negative")
	}
	m.Attributes.Set("max-size", strconv.FormatInt(n, 10))
	return nil
}

// Setup is the a=setup role (RFC 4145 §4), which RFC 6135 §4 applies to MSRP
// to say which endpoint opens the TCP connection.
type Setup string

// Setup roles.
const (
	SetupActive  Setup = "active"  // opens the connection
	SetupPassive Setup = "passive" // accepts the connection
	SetupActPass Setup = "actpass" // either; the answerer decides
	// SetupHoldConn is recognised when read but never written: RFC 6135
	// §4.2.1 forbids it in MSRP and has a receiver treat it as if a=setup
	// were absent, which MediaSetup does.
	SetupHoldConn Setup = "holdconn"
)

func parseSetup(v string) (Setup, error) {
	for _, r := range []Setup{SetupActive, SetupPassive, SetupActPass, SetupHoldConn} {
		if strings.EqualFold(v, string(r)) {
			return r, nil
		}
	}
	return "", fmt.Errorf("sdp: a=setup: unknown role %.32q", v)
}

// Setup returns the media-level a=setup role as written, in lower case,
// holdconn included. Use Session.MediaSetup for the role that applies.
func (m *Media) Setup() (Setup, error) {
	return setupOf(m.Attributes)
}

func setupOf(as Attributes) (Setup, error) {
	v, err := as.singleValue("setup")
	if err != nil {
		return "", err
	}
	return parseSetup(v)
}

// SetSetup replaces a=setup, or appends it when absent. holdconn is refused
// (RFC 6135 §4.2.1).
func (m *Media) SetSetup(r Setup) error {
	canonical, err := parseWritableSetup(r)
	if err != nil {
		return err
	}
	m.Attributes.Set("setup", string(canonical))
	return nil
}

// parseWritableSetup is parseSetup without holdconn, for values this package
// is asked to put on the wire.
func parseWritableSetup(r Setup) (Setup, error) {
	canonical, err := parseSetup(string(r))
	if err == nil && canonical == SetupHoldConn {
		err = errors.New("sdp: a=setup: holdconn must not be sent in MSRP (RFC 6135 §4.2.1)")
	}
	return canonical, err
}

// MediaSetup returns the a=setup role that applies to media line i: its own,
// or the session-level one, which RFC 4145 §4 also allows. A holdconn value
// is ignored at either level, as RFC 6135 §4.2.1 requires of an MSRP
// receiver, so the result is never holdconn. ErrNoAttribute means no role
// applies; RFC 4975 §8.5 then makes the offerer the active party.
func (s *Session) MediaSetup(i int) (Setup, error) {
	m, err := s.media(i)
	if err != nil {
		return "", err
	}
	r, err := m.Setup()
	if errors.Is(err, ErrNoAttribute) || r == SetupHoldConn {
		r, err = setupOf(s.Attributes)
	}
	if err == nil && r == SetupHoldConn {
		return "", fmt.Errorf("%w: a=setup (holdconn is ignored)", ErrNoAttribute)
	}
	return r, err
}

// TCPConnection is the a=connection value (RFC 4145 §5).
type TCPConnection string

// TCPConnection values.
const (
	ConnectionNew      TCPConnection = "new"
	ConnectionExisting TCPConnection = "existing"
)

// TCPConnection returns a=connection, in lower case.
func (m *Media) TCPConnection() (TCPConnection, error) {
	v, err := m.Attributes.singleValue("connection")
	if err != nil {
		return "", err
	}
	for _, c := range []TCPConnection{ConnectionNew, ConnectionExisting} {
		if strings.EqualFold(v, string(c)) {
			return c, nil
		}
	}
	return "", fmt.Errorf("sdp: a=connection: unknown value %.32q", v)
}

// Direction is a media direction attribute (RFC 8866 §6.7).
type Direction string

// Directions.
const (
	SendRecv Direction = "sendrecv"
	SendOnly Direction = "sendonly"
	RecvOnly Direction = "recvonly"
	Inactive Direction = "inactive"
)

func parseDirection(name string) (Direction, bool) {
	for _, d := range []Direction{SendRecv, SendOnly, RecvOnly, Inactive} {
		if strings.EqualFold(name, string(d)) {
			return d, true
		}
	}
	return "", false
}

func isDirection(a Attribute) bool {
	_, ok := parseDirection(a.Name)
	return ok
}

// Direction returns the media-level direction attribute. More than one, or
// one with a value, is an error: the four are mutually exclusive properties.
func (m *Media) Direction() (Direction, error) {
	return directionOf(m.Attributes)
}

func directionOf(as Attributes) (Direction, error) {
	var found Direction
	for _, a := range as {
		d, ok := parseDirection(a.Name)
		if !ok {
			continue
		}
		if a.Value != "" {
			return "", fmt.Errorf("sdp: a=%s: takes no value", d)
		}
		if found != "" {
			return "", fmt.Errorf("sdp: more than one direction attribute (%s, %s)", found, d)
		}
		found = d
	}
	if found == "" {
		return "", fmt.Errorf("%w: direction", ErrNoAttribute)
	}
	return found, nil
}

// SetDirection replaces the direction attribute where it stands, or appends
// one when there is none.
func (m *Media) SetDirection(d Direction) error {
	canonical, ok := parseDirection(string(d))
	if !ok {
		return fmt.Errorf("sdp: unknown direction %.32q", d)
	}
	m.Attributes.replace(isDirection, Attribute{Name: string(canonical)})
	return nil
}

// MediaDirection returns the direction that applies to media line i: its
// own attribute, else the session-level one, else sendrecv (RFC 8866 §6.7,
// RFC 3264 §5.1).
func (s *Session) MediaDirection(i int) (Direction, error) {
	m, err := s.media(i)
	if err != nil {
		return "", err
	}
	d, err := m.Direction()
	if errors.Is(err, ErrNoAttribute) {
		d, err = directionOf(s.Attributes)
	}
	if errors.Is(err, ErrNoAttribute) {
		return SendRecv, nil
	}
	return d, err
}

func (s *Session) media(i int) (*Media, error) {
	if i < 0 || i >= len(s.Media) {
		return nil, fmt.Errorf("sdp: no media description %d", i)
	}
	return &s.Media[i], nil
}
