package sdp

import (
	"errors"
	"strconv"
	"strings"
)

// Each line type has a parse function that turns the text after "=" into a
// value and a validate function that checks a value, whether parsed or built
// by a caller. Field separators are single spaces: RFC 8866 §9 has no notion
// of runs of whitespace, so "IN  IP4" is malformed rather than tolerated.

func parseOrigin(v string) (Origin, error) {
	f := strings.Split(v, " ")
	if len(f) != 6 {
		return Origin{}, errors.New("want <username> <sess-id> <sess-version> <nettype> <addrtype> <address>")
	}
	o := Origin{Username: f[0], SessionID: f[1], SessionVersion: f[2], NetType: f[3], AddrType: f[4], Address: f[5]}
	return o, o.validate()
}

func (o Origin) validate() error {
	switch {
	case !isNonWS(o.Username):
		return errors.New("username must be a non-empty string without spaces")
	case !isDigits(o.SessionID):
		return errors.New("session id must be decimal digits")
	case !isDigits(o.SessionVersion):
		return errors.New("session version must be decimal digits")
	case !isToken(o.NetType):
		return errors.New("network type must be a token")
	case !isToken(o.AddrType):
		return errors.New("address type must be a token")
	case !isNonWS(o.Address):
		return errors.New("address must be a non-empty string without spaces")
	}
	return nil
}

// String returns the o= value, without the "o=" prefix.
func (o Origin) String() string {
	return strings.Join([]string{o.Username, o.SessionID, o.SessionVersion, o.NetType, o.AddrType, o.Address}, " ")
}

func parseConnection(v string) (Connection, error) {
	f := strings.Split(v, " ")
	if len(f) != 3 {
		return Connection{}, errors.New("want <nettype> <addrtype> <connection-address>")
	}
	c := Connection{NetType: f[0], AddrType: f[1], Address: f[2]}
	return c, c.validate()
}

func (c Connection) validate() error {
	switch {
	case !isToken(c.NetType):
		return errors.New("network type must be a token")
	case !isToken(c.AddrType):
		return errors.New("address type must be a token")
	case !isNonWS(c.Address):
		return errors.New("address must be a non-empty string without spaces")
	}
	return nil
}

// String returns the c= value, without the "c=" prefix.
func (c Connection) String() string {
	return c.NetType + " " + c.AddrType + " " + c.Address
}

func parseBandwidth(v string) (Bandwidth, error) {
	typ, val, ok := strings.Cut(v, ":")
	if !ok {
		return Bandwidth{}, errors.New("want <bwtype>:<bandwidth>")
	}
	n, ok := parseUint(val)
	if !ok {
		return Bandwidth{}, errors.New("bandwidth must be decimal digits")
	}
	b := Bandwidth{Type: typ, Value: n}
	return b, b.validate()
}

func (b Bandwidth) validate() error {
	if !isToken(b.Type) {
		return errors.New("bandwidth type must be a token")
	}
	return nil
}

// String returns the b= value, without the "b=" prefix.
func (b Bandwidth) String() string {
	return b.Type + ":" + strconv.FormatUint(b.Value, 10)
}

func parseTime(v string) (Time, error) {
	f := strings.Split(v, " ")
	if len(f) != 2 {
		return Time{}, errors.New("want <start-time> <stop-time>")
	}
	start, ok1 := parseUint(f[0])
	stop, ok2 := parseUint(f[1])
	if !ok1 || !ok2 {
		return Time{}, errors.New("start and stop time must be decimal digits")
	}
	return Time{Start: start, Stop: stop}, nil
}

// validateRepeat checks an r= value: a repeat interval that does not start
// with 0, an active duration and at least one offset (RFC 8866 §5.10).
func validateRepeat(v string) error {
	f := strings.Split(v, " ")
	if len(f) < 3 {
		return errors.New("want <repeat-interval> <active-duration> <offsets>")
	}
	if f[0] == "" || f[0][0] == '0' {
		return errors.New("repeat interval must be positive")
	}
	for _, t := range f {
		if !isTypedTime(t) {
			return errors.New("times must be digits with an optional d, h, m or s unit")
		}
	}
	return nil
}

// validateZones checks a z= value: pairs of an adjustment time and a signed
// typed-time offset (RFC 8866 §5.11).
func validateZones(v string) error {
	f := strings.Split(v, " ")
	if len(f)%2 != 0 {
		return errors.New("want pairs of <adjustment-time> <offset>")
	}
	for i := 0; i < len(f); i += 2 {
		if !isDigits(f[i]) || !isTypedTime(strings.TrimPrefix(f[i+1], "-")) {
			return errors.New("want pairs of <adjustment-time> <offset>")
		}
	}
	return nil
}

func parseAttribute(v string) (Attribute, error) {
	name, value, hasValue := strings.Cut(v, ":")
	if hasValue && value == "" {
		return Attribute{}, errors.New("attribute value after ':' must not be empty")
	}
	a := Attribute{Name: name, Value: value}
	return a, a.validate()
}

func (a Attribute) validate() error {
	if !isToken(a.Name) {
		return errors.New("attribute name must be a token")
	}
	if a.Value != "" && !isText(a.Value) {
		return errors.New("attribute value must not contain NUL, CR or LF")
	}
	return nil
}

// String returns the a= value, without the "a=" prefix.
func (a Attribute) String() string {
	if a.Value == "" {
		return a.Name
	}
	return a.Name + ":" + a.Value
}

// parseMediaLine parses the m= line itself; the lines that follow it are
// added by the parser.
func parseMediaLine(v string) (Media, error) {
	f := strings.Split(v, " ")
	if len(f) < 4 {
		return Media{}, errors.New("want <media> <port>[/<count>] <proto> <fmt> ...")
	}
	m := Media{Type: f[0], Proto: f[2], Formats: f[3:]}
	port, count, hasCount := strings.Cut(f[1], "/")
	p, ok := parseUint(port)
	if !ok || p > 65535 {
		return Media{}, errors.New("port must be a number from 0 to 65535")
	}
	m.Port = int(p)
	if hasCount {
		n, ok := parseUint(count)
		if !ok || n == 0 || n > 65535 {
			return Media{}, errors.New("number of ports must be a number from 1 to 65535")
		}
		m.PortCount = int(n)
	}
	return m, m.validateLine()
}

// validateLine checks the fields that make up the m= line.
func (m *Media) validateLine() error {
	switch {
	case !isToken(m.Type):
		return errors.New("media type must be a token")
	case m.Port < 0 || m.Port > 65535:
		return errors.New("port must be a number from 0 to 65535")
	case m.PortCount < 0 || m.PortCount > 65535:
		return errors.New("number of ports must be a number from 1 to 65535")
	case !isProto(m.Proto):
		return errors.New("protocol must be tokens separated by '/'")
	case len(m.Formats) == 0:
		return errors.New("at least one format is required")
	}
	for _, f := range m.Formats {
		if !isToken(f) {
			return errors.New("formats must be tokens")
		}
	}
	return nil
}

func (m *Media) line() string {
	var b strings.Builder
	b.WriteString(m.Type)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(m.Port))
	if m.PortCount > 0 {
		b.WriteByte('/')
		b.WriteString(strconv.Itoa(m.PortCount))
	}
	b.WriteByte(' ')
	b.WriteString(m.Proto)
	for _, f := range m.Formats {
		b.WriteByte(' ')
		b.WriteString(f)
	}
	return b.String()
}
