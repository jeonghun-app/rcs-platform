package sdp

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
)

// Validate reports whether s can be serialized as a well-formed description:
// every value follows the syntax the parser enforces, at least one t= line is
// present and every media description has a connection (RFC 8866 §5.7).
func (s *Session) Validate() error {
	if err := s.Origin.validate(); err != nil {
		return fmt.Errorf("sdp: o=: %w", err)
	}
	if !isText(s.Name) {
		return errors.New(`sdp: s=: the session name must be non-empty without NUL, CR or LF; "-" means no name`)
	}
	if s.Information != "" && !isText(s.Information) {
		return errors.New("sdp: i=: value must not contain NUL, CR or LF")
	}
	if s.URI != "" && !isNonWS(s.URI) {
		return errors.New("sdp: u=: value must contain no spaces or control characters")
	}
	for _, e := range s.Emails {
		if !isText(e) {
			return errors.New("sdp: e=: value must be non-empty without NUL, CR or LF")
		}
	}
	for _, p := range s.Phones {
		if !isText(p) {
			return errors.New("sdp: p=: value must be non-empty without NUL, CR or LF")
		}
	}
	if s.Connection != nil {
		if err := s.Connection.validate(); err != nil {
			return fmt.Errorf("sdp: c=: %w", err)
		}
	}
	if err := validateBandwidths(s.Bandwidths); err != nil {
		return err
	}
	if len(s.Times) == 0 {
		return errors.New(`sdp: at least one "t=" line is required`)
	}
	for _, t := range s.Times {
		for _, r := range t.Repeats {
			if err := validateRepeat(r); err != nil {
				return fmt.Errorf("sdp: r=: %w", err)
			}
		}
	}
	if s.TimeZones != "" {
		if err := validateZones(s.TimeZones); err != nil {
			return fmt.Errorf("sdp: z=: %w", err)
		}
	}
	if s.Key != "" && !isText(s.Key) {
		return errors.New("sdp: k=: value must not contain NUL, CR or LF")
	}
	if err := validateAttributes(s.Attributes); err != nil {
		return err
	}
	for i := range s.Media {
		if err := s.Media[i].validate(s.Connection != nil); err != nil {
			return fmt.Errorf("sdp: media %d: %w", i, err)
		}
	}
	return nil
}

func (m *Media) validate(sessionConnection bool) error {
	if err := m.validateLine(); err != nil {
		return fmt.Errorf("m=: %w", err)
	}
	if m.Information != "" && !isText(m.Information) {
		return errors.New("i=: value must not contain NUL, CR or LF")
	}
	if len(m.Connections) == 0 && !sessionConnection {
		return errors.New(`no "c=" line here or at session level`)
	}
	for _, c := range m.Connections {
		if err := c.validate(); err != nil {
			return fmt.Errorf("c=: %w", err)
		}
	}
	if err := validateBandwidths(m.Bandwidths); err != nil {
		return err
	}
	if m.Key != "" && !isText(m.Key) {
		return errors.New("k=: value must not contain NUL, CR or LF")
	}
	return validateAttributes(m.Attributes)
}

func validateBandwidths(bs []Bandwidth) error {
	for _, b := range bs {
		if err := b.validate(); err != nil {
			return fmt.Errorf("b=: %w", err)
		}
	}
	return nil
}

func validateAttributes(as Attributes) error {
	for _, a := range as {
		if err := a.validate(); err != nil {
			return fmt.Errorf("a=%.32q: %w", a.Name, err)
		}
	}
	return nil
}

// Marshal serializes s with CRLF line endings after checking it with
// Validate, so a value that would break the line structure is an error
// rather than output.
func (s *Session) Marshal() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	line := func(typ byte, value string) {
		b.WriteByte(typ)
		b.WriteByte('=')
		b.WriteString(value)
		b.WriteString("\r\n")
	}
	optional := func(typ byte, value string) {
		if value != "" {
			line(typ, value)
		}
	}
	line('v', "0")
	line('o', s.Origin.String())
	line('s', s.Name)
	optional('i', s.Information)
	optional('u', s.URI)
	for _, e := range s.Emails {
		line('e', e)
	}
	for _, p := range s.Phones {
		line('p', p)
	}
	if s.Connection != nil {
		line('c', s.Connection.String())
	}
	for _, bw := range s.Bandwidths {
		line('b', bw.String())
	}
	for _, t := range s.Times {
		line('t', strconv.FormatUint(t.Start, 10)+" "+strconv.FormatUint(t.Stop, 10))
		for _, r := range t.Repeats {
			line('r', r)
		}
	}
	optional('z', s.TimeZones)
	optional('k', s.Key)
	for _, a := range s.Attributes {
		line('a', a.String())
	}
	for i := range s.Media {
		m := &s.Media[i]
		line('m', m.line())
		optional('i', m.Information)
		for _, c := range m.Connections {
			line('c', c.String())
		}
		for _, bw := range m.Bandwidths {
			line('b', bw.String())
		}
		optional('k', m.Key)
		for _, a := range m.Attributes {
			line('a', a.String())
		}
	}
	return b.Bytes(), nil
}
