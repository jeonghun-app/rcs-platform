package sdp

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// MSRPRewrite is what pcscf substitutes into an MSRP media line so that the
// far end connects to, or is connected from, msrp-relay instead of the party
// that wrote the description (ADR 0004).
type MSRPRewrite struct {
	Connection Connection
	Port       int
	// Path replaces a=path. The m= transport is set to match the scheme of
	// its first URI, since the relay may use TLS on one side and TCP on the
	// other.
	Path []string
	// Setup is the role written to a=setup: active, passive or actpass;
	// holdconn is refused (RFC 6135 §4.2.1).
	Setup Setup
	// Answer says the description being rewritten is an SDP answer. An offer
	// must not carry a=setup:passive (RFC 6135 §4.2.2), so passive is refused
	// unless Answer is set. The zero value is the strict one: forgetting to
	// set it on an answer fails loudly instead of producing a bad offer.
	Answer bool
}

// RewriteMSRP applies rw to media line i. Only the c= that applies to the line,
// the m= port and transport, a=path and a=setup change; a=path and a=setup
// keep their position among the other attributes and every other media line
// is left as it was. Everything is checked before anything changes, so on
// error s is untouched.
//
// A line offered with port 0 is refused with ErrMediaDisabled: there is
// nothing to anchor, and the line passes through as it is.
func (s *Session) RewriteMSRP(i int, rw MSRPRewrite) error {
	m, err := s.media(i)
	if err != nil {
		return err
	}
	if !m.IsMSRP() {
		return ErrNotMSRP
	}
	if m.Port == 0 {
		return ErrMediaDisabled
	}
	if _, err := m.Path(); err != nil {
		return err
	}
	if err := rw.Connection.validate(); err != nil {
		return fmt.Errorf("sdp: rewrite: c=: %w", err)
	}
	if rw.Port < 1 || rw.Port > 65535 {
		return errors.New("sdp: rewrite: port must be from 1 to 65535")
	}
	if err := validatePath(rw.Path); err != nil {
		return err
	}
	setup, err := parseWritableSetup(rw.Setup)
	if err != nil {
		return err
	}
	if setup == SetupPassive && !rw.Answer {
		return errors.New("sdp: rewrite: an offer must not use a=setup:passive (RFC 6135 §4.2.2)")
	}

	s.setMediaConnection(i, rw.Connection)
	m.Port = rw.Port
	m.Proto = ProtoMSRP
	if secure, _ := msrpScheme(rw.Path[0]); secure {
		m.Proto = ProtoMSRPS
	}
	m.Attributes.Set("path", strings.Join(rw.Path, " "))
	m.Attributes.Set("setup", string(setup))
	return nil
}

// SetMediaConnection makes c the connection that applies to media line i
// without changing the connection of any other line.
//
// A line with its own c= lines gets c in their place. A line that inherits
// the session-level c= gets c written there when no other line inherits it,
// so the replaced address does not linger in the description where the far
// end can still read it; when other lines inherit it too, the line gets a
// media-level c= of its own instead (RFC 8866 §5.7).
func (s *Session) SetMediaConnection(i int, c Connection) error {
	if _, err := s.media(i); err != nil {
		return err
	}
	if err := c.validate(); err != nil {
		return fmt.Errorf("sdp: c=: %w", err)
	}
	s.setMediaConnection(i, c)
	return nil
}

func (s *Session) setMediaConnection(i int, c Connection) {
	m := &s.Media[i]
	if len(m.Connections) == 0 && s.Connection != nil && !s.othersInheritConnection(i) {
		s.Connection = &c
		return
	}
	m.Connections = []Connection{c}
}

func (s *Session) othersInheritConnection(i int) bool {
	return slices.ContainsFunc(s.Media[:i], noOwnConnection) || slices.ContainsFunc(s.Media[i+1:], noOwnConnection)
}

func noOwnConnection(m Media) bool { return len(m.Connections) == 0 }
