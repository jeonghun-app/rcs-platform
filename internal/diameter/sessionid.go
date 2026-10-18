package diameter

import (
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// SessionIDGenerator produces Session-Id values in the RFC 6733 §8.8 form
// `<DiameterIdentity>;<high 32 bits>;<low 32 bits>[;<optional value>]`, where
// high and low are the halves of a 64-bit counter.
//
// The counter starts with the NTP time of start-up in its high half and zero in
// its low half, as §8.8 suggests, so a restarted node with the same identity
// does not reuse an earlier session's identifier. Under ADR 0005 each instance
// has its own Origin-Host, which makes the identifiers unique across
// instances. It is safe for concurrent use.
type SessionIDGenerator struct {
	host string
	next atomic.Uint64
}

// NewSessionIDGenerator returns a generator for the node identity host,
// seeded from start (normally the node's start-up time).
func NewSessionIDGenerator(host string, start time.Time) *SessionIDGenerator {
	g := &SessionIDGenerator{host: host}
	g.next.Store(uint64(uint32(start.Unix()+ntpUnixOffset)) << 32)
	return g
}

// Next returns a new Session-Id. A non-empty optional value is appended as the
// fourth part; it must not carry subscriber identities, because a Session-Id
// travels to every Diameter node on the path and may be logged there.
func (g *SessionIDGenerator) Next(optional string) string {
	v := g.next.Add(1) - 1
	var b strings.Builder
	b.Grow(len(g.host) + 22 + len(optional))
	b.WriteString(g.host)
	b.WriteByte(';')
	b.WriteString(strconv.FormatUint(v>>32, 10))
	b.WriteByte(';')
	b.WriteString(strconv.FormatUint(v&0xffffffff, 10))
	if optional != "" {
		b.WriteByte(';')
		b.WriteString(optional)
	}
	return b.String()
}
