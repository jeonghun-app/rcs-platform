package diameter

import (
	"context"
	"errors"
	"slices"
	"sync"
)

// ErrApplicationNotNegotiated means the request's application is not among
// those both nodes advertised in the capabilities exchange, so the peer must
// not be sent it (RFC 6733 §5.3).
var ErrApplicationNotNegotiated = errors.New("diameter: application not negotiated with the peer")

// Peer is a remote Diameter node. A peer accepted by [Node.Serve] lives as
// long as its connection; a peer from [Node.Connect] outlives its connections
// and is reconnected until the node shuts down.
type Peer struct {
	cfg *PeerConfig // nil for an accepted peer

	mu    sync.Mutex
	conn  *conn
	host  string
	realm string
	apps  []uint32
}

func (p *Peer) attach(c *conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.conn = c
	p.host = c.caps.host
	p.realm = c.caps.realm
	p.apps = c.apps
}

func (p *Peer) detach(c *conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == c {
		p.conn = nil
	}
}

func (p *Peer) current() *conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conn
}

// Host is the peer's Origin-Host from the latest capabilities exchange, or
// the configured host before the first one.
func (p *Peer) Host() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.host
}

// Realm is the peer's Origin-Realm, like [Peer.Host].
func (p *Peer) Realm() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.realm
}

// Applications are the application ids both nodes support.
func (p *Peer) Applications() []uint32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.apps)
}

// Available reports whether the peer can take a request now: it has an open
// connection whose watchdog is in the OKAY state (RFC 3539 §3.4.1) and that
// is not being disconnected.
func (p *Peer) Available() bool {
	c := p.current()
	return c != nil && c.available()
}

// Send sends req and waits for its answer, which is matched by Hop-by-Hop
// Identifier. It sets the R bit, a fresh Hop-by-Hop Identifier and, when req
// has none, an End-to-End Identifier; a caller retrying on another peer keeps
// the End-to-End Identifier and sets [FlagRetransmit] (RFC 6733 §5.5.4).
//
// The wait ends with the answer, at the context's end, or after the node's
// RequestTimeout, whichever comes first. An answer reporting a failure is
// returned as an answer with a nil error; inspect its Result-Code.
func (p *Peer) Send(ctx context.Context, req *Message) (*Message, error) {
	c := p.current()
	if c == nil {
		return nil, ErrPeerUnavailable
	}
	if req.ApplicationID == AppCommon || !slices.Contains(c.apps, req.ApplicationID) {
		return nil, ErrApplicationNotNegotiated
	}
	return c.roundTrip(ctx, req, false)
}
