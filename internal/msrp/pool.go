package msrp

import (
	"context"
	"errors"
	"net"
	"sync"
)

// Registry is a Binder over sessions created ahead of time, the way rcs-as
// creates one when it answers an INVITE and then waits for the relay to
// connect. A session leaves the registry when it closes.
type Registry struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

// Add makes s reachable through Bind.
func (r *Registry) Add(s *Session) error {
	id := s.local.SessionID
	r.mu.Lock()
	if r.sessions == nil {
		r.sessions = map[string]*Session{}
	}
	if r.sessions[id] != nil {
		r.mu.Unlock()
		return errors.New("msrp: session id already registered")
	}
	r.sessions[id] = s
	r.mu.Unlock()

	err := s.whenClosed(func() { r.remove(s) })
	if err != nil {
		r.remove(s)
	}
	return err
}

func (r *Registry) remove(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[s.local.SessionID] == s {
		delete(r.sessions, s.local.SessionID)
	}
}

// Bind implements Binder.
func (r *Registry) Bind(_ *Conn, to URI) (*Session, error) {
	r.mu.Lock()
	s := r.sessions[to.SessionID]
	r.mu.Unlock()
	if s == nil || !s.local.Equal(to) {
		return nil, ErrNoSession
	}
	return s, nil
}

// Pool opens sessions on the active side, sharing one connection per
// scheme, host and port as §5.4 recommends. msrp-relay uses one toward
// rcs-as instances. The Dial field must be set before use.
type Pool struct {
	// Dial connects to the host of to; it decides on TLS from to.Secure.
	Dial   func(ctx context.Context, to URI) (net.Conn, error)
	Config Config

	mu    sync.Mutex
	conns map[string]*Conn
}

// Open binds s to a connection toward its first remote hop, dialling one
// if none is open, and performs Conn.Open.
func (p *Pool) Open(ctx context.Context, s *Session) error {
	remote := s.Remote()
	if len(remote) == 0 {
		return errors.New("msrp: an active session needs the remote path")
	}
	c, err := p.conn(ctx, remote[0])
	if err != nil {
		return err
	}
	return c.Open(ctx, s)
}

func (p *Pool) conn(ctx context.Context, to URI) (*Conn, error) {
	key := to.connKey()
	p.mu.Lock()
	c := p.conns[key]
	p.mu.Unlock()
	if c != nil && !c.isClosed() {
		return c, nil
	}
	if p.Dial == nil {
		return nil, errors.New("msrp: Pool.Dial is not set")
	}
	nc, err := p.Dial(ctx, to)
	if err != nil {
		return nil, err
	}
	fresh, err := NewActiveConn(nc, p.Config)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}

	// Two Opens may have dialled at once; keep the first connection.
	p.mu.Lock()
	if p.conns == nil {
		p.conns = map[string]*Conn{}
	}
	if c := p.conns[key]; c != nil && !c.isClosed() {
		p.mu.Unlock()
		_ = fresh.Close()
		return c, nil
	}
	p.conns[key] = fresh
	p.mu.Unlock()
	return fresh, nil
}

// Close closes every pooled connection.
func (p *Pool) Close() error {
	p.mu.Lock()
	conns := p.conns
	p.conns = nil
	p.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	return nil
}
