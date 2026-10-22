package runtime

import (
	"bufio"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/jeonghun-app/rcs-platform/internal/proxyproto"
)

// proxyListener lets the admin server take a PROXY protocol v2 header in
// front of a connection, as an NLB health check sends when its target
// group has proxy protocol on (#230), from the peers in networks only.
// A connection without a header is served as before, so ECS's container
// health check, -healthcheck on loopback, still works. A header from a
// peer outside networks, or one that does not parse, closes the
// connection before any HTTP is read.
type proxyListener struct {
	net.Listener
	networks []netip.Prefix
}

func (l proxyListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &proxyConn{Conn: c, networks: l.networks, r: bufio.NewReader(c)}, nil
}

// errProxyHeader is the read error of a connection whose PROXY header was
// refused: net/http then closes it without an answer.
var errProxyHeader = errors.New("runtime: admin connection's PROXY header refused")

// proxyConn reads and drops a PROXY header at the start of the
// connection, on the first Read, so that the http.Server's read deadline
// for the request header bounds it and Accept never waits on a client.
type proxyConn struct {
	net.Conn
	networks []netip.Prefix
	r        *bufio.Reader
	once     sync.Once
	err      error
}

func (c *proxyConn) Read(b []byte) (int, error) {
	c.once.Do(c.dropHeader)
	if c.err != nil {
		return 0, c.err
	}
	return c.r.Read(b)
}

func (c *proxyConn) dropHeader() {
	// Fewer bytes than a signature, then EOF or a deadline, is no header:
	// what was read stays buffered for the request.
	first, _ := c.r.Peek(proxyproto.SignatureLen)
	if !proxyproto.HasSignature(first) {
		return
	}
	if !c.fromNetworks() {
		c.refuse()
		return
	}
	if _, err := proxyproto.Read(c.r); err != nil {
		c.refuse()
	}
}

// refuse closes the connection, so that net/http, which answers a read
// error 400, has nowhere to write: a refused header gets no answer at all.
func (c *proxyConn) refuse() {
	c.err = errProxyHeader
	_ = c.Conn.Close()
}

// fromNetworks reports whether the socket peer is in c.networks.
func (c *proxyConn) fromNetworks() bool {
	ap, err := netip.ParseAddrPort(c.Conn.RemoteAddr().String())
	if err != nil {
		return false
	}
	a := ap.Addr().Unmap()
	for _, p := range c.networks {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
