package runtime

import (
	"bufio"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/pii"
	"github.com/jeonghun-app/rcs-platform/internal/proxyproto"
)

// proxyListener lets the admin server take a PROXY protocol v2 header in
// front of a connection, as an NLB health check sends when its target
// group has proxy protocol on (#230), from the peers in networks only.
// A connection without a header is served as before, so ECS's container
// health check, -healthcheck on loopback, still works. A header from a
// peer outside networks, or one that does not parse, closes the
// connection before any HTTP is read, and refusals counts and logs it.
type proxyListener struct {
	net.Listener
	networks []netip.Prefix
	refusals *proxyRefusals
}

func (l proxyListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &proxyConn{Conn: c, networks: l.networks, refusals: l.refusals, r: bufio.NewReader(c)}, nil
}

// metricProxyHeaderRefused counts the admin connections closed for their
// PROXY header. It is an alarm candidate: a health check refused gets no
// answer, so an RCS_ADMIN_PROXY_NETWORKS that misses an NLB subnet fails
// every check from it, and an NLB whose targets are all unhealthy sends
// to all of them, so the readiness gate would be gone without a sign
// (#555 security review).
const metricProxyHeaderRefused = "admin.proxy_header_refused"

// refusalLogEvery spaces the warn lines of refused headers: an NLB node
// checks every few seconds, and the count holds them all.
const refusalLogEvery = time.Minute

// Why a header was refused, as the warn line says.
const (
	refusedOutside = "peer outside RCS_ADMIN_PROXY_NETWORKS"
	refusedInvalid = "header does not parse or ends early"
)

// proxyRefusals counts each refused header and logs one at most every
// refusalLogEvery, with the peer's address truncated (pii.ClientIP). It
// is shared by the listener's connections.
type proxyRefusals struct {
	metrics *Metrics
	log     *slog.Logger
	now     func() time.Time
	// logged is the UnixNano of the last line, 0 before the first.
	logged atomic.Int64
}

func (r *proxyRefusals) refused(peer net.Addr, why string) {
	r.metrics.Count(metricProxyHeaderRefused, 1)
	now := r.now().UnixNano()
	last := r.logged.Load()
	if (last == 0 || now-last >= int64(refusalLogEvery)) && r.logged.CompareAndSwap(last, now) {
		r.log.Warn("admin connection's PROXY header refused", slog.String("reason", why), pii.ClientIP("peer", peer.String()))
	}
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
	refusals *proxyRefusals
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
		c.refuse(refusedOutside)
		return
	}
	if _, err := proxyproto.Read(c.r); err != nil {
		c.refuse(refusedInvalid)
	}
}

// refuse closes the connection, so that net/http, which answers a read
// error 400, has nowhere to write: a refused header gets no answer at all.
func (c *proxyConn) refuse(why string) {
	c.err = errProxyHeader
	c.refusals.refused(c.Conn.RemoteAddr(), why)
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
