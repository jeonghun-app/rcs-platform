package routing

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// ASResolver gives every address of an application server's host, in the
// order to try them: proxy.DNSResolver.ResolveAll.
type ASResolver interface {
	ResolveAll(ctx context.Context, u sip.URI) ([]transport.Destination, error)
}

// maxDownServers bounds the addresses asDown keeps: the application
// servers have a handful of tasks.
const maxDownServers = 256

// asDown holds the application server addresses whose branch just failed
// for want of a connection or of any response, each until the DNS answer
// that gave it could have changed (Config.ASDownFor): a task that stopped
// stays in the answer that long (#574).
type asDown struct {
	mu    sync.Mutex
	until map[netip.AddrPort]time.Time
}

func (d *asDown) mark(a netip.AddrPort, until time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.until == nil {
		d.until = map[netip.AddrPort]time.Time{}
	}
	if _, ok := d.until[a]; !ok && len(d.until) >= maxDownServers {
		clear(d.until)
	}
	d.until[a] = until
}

func (d *asDown) is(a netip.AddrPort, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	until, ok := d.until[a]
	if ok && !now.Before(until) {
		delete(d.until, a)
		return false
	}
	return ok
}

// asAddresses are the addresses of server to try, in the resolver's order
// but those that just failed last, so that every one is still tried before
// the default handling applies. It is nil without a resolver, or when the
// server's host does not resolve: the proxy then resolves the branch, and
// its failure is the default handling's (RFC 3263 §4.3).
func (rt *Router) asAddresses(ctx context.Context, server sip.URI) []transport.Destination {
	if rt.cfg.Resolver == nil {
		return nil
	}
	all, err := rt.cfg.Resolver.ResolveAll(ctx, server)
	if err != nil || len(all) == 0 {
		return nil
	}
	now := rt.cfg.Now()
	var up, down []transport.Destination
	for _, d := range all {
		if rt.down.is(d.Addr, now) {
			down = append(down, d)
		} else {
			up = append(up, d)
		}
	}
	return append(up, down...)
}

// failsOver reports a branch to an application server that ended for want
// of a connection, or of any response, so that the server cannot have
// acted on the request as far as the S-CSCF can tell: the transport failed
// (the proxy's 503, §16.9), or Timer B or F fired with nothing received.
// The server's own timeout (ASTimeout) is not: it is the default
// handling's, settled with the server's return (takeUp). Neither is a
// local want of capacity, which a 503 with Retry-After answers (#574).
func failsOver(f proxy.BranchFailure) bool {
	switch {
	case f.Err == nil, f.Provisional, f.Response == nil,
		errors.Is(f.Err, proxy.ErrTargetTimeout), errors.Is(f.Err, proxy.ErrMaxBreadth),
		errors.Is(f.Err, transport.ErrNoFlow), errors.Is(f.Err, transport.ErrQueueFull),
		errors.Is(f.Err, transport.ErrTooManyConnections):
		return false
	}
	return f.Response.StatusCode == 503 || errors.Is(f.Err, transaction.ErrTimeout)
}
