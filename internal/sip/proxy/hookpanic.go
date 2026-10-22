package proxy

import (
	"context"
	"errors"

	"github.com/jeonghun-app/rcs-platform/internal/panics"
)

// MetricHookPanics counts the panics recovered from the hooks a service gives
// the proxy (#428).
const MetricHookPanics = "proxy.hook_panics"

// Metrics receives the proxy's counts; *runtime.Metrics is one.
type Metrics = panics.Counter

// errHookPanic fails a branch whose Prepare panicked, as Prepare's error
// does (500), or whose Resolver did, as the Resolver's error does (a 503 from
// the next hop, which goes upstream as 500).
var errHookPanic = errors.New("proxy: a service hook panicked")

// route asks the Router for its Decision. A panic in it is answered 500, and
// an ACK it was for is dropped.
func (p *Proxy) route(ctx context.Context, in *Request) Decision {
	dec := Decision{Status: 500}
	p.hook("Route", func() { dec = p.router.Route(ctx, in) })
	return dec
}

// hook runs f, which calls a hook the service gave the proxy (the Router,
// a Decision's hooks, the Resolver, DrainAnswer), and reports whether it
// returned. A panic in it is recovered here, on the hook's goroutine, so that
// it ends only the request, branch or response the hook was for: the caller
// answers or drops that as it would after the hook's error. The panic is
// counted, and logged without its value, which may hold message content, at
// most once a minute for each hook.
//
// The proxy calls no hook with a lock of its own held, so none is left held.
// A hook that panics while it holds a lock of the service's still leaves that
// one held.
func (p *Proxy) hook(name string, f func()) bool { return p.panics.Run(name, f) }
