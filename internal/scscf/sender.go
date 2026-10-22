package scscf

import (
	"context"
	"errors"
	"fmt"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/routing"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// viaHost is the host of the Via scscf puts on what it sends as a client:
// the transport writes the listener's address over it (RFC 3261 §18.1.1),
// as rcs-as's sends do.
const viaHost = "invalid"

// sender sends the requests scscf starts itself, the reg event's NOTIFYs
// and the third-party REGISTERs, in client transactions of the proxy's
// transaction layer (regevent.Sender, routing.Sender): to the first Route,
// or without one to the Request-URI, as resolved, over the core listener.
type sender struct {
	layer    func() *transaction.Layer
	resolver proxy.Resolver
	listener string
	branch   func() (string, error)
}

// errNoLayer is a send before the proxy is up, which nothing answers.
var errNoLayer = errors.New("scscf: not serving yet")

// Send sends req and returns its final response, or an error when there is
// none: no next hop, a transport failure, a timeout (Timer F or B), or ctx
// ending first, which ends the transaction.
func (s *sender) Send(ctx context.Context, req *sip.Request) (*sip.Response, error) {
	layer := s.layer()
	if layer == nil {
		return nil, errNoLayer
	}
	next := req.URI
	if routes, err := req.Header.Route(); err != nil {
		return nil, fmt.Errorf("scscf: Route: %w", err)
	} else if len(routes) > 0 {
		next = routes[0].URI
	}
	dst, err := s.resolver.Resolve(ctx, next)
	if err != nil {
		return nil, fmt.Errorf("scscf: next hop: %w", err)
	}
	return s.SendTo(ctx, req, dst)
}

// SendTo is Send to dst, an address of the next hop (routing.Sender's
// SendTo): a send that fails before req is written, a connection not made
// above all, wraps routing.ErrNotSent, so that a third-party REGISTER goes
// on to the server's next address (#580).
func (s *sender) SendTo(ctx context.Context, req *sip.Request, dst transport.Destination) (*sip.Response, error) {
	layer := s.layer()
	if layer == nil {
		return nil, errNoLayer
	}
	dst.Listener = s.listener
	branch, err := s.branch()
	if err != nil {
		return nil, err
	}
	v := sip.Via{Transport: string(transport.TCP), Host: viaHost}
	v.Params.Set("branch", branch)
	if err := req.Header.Prepend("Via", v.String()); err != nil {
		return nil, err
	}
	type result struct {
		res *sip.Response
		err error
	}
	answered := make(chan result, 1)
	tx, err := layer.Request(req, dst, func(res *sip.Response, err error) {
		if err != nil || res.StatusCode >= 200 {
			select {
			case answered <- result{res, err}:
			default:
			}
		}
	})
	if err != nil {
		return nil, fmt.Errorf("scscf: send: %w: %w", routing.ErrNotSent, err)
	}
	select {
	case r := <-answered:
		return r.res, r.err
	case <-ctx.Done():
		tx.Terminate()
		return nil, ctx.Err()
	}
}
