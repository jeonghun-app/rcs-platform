package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// Request is a request the proxy has validated (RFC 3261 §16.3) and whose Route
// it has preprocessed (§16.4), as the Router sees it.
type Request struct {
	// Message is the request after preprocessing: a strict router's rewrite
	// undone and this proxy's own Route values removed. It is shared by every
	// branch, so the Router and the hooks must not modify it; Decision.Prepare
	// gets a copy per branch for that.
	Message *sip.Request
	// Source is where the request came from: the flow, and the listener, which
	// tells a service with client-facing and core listeners which side sent it.
	Source transport.Source
	// Routed holds the Route values that named this proxy and were removed,
	// topmost first. The URI of a consumed Route is how a request carries state
	// back to the proxy that put it in a Record-Route, Path or Service-Route:
	// pcscf finds the client flow in the user part (RFC 5626 §5.2), scscf the
	// signed iFC position in a parameter (ADR 0005). A proxy that inserted two
	// Record-Route values (RFC 5658 §5) finds both here.
	Routed []sip.Address
}

// Initial reports whether the request is outside a dialog: its To has no tag
// (RFC 3261 §12.2). In-dialog requests are normally forwarded where their Route
// or Request-URI says, without a location lookup (§16.12).
func (r *Request) Initial() bool {
	to, err := r.Message.Header.To()
	return err == nil && to.Tag() == ""
}

// Router decides where a request goes: the target set of RFC 3261 §16.5, or an
// answer. It is the location service of the RFC, supplied by each service
// (registrar lookup in scscf, flow lookup in pcscf, HSS query in icscf).
//
// Route runs on a goroutine of its own, never the one reading the network, so
// it may block on a database or another service. The ctx it and the Decision's
// hooks get is cancelled when the proxy closes, and once the request has its
// final response and every branch has ended. A CANCEL from upstream does not
// cancel it, so a hook can still clean up after a cancelled call; a request
// cancelled while Route runs is answered 487 when it returns.
//
// An ACK for a 2xx is forwarded statelessly (§16.11): only the first target is
// used and nothing can be answered, and since its retransmissions must go
// where the first copy went, the choice must depend on the message alone.
type Router interface {
	Route(ctx context.Context, r *Request) Decision
}

// RouterFunc adapts a function to Router.
type RouterFunc func(ctx context.Context, r *Request) Decision

// Route calls f.
func (f RouterFunc) Route(ctx context.Context, r *Request) Decision { return f(ctx, r) }

// Decision is a Router's answer. Exactly one of Response, Status and Targets is
// used, in that order of precedence; an empty Decision is answered with 480
// Temporarily Unavailable, which §16.5 prescribes for an empty target set.
type Decision struct {
	// Response answers the request instead of forwarding it, for a service that
	// is the UAS of some requests (the scscf registrar). It must have been built
	// for this request with sip.NewResponse. A 2xx to an INVITE is sent once:
	// retransmitting it until the ACK arrives (§13.3.1.4) is the UAS core's job.
	Response *sip.Response
	// Status answers the request with a response the proxy builds, such as 404
	// or 403, when no header beyond the mandatory ones is needed.
	Status int
	Reason string

	// Targets are forwarded to as §16.6 describes, highest Q first: targets with
	// the same Q are tried in parallel and the next lower Q only once all of
	// them have failed, which is parallel and sequential forking in one (§16.6,
	// RFC 3261 §20.10 for q). The zero Q of every target means one parallel
	// group.
	Targets []Target
	// RecordRoute values are inserted into every forwarded request, topmost
	// first, so the proxy stays on the path of the dialog (§16.6 step 4). Each
	// must be a SIP or SIPS URI with the lr parameter. A proxy that moves a
	// request between interfaces, such as pcscf between its client and core
	// listeners, inserts two: the one the next hop sees on top, and the one
	// the previous hop sees below it (RFC 5658 §5). Not used for an ACK.
	RecordRoute []sip.Address

	// Prepare, if set, changes each branch's copy of the request before it is
	// sent (§16.6 step 5): pcscf rewrites SDP and strips headers that must not
	// leave the network, for example. It runs once per branch, after the
	// Request-URI, Max-Forwards, Record-Route and the target's Routes are in
	// place and before the next hop is chosen, on a goroutine that may block.
	// The body may be replaced but not modified in place. An error fails the
	// branch with 500.
	Prepare func(ctx context.Context, t Target, req *sip.Request) error
	// OnResponse, if set, sees each response just before it is forwarded
	// upstream and may change its header fields, such as pcscf recording the
	// Service-Route of a 200 to REGISTER (RFC 3608). It must not change the body,
	// or the To tag of a 1xx or 2xx (§16.7 step 9). Calls for one request are in
	// order, on a goroutine that may block, which delays only that request's
	// responses.
	OnResponse func(ctx context.Context, res *sip.Response)
	// OnBranchFailure, if set, is told about every branch that ended without a
	// 2xx, and may return targets to try in its place while the request is still
	// being forwarded. The authoritative proxy of RFC 5626 §7 uses it to forget a
	// binding whose flow failed (430) and try the same instance over another
	// flow. Targets returned after a 2xx or 6xx, a CANCEL, or past
	// Config.MaxBranches are ignored. It runs on a goroutine that may block.
	OnBranchFailure func(ctx context.Context, f BranchFailure) []Target
}

// Target is one destination of a forwarded request.
type Target struct {
	// URI becomes the Request-URI of the branch (§16.6 step 2). Forwarding to a
	// Request-URI the proxy is not responsible for keeps it as it is.
	URI sip.URI
	// Q orders sequential forking, in thousandths as sip.Contact.Q reports it.
	Q int
	// Routes are pushed onto the Route header field, topmost first (§16.6 step
	// 6): the Path of a registration (RFC 3327) or the route to an application
	// server.
	Routes []sip.Address
	// Destination, if set, is the next hop and Resolver is not asked, as when
	// pcscf sends a terminating request over the client's flow.
	Destination *transport.Destination
}

// Forward is the decision to send a request on to its Request-URI unchanged,
// following its Route if it has one: what §16.12 does with an in-dialog request,
// and with a request for a domain the proxy is not responsible for (§16.5).
func Forward(r *Request) Decision { return Decision{Targets: []Target{{URI: r.Message.URI}}} }

// BranchFailure describes a branch that ended without a 2xx.
type BranchFailure struct {
	Target Target
	// Response is the final response the branch counts as: the one received, or
	// one the proxy made up for a failure that produced none, such as 408 when
	// Timer B or Timer C fired without any response (§16.8), 430 when the
	// target's flow is gone (RFC 5626 §5.3.1), or 503 when the transport failed
	// (§16.9). Its top Via, the proxy's own, has been removed.
	Response *sip.Response
	// Err is the transport, timer or Prepare error behind a response the proxy
	// made up, nil for a received one.
	Err error
}

// Resolver finds the next hop for a URI (the first Route, or the Request-URI if
// there is none, §16.6 step 7). RFC 3263 resolution belongs to the service, which
// knows its DNS, service discovery and TLS names; it runs on a goroutine that may
// block.
type Resolver interface {
	Resolve(ctx context.Context, u sip.URI) (transport.Destination, error)
}

// ErrUnresolvable means a Resolver found no next hop for a URI.
var ErrUnresolvable = errors.New("proxy: cannot resolve the next hop")

// NumericResolver resolves SIP and SIPS URIs whose host is an IP address, which
// is the part of RFC 3263 §4 that needs no DNS: the transport parameter, or TLS
// for SIPS and UDP otherwise, and the port in the URI or the transport's default.
// It is the default Resolver.
type NumericResolver struct{}

// Resolve implements Resolver.
func (NumericResolver) Resolve(_ context.Context, u sip.URI) (transport.Destination, error) {
	if !u.IsSIP() {
		return transport.Destination{}, fmt.Errorf("%w: %s URI", ErrUnresolvable, u.Scheme)
	}
	addr, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(u.Host, "["), "]"))
	if err != nil {
		return transport.Destination{}, fmt.Errorf("%w: host is not an IP address", ErrUnresolvable)
	}
	network := transport.UDP
	if u.Scheme == "sips" {
		network = transport.TLS
	}
	if t, ok := u.Param("transport"); ok {
		switch strings.ToLower(t) {
		case "udp":
			network = transport.UDP
		case "tcp":
			network = transport.TCP
		case "tls":
			network = transport.TLS
		default:
			return transport.Destination{}, fmt.Errorf("%w: unsupported transport parameter", ErrUnresolvable)
		}
		// RFC 3261 §26.2.2: a SIPS URI must be reached over TLS whatever its
		// transport parameter says.
		if u.Scheme == "sips" {
			network = transport.TLS
		}
	}
	port := u.Port
	if port == 0 {
		port = network.DefaultPort()
	}
	return transport.Destination{Network: network, Addr: netip.AddrPortFrom(addr.Unmap(), uint16(port))}, nil
}
