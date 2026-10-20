package icscf

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// The procedures, as metric names know them.
const (
	kindRegister    = "register"
	kindTerminating = "terminating"
	kindRouted      = "routed"
)

// Router is the I-CSCF's proxy.Router. It keeps nothing about users between
// requests: every REGISTER asks the HSS with a UAR and every terminating
// initial request with an LIR, so any instance can take any request.
type Router struct {
	hss             HSS
	scscfs          []candidate
	home            []byte
	retryAfter      string
	registerTimeout time.Duration
	resolver        AllResolver
	ids             sip.IDGenerator
	metrics         Metrics
	log             *slog.Logger
	now             func() time.Time
	unknownLog      everyMinute
	failed          recentFailures
}

// failedFor is how long an S-CSCF address a request could not be sent to
// goes to the back of the list: a stopped task's address stays in DNS
// answers for their TTL after Cloud Map drops it.
const failedFor = 30 * time.Second

// maxFailedAddrs bounds the addresses remembered; past it a new failure is
// not remembered until older ones expire.
const maxFailedAddrs = 1024

// recentFailures remembers the S-CSCF addresses a request could not be
// sent to in the last failedFor.
type recentFailures struct {
	mu    sync.Mutex
	until map[netip.AddrPort]time.Time
}

func (f *recentFailures) mark(a netip.AddrPort, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.until == nil {
		f.until = make(map[netip.AddrPort]time.Time)
	}
	if len(f.until) >= maxFailedAddrs {
		for k, t := range f.until {
			if !now.Before(t) {
				delete(f.until, k)
			}
		}
		if len(f.until) >= maxFailedAddrs {
			return
		}
	}
	f.until[a] = now.Add(failedFor)
}

// order puts the addresses that failed lately after the others, each group
// in the order it came in.
func (f *recentFailures) order(dsts []transport.Destination, now time.Time) []transport.Destination {
	f.mu.Lock()
	defer f.mu.Unlock()
	failed := func(d transport.Destination) bool {
		t, ok := f.until[d.Addr]
		return ok && now.Before(t)
	}
	out := make([]transport.Destination, 0, len(dsts))
	for _, d := range dsts {
		if !failed(d) {
			out = append(out, d)
		}
	}
	for _, d := range dsts {
		if failed(d) {
			out = append(out, d)
		}
	}
	return out
}

// everyMinute allows one event a minute, for a log line that a fault can
// repeat for every request.
type everyMinute struct{ last atomic.Int64 }

func (e *everyMinute) allow(now time.Time) bool {
	last := e.last.Load()
	if last != 0 && now.UnixNano()-last < int64(time.Minute) {
		return false
	}
	return e.last.CompareAndSwap(last, now.UnixNano())
}

// New returns a Router for cfg, or an error naming the first invalid setting.
func New(cfg Config) (*Router, error) {
	cfg.setDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Router{
		hss:             cfg.HSS,
		scscfs:          newCandidates(cfg.SCSCFs),
		home:            []byte(cfg.HomeDomain),
		retryAfter:      strconv.FormatInt(int64(cfg.RetryAfter/time.Second), 10),
		registerTimeout: cfg.RegisterTimeout,
		resolver:        cfg.Resolver,
		ids:             cfg.IDs,
		metrics:         cfg.Metrics,
		log:             cfg.Logger,
		now:             cfg.Now,
	}, nil
}

// Route implements proxy.Router.
func (r *Router) Route(ctx context.Context, req *proxy.Request) proxy.Decision {
	m := req.Message
	switch {
	case m.Method == "ACK" && req.Initial():
		// An ACK belongs to a dialog or to a non-2xx the proxy absorbs
		// itself; one without a To tag is for neither, and asking the HSS
		// about it would cost an LIR per ACK (review of #274). It is
		// dropped.
		r.count(kindRouted, "dropped_ack")
		return proxy.Decision{}
	case m.Method == "REGISTER":
		return r.register(ctx, m)
	case !req.Initial() || m.Header.Has("Route"):
		// A request inside a dialog goes where its Route or Request-URI
		// says (RFC 3261 §16.12), and so does one whose Route continues
		// past this I-CSCF (TS 24.229 §5.3.2.1): neither needs the HSS.
		r.count(kindRouted, "forwarded")
		return forwarding(proxy.Forward(req))
	}
	return r.terminating(ctx, m)
}

// register applies TS 24.229 §5.3.1.2 and §5.3.1.3.
func (r *Router) register(ctx context.Context, m *sip.Request) proxy.Decision {
	impu, ok := publicIdentity(m)
	if !ok {
		// No HSS knows an identity that is not one; it would answer 5001.
		return r.reject(kindRegister, 403)
	}
	impi, ok := privateIdentity(m, impu)
	if !ok {
		return r.reject(kindRegister, 403)
	}
	uaa, err := r.hss.UAR(ctx, &cx.UAR{
		UserName:                 impi,
		PublicIdentity:           impu,
		VisitedNetworkIdentifier: r.visitedNetwork(m),
		AuthorizationType:        authorizationType(m),
	})
	if ctx.Err() != nil {
		return r.cancelled(kindRegister)
	}
	if err != nil || couldNotComplete(uaa.Result) {
		return r.hssUnavailable(kindRegister, m)
	}
	if !uaa.Result.IsSuccess() {
		// §5.3.1.3: every negative answer is 403.
		return r.reject(kindRegister, 403)
	}
	scscf, err := r.scscf(uaa.Result, uaa.ServerName, uaa.ServerCapabilities)
	switch {
	case errors.Is(err, errBadServerName):
		return r.hssUnavailable(kindRegister, m)
	case errors.Is(err, errUnknownName):
		return r.withRetryAfter(kindRegister, m, 500)
	case err != nil:
		r.metrics.Count("icscf.scscf.no_capable", 1)
		return r.reject(kindRegister, 600) // §5.3.1.3
	}
	r.count(kindRegister, "forwarded")
	// §5.3.1.2: the REGISTER's Request-URI becomes the S-CSCF's. The
	// branch is bounded so that a silent S-CSCF is answered 504 while the
	// client still waits (§5.3.1.3; re-selection is not done, see the
	// package documentation).
	dsts, ok := r.destinations(ctx, scscf)
	if !ok {
		return r.unreachableNow(kindRegister, m)
	}
	target := func(dst *transport.Destination) proxy.Target {
		return proxy.Target{URI: scscf, Timeout: r.registerTimeout, Destination: dst}
	}
	d := forwarding(proxy.Decision{Targets: []proxy.Target{target(first(dsts))}})
	// An S-CSCF that cannot be sent to gets the client a Retry-After, as
	// for a terminating request (review of #276); one that does not answer
	// in time still gets it 504, and is not tried again, since it may have
	// taken the REGISTER.
	r.answerUnreachable(&d, kindRegister, rest(dsts), target)
	return d
}

// terminating applies TS 24.229 §5.3.2.1 and §5.3.2.2 to an initial request
// for a user of the home network.
func (r *Router) terminating(ctx context.Context, m *sip.Request) proxy.Decision {
	uri := telForm(m.URI)
	impu, ok := identity.CanonicalIMPU(uri.String())
	if !ok {
		// No user of the network has such an identity; the HSS would
		// answer 5001.
		return r.reject(kindTerminating, 404)
	}
	lia, err := r.hss.LIR(ctx, &cx.LIR{PublicIdentity: impu})
	if ctx.Err() != nil {
		return r.cancelled(kindTerminating)
	}
	if err != nil || couldNotComplete(lia.Result) {
		return r.hssUnavailable(kindTerminating, m)
	}
	switch cxclient.Classify(lia.Result) {
	case cxclient.Success:
	case cxclient.NotRegistered:
		// §5.3.2.1: known, not registered, and no services for an
		// unregistered user.
		return r.reject(kindTerminating, 480)
	default:
		// §5.3.2.2: 5001 and every other negative answer.
		return r.reject(kindTerminating, 404)
	}
	scscf, err := r.scscf(lia.Result, lia.ServerName, lia.ServerCapabilities)
	switch {
	case errors.Is(err, errBadServerName):
		return r.hssUnavailable(kindTerminating, m)
	case errors.Is(err, errUnknownName):
		return r.withRetryAfter(kindTerminating, m, 500)
	case err != nil:
		// TS 24.229 names no response for a terminating request no
		// configured S-CSCF can take. It is a provisioning problem, so
		// retrying will not help; it is counted apart so it can be
		// alarmed (decided on #274).
		r.metrics.Count("icscf.scscf.no_capable", 1)
		return r.reject(kindTerminating, 480)
	}
	r.count(kindTerminating, "forwarded")
	// §5.3.2.1: the S-CSCF becomes the topmost Route, and the Request-URI
	// stays, in tel form when it named a telephone number.
	dsts, ok := r.destinations(ctx, scscf)
	if !ok {
		return r.unreachableNow(kindTerminating, m)
	}
	target := func(dst *transport.Destination) proxy.Target {
		return proxy.Target{URI: uri, Routes: []sip.Address{{URI: looseRoute(scscf)}}, Destination: dst}
	}
	d := forwarding(proxy.Decision{Targets: []proxy.Target{target(first(dsts))}})
	r.answerUnreachable(&d, kindTerminating, rest(dsts), target)
	return d
}

// answerUnreachable gives the 500 the proxy ends a request in, a REGISTER or
// a terminating one, when it could not send it to the S-CSCF, a
// Retry-After, as the HSS's
// failures get: the S-CSCF the user needs exists and will be back (decided
// on #274). The proxy counts the branch as a 503 of its own (RFC 3261 §16.9)
// and turns it into 500 (§16.7 step 6); a 503 would not reach the caller
// either, since the proxy upstream turns it into a 500 and drops the
// Retry-After, while it passes a 500's on. A 500 from the S-CSCF itself, or a
// 503 it sent, gets none.
//
// Before that, each further address of the S-CSCF (next) is tried in turn
// with target, so a task that is gone does not fail the request while
// others serve the same name.
func (r *Router) answerUnreachable(d *proxy.Decision, kind string, next []transport.Destination, target func(*transport.Destination) proxy.Target) {
	var (
		unreachable atomic.Bool
		mu          sync.Mutex
	)
	d.OnBranchFailure = func(_ context.Context, f proxy.BranchFailure) []proxy.Target {
		if f.Err == nil || f.Response == nil || f.Response.StatusCode != 503 {
			return nil
		}
		if dst := f.Target.Destination; dst != nil && dst.Addr.IsValid() {
			r.failed.mark(dst.Addr, r.now())
		}
		mu.Lock()
		defer mu.Unlock()
		if len(next) > 0 {
			dst := next[0]
			next = next[1:]
			r.metrics.Count("icscf.scscf.next_address", 1)
			return []proxy.Target{target(&dst)}
		}
		unreachable.Store(true)
		return nil
	}
	strip := d.OnResponse
	d.OnResponse = func(ctx context.Context, res *sip.Response) {
		strip(ctx, res)
		if res.StatusCode != 500 || !unreachable.Load() {
			return
		}
		r.metrics.Count("icscf.scscf.unreachable", 1)
		r.count(kind, "500")
		if !res.Header.Has("Retry-After") {
			_ = res.Header.Add("Retry-After", r.retryAfter)
		}
	}
}

// destinations are the addresses of the S-CSCF at u, in the order to try
// them, when there is a resolver; false when there is one and it finds
// none, which leaves the S-CSCF as unreachable as a refused connection.
func (r *Router) destinations(ctx context.Context, u sip.URI) ([]transport.Destination, bool) {
	if r.resolver == nil {
		return nil, true
	}
	dsts, err := r.resolver.ResolveAll(ctx, u)
	if err != nil || len(dsts) == 0 {
		return nil, false
	}
	return r.failed.order(dsts, r.now()), true
}

// first is the first destination, nil for none: the proxy resolves then.
func first(dsts []transport.Destination) *transport.Destination {
	if len(dsts) == 0 {
		return nil
	}
	return &dsts[0]
}

// rest is every destination after the first.
func rest(dsts []transport.Destination) []transport.Destination {
	if len(dsts) < 2 {
		return nil
	}
	return dsts[1:]
}

// unreachableNow answers a request whose S-CSCF has no address: 500 with
// Retry-After, as one whose every address refused it.
func (r *Router) unreachableNow(kind string, m *sip.Request) proxy.Decision {
	r.metrics.Count("icscf.scscf.unreachable", 1)
	return r.withRetryAfter(kind, m, 500)
}

// couldNotComplete reports whether an answer says the HSS could not do what
// was asked rather than that the user may not have it: a protocol error, a
// transient 4xxx, or DIAMETER_UNABLE_TO_COMPLY, which TS 29.228 §6.1.1.1
// gives for an HSS failure such as a database error. TS 24.229 §5.3.1.3 has
// those answered as a query that could not be completed, not refused
// (decided on #274).
func couldNotComplete(r cx.Result) bool {
	switch cxclient.Classify(r) {
	case cxclient.Unavailable, cxclient.Failure:
		return true
	}
	return false
}

var (
	errBadServerName = errors.New("icscf: the HSS named an S-CSCF that is not a SIP URI")
	errNoSCSCF       = errors.New("icscf: no configured S-CSCF has the mandatory capabilities")
	errUnknownName   = errors.New("icscf: the HSS named an S-CSCF that is not configured")
)

// scscf is the S-CSCF a successful UAA or LIA names, or else the first one
// its capabilities allow (rank). Server-Name values inside the capabilities
// are the operator steering the choice, and TS 29.228 §6.7 has the I-CSCF
// then disregard the capabilities: the first of them is taken as a name.
//
// A name is the configured S-CSCF it matches (configured), never the name
// as written: the HSS stores names as sip:scscf.<namespace>, without the
// transport and port the configuration gives, and routed raw it would
// leave over UDP, which icscf has no listener for (review of #274).
func (r *Router) scscf(result cx.Result, name string, caps *cx.ServerCapabilities) (sip.URI, error) {
	if name == "" && caps != nil && len(caps.ServerNames) > 0 {
		name = caps.ServerNames[0]
	}
	if name != "" {
		u, err := sip.ParseURI(name)
		if err != nil || !u.IsSIP() || u.Host == "" {
			// §5.3.1.3 counts incorrect information from the HSS as a
			// query that could not be completed.
			r.metrics.Count("icscf.hss.bad_server_name", 1)
			r.log.Warn("icscf: the HSS named an S-CSCF that is not a SIP URI", slog.String("result", result.String()))
			return sip.URI{}, errBadServerName
		}
		if c, ok := r.configured(u); ok {
			return c, nil
		}
		r.metrics.Count("icscf.scscf.unknown_name", 1)
		// The counter carries the volume; one line a minute says why,
		// with the result code only (review of #274).
		if r.unknownLog.allow(r.now()) {
			r.log.Warn("icscf: the HSS named an S-CSCF that is not configured", slog.String("result", result.String()))
		}
		return sip.URI{}, errUnknownName
	}
	ranked := rank(r.scscfs, caps)
	if len(ranked) == 0 {
		return sip.URI{}, errNoSCSCF
	}
	return ranked[0], nil
}

// configured is the configured S-CSCF whose URI has u's scheme and host,
// and its port if u gives one: the configuration says how to reach it.
func (r *Router) configured(u sip.URI) (sip.URI, bool) {
	for _, c := range r.scscfs {
		if c.uri.Scheme == u.Scheme && strings.EqualFold(c.uri.Host, u.Host) && (u.Port == 0 || u.Port == port(c.uri)) {
			return c.uri, true
		}
	}
	return sip.URI{}, false
}

// port is u's port, or its transport's default (RFC 3261 §19.1.2).
func port(u sip.URI) int {
	if u.Port != 0 {
		return u.Port
	}
	if t, _ := u.Param("transport"); u.Scheme == "sips" || strings.EqualFold(t, "tls") {
		return 5061
	}
	return 5060
}

// looseRoute returns u with lr: the S-CSCF is a loose router, and the
// proxy would treat a Route without lr as a strict router's and move the
// Request-URI into the Route (RFC 3261 §16.6 step 6). The HSS's name may
// lack it, since a name is not a route.
func looseRoute(u sip.URI) sip.URI {
	if _, ok := u.Param("lr"); ok {
		return u
	}
	u.Params = slices.Clone(u.Params)
	u.Params.SetFlag("lr")
	return u
}

// forwarding adds to d what every forwarded request and its responses need:
// TS 24.229 §5.3.2.1 has the I-CSCF discard P-Profile-Key wherever it
// appears, which only an I-CSCF that sets it from the HSS's wildcarded
// identity may send, and this one does not.
func forwarding(d proxy.Decision) proxy.Decision {
	d.Prepare = func(_ context.Context, _ proxy.Target, req *sip.Request) error {
		req.Header.Del("P-Profile-Key")
		return nil
	}
	d.OnResponse = func(_ context.Context, res *sip.Response) {
		res.Header.Del("P-Profile-Key")
	}
	return d
}

// reject answers with code, which needs no header field beyond the
// mandatory ones.
func (r *Router) reject(kind string, code int) proxy.Decision {
	r.count(kind, strconv.Itoa(code))
	return proxy.Decision{Status: code}
}

// hssUnavailable answers a request the HSS could not be asked about: 480
// (TS 24.229 §5.3.1.3) with Retry-After, which tells a client when to try
// again. 503 is kept for the I-CSCF's own overload (the transaction
// layer's cap), so the two can be told apart.
func (r *Router) hssUnavailable(kind string, m *sip.Request) proxy.Decision {
	r.metrics.Count("icscf.hss.unavailable", 1)
	return r.withRetryAfter(kind, m, 480)
}

// withRetryAfter answers with code and Retry-After, or with code alone when
// the response cannot be built.
func (r *Router) withRetryAfter(kind string, m *sip.Request, code int) proxy.Decision {
	r.count(kind, strconv.Itoa(code))
	tag, err := r.ids.Tag()
	if err != nil {
		return proxy.Decision{Status: code}
	}
	res, err := sip.NewResponse(m, code, "", tag)
	if err != nil {
		return proxy.Decision{Status: code}
	}
	if err := res.Header.Add("Retry-After", r.retryAfter); err != nil {
		return proxy.Decision{Status: code}
	}
	return proxy.Decision{Response: res}
}

// cancelled is the Decision for a request cancelled while the HSS was
// asked: the proxy answers it 487 and its CANCEL 200 (TS 24.229 §5.3.2.2),
// whatever the Decision, and the answer, if one comes, is dropped.
func (r *Router) cancelled(kind string) proxy.Decision {
	r.count(kind, "cancelled")
	return proxy.Decision{Status: 487}
}

func (r *Router) count(kind, what string) {
	r.metrics.Count("icscf."+kind+"."+what, 1)
}
