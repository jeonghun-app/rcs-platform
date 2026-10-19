package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// DefaultDNSTTL is how long a DNSResolver reuses an answer by default: the
// TTL the platform gives its Cloud Map records.
const DefaultDNSTTL = 10 * time.Second

// DefaultDNSStale is how long past its TTL a DNSResolver still uses an answer
// by default while it is refreshed: a short outage or throttling of the VPC
// resolver then fails no request and delays none, while instances keep
// their addresses that long in any case.
const DefaultDNSStale = 5 * time.Minute

// maxDNSNames bounds the names a DNSResolver keeps answers for: the core has
// a handful.
const maxDNSNames = 256

// minLookupBackoff and maxLookupBackoff bound the wait before a name whose
// lookup failed is looked up again; refreshTimeout bounds a refresh in the
// background.
const (
	minLookupBackoff = 5 * time.Second
	maxLookupBackoff = time.Minute
	refreshTimeout   = 10 * time.Second
)

// failureLogEvery is how often a DNSResolver logs a name whose lookups keep
// failing: once when they start, then at most this often.
const failureLogEvery = time.Minute

// DNSResolver resolves SIP and SIPS URIs to the private addresses of their
// host, for services that reach one another by name inside the VPC, such as
// pcscf, icscf and scscf through Cloud Map (icscf.<namespace>). It looks up
// only names inside Namespace, A and AAAA records, uses only the answers
// that are private addresses (runtime.IsPrivateAddr, ADR 0007 §5), and
// keeps them for TTL; a host that is already an address is checked the
// same way. The transport and port follow the URI as for NumericResolver;
// TLS verifies the host name.
//
// A name has one lookup at a time, which no caller waits on while there is
// an answer to use, and a failure backs the next lookup off (lookup).
//
// ResolveAll gives every address in a random order, so that requests spread
// over the instances and a caller can try the next address when one fails,
// as pcscf does for icscf (TS 24.229 §5.2.2.1); Resolve gives the first.
//
// A Cloud Map answer holds at most eight records, chosen at random when
// more instances are registered: each answer then spreads over a different
// eight, which suits CSCF fleets of that size. The TTL stands in for the
// record TTL, which Go's resolver does not report; keep it no longer than
// the namespace's.
type DNSResolver struct {
	// Lookup resolves a host name; nil is net.DefaultResolver.LookupNetIP.
	Lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)
	// TTL is how long an answer is reused; zero is DefaultDNSTTL.
	TTL time.Duration
	// Stale is how long past its TTL an answer is still used when a new
	// lookup fails; zero is DefaultDNSStale.
	Stale time.Duration
	// Namespace is the Cloud Map namespace, RCS_SERVICE_NAMESPACE: a name
	// outside it (runtime.InServiceNamespace) is not looked up, so a URI a
	// client wrote cannot spend the VPC resolver's packet budget. Empty, no
	// name is looked up and only addresses resolve.
	Namespace string
	// Allow says which addresses may be used; nil is runtime.IsPrivateAddr.
	// A test or dev stack on one host may add loopback.
	Allow func(netip.Addr) bool
	// Logger hears of failed lookups; nil is slog.Default().
	Logger *slog.Logger
	// Now and Shuffle are for tests: the clock, and the order of the
	// addresses (rand.Shuffle by default).
	Now     func() time.Time
	Shuffle func(n int, swap func(i, j int))

	mu    sync.Mutex
	names map[string]dnsAnswer
	// refreshes counts the lookups under way, which tests wait for.
	refreshes sync.WaitGroup
}

// dnsAnswer is what a DNSResolver keeps of a name: its last answer, until
// expires and then for Stale if lookups fail, and since when they have
// failed, with when that was last logged.
type dnsAnswer struct {
	addrs             []netip.Addr
	expires           time.Time
	failing, reported time.Time
	// inflight, if set, is closed when the lookup under way ends.
	inflight chan struct{}
	// failures counts the failed lookups in a row, retryAt is when the next
	// may start, and err is the last one's error.
	failures int
	retryAt  time.Time
	err      error
}

// Resolve implements Resolver: the first of ResolveAll.
func (r *DNSResolver) Resolve(ctx context.Context, u sip.URI) (transport.Destination, error) {
	all, err := r.ResolveAll(ctx, u)
	if err != nil {
		return transport.Destination{}, err
	}
	return all[0], nil
}

// ResolveAll returns a destination at each usable address of u's host, in a
// random order. The error wraps ErrUnresolvable, and the lookup's own error
// when that failed.
func (r *DNSResolver) ResolveAll(ctx context.Context, u sip.URI) ([]transport.Destination, error) {
	d, err := NumericResolver{}.withAddr(u, netip.IPv6Unspecified())
	if err != nil {
		return nil, err
	}
	// One name however it is written, so it is looked up and kept once.
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(u.Host, "["), "]")), ".")
	var addrs []netip.Addr
	named := false
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a.Unmap()}
	} else if !runtime.InServiceNamespace(host, r.Namespace) {
		return nil, fmt.Errorf("%w: %s is outside the service namespace", ErrUnresolvable, host)
	} else if addrs, err = r.lookup(ctx, host); err != nil {
		return nil, err
	} else {
		named = true
	}
	allow := runtime.IsPrivateAddr
	if r.Allow != nil {
		allow = r.Allow
	}
	var out []transport.Destination
	for _, a := range addrs {
		if !allow(a) {
			continue
		}
		dst := d
		dst.Addr = netip.AddrPortFrom(a, d.Addr.Port())
		if dst.Network == transport.TLS && named {
			dst.ServerName = host
		}
		out = append(out, dst)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no private address", ErrUnresolvable)
	}
	shuffle := rand.Shuffle
	if r.Shuffle != nil {
		shuffle = r.Shuffle
	}
	shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out, nil
}

// lookup returns the addresses of host. A fresh answer is used as it is. A
// stale one is used at once while a single lookup refreshes it in the
// background, so no caller waits on a resolver that times out; after a
// failure the next refresh waits a backoff that doubles from
// minLookupBackoff to maxLookupBackoff. With no usable answer the callers
// share one lookup, and within the backoff they get its error without one.
func (r *DNSResolver) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	t := r.now()
	r.mu.Lock()
	a := r.names[host]
	switch {
	case a.addrs != nil && t.Before(a.expires):
		r.mu.Unlock()
		return a.addrs, nil
	case a.addrs != nil && t.Before(a.expires.Add(r.stale())):
		if a.inflight == nil && !t.Before(a.retryAt) {
			r.startLocked(host, t, a)
		}
		r.mu.Unlock()
		return a.addrs, nil
	case a.inflight == nil && t.Before(a.retryAt):
		err := a.err
		r.mu.Unlock()
		return nil, err
	}
	done := a.inflight
	if done == nil {
		done = r.startLocked(host, t, a)
	}
	r.mu.Unlock()
	select {
	case <-done:
		return r.result(host)
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: lookup of %s: %w", ErrUnresolvable, host, ctx.Err())
	}
}

// startLocked starts the one lookup of host, which no caller's ctx ends: a
// request that is cancelled must not make the name fail for the others. mu
// must be held.
func (r *DNSResolver) startLocked(host string, t time.Time, a dnsAnswer) chan struct{} {
	done := make(chan struct{})
	a.inflight = done
	r.keepLocked(host, t, a)
	r.refreshes.Add(1)
	go func() {
		defer r.refreshes.Done()
		ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
		defer cancel()
		r.do(ctx, host, done)
	}()
	return done
}

// result is what the last lookup of host left: its usable answer, or its
// error.
func (r *DNSResolver) result(host string) ([]netip.Addr, error) {
	t := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.names[host]
	if a.addrs != nil && t.Before(a.expires.Add(r.stale())) {
		return a.addrs, nil
	}
	if a.err != nil {
		return nil, a.err
	}
	return nil, fmt.Errorf("%w: no answer for %s", ErrUnresolvable, host)
}

// do looks host up and records the outcome, then closes done. A failure is
// logged at its first occurrence in a run, and then at most every
// failureLogEvery, with its class, which tells a missing record, a
// configuration error, from a resolver that does not answer.
func (r *DNSResolver) do(ctx context.Context, host string, done chan struct{}) {
	defer close(done)
	lookup := net.DefaultResolver.LookupNetIP
	if r.Lookup != nil {
		lookup = r.Lookup
	}
	addrs, err := lookup(ctx, "ip", host)
	if err == nil && len(addrs) == 0 {
		err = &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}
	t := r.now()
	r.mu.Lock()
	a := r.names[host]
	a.inflight = nil
	if err == nil {
		// A copy: the slice is Lookup's, which may keep it.
		kept := make([]netip.Addr, len(addrs))
		for i, v := range addrs {
			kept[i] = v.Unmap()
		}
		addrs = kept
		ttl := r.TTL
		if ttl <= 0 {
			ttl = DefaultDNSTTL
		}
		r.keepLocked(host, t, dnsAnswer{addrs: addrs, expires: t.Add(ttl)})
		r.mu.Unlock()
		return
	}
	a.failures++
	backoff := min(minLookupBackoff<<(min(a.failures, 8)-1), maxLookupBackoff)
	a.retryAt = t.Add(backoff)
	a.err = fmt.Errorf("%w: lookup of %s failed (%s): %w", ErrUnresolvable, host, lookupFailure(err), err)
	if a.failing.IsZero() {
		a.failing = t
	}
	report := a.reported.IsZero() || t.Sub(a.reported) >= failureLogEvery
	if report {
		a.reported = t
	}
	stale := a.addrs != nil && t.Before(a.expires.Add(r.stale()))
	r.keepLocked(host, t, a)
	r.mu.Unlock()
	if !report {
		return
	}
	log := r.Logger
	if log == nil {
		log = slog.Default()
	}
	log.Warn("DNS lookup failed", slog.String("host", host), slog.String("failure", lookupFailure(err)),
		slog.Bool("using_stale_answer", stale), slog.Duration("failing_for", t.Sub(a.failing)),
		slog.Duration("next_lookup_in", backoff), slog.String("error", err.Error()))
}

func (r *DNSResolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *DNSResolver) stale() time.Duration {
	if r.Stale > 0 {
		return r.Stale
	}
	return DefaultDNSStale
}

// keepLocked stores a's answer for host, making room if the names are at
// maxDNSNames: the answers no longer usable go first, or else any one.
func (r *DNSResolver) keepLocked(host string, t time.Time, a dnsAnswer) {
	if r.names == nil {
		r.names = map[string]dnsAnswer{}
	}
	if _, ok := r.names[host]; !ok && len(r.names) >= maxDNSNames {
		stale := r.Stale
		if stale <= 0 {
			stale = DefaultDNSStale
		}
		for name, old := range r.names {
			if old.inflight == nil && !t.Before(old.expires.Add(stale)) && !t.Before(old.retryAt) {
				delete(r.names, name)
			}
		}
		for name, old := range r.names {
			if len(r.names) < maxDNSNames {
				break
			}
			if old.inflight == nil {
				delete(r.names, name)
			}
		}
	}
	r.names[host] = a
}

// lookupFailure names the class of a failed lookup for logs and errors.
func lookupFailure(err error) string {
	var de *net.DNSError
	switch {
	case errors.As(err, &de) && de.IsNotFound:
		return "not found"
	case errors.As(err, &de) && de.IsTimeout, errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "error"
	}
}
