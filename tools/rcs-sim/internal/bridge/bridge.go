// Package bridge is rcs-bridge (#658): a small HTTP and WebSocket API
// through which an application sends and receives RCS standalone messages
// (RCC.07 pager mode) through the platform without speaking SIP, IMS AKA,
// CPIM or IMDN itself. docs/rcs-bridge.md is its contract.
//
// Each endpoint the application names is a test subscriber of its own: the
// bridge provisions it in hss (Provisioner), registers it with IMS AKA
// through pcscf on a flow of its own and keeps the registration refreshed
// (SIP), and turns what the network sends it into events on the WebSocket
// stream. An endpoint can go offline and online again, as a car whose
// ignition is off does, so that rcs-as's store-and-forward delivers what
// it kept once the endpoint registers again.
//
// The SIP and hss sides are interfaces, so the API, the endpoints'
// lifecycle and the event fan-out are tested with both injected; NewSIP and
// NewHSS are the real ones.
//
// Logs carry endpoint names and identities only through internal/pii.
// Message bodies, keys and the token never reach a log.
package bridge

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/pii"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/sipua"
)

// Defaults.
const (
	// DefaultMaxEndpoints is the demo's scale (#658): this many endpoints
	// online at once, registered or trying to register. Offline ones do
	// not count.
	DefaultMaxEndpoints = 64
	// DefaultOpTimeout bounds each piece of SIP or hss work a request, a
	// refresh or a retry does.
	DefaultOpTimeout = 30 * time.Second
)

// Subscriber is an endpoint's test subscription, as the Provisioner made
// it. Credentials hold the AKA keys; they print as a placeholder.
type Subscriber struct {
	IMPI string
	// IMPU is the SIP identity the endpoint registers and sends as,
	// sip:+<MSISDN>@<domain>; Tel is the tel URI of the same number, in
	// the same implicit registration set (docs/architecture.md §4).
	IMPU, Tel   sip.URI
	Credentials sipua.Credentials
	// InstanceID is the +sip.instance of the endpoint's flows (RFC 5626
	// §4.1).
	InstanceID string
}

// Provisioner gives an endpoint its subscription. The bridge calls it
// once per endpoint and process, and keeps what it returns.
type Provisioner interface {
	Provision(ctx context.Context, name string) (Subscriber, error)
}

// SIP registers subscribers. receive is called for each pager-mode MESSAGE
// the network sends the line, on the line's reading goroutine, so it does
// not block; it returns the status to answer with.
type SIP interface {
	Register(ctx context.Context, s Subscriber, receive func(Incoming) int) (Line, time.Duration, error)
}

// Line is one registered flow of an endpoint.
type Line interface {
	// Refresh registers again on the same flow and returns the expiry
	// granted.
	Refresh(ctx context.Context) (time.Duration, error)
	// Send sends a pager-mode MESSAGE with a message/cpim body to target
	// and returns the final status; a transaction timeout is 408 (RFC
	// 3261 §8.1.3.1). An error is a failure without a final response.
	Send(ctx context.Context, target sip.URI, cpim []byte) (int, error)
	// Unregister removes the registration and closes the line.
	Unregister(ctx context.Context) error
	// Close closes the line without unregistering.
	Close()
	// Done is closed once the line has failed or been closed.
	Done() <-chan struct{}
}

// Incoming is a MESSAGE the network sent a line.
type Incoming struct {
	// From is the SIP From's URI: the sender as the network names it,
	// where a notification goes back to (RFC 5438 §12.1.3.1).
	From sip.URI
	// ContentType is the media type of the body, type/subtype without
	// parameters, in lower case.
	ContentType string
	Body        []byte
	// Line is the line it came on, which its delivery notification goes
	// back on: a message can arrive before Register has returned the line
	// (rcs-as delivers what it kept on the third-party REGISTER).
	Line Line
}

// Config configures a Bridge.
type Config struct {
	// Domain is the home network domain.
	Domain      string
	Provisioner Provisioner
	SIP         SIP
	// Token is the bearer token every request needs.
	Token secret.Key
	// MaxEndpoints bounds the endpoints online at once; zero is
	// DefaultMaxEndpoints. However many are offline, a process holds at
	// most as many endpoints as the bridge has subscriber slots.
	MaxEndpoints int
	// OpTimeout bounds each piece of SIP or hss work; zero is
	// DefaultOpTimeout.
	OpTimeout time.Duration
	// Clock runs the refresh and retry timers and the event stream's
	// pings; nil is the system clock.
	Clock transaction.Clock
	// Now is the time events and notifications carry; nil is time.Now.
	Now func() time.Time
	// Rand supplies Message-IDs; nil is crypto/rand.
	Rand io.Reader
	// Logger gets the bridge's log lines; nil discards them.
	Logger *slog.Logger
}

// Bridge holds the endpoints and serves the API (Handler).
type Bridge struct {
	cfg Config
	log *slog.Logger
	hub *hub
	// ctx ends with Close: background work, and every operation, stops.
	ctx    context.Context
	cancel context.CancelFunc

	// provisionMu makes one endpoint at a time, so that two new ones
	// never race for the same subscriber slot in hss.
	provisionMu sync.Mutex

	mu        sync.Mutex
	endpoints map[string]*endpoint
	// byNumber finds an endpoint by its MSISDN, "+" and digits, which is
	// how the network names a sender: tel:+..., or sip:+...@domain.
	byNumber map[string]*endpoint
	// online counts the endpoints wanted online (MaxEndpoints).
	online int
	closed bool
	wg     sync.WaitGroup
}

// ErrClosed is returned once Close has been called.
var ErrClosed = errors.New("bridge: closed")

// New returns a Bridge with no endpoints.
func New(cfg Config) (*Bridge, error) {
	switch {
	case cfg.Provisioner == nil || cfg.SIP == nil:
		return nil, errors.New("bridge: a Provisioner and a SIP are needed")
	case cfg.Token.IsZero():
		return nil, errors.New("bridge: no token")
	case cfg.Domain == "":
		return nil, errors.New("bridge: no home domain")
	}
	if cfg.MaxEndpoints <= 0 {
		cfg.MaxEndpoints = DefaultMaxEndpoints
	}
	if cfg.OpTimeout <= 0 {
		cfg.OpTimeout = DefaultOpTimeout
	}
	if cfg.Clock == nil {
		cfg.Clock = transaction.SystemClock
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Bridge{
		cfg: cfg, log: log, hub: newHub(), ctx: ctx, cancel: cancel,
		endpoints: map[string]*endpoint{}, byNumber: map[string]*endpoint{},
	}, nil
}

// Handler is the HTTP API (docs/rcs-bridge.md).
func (b *Bridge) Handler() http.Handler { return b.routes() }

// Close ends the event streams, unregisters every endpoint (within ctx)
// and stops the bridge's background work.
func (b *Bridge) Close(ctx context.Context) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	eps := make([]*endpoint, 0, len(b.endpoints))
	for _, e := range b.endpoints {
		eps = append(eps, e)
	}
	b.mu.Unlock()
	b.hub.close()
	b.cancel()
	var wg sync.WaitGroup
	for _, e := range eps {
		wg.Go(func() { e.shutdown(ctx) })
	}
	wg.Wait()
	b.wg.Wait()
}

// endpoint returns the endpoint called name, provisioning it the first
// time; created reports that it did.
func (b *Bridge) endpoint(ctx context.Context, name string) (e *endpoint, created bool, err error) {
	if e, err := b.lookup(name); e != nil || err != nil {
		return e, false, err
	}
	b.provisionMu.Lock()
	defer b.provisionMu.Unlock()
	if e, err := b.lookup(name); e != nil || err != nil {
		return e, false, err
	}
	b.mu.Lock()
	full := len(b.endpoints) >= slots
	b.mu.Unlock()
	if full {
		return nil, false, errAllSlots
	}
	sub, err := b.cfg.Provisioner.Provision(ctx, name)
	if err != nil {
		return nil, false, err
	}
	number, ok := numberOf(sub.Tel)
	if !ok {
		return nil, false, errors.New("bridge: the subscription has no telephone number")
	}
	e = newEndpoint(b, name, sub, number)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, false, ErrClosed
	}
	b.endpoints[name] = e
	b.byNumber[number] = e
	b.wg.Go(e.work)
	b.log.Info("endpoint provisioned", pii.Identity("endpoint", name), pii.URI("impu", sub.IMPU.String()))
	return e, true, nil
}

var (
	errFull     = errors.New("bridge: as many endpoints as the bridge allows are online; put one offline first")
	errAllSlots = errors.New("bridge: the bridge holds an endpoint for each of its subscriber slots")
)

// onlineFull reports whether putting name online would pass MaxEndpoints:
// one more online when it is not online already. It takes b.mu and e.mu
// one after the other, never together: setOnline holds e.mu while it
// counts under b.mu.
func (b *Bridge) onlineFull(name string) bool {
	b.mu.Lock()
	e := b.endpoints[name]
	b.mu.Unlock()
	if e != nil {
		e.mu.Lock()
		online := e.online
		e.mu.Unlock()
		if online {
			return false
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.online >= b.cfg.MaxEndpoints
}

// countOnline counts an endpoint going online (up) or offline, and
// reports false, counting nothing, when one more would be online than
// MaxEndpoints allows.
func (b *Bridge) countOnline(up bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !up {
		b.online--
		return true
	}
	if b.online >= b.cfg.MaxEndpoints {
		return false
	}
	b.online++
	return true
}

// lookup returns the endpoint called name, nil if there is none.
func (b *Bridge) lookup(name string) (*endpoint, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, ErrClosed
	}
	return b.endpoints[name], nil
}

// nameOf is the name of the endpoint u names, "" if it is none of the
// bridge's.
func (b *Bridge) nameOf(u sip.URI) string {
	n, ok := numberOf(u)
	if !ok {
		return ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.byNumber[n]; e != nil {
		return e.name
	}
	return ""
}

// opContext bounds one operation, and ends with the bridge.
func (b *Bridge) opContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(b.ctx, b.cfg.OpTimeout)
}
