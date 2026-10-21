package routing

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// Metrics receives the router's counters; *runtime.Metrics implements it.
type Metrics interface {
	Count(name string, n int64)
}

// Registrar makes an identity the S-CSCF has no record of an unregistered
// user it serves; *registrar.Registrar implements it. It fails with
// registrar.ErrUnknownUser for an identity the HSS does not know.
type Registrar interface {
	Unregistered(ctx context.Context, impu string) (*state.Registration, error)
}

// Config configures a Router.
type Config struct {
	// Store is the state every scscf instance shares.
	Store state.Store
	// Registrar serves the unregistered users terminating requests name.
	Registrar Registrar
	// ODIKey signs a request's place in its iFC chain toward an application
	// server (ADR 0005), at least MinODIKeyBytes long, and the same on every
	// scscf instance, any of which may get the request back.
	ODIKey []byte
	// ODILifetime is how long an application server may take to send the
	// request back; DefaultODILifetime when 0.
	ODILifetime time.Duration
	// ASTimeout bounds the wait for an application server's answer to a
	// request other than INVITE, after which its default handling applies
	// (TS 24.229 §5.4.3.2); DefaultASTimeout when 0.
	ASTimeout time.Duration
	// ICSCF is where an originating request goes once its iFC chain is
	// done, toward the terminating user's S-CSCF: the I-CSCF of the home
	// network, with lr.
	ICSCF sip.URI
	// HomeDomain is the domain of the home network's SIP URIs: a tel URI
	// with a global number is sent on as the SIP URI of the number in it.
	HomeDomain string
	// RecordRoute is the S-CSCF's own Record-Route value, its service name
	// with lr (ADR 0005), which keeps it on the route of the dialogs it
	// forwards, so that their requests come back through InDialog.
	RecordRoute sip.Address
	// Self are the URIs that name this S-CSCF, as proxy.Config.Self: no
	// request inside a dialog is sent to them.
	Self []sip.URI
	// ApplicationServers are the hosts of the application servers a request
	// inside a dialog may go to, such as rcs-as's service name.
	ApplicationServers []string
	// EdgeProxyHosts and EdgeProxyNets are the names and addresses of the
	// P-CSCF tasks' core listeners: a request inside a dialog may go to one
	// whose URI names a flow by its user part.
	EdgeProxyHosts []string
	EdgeProxyNets  []netip.Prefix
	// RepairTimeout bounds the background repair of an identity's item;
	// DefaultRepairTimeout when 0.
	RepairTimeout time.Duration
	Now           func() time.Time
	// Rand makes response tags; crypto/rand when nil.
	Rand    io.Reader
	Logger  *slog.Logger
	Metrics Metrics
}

// Defaults of Config.
const (
	// DefaultRepairTimeout bounds a repair: the store's two calls, a read
	// and a conditional write.
	DefaultRepairTimeout = 5 * time.Second
	// DefaultODILifetime is Timer B and F at the default T1 (RFC 3261
	// §17.1.1.2), past which the request has failed anyway.
	DefaultODILifetime = 32 * time.Second
	// DefaultASTimeout leaves the client most of its Timer F (32 s) for
	// what follows a server that does not answer.
	DefaultASTimeout = 5 * time.Second
)

// Router routes the requests of the users the S-CSCF serves, outside
// dialogs and inside.
type Router struct {
	cfg Config
	log *slog.Logger
	ids sip.IDGenerator
	// repairs counts the identity repairs under way, for Wait.
	repairs sync.WaitGroup
	svc     services
}

// New validates cfg and returns a Router.
func New(cfg Config) (*Router, error) {
	if cfg.Store == nil {
		return nil, errors.New("routing: Store is required")
	}
	rr := cfg.RecordRoute.URI
	if !rr.IsSIP() || rr.Host == "" || !rr.Params.Has("lr") {
		return nil, errors.New("routing: RecordRoute must be a SIP URI with lr")
	}
	if len(cfg.Self) == 0 {
		return nil, errors.New("routing: Self is required")
	}
	if cfg.Registrar == nil {
		return nil, errors.New("routing: Registrar is required")
	}
	if len(cfg.ODIKey) < MinODIKeyBytes {
		return nil, errors.New("routing: ODIKey must be at least 32 bytes")
	}
	if !cfg.ICSCF.IsSIP() || cfg.ICSCF.Host == "" || !cfg.ICSCF.Params.Has("lr") {
		return nil, errors.New("routing: ICSCF must be a SIP URI with lr")
	}
	if cfg.HomeDomain == "" {
		return nil, errors.New("routing: HomeDomain is required")
	}
	cfg.ODIKey = slices.Clone(cfg.ODIKey)
	if cfg.ODILifetime <= 0 {
		cfg.ODILifetime = DefaultODILifetime
	}
	if cfg.ASTimeout <= 0 {
		cfg.ASTimeout = DefaultASTimeout
	}
	if cfg.RepairTimeout <= 0 {
		cfg.RepairTimeout = DefaultRepairTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.Metrics == nil {
		cfg.Metrics = noMetrics{}
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Router{cfg: cfg, log: log, ids: sip.IDGenerator{Rand: cfg.Rand}}, nil
}

type noMetrics struct{}

func (noMetrics) Count(string, int64) {}

func (rt *Router) count(name string) { rt.cfg.Metrics.Count(name, 1) }

// Wait returns once the identity repairs under way are done: for a
// shutdown, and for tests.
func (rt *Router) Wait() { rt.repairs.Wait() }

// internalLog logs a failure by its step and error, which name no identity.
func (rt *Router) internalLog(what string, err error) {
	rt.log.Error("routing: internal failure", "step", what, "error", err.Error())
	rt.count("routing.internal_errors")
}
