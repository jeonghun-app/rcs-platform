package routing

import (
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// Metrics receives the router's counters; *runtime.Metrics implements it.
type Metrics interface {
	Count(name string, n int64)
}

// Config configures a Router.
type Config struct {
	// Store is the state every scscf instance shares.
	Store state.Store
	// RecordRoute is the S-CSCF's own Record-Route value, its service name
	// with transport=tcp and lr (ADR 0005, #208), which keeps it on the
	// route of the dialogs it forwards, so that their requests come back
	// through InDialog.
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
	// EdgeProxyPublicHosts are the names and addresses clients reach the
	// P-CSCF at. rcsjta puts the Route of a dialog's first INVITE, one of
	// them, after the dialog's route set in its session refreshes (#14):
	// a next hop that names one ends the route set.
	EdgeProxyPublicHosts []string
	// RepairTimeout bounds the background repair of an identity's item;
	// DefaultRepairTimeout when 0.
	RepairTimeout time.Duration
	Now           func() time.Time
	// Rand makes response tags; crypto/rand when nil.
	Rand    io.Reader
	Logger  *slog.Logger
	Metrics Metrics
}

// DefaultRepairTimeout bounds a repair: the store's two calls, a read and a
// conditional write.
const DefaultRepairTimeout = 5 * time.Second

// Router routes terminating requests and requests inside dialogs.
type Router struct {
	cfg Config
	log *slog.Logger
	ids sip.IDGenerator
	// repairs counts the identity repairs under way, for Wait.
	repairs sync.WaitGroup
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
	if t, ok := rr.Param("transport"); !ok || !strings.EqualFold(t, "tcp") {
		// pcscf refuses a dialog's requests along a route to the S-CSCF
		// over any other transport (#208).
		return nil, errors.New("routing: RecordRoute must carry transport=tcp")
	}
	if len(cfg.Self) == 0 {
		return nil, errors.New("routing: Self is required")
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
