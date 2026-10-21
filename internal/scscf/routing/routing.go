package routing

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"slices"
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
	// with transport=tcp and lr (ADR 0005, #208), which keeps it on the
	// route of the dialogs it forwards, so that their requests come back
	// through InDialog.
	RecordRoute sip.Address
	// Self are the URIs that name this S-CSCF, as proxy.Config.Self, its
	// service name and its task's address: no request inside a dialog is
	// sent to them.
	Self []sip.URI
	// DialogKeys sign the Record-Route values the S-CSCF writes, so that a
	// request inside a dialog goes on only to a hop the dialog was set up
	// through (#322), and a request's place in its iFC chain toward an
	// application server (odi, ADR 0005): the first signs, each verifies,
	// so that a key is rotated by putting the new one first and keeping the
	// old one until what it signed has ended. The same on every scscf
	// instance, any of which may get a request back.
	DialogKeys []DialogKey
	// EdgeProxyPort is the port of the P-CSCF tasks' core listener, over
	// TCP; DefaultEdgeProxyPort when 0. With the application servers'
	// ports, it is where a request inside a dialog may go, whatever the
	// signed hops say.
	EdgeProxyPort int
	// ApplicationServers are the SIP listeners of the application servers,
	// such as rcs-as's service name with its port and transport=tcp: a
	// request inside a dialog may go to the port and transport of one. The
	// host is not compared, as a server's task writes its own address.
	ApplicationServers []sip.URI
	// EdgeProxyPublicHosts are the names and addresses clients reach the
	// P-CSCF at. rcsjta puts the Route of a dialog's first INVITE, one of
	// them, after the dialog's route set in its session refreshes (#14):
	// a next hop that names one ends the route set.
	EdgeProxyPublicHosts []string
	// Sender sends the third-party REGISTERs (Registered); none are sent
	// without one.
	Sender Sender
	// ThirdPartyTimeout bounds each third-party REGISTER's transaction;
	// DefaultThirdPartyTimeout when 0.
	ThirdPartyTimeout time.Duration
	// MaxThirdParty bounds the third-party registrations at one application
	// server at a time; up to four times as many wait for it, past which
	// one is dropped and counted. DefaultMaxThirdParty when 0.
	MaxThirdParty int
	// RepairTimeout bounds the background repair of an identity's item;
	// DefaultRepairTimeout when 0.
	RepairTimeout time.Duration
	Now           func() time.Time
	// Rand makes response tags; crypto/rand when nil.
	Rand    io.Reader
	Logger  *slog.Logger
	Metrics Metrics
}

// maxDialogKeys are the current key and the previous one: a rotation keeps
// the old key only until what it signed has ended, and a list that grows
// with each one would keep every key that ever leaked.
const maxDialogKeys = 2

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
	// DefaultEdgeProxyPort is pcscf's core listener (docs/pcscf.md).
	DefaultEdgeProxyPort = 5070
	// DefaultThirdPartyTimeout is a non-INVITE transaction's Timer F
	// at a third of the default (RFC 3261 §17.1.2.2): a server slower than
	// that is as good as none for a registration.
	DefaultThirdPartyTimeout = 10 * time.Second
	// DefaultMaxThirdParty leaves room for a burst of registrations, such
	// as clients coming back after an outage, without holding unbounded
	// goroutines for servers that do not answer.
	DefaultMaxThirdParty = 256
)

// checkHosts refuses an entry of cfg that names no host, which would be
// taken for a URI without one, such as a tel URI, or no port (#322).
func checkHosts(cfg Config) error {
	for _, u := range cfg.Self {
		if u.Host == "" {
			return errors.New("routing: an entry of Self has no host")
		}
	}
	for _, u := range cfg.ApplicationServers {
		if !u.IsSIP() || u.Host == "" || u.Port == 0 {
			return errors.New("routing: each of ApplicationServers must be a SIP URI with a host and a port")
		}
	}
	if slices.Contains(cfg.EdgeProxyPublicHosts, "") {
		return errors.New("routing: an entry of EdgeProxyPublicHosts is empty")
	}
	return nil
}

// isKeyID reports whether id is a key ID: 1 to 8 letters and digits, which
// a URI parameter carries as they are.
func isKeyID(id string) bool {
	if id == "" || len(id) > 8 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9') {
			return false
		}
	}
	return true
}

// Router routes the requests of the users the S-CSCF serves, outside
// dialogs and inside.
type Router struct {
	cfg Config
	log *slog.Logger
	ids sip.IDGenerator
	// repairs counts the identity repairs under way, for Stop.
	repairs sync.WaitGroup
	svc     services
	tp      thirdParty
	// stopped is set by Stop, under stop, which a repair or a third-party
	// registration takes to be counted in its WaitGroup: none is added
	// once Stop waits (#379 QA).
	stop    sync.Mutex
	stopped bool
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
	if cfg.Registrar == nil {
		return nil, errors.New("routing: Registrar is required")
	}
	if !cfg.ICSCF.IsSIP() || cfg.ICSCF.Host == "" || !cfg.ICSCF.Params.Has("lr") {
		return nil, errors.New("routing: ICSCF must be a SIP URI with lr")
	}
	if cfg.HomeDomain == "" {
		return nil, errors.New("routing: HomeDomain is required")
	}
	if cfg.ODILifetime <= 0 {
		cfg.ODILifetime = DefaultODILifetime
	}
	if cfg.ASTimeout <= 0 {
		cfg.ASTimeout = DefaultASTimeout
	}
	if err := checkHosts(cfg); err != nil {
		return nil, err
	}
	if len(cfg.DialogKeys) == 0 || len(cfg.DialogKeys) > maxDialogKeys {
		return nil, errors.New("routing: DialogKeys needs the current key, and at most the previous one")
	}
	ids := map[string]bool{}
	cfg.DialogKeys = slices.Clone(cfg.DialogKeys)
	for i, k := range cfg.DialogKeys {
		if !isKeyID(k.ID) || ids[k.ID] || len(k.Key) < MinDialogKeyBytes {
			return nil, errors.New("routing: each DialogKey needs its own ID of letters and digits and a key of at least 32 bytes")
		}
		ids[k.ID] = true
		cfg.DialogKeys[i].Key = slices.Clone(k.Key)
	}
	if cfg.ThirdPartyTimeout <= 0 {
		cfg.ThirdPartyTimeout = DefaultThirdPartyTimeout
	}
	if cfg.MaxThirdParty <= 0 {
		cfg.MaxThirdParty = DefaultMaxThirdParty
	}
	if cfg.EdgeProxyPort == 0 {
		cfg.EdgeProxyPort = DefaultEdgeProxyPort
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
	rt := &Router{cfg: cfg, log: log, ids: sip.IDGenerator{Rand: cfg.Rand}}
	rt.tp.servers = map[string]*serverQueue{}
	return rt, nil
}

type noMetrics struct{}

func (noMetrics) Count(string, int64) {}

func (rt *Router) count(name string) { rt.cfg.Metrics.Count(name, 1) }

// Stop stops the Router from starting identity repairs and third-party
// registrations, and returns once those under way are done: for a
// shutdown, once the registrar tells it of no more, and for tests.
// Requests are still routed.
func (rt *Router) Stop() {
	rt.stop.Lock()
	rt.stopped = true
	rt.stop.Unlock()
	rt.repairs.Wait()
	rt.tp.wg.Wait()
}

// internalLog logs a failure by its step and error, which name no identity.
func (rt *Router) internalLog(what string, err error) {
	rt.log.Error("routing: internal failure", "step", what, "error", err.Error())
	rt.count("routing.internal_errors")
}
