package registrar

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// HSS is the part of the Cx client the registrar uses; *cxclient.Client
// implements it.
type HSS interface {
	Authenticate(ctx context.Context, r *cx.MAR, schemes []string) (*cx.MAA, error)
	MAR(ctx context.Context, r *cx.MAR) (*cx.MAA, error)
	SAR(ctx context.Context, r *cx.SAR) (*cx.SAA, error)
}

var _ HSS = (*cxclient.Client)(nil)

// Metrics receives the registrar's counters; *runtime.Metrics implements it.
type Metrics interface {
	Count(name string, n int64)
}

// Defaults of Config.
const (
	DefaultExpires           = time.Hour
	DefaultMinExpires        = 5 * time.Minute
	DefaultMaxExpires        = 2 * time.Hour
	DefaultChallengeLifetime = 4 * time.Minute
	DefaultChallengeLimit    = 10
	DefaultChallengeWindow   = time.Minute
	// A flow's budget is small: a UE's first registration needs one
	// challenge, or two with a stale nonce; an AUTS over the same flow
	// costs it nothing more, and a challenge whose MAR never reached the
	// HSS is given back. A registered UE's flow, while
	// it stays on it, gets more, for the refreshes it shares with no one; a
	// reconnection comes over a new flow and counts as any other.
	DefaultFlowChallengeLimit           = 3
	DefaultRegisteredFlowChallengeLimit = 6
	DefaultResyncLimit                  = 3
	// DefaultUnregisteredTTL is how long an unregistered user's profile is
	// kept after SAR UNREGISTERED_USER, for the terminating requests that
	// follow (state.Registration.Unregistered).
	DefaultUnregisteredTTL = time.Hour
)

// Config configures a Registrar.
type Config struct {
	// Store is the state every scscf instance shares (ADR 0005).
	Store state.Store
	// HSS answers MAR and SAR.
	HSS HSS
	// Realm is the home network domain: the Digest realm, and the domain of
	// an IMPI derived from an IMPU (TS 24.229 §5.4.1.2.1).
	Realm string
	// ServiceRoute is the S-CSCF's service URI, such as sip:scscf.rcs.local;
	// the registrar returns it with lr and orig (TS 24.229 §5.4.1.2.2) so
	// that originating requests come back to any instance, and with
	// transport=tcp unless it names a transport.
	ServiceRoute sip.URI
	// NonceKey authenticates Digest nonces; every instance uses the same one
	// (digest.ServerConfig.NonceKey).
	NonceKey []byte
	// Schemes is the order in which MAR tries the authentication schemes when
	// the client named none; cxclient.DefaultSchemes when nil.
	Schemes []string
	// DefaultExpires applies to a contact without an expiry of its own,
	// MaxExpires caps what a client asks for, and a request below MinExpires
	// is answered 423 (RFC 3261 §10.3 step 7).
	DefaultExpires, MinExpires, MaxExpires time.Duration
	// ChallengeLifetime is how long a 401's challenge can be answered; at most
	// state.MaxChallengeLifetime.
	ChallengeLifetime time.Duration
	// ChallengeLimit bounds the challenges that one IMPI gets in a
	// ChallengeWindow, counted by every instance together, over every flow
	// but its registered UE's; FlowChallengeLimit bounds those of one P-CSCF
	// flow, and RegisteredFlowChallengeLimit those of a flow a live binding
	// came over, which count in nothing else. Past a limit a REGISTER is
	// answered 500 with Retry-After, without a MAR, so that a flood of
	// REGISTERs for one subscriber cannot starve the subscriber's own MAR
	// behind the HSS's lock on it, nor use up its registered UE's budget
	// (#201, limits.go).
	ChallengeLimit, FlowChallengeLimit, RegisteredFlowChallengeLimit int
	ChallengeWindow                                                  time.Duration
	// ResyncLimit bounds the resynchronisations of one IMPI in a
	// ChallengeLifetime, those of its registered UE's flow apart.
	ResyncLimit int
	// UnregisteredTTL is how long an unregistered user's record lasts
	// (Unregistered); DefaultUnregisteredTTL when 0.
	UnregisteredTTL time.Duration
	// TrustIntegrityProtected lets a re-registration whose Authorization
	// carries integrity-protected="tls-yes" go without a challenge (TS 24.229
	// §5.4.1.2.1). It needs a P-CSCF that sets the parameter itself, for a
	// connection it has authenticated, and removes it from what clients
	// send. This platform's pcscf removes it and sets none (#198), so no such
	// mode exists yet: cmd/scscf must not tie this to its environment or
	// configuration, and every REGISTER is challenged.
	TrustIntegrityProtected bool

	Now     func() time.Time
	Rand    io.Reader
	Metrics Metrics
	// Logger receives failures without identities, which are only logged
	// through internal/pii, and never credentials. Nil discards them.
	Logger *slog.Logger
}

// Registrar handles REGISTER requests (TS 24.229 §5.4.1).
type Registrar struct {
	cfg    Config
	digest *digest.Server
	ids    sip.IDGenerator
	log    *slog.Logger
	// notes are the attempt counts this instance saw over their limit.
	notes limitNotes
	// countLogged is when quietInternal last logged, in Unix ns.
	countLogged atomic.Int64
}

// New validates cfg and returns a Registrar.
func New(cfg Config) (*Registrar, error) {
	if cfg.Store == nil || cfg.HSS == nil {
		return nil, errors.New("registrar: Store and HSS are required")
	}
	if cfg.ServiceRoute.Host == "" || !cfg.ServiceRoute.IsSIP() {
		return nil, errors.New("registrar: ServiceRoute must be a SIP URI")
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
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.DefaultExpires == 0 {
		cfg.DefaultExpires = DefaultExpires
	}
	if cfg.MinExpires == 0 {
		cfg.MinExpires = DefaultMinExpires
	}
	if cfg.MaxExpires == 0 {
		cfg.MaxExpires = DefaultMaxExpires
	}
	if cfg.ChallengeLifetime == 0 {
		cfg.ChallengeLifetime = DefaultChallengeLifetime
	}
	if cfg.ChallengeLimit <= 0 {
		cfg.ChallengeLimit = DefaultChallengeLimit
	}
	if cfg.ChallengeWindow <= 0 {
		cfg.ChallengeWindow = DefaultChallengeWindow
	}
	if cfg.FlowChallengeLimit <= 0 {
		cfg.FlowChallengeLimit = DefaultFlowChallengeLimit
	}
	if cfg.RegisteredFlowChallengeLimit <= 0 {
		cfg.RegisteredFlowChallengeLimit = DefaultRegisteredFlowChallengeLimit
	}
	if cfg.ResyncLimit <= 0 {
		cfg.ResyncLimit = DefaultResyncLimit
	}
	if cfg.UnregisteredTTL <= 0 {
		cfg.UnregisteredTTL = DefaultUnregisteredTTL
	}
	switch {
	case cfg.MinExpires > cfg.MaxExpires || cfg.DefaultExpires < cfg.MinExpires || cfg.DefaultExpires > cfg.MaxExpires:
		return nil, errors.New("registrar: need MinExpires <= DefaultExpires <= MaxExpires")
	case cfg.ChallengeLifetime > state.MaxChallengeLifetime:
		return nil, fmt.Errorf("registrar: ChallengeLifetime over %s", state.MaxChallengeLifetime)
	}
	if cfg.Schemes == nil {
		cfg.Schemes = cxclient.DefaultSchemes
	}
	srv, err := digest.NewServer(digest.ServerConfig{
		Realm:         cfg.Realm,
		NonceKey:      cfg.NonceKey,
		NonceLifetime: cfg.ChallengeLifetime,
		// A challenge is taken from the store on its first use, so a nonce is
		// never checked twice and the counts need not be shared.
		NonceCounts: digest.NewMemoryNonceCounts(cfg.Now),
		Now:         cfg.Now,
		Random:      cfg.Rand,
	})
	if err != nil {
		return nil, fmt.Errorf("registrar: %w", err)
	}
	return &Registrar{cfg: cfg, digest: srv, ids: sip.IDGenerator{Rand: cfg.Rand}, log: cfg.Logger}, nil
}

// Register answers a REGISTER that src sent: a challenge, a refusal, or the
// bindings after the change. It always returns a response, built with
// sip.NewResponse, for proxy.Decision.Response. It blocks for the Cx and
// store round trips.
func (g *Registrar) Register(ctx context.Context, req *sip.Request, src transport.Source) *sip.Response {
	_ = src
	r, f := parseRegister(req, g.cfg.Realm)
	if f != nil {
		g.count("registrar.refused")
		return g.fail(req, f)
	}
	res, f := g.register(ctx, req, r)
	if f != nil {
		g.count("registrar.refused")
		return g.fail(req, f)
	}
	return res
}

// failure is a response the registrar refuses or challenges with.
type failure struct {
	code   int
	reason string
	// fields are added to the response, such as WWW-Authenticate or
	// Min-Expires.
	fields [][2]string
}

func refuse(code int, reason string) *failure { return &failure{code: code, reason: reason} }

// Error lets a failure travel as an error out of a step that also returns
// storage errors.
func (f *failure) Error() string { return "registrar: refused with " + strconv.Itoa(f.code) }

func (g *Registrar) fail(req *sip.Request, f *failure) *sip.Response {
	res := g.response(req, f.code, f.reason)
	for _, kv := range f.fields {
		if err := res.Header.Add(kv[0], kv[1]); err != nil {
			return g.response(req, 500, "")
		}
	}
	return res
}

// response builds a response to req. One that cannot be built, which only a
// To the parser accepted but cannot write could cause, is a 500 without a To
// tag; the client's transaction still ends.
func (g *Registrar) response(req *sip.Request, code int, reason string) *sip.Response {
	tag, err := g.ids.Tag()
	var res *sip.Response
	if err == nil {
		res, err = sip.NewResponse(req, code, reason, tag)
	}
	if err != nil {
		g.log.Error("registrar: building a response", slog.Int("status", code), slog.String("error", err.Error()))
		return &sip.Response{StatusCode: 500, Reason: sip.DefaultReason(500)}
	}
	return res
}

func (g *Registrar) count(name string) { g.cfg.Metrics.Count(name, 1) }

type noMetrics struct{}

func (noMetrics) Count(string, int64) {}
