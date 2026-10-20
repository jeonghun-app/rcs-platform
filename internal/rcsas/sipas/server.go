package sipas

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
)

// busyRetryAfter is the Retry-After, in seconds, of the 503 for a store that
// stayed busy through its retries (store.ErrBusy): the conflicting write is
// over within a moment.
const busyRetryAfter = "1"

// The default bounds on sessions. A session holds a leg and its MSRP
// state, a few KiB; a user has one per conversation it has open, and its
// client ends those it no longer uses.
const (
	DefaultMaxSessions        = 20_000
	DefaultMaxSessionsPerUser = 64
)

// Engine is what Server needs from the messaging engine, which
// *messaging.Engine is.
type Engine interface {
	Submit(ctx context.Context, o messaging.Origin) error
	OpenLeg(p messaging.LegParams) (*messaging.Leg, error)
	Offer(p messaging.LegParams) (*messaging.Leg, error)
	InviteFailed(inv messaging.Invitation, err error)
	UserRegistered(user string, newFlow bool)
}

// Config configures a Server.
type Config struct {
	// Core is where rcs-as sends the requests it originates, as their first
	// Route: scscf (RCSAS_CORE_URI), a SIP URI with lr.
	Core sip.URI
	// Host is this task's address (ADR 0005), the host of the Call-IDs it
	// makes.
	Host string
	// Contact is this task's SIP URI, the Contact of its sessions, where
	// the requests in their dialogs reach it.
	Contact sip.URI
	// MaxMessageSize is the a=max-size of its SDP; zero leaves it out.
	MaxMessageSize int
	// MaxSessions bounds the sessions this task holds, and
	// MaxSessionsPerUser those of one user among them (threat model T9);
	// zero takes DefaultMaxSessions and DefaultMaxSessionsPerUser.
	MaxSessions        int
	MaxSessionsPerUser int
	// Listener names the transport listener rcs-as's own requests leave
	// through, whose sent-by their Via carries.
	Listener string
	// Resolver finds the next hop of the requests rcs-as sends; nil is
	// proxy.NumericResolver.
	Resolver proxy.Resolver
	// Rand draws tags, branches and Call-IDs; nil is crypto/rand.
	Rand io.Reader
	// Clock runs the session timers; nil is the system clock.
	Clock msrp.Clock
	// Metrics counts events, without identifiers; nil counts nothing.
	Metrics messaging.Counter
	// Logger receives operational events, never identities or content; nil
	// discards them.
	Logger *slog.Logger
}

// Server is rcs-as's SIP layer: the proxy's Router and the engine's
// Deliverer. Bind gives it the engine and the transaction layer before the
// transport takes requests.
type Server struct {
	cfg    Config
	ids    sip.IDGenerator
	engine Engine
	layer  *transaction.Layer
	// sender sends the ACKs of 2xx responses, which belong to no
	// transaction (RFC 3261 §13.2.2.4).
	sender transaction.Sender

	mu       sync.Mutex
	closed   bool
	sessions map[string]*session
	perUser  map[string]int
	// registered is when each user's registration, as rcs-as last heard
	// of it, runs out (register).
	registered map[string]time.Time
}

// New returns a Server for cfg.
func New(cfg Config) (*Server, error) {
	if !cfg.Core.IsSIP() {
		return nil, errors.New("sipas: Core must be a SIP URI")
	}
	if cfg.Host == "" {
		return nil, errors.New("sipas: Host is required")
	}
	if !cfg.Contact.IsSIP() {
		return nil, errors.New("sipas: Contact must be a SIP URI")
	}
	if cfg.Resolver == nil {
		cfg.Resolver = proxy.NumericResolver{}
	}
	if cfg.Metrics == nil {
		cfg.Metrics = noMetrics{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Clock == nil {
		cfg.Clock = systemClock{}
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = DefaultMaxSessions
	}
	if cfg.MaxSessionsPerUser <= 0 {
		cfg.MaxSessionsPerUser = DefaultMaxSessionsPerUser
	}
	return &Server{
		cfg: cfg, ids: sip.IDGenerator{Rand: cfg.Rand},
		sessions: map[string]*session{}, perUser: map[string]int{}, registered: map[string]time.Time{},
	}, nil
}

// Bind gives s the engine it submits to, the transaction layer it sends
// through, which is the proxy's (proxy.Proxy.Layer), and the transport
// under it. It must be called before the transport takes requests and
// before the engine delivers.
func (s *Server) Bind(e Engine, l *transaction.Layer, tr transaction.Sender) {
	s.engine, s.layer, s.sender = e, l, tr
}

type noMetrics struct{}

func (noMetrics) Count(string, int64) {}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) AfterFunc(d time.Duration, f func()) msrp.Timer { return time.AfterFunc(d, f) }

// Route implements proxy.Router.
func (s *Server) Route(_ context.Context, r *proxy.Request) proxy.Decision {
	switch m := r.Message.Method; {
	case m == "ACK":
		// The ACK of a 2xx rcs-as sent went to its UAS (proxy.UAS.ACK);
		// any other is dropped, as nothing answers an ACK.
		return proxy.Decision{Status: 481}
	case !r.Initial():
		return proxy.Decision{Serve: s.inDialog}
	case m == "MESSAGE":
		return proxy.Decision{Serve: s.message}
	case m == "INVITE":
		return proxy.Decision{Serve: s.invite}
	case m == "REGISTER":
		return proxy.Decision{Serve: s.register}
	case m == "OPTIONS":
		// SESSION_CONTINUED: the chain goes on along the Route scscf put
		// below its own entry, back to scscf.
		return proxy.Forward(r)
	default:
		// 405 must say what is allowed (RFC 3261 §21.4.6).
		s.cfg.Metrics.Count("sip.refused.method", 1)
		tag, err := s.ids.Tag()
		if err != nil {
			return proxy.Decision{Status: 500}
		}
		res, err := sip.NewResponse(r.Message, 405, "", tag)
		if err != nil || res.Header.Set("Allow", allowed) != nil {
			return proxy.Decision{Status: 500}
		}
		return proxy.Decision{Response: res}
	}
}

// allowed are the methods rcs-as takes.
const allowed = "INVITE, ACK, CANCEL, BYE, UPDATE, MESSAGE, OPTIONS, REGISTER"

// message serves a pager-mode MESSAGE: the engine stores it, and 202 says
// so (RFC 3428 §7).
func (s *Server) message(ctx context.Context, u *proxy.UAS) {
	req := u.Request().Message
	o, code := s.origin(req)
	if code == 0 {
		code = s.submit(ctx, o)
	}
	s.cfg.Metrics.Count(fmt.Sprintf("sip.message.%d", code), 1)
	s.respond(u, req, code)
}

// origin reads the engine's Origin from req, or the status that refuses it.
func (s *Server) origin(req *sip.Request) (messaging.Origin, int) {
	if ct, err := req.Header.ContentType(); err != nil || !strings.EqualFold(ct.Type+"/"+ct.Subtype, cpim.ContentType) {
		return messaging.Origin{}, 415
	}
	sender, identities, code := asserted(req)
	if code != 0 {
		return messaging.Origin{}, code
	}
	recipient, ok := UserOf(req.URI.String())
	if !ok {
		return messaging.Origin{}, 404
	}
	conv, err := messaging.ParseConversationHeaders(req.Header.Get("Conversation-ID"),
		req.Header.Get("Contribution-ID"), req.Header.Get("InReplyTo-Contribution-ID"))
	if err != nil {
		return messaging.Origin{}, 400
	}
	return messaging.Origin{
		Sender: sender, Identities: identities, Recipient: recipient, Conversation: conv,
		Mode: store.Standalone, Pager: true, CPIM: req.Body,
	}, 0
}

// submit hands o to the engine and returns the status that answers it.
func (s *Server) submit(ctx context.Context, o messaging.Origin) int {
	err := s.engine.Submit(ctx, o)
	var r *messaging.Rejection
	switch {
	case err == nil:
		return 202
	case errors.As(err, &r):
		return refusalStatus(r.Reason)
	case errors.Is(err, store.ErrBusy):
		return 503
	default:
		return 500
	}
}

// refusalStatus is the SIP status of a message the engine refused: 413
// for its size, 415 for its type, 400 for what does not parse, and 403 for
// the rest, which the client must not send again unchanged.
func refusalStatus(r messaging.Reason) int {
	switch r {
	case messaging.ReasonTooLarge:
		return 413
	case messaging.ReasonContentType:
		return 415
	case messaging.ReasonMalformed, messaging.ReasonIMDNMalformed:
		return 400
	}
	return 403
}

// respond answers req with code. A 503 says when to try again; a 415 what
// to send (RFC 3261 §21.4.13); a 405 what is allowed; a 420 what is not
// supported (§21.4.15); a 422 the shortest session interval taken (RFC
// 4028 §6).
func (s *Server) respond(u *proxy.UAS, req *sip.Request, code int) {
	tag, err := s.ids.Tag()
	if err != nil {
		return // the proxy answers 500
	}
	res, err := sip.NewResponse(req, code, "", tag)
	if err != nil {
		return
	}
	switch code {
	case 503:
		err = res.Header.Set("Retry-After", busyRetryAfter)
	case 415:
		accept := cpim.ContentType
		if req.Method == "INVITE" || req.Method == "UPDATE" {
			accept = sdpType
		}
		err = res.Header.Set("Accept", accept)
	case 405:
		err = res.Header.Set("Allow", allowed)
	case 420:
		err = res.Header.Set("Unsupported", strings.Join(unsupported(req), ", "))
	case 422:
		err = res.Header.Set("Min-SE", strconv.Itoa(minSessionExpires))
	}
	if err != nil {
		return
	}
	if err := u.Respond(res); err != nil {
		s.cfg.Metrics.Count("sip.respond_failed", 1)
	}
}
