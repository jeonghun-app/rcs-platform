package sipas

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
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

// Engine is what Server needs from the messaging engine.
type Engine interface {
	Submit(ctx context.Context, o messaging.Origin) error
}

// Config configures a Server.
type Config struct {
	// Core is where rcs-as sends the requests it originates, as their first
	// Route: scscf (RCSAS_CORE_URI), a SIP URI with lr.
	Core sip.URI
	// Host is this task's address (ADR 0005), the host of the Call-IDs it
	// makes.
	Host string
	// Listener names the transport listener rcs-as's own requests leave
	// through, whose sent-by their Via carries.
	Listener string
	// Resolver finds the next hop of the requests rcs-as sends; nil is
	// proxy.NumericResolver.
	Resolver proxy.Resolver
	// Rand draws tags, branches and Call-IDs; nil is crypto/rand.
	Rand io.Reader
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
}

// New returns a Server for cfg.
func New(cfg Config) (*Server, error) {
	if !cfg.Core.IsSIP() {
		return nil, errors.New("sipas: Core must be a SIP URI")
	}
	if cfg.Host == "" {
		return nil, errors.New("sipas: Host is required")
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
	return &Server{cfg: cfg, ids: sip.IDGenerator{Rand: cfg.Rand}}, nil
}

// Bind gives s the engine it submits to and the transaction layer it sends
// through, which is the proxy's (proxy.Proxy.Layer). It must be called
// before the transport takes requests and before the engine delivers.
func (s *Server) Bind(e Engine, l *transaction.Layer) {
	s.engine, s.layer = e, l
}

type noMetrics struct{}

func (noMetrics) Count(string, int64) {}

// Route implements proxy.Router.
func (s *Server) Route(_ context.Context, r *proxy.Request) proxy.Decision {
	switch m := r.Message.Method; {
	case m == "MESSAGE" && r.Initial():
		return proxy.Decision{Serve: s.message}
	case m == "MESSAGE":
		// Pager mode has no dialog (RFC 3428 §4).
		return proxy.Decision{Status: 481}
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

// allowed are the methods rcs-as takes today.
const allowed = "MESSAGE, OPTIONS"

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
	// The network asserts the sender (RFC 3325 §9.1): the first identity
	// is the one the engine keys by, and every one of them, as asserted
	// and in canonical form, is one the sender may name in its CPIM From.
	pai, err := req.Header.PAssertedIdentity()
	if err != nil || len(pai) == 0 {
		return messaging.Origin{}, 403
	}
	sender, ok := UserOf(pai[0].URI.String())
	if !ok {
		return messaging.Origin{}, 403
	}
	var identities []string
	for _, a := range pai {
		raw := a.URI.String()
		identities = append(identities, raw)
		if c, ok := UserOf(raw); ok && c != sender {
			identities = append(identities, c)
		}
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
// to send (RFC 3261 §21.4.13); a 405 what is allowed.
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
		err = res.Header.Set("Accept", cpim.ContentType)
	}
	if err != nil {
		return
	}
	if err := u.Respond(res); err != nil {
		s.cfg.Metrics.Count("sip.respond_failed", 1)
	}
}
