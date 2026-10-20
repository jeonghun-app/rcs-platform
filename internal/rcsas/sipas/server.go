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

// busyRetryAfter is the Retry-After, in seconds, of the answer to a message
// the store stayed busy for through its retries (store.ErrBusy): the
// conflicting write is over within a moment.
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
	// HomeDomain is the operator's IMS domain (RCS_IMS_DOMAIN), at which
	// a SIP URI whose user part is a global number names that number
	// (UserOf).
	HomeDomain string
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
	if cfg.HomeDomain == "" {
		return nil, errors.New("sipas: HomeDomain is required")
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

// ownTagPrefix starts the From tag of every request rcs-as originates, on
// every task, so that one that comes back to it is known. It does when a
// profile routes rcs-as's terminating requests to rcs-as again, lacking the
// P-Served-User exclusion of the default one (docs/hss.md): rcs-as would
// take its own delivery for a new message and send it once more, without
// end. A client that writes such a tag only has its own request refused.
const ownTagPrefix = "rcsas-"

// ownTag is a From tag for a request rcs-as originates.
func (s *Server) ownTag() (string, error) {
	tag, err := s.ids.Tag()
	return ownTagPrefix + tag, err
}

// looped reports a request rcs-as originated itself.
func looped(req *sip.Request) bool {
	from, err := req.Header.From()
	return err == nil && strings.HasPrefix(from.Tag(), ownTagPrefix)
}

// Route implements proxy.Router.
func (s *Server) Route(_ context.Context, r *proxy.Request) proxy.Decision {
	if r.Initial() && r.Message.Method != "ACK" && looped(r.Message) {
		// 482 Loop Detected (RFC 3261 §21.4.20); the sender of the
		// request, rcs-as itself, takes it as a failure and tries again
		// later, until the profile is put right.
		s.cfg.Metrics.Count("sip.loop", 1)
		return proxy.Decision{Status: 482}
	}
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
	if bad := unsupported(req); len(bad) > 0 {
		// RFC 3261 §8.2.2.3: a client that requires an extension rcs-as
		// lacks must not have its request served without it.
		s.cfg.Metrics.Count("sip.message.420", 1)
		s.respondWith(u, req, 420, [2]string{"Unsupported", strings.Join(bad, ", ")})
		return
	}
	if ct, err := req.Header.ContentType(); err != nil || !strings.EqualFold(ct.Type+"/"+ct.Subtype, cpim.ContentType) {
		// What to send instead (RFC 3261 §21.4.13). A CPIM body whose
		// content the engine refuses is answered 415 without it: it is
		// the type the client sent already.
		s.cfg.Metrics.Count("sip.message.415", 1)
		s.respondWith(u, req, 415, [2]string{"Accept", cpim.ContentType})
		return
	}
	o, code := s.origin(req)
	busy := false
	if code == 0 {
		code, busy = s.submit(ctx, o)
	}
	s.cfg.Metrics.Count(fmt.Sprintf("sip.message.%d", code), 1)
	if busy {
		s.respondRetry(u, req, code)
		return
	}
	s.respond(u, req, code)
}

// unsupported are the option tags of req's Require, none of which rcs-as
// supports for a MESSAGE.
func unsupported(req *sip.Request) []string {
	tags, err := req.Header.Require()
	if err != nil {
		// Unreadable: what it requires is not known to be supported.
		return []string{"(malformed)"}
	}
	return tags
}

// origin reads the engine's Origin from req, or the status that refuses it.
func (s *Server) origin(req *sip.Request) (messaging.Origin, int) {
	sender, identities, code := s.asserted(req)
	if code != 0 {
		return messaging.Origin{}, code
	}
	recipient, ok := messaging.UserOf(req.URI.String(), s.cfg.HomeDomain)
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

// asserted reads the sender the network asserted (RFC 3325 §9.1), never a
// header the client wrote, or the status that refuses the request: 403. It
// takes what pcscf asserts (#208): one identity, or a SIP identity and the
// tel URI of its implicit registration set (#16 decision 5), which are one
// user. So at most one of each scheme, and a SIP identity that is itself a
// number must be the tel URI's number; two different numbers are no pair
// pcscf makes. The user is the tel URI when one is asserted, which every
// SIP identity of the set is paired with, and the SIP identity's UserOf
// otherwise. Each identity as asserted is one the sender may name itself
// by, as is any other form of it (the engine compares them with UserOf).
func (s *Server) asserted(req *sip.Request) (string, []string, int) {
	pai, err := req.Header.PAssertedIdentity()
	if err != nil || len(pai) == 0 || len(pai) > 2 {
		return s.refuseAsserted()
	}
	var sipUser, telUser string
	var identities []string
	for _, a := range pai {
		raw := a.URI.String()
		user, ok := messaging.UserOf(raw, s.cfg.HomeDomain)
		if !ok {
			return s.refuseAsserted()
		}
		switch a.URI.Scheme {
		case "tel":
			if telUser != "" {
				return s.refuseAsserted()
			}
			telUser = user
		default: // sip or sips, as UserOf took it
			if sipUser != "" {
				return s.refuseAsserted()
			}
			sipUser = user
		}
		identities = append(identities, raw)
	}
	if telUser == "" {
		return sipUser, identities, 0
	}
	if sipUser != "" && strings.HasPrefix(sipUser, "tel:") && sipUser != telUser {
		return s.refuseAsserted()
	}
	return telUser, identities, 0
}

func (s *Server) refuseAsserted() (string, []string, int) {
	s.cfg.Metrics.Count("sip.asserted.refused", 1)
	return "", nil, 403
}

// submit hands o to the engine and returns the status that answers it,
// and whether it is the store being busy, which says when to try again.
// That answer is 500, not 503: scscf, a proxy, would turn a 503 from rcs-as
// into a 500 of its own and drop its Retry-After (RFC 3261 §16.7 step 6),
// and it passes a 500 on as it is, Retry-After included (§20.33).
func (s *Server) submit(ctx context.Context, o messaging.Origin) (int, bool) {
	err := s.engine.Submit(ctx, o)
	var r *messaging.Rejection
	switch {
	case err == nil:
		return 202, false
	case errors.As(err, &r):
		return refusalStatus(r.Reason), false
	case errors.Is(err, store.ErrBusy):
		return 500, true
	default:
		return 500, false
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

// respond answers req with code.
func (s *Server) respond(u *proxy.UAS, req *sip.Request, code int) {
	s.respondWith(u, req, code)
}

// respondRetry answers req with code and says when to try again: the
// conflicting store write is over within a moment.
func (s *Server) respondRetry(u *proxy.UAS, req *sip.Request, code int) {
	s.respondWith(u, req, code, [2]string{"Retry-After", busyRetryAfter})
}

func (s *Server) respondWith(u *proxy.UAS, req *sip.Request, code int, fields ...[2]string) {
	tag, err := s.ids.Tag()
	if err != nil {
		return // the proxy answers 500
	}
	res, err := sip.NewResponse(req, code, "", tag)
	if err != nil {
		return
	}
	for _, f := range fields {
		if err := res.Header.Set(f[0], f[1]); err != nil {
			return
		}
	}
	if err := u.Respond(res); err != nil {
		s.cfg.Metrics.Count("sip.respond_failed", 1)
	}
}
