// Package chatbotapi is rcs-as's chatbot API, which maap alone calls (ADR
// 0009 §4, §6, §7, §12): POST /v1/chatbot/messages and
// /v1/chatbot/notifications, on a listener of its own apart from SIP and
// admin (ADR 0007 §2). maap faces the internet and the core does not trust
// it, so this is where its requests are bounded: maap's token, strict bodies
// (internal/chatbot), refusals outside its scope and per-task backstops
// (§9). A compromised maap can then speak for chatbots only, to subscribers
// only, and only so fast. A request that passes every check is handed to an
// [Acceptor].
//
// #698 builds it in three steps: the listener, the token and the switch;
// the decoding of bodies; then the scope and the backstops, which are not
// applied yet.
package chatbotapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

// MinMessageSize is the smallest RCSAS_MAX_MESSAGE_SIZE with the switch on:
// a chatbot's largest content and 8 KiB for the CPIM rcs-as writes around
// it (ADR 0009 §5), so that nothing maap accepts is refused for size here.
const MinMessageSize = chatbot.MaxContentBytes + 8<<10

// minBodyRate is the slowest a caller holding a decode slot may send its
// body, in bytes a second; maap is in the same VPC and far faster. Without
// a deadline of its own a body trickled byte by byte would hold its slot
// as long as the sender liked (#723 review).
const minBodyRate = 256 << 10

// bodyTime is how long a request holding a slot has to send a body of at
// most maxBytes: 1 s, and 1 s for every minBodyRate bytes (6.8 s for a
// message, 1.03 s for a notification).
func bodyTime(maxBytes int64) time.Duration {
	return time.Second + time.Duration(maxBytes)*time.Second/minBodyRate
}

// Retry-After of a 503 for the switch or the acceptor, and of one for a
// full decode cap, which frees within a second.
const (
	retryUnavailable = "5"
	retryBusy        = "1"
)

// ErrUnavailable is what an Acceptor returns when it cannot take a request
// now; the answer is 503 with Retry-After.
var ErrUnavailable = errors.New("chatbotapi: unavailable")

// Acceptor takes the requests that passed every check: so far, a body that
// decoded and validated (chatbot.DecodeEnvelope). nil is 202,
// ErrUnavailable 503 and any other error 500.
type Acceptor interface {
	AcceptMessage(ctx context.Context, m chatbot.BotMessage) error
	AcceptNotification(ctx context.Context, n chatbot.BotNotification) error
}

// unavailable is the Acceptor until #699 (messages) and #706
// (notifications) bring theirs.
type unavailable struct{}

func (unavailable) AcceptMessage(context.Context, chatbot.BotMessage) error { return ErrUnavailable }
func (unavailable) AcceptNotification(context.Context, chatbot.BotNotification) error {
	return ErrUnavailable
}

// TokenPair is maap's current and next token (RCSAS_MAAP_TOKEN and
// RCSAS_MAAP_TOKEN_NEXT, ADR 0007 §4); either may be empty.
type TokenPair struct {
	Current, Next secret.Key
}

// Config is the chatbot API's configuration.
type Config struct {
	// On is the switch of ADR 0009 §12: RCSAS_CHATBOTS=on with
	// RCS_CHATBOT_DOMAIN set. Off, an authenticated request is 503.
	On     bool
	Domain chatbot.Domain
	Tokens TokenPair
	// Decodes bounds the bodies decoded and validated at once.
	Decodes int
}

// API serves the chatbot API. It is safe for concurrent use.
type API struct {
	cfg      Config
	acceptor Acceptor
	tokens   []acceptedToken
	// slots holds a token for each body being decoded (RCSAS_CHATBOT_DECODES).
	slots   chan struct{}
	log     *slog.Logger
	metrics *runtime.Metrics
}

type acceptedToken struct {
	digest [sha256.Size]byte
	// slot is "current" or "next", for the audit line of a rotation.
	slot string
}

// New returns the API of cfg, handing what passes to acc; a nil acc
// answers 503.
func New(cfg Config, acc Acceptor, logger *slog.Logger, m *runtime.Metrics) *API {
	if acc == nil {
		acc = unavailable{}
	}
	a := &API{
		cfg: cfg, acceptor: acc, slots: make(chan struct{}, cfg.Decodes), log: logger, metrics: m,
	}
	for _, t := range []struct {
		key  secret.Key
		slot string
	}{{cfg.Tokens.Current, "current"}, {cfg.Tokens.Next, "next"}} {
		if !t.key.IsZero() {
			a.tokens = append(a.tokens, acceptedToken{sha256.Sum256(t.key.Reveal()), t.slot})
		}
	}
	return a
}

// Server returns an HTTP server of the API. A request holding a decode
// slot gets a read deadline of its own (bodyTime), so ReadTimeout bounds
// only the headers of the others; WriteTimeout leaves the acceptor time
// for its store calls.
func (a *API) Server() *http.Server {
	return &http.Server{
		Handler:           a,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          runtime.HTTPErrorLog(a.log),
	}
}

// answer is a response other than 202. Its reason names a rule, never a
// value of the request.
type answer struct {
	status             int
	reason, retryAfter string
}

// call is one request, with the decode slot it may hold.
type call struct {
	w         *statusRecorder
	r         *http.Request
	op, token string
	holding   bool
	slots     chan struct{}
}

// releaseSlot frees the call's decode slot, if it holds one: once the body
// is checked, before the acceptor's store calls, and in any case when the
// request ends.
func (c *call) releaseSlot() {
	if c.holding {
		c.holding = false
		<-c.slots
	}
}

// ServeHTTP answers every request, in the order of checks in
// docs/rcs-as.md, and writes one audit line for it.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	c := &call{w: &statusRecorder{ResponseWriter: w}, r: r, op: "other", token: "none", slots: a.slots}
	// Deferred, so that a panic frees the slot and leaves its audit line;
	// net/http then ends the connection, as for any panic (#723 review).
	defer func() {
		p := recover()
		c.releaseSlot()
		status := c.w.status
		switch {
		case status == 0 && p != nil:
			status = http.StatusInternalServerError
		case status == 0:
			status = http.StatusOK
		}
		a.metrics.Count("chatbot.api."+c.op+"."+strconv.Itoa(status), 1)
		// Nothing of the request but its operation: the body holds
		// identifiers and chatbot free text.
		a.log.LogAttrs(r.Context(), slog.LevelInfo, "audit: chatbot API request",
			slog.String("operation", c.op), slog.Int("status", status), slog.String("token", c.token))
		if p != nil {
			panic(p)
		}
	}()
	if ans := a.serve(c); ans != nil {
		writeAnswer(c.w, ans)
		return
	}
	c.w.Header().Set("Content-Type", "application/json")
	c.w.WriteHeader(http.StatusAccepted)
	_, _ = io.WriteString(c.w, "{}\n")
}

// serve runs the checks every request meets, then the operation's own.
// The token comes first, so that a caller without one learns nothing of the
// paths or the switch; the decode cap comes before the body is read.
func (a *API) serve(c *call) *answer {
	switch c.r.URL.Path {
	case "/v1/chatbot/messages":
		c.op = "messages"
	case "/v1/chatbot/notifications":
		c.op = "notifications"
	}
	slot, ok := a.authenticate(c.r)
	if !ok {
		return &answer{status: http.StatusUnauthorized, reason: "a bearer token of maap's is required"}
	}
	c.token = slot
	switch {
	case c.op == "other":
		return &answer{status: http.StatusNotFound, reason: "no such resource"}
	case c.r.Method != http.MethodPost:
		c.w.Header().Set("Allow", http.MethodPost)
		return &answer{status: http.StatusMethodNotAllowed, reason: "only POST is served"}
	case !a.cfg.On:
		return &answer{http.StatusServiceUnavailable, "the chatbot API is off", retryUnavailable}
	}
	select {
	case a.slots <- struct{}{}:
		c.holding = true
	default:
		// Waiting would hold the connection and its buffers, which is
		// what the cap bounds.
		a.metrics.Count("chatbot.api.decode_busy", 1)
		return &answer{http.StatusServiceUnavailable, "too many bodies are being read", retryBusy}
	}
	if ct, _, err := mime.ParseMediaType(c.r.Header.Get("Content-Type")); err != nil || ct != "application/json" {
		return &answer{status: http.StatusUnsupportedMediaType, reason: "the body must be application/json"}
	}
	if c.op == "messages" {
		return a.message(c)
	}
	return a.notification(c)
}

func (a *API) message(c *call) *answer {
	var m chatbot.BotMessage
	if ans := decode(c, chatbot.MaxBotMessageBytes, &m); ans != nil {
		return ans
	}
	c.releaseSlot()
	return accepted(a.acceptor.AcceptMessage(c.r.Context(), m))
}

func (a *API) notification(c *call) *answer {
	var n chatbot.BotNotification
	if ans := decode(c, chatbot.MaxBotNotificationBytes, &n); ans != nil {
		return ans
	}
	c.releaseSlot()
	return accepted(a.acceptor.AcceptNotification(c.r.Context(), n))
}

// decode reads the call's body into v, which DecodeEnvelope validates.
func decode(c *call, maxBytes int64, v any) *answer {
	// A writer without a connection, a test recorder, has no deadline to
	// set and none to wait on.
	_ = http.NewResponseController(c.w).SetReadDeadline(time.Now().Add(bodyTime(maxBytes)))
	err := chatbot.DecodeEnvelope(c.r.Body, maxBytes, v)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, chatbot.ErrBodyTooLarge):
		return &answer{status: http.StatusRequestEntityTooLarge, reason: "the body is over " + strconv.FormatInt(maxBytes>>10, 10) + " KiB"}
	case errors.Is(err, chatbot.ErrInvalidEnvelope):
		// The package's errors name the rule broken, never the value.
		return &answer{status: http.StatusBadRequest, reason: err.Error()}
	}
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		// The body's own deadline (bodyTime) passed.
		return &answer{status: http.StatusRequestTimeout, reason: "the body did not arrive in time"}
	}
	return &answer{status: http.StatusBadRequest, reason: "the body could not be read"}
}

func accepted(err error) *answer {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrUnavailable):
		return &answer{http.StatusServiceUnavailable, "rcs-as cannot take it now", retryUnavailable}
	}
	return &answer{status: http.StatusInternalServerError, reason: "internal error"}
}

// authenticate checks the bearer token against maap's two (ADR 0007 §4): as
// SHA-256 digests, in constant time and without stopping at a match, so
// that neither its length nor which one it matches shows in the timing.
func (a *API) authenticate(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	var token string
	if len(values) == 1 {
		if scheme, t, ok := strings.Cut(values[0], " "); ok && strings.EqualFold(scheme, "Bearer") {
			token = t
		}
	}
	if token == "" {
		return "", false
	}
	presented := sha256.Sum256([]byte(token))
	matched := -1
	for i := range a.tokens {
		matched = subtle.ConstantTimeSelect(subtle.ConstantTimeCompare(presented[:], a.tokens[i].digest[:]), i, matched)
	}
	if matched < 0 {
		return "", false
	}
	return a.tokens[matched].slot, true
}

// writeAnswer answers {"error": "<reason>"}. It closes the connection:
// most answers come before the body is read, and net/http would otherwise
// read up to 256 KiB of it before the status line, so a body still arriving
// would hold the answer back (#723 review).
func writeAnswer(w http.ResponseWriter, ans *answer) {
	h := w.Header()
	if ans.status == http.StatusUnauthorized {
		h.Set("WWW-Authenticate", `Bearer realm="rcs-as"`)
	}
	if ans.retryAfter != "" {
		h.Set("Retry-After", ans.retryAfter)
	}
	h.Set("Content-Type", "application/json")
	h.Set("Connection", "close")
	w.WriteHeader(ans.status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": ans.reason})
}

// statusRecorder keeps the first status written, the one net/http sends,
// for the audit line and the metric (0 until then).
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the connection (decode's read
// deadline).
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
