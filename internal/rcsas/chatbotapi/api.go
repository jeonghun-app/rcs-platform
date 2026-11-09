// Package chatbotapi is rcs-as's chatbot API, which maap alone calls (ADR
// 0009 §4, §6, §7, §12): POST /v1/chatbot/messages and
// /v1/chatbot/notifications, on a listener of its own apart from SIP and
// admin (ADR 0007 §2). maap faces the internet and the core does not trust
// it, so this is where its requests are bounded: maap's token, strict bodies
// (internal/chatbot), refusals outside its scope and per-task backstops
// (§9). A compromised maap can then speak for chatbots only, to subscribers
// only, and only so fast.
//
// #698 builds it in three steps: the listener, the token and the switch
// first; then the decoding of bodies; then the scope and the backstops.
// Until the second, an authenticated request with the switch on is 503.
package chatbotapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
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

// retryUnavailable is the Retry-After of a 503 for the switch.
const retryUnavailable = "5"

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
}

// API serves the chatbot API. It is safe for concurrent use.
type API struct {
	cfg     Config
	tokens  []acceptedToken
	log     *slog.Logger
	metrics *runtime.Metrics
}

type acceptedToken struct {
	digest [sha256.Size]byte
	// slot is "current" or "next", for the audit line of a rotation.
	slot string
}

// New returns the API of cfg.
func New(cfg Config, logger *slog.Logger, m *runtime.Metrics) *API {
	a := &API{cfg: cfg, log: logger, metrics: m}
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

// Server returns an HTTP server of the API. WriteTimeout leaves a request
// time for the store calls that accepting it will take (#699).
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

// call is one request.
type call struct {
	w         *statusRecorder
	r         *http.Request
	op, token string
}

// ServeHTTP answers every request, in the order of checks in
// docs/rcs-as.md, and writes one audit line for it.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	c := &call{w: &statusRecorder{ResponseWriter: w}, r: r, op: "other", token: "none"}
	// Deferred, so that a panic leaves its audit line too; net/http then
	// ends the connection, as for any panic (#723 review).
	defer func() {
		p := recover()
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
	writeAnswer(c.w, a.serve(c))
}

// serve runs the checks every request meets. The token comes first, so
// that a caller without one learns nothing of the paths or the switch.
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
	// Bodies are decoded in the next step of #698.
	return &answer{http.StatusServiceUnavailable, "rcs-as takes no chatbot request yet", retryUnavailable}
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
