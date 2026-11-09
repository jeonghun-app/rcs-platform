package maap

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

// scope is what a caller of the internal listener may do (ADR 0009 §7; the
// table is in docs/api/maap-scopes.md).
type scope uint8

// scopeOperator is the operator: registry, credentials, webhook settings,
// permissions, limits, blocks and number recycling. #683 adds rcs-as's.
const scopeOperator scope = 1 << iota

func (s scope) String() string {
	if s == scopeOperator {
		return "operator"
	}
	return "none"
}

// maxOperatorBody bounds an operator request body (ADR 0009 §9).
const maxOperatorBody = 16 << 10

// apiError is an answer other than success. Messages say what is wrong
// with the request without quoting it.
type apiError struct {
	status     int
	message    string
	retryAfter string
}

func (e *apiError) Error() string { return e.message }

func fail(status int, message string) error { return &apiError{status: status, message: message} }

// decoder bounds the request bodies decoded and validated at once in a
// task, across every listener: chatbot.DecodeEnvelope allocates about 8
// bytes per input byte and chatbot.ValidateContent up to about 30, so one
// send of #683 may take about 20 MB (#682). docs/maap.md has the rule the
// cap and the task's memory follow.
type decoder struct {
	slots   chan struct{}
	metrics *runtime.Metrics
}

func newDecoder(n int, m *runtime.Metrics) *decoder {
	return &decoder{slots: make(chan struct{}, n), metrics: m}
}

// tryAcquire takes a slot if one is free, without waiting.
func (d *decoder) tryAcquire() (release func(), ok bool) {
	select {
	case d.slots <- struct{}{}:
		return sync.OnceFunc(func() { <-d.slots }), true
	default:
		return nil, false
	}
}

// decode reads r's body, at most maxBytes, into v with chatbot.DecodeEnvelope.
// With no slot free it answers 503 with Retry-After at once, before the body
// is read: waiting would hold the connection and its buffers, which is what
// the cap bounds. On success the caller holds the slot until it has
// validated what it decoded, and then calls release; on an error the slot is
// already free.
func (d *decoder) decode(r *http.Request, maxBytes int64, v any) (release func(), err error) {
	release, ok := d.tryAcquire()
	if !ok {
		d.metrics.Count("api.decode_busy", 1)
		return nil, &apiError{http.StatusServiceUnavailable, "too many request bodies are being read", "1"}
	}
	if err := chatbot.DecodeEnvelope(r.Body, maxBytes, v); err != nil {
		release()
		switch {
		case errors.Is(err, chatbot.ErrBodyTooLarge):
			return nil, fail(http.StatusRequestEntityTooLarge, "the body is larger than "+strconv.FormatInt(maxBytes>>10, 10)+" KiB")
		case errors.Is(err, chatbot.ErrInvalidEnvelope):
			// The package's errors name the rule broken, never the value.
			return nil, fail(http.StatusBadRequest, err.Error())
		}
		return nil, fail(http.StatusBadRequest, "the body could not be read")
	}
	return release, nil
}

// refuseControls refuses an envelope string that a handler writes into a
// header (SIP, CPIM, HTTP) or a log. DecodeEnvelope bounds every string but
// not what it holds: an escape such as \r\n decodes to CR LF, which would
// end a header block, and a NUL may cut it short (#687 review). C0
// controls and DEL are refused, tab included. Content is not such a string:
// chatbot.ValidateContent checks it. The answer names field, never the value.
func refuseControls(field, v string) error {
	for i := 0; i < len(v); i++ {
		if c := v[i]; c < 0x20 || c == 0x7f {
			return fail(http.StatusBadRequest, field+" holds a control character")
		}
	}
	return nil
}

type acceptedToken struct {
	digest [sha256.Size]byte
	scope  scope
	// slot is "current" or "next", for the audit log of a rotation.
	slot string
}

// internalAPI is the internal listener's handler: the operator API, and
// rcs-as's API once #683 adds it. It never mounts the public chatbot API,
// so that neither is reachable through the other (ADR 0009 §7, memo G1).
type internalAPI struct {
	mux     *http.ServeMux
	tokens  []acceptedToken
	decoder *decoder
	log     *slog.Logger
	metrics *runtime.Metrics
}

func newInternalAPI(operator TokenPair, d *decoder, rt *runtime.Runtime) *internalAPI {
	a := &internalAPI{mux: http.NewServeMux(), decoder: d, log: rt.Logger, metrics: rt.Metrics}
	for _, t := range []struct {
		value TokenPair
		scope scope
	}{{operator, scopeOperator}} {
		if !t.value.Current.IsZero() {
			a.tokens = append(a.tokens, acceptedToken{sha256.Sum256(t.value.Current.Reveal()), t.scope, "current"})
		}
		if !t.value.Next.IsZero() {
			a.tokens = append(a.tokens, acceptedToken{sha256.Sum256(t.value.Next.Reveal()), t.scope, "next"})
		}
	}
	return a
}

// ServeHTTP implements http.Handler. A path no route serves is 404.
func (a *internalAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	a.mux.ServeHTTP(w, r)
}

type handler func(w http.ResponseWriter, r *http.Request) error

// route serves h at pattern for the callers in allowed. The token is
// checked before h runs, so before any body is read.
func (a *internalAPI) route(pattern, name string, allowed scope, h handler) {
	a.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		tok, err := a.authenticate(r, allowed)
		if err == nil {
			err = h(rec, r)
		}
		if err != nil {
			writeError(rec, err)
		}
		a.metrics.Count("api."+name+"."+strconv.Itoa(rec.status), 1)
		attrs := []slog.Attr{slog.String("operation", name), slog.Int("status", rec.status)}
		if tok != nil {
			attrs = append(attrs, slog.String("caller", tok.scope.String()), slog.String("token", tok.slot))
		} else {
			attrs = append(attrs, slog.String("caller", "unauthenticated"))
		}
		// The path, the body and the token are never logged.
		a.log.LogAttrs(r.Context(), slog.LevelInfo, "audit: internal request", attrs...)
	})
}

// authenticate checks the bearer token (ADR 0007 §4): the presented token
// and every accepted one are compared as SHA-256 digests, in constant time
// and without stopping at a match, so neither its length nor which caller it
// belongs to shows in the timing. 503 when no token is configured, 401 for
// a missing or unknown token, 403 outside the token's scope.
func (a *internalAPI) authenticate(r *http.Request, allowed scope) (*acceptedToken, error) {
	if len(a.tokens) == 0 {
		return nil, fail(http.StatusServiceUnavailable, "no token is configured")
	}
	values := r.Header.Values("Authorization")
	var token string
	if len(values) == 1 {
		scheme, t, ok := strings.Cut(values[0], " ")
		// The length check keeps EqualFold to ASCII ("K", Kelvin, folds to k).
		if ok && len(scheme) == len("Bearer") && strings.EqualFold(scheme, "Bearer") {
			token = t
		}
	}
	if token == "" {
		return nil, fail(http.StatusUnauthorized, "a bearer token is required")
	}
	presented := sha256.Sum256([]byte(token))
	matched := -1
	for i := range a.tokens {
		match := subtle.ConstantTimeCompare(presented[:], a.tokens[i].digest[:])
		matched = subtle.ConstantTimeSelect(match, i, matched)
	}
	if matched < 0 {
		return nil, fail(http.StatusUnauthorized, "the bearer token is not accepted")
	}
	tok := &a.tokens[matched]
	if tok.scope&allowed == 0 {
		return tok, fail(http.StatusForbidden, "the token's caller may not use this operation")
	}
	return tok, nil
}

// writeError answers err as {"error": "..."}. An error without an answer of
// its own is 500; later handlers classify store failures before this.
func writeError(w http.ResponseWriter, err error) {
	var ae *apiError
	if !errors.As(err, &ae) {
		ae = &apiError{status: http.StatusInternalServerError, message: "internal error"}
	}
	h := w.Header()
	if ae.status == http.StatusUnauthorized {
		h.Set("WWW-Authenticate", `Bearer realm="maap"`)
	}
	if ae.retryAfter != "" {
		h.Set("Retry-After", ae.retryAfter)
	}
	h.Set("Content-Type", "application/json")
	w.WriteHeader(ae.status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": ae.message})
}

// statusRecorder keeps the status a handler answered, for the audit log
// and the metric.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
