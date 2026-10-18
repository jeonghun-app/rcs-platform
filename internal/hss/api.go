package hss

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/hss/ifcjson"
	"github.com/jeonghun-app/rcs-platform/internal/hss/keyring"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// Scope is what a caller of the provisioning API may do (ADR 0007 §3; the
// table is in docs/api/hss-scopes.md).
type Scope uint8

// Scopes.
const (
	// ScopeAdmin is the operator: all provisioning, including writing keys,
	// which are never returned.
	ScopeAdmin Scope = 1 << iota
	// ScopeACS is acs: read a subscription and issue its IMS and FT
	// credentials.
	ScopeACS
	// ScopeFT is ft-server: read the FT credential.
	ScopeFT
)

func (s Scope) String() string {
	switch s {
	case ScopeAdmin:
		return "admin"
	case ScopeACS:
		return "acs"
	case ScopeFT:
		return "ft-server"
	}
	return "none"
}

// Tokens are the bearer tokens the API accepts, up to two per caller so a
// token can rotate without downtime (ADR 0007 §4): current and next.
type Tokens struct {
	Admin, ACS, FT []string
}

// MinTokenLength is the shortest token accepted in staging and prod: 256
// bits as 43 base64url characters, the shortest common encoding (ADR 0007
// §4). Hex encodings are longer.
const MinTokenLength = 43

// Body limits. A subscription at the model's limits is under 16 KiB; a
// service profile at ifcjson's limits stays well under 256 KiB.
const (
	maxSubscriptionBody = 64 << 10
	maxProfileBody      = 256 << 10
	maxSmallBody        = 4 << 10
)

// DefaultPushTimeout bounds the RTR and PPR a provisioning request causes.
const DefaultPushTimeout = 5 * time.Second

// APIOptions configures the provisioning API.
type APIOptions struct {
	Tokens Tokens
	// ACSRate and ACSBurst limit each acs token: requests per second and
	// the burst allowed (ADR 0007: a leaked acs token must not let its holder
	// harvest credentials quickly). Zero rate means DefaultACSRate.
	ACSRate  float64
	ACSBurst int
	// Notifier sends RTR and PPR after provisioning changes; nil sends
	// nothing.
	Notifier Notifier
	// DefaultProfile is used by subscriptions created without one.
	DefaultProfile string
	// PushTimeout bounds the requests one change causes.
	PushTimeout time.Duration
	// FanoutWorkers bounds the PPRs sent at once after a shared profile
	// changes; 8 when zero.
	FanoutWorkers int
	// StoreTimeout bounds the store work of one request, lock waits
	// included; DefaultAPIStoreTimeout when zero.
	StoreTimeout time.Duration
	// Now is the clock of the rate limits; time.Now when nil.
	Now func() time.Time
}

// DefaultAPIStoreTimeout bounds the store work of one API request. Without
// it a request whose store calls are slow would hold its subscriber's lock,
// and so delay Cx for every subscriber of the stripe, for as long as the
// SDK retries.
const DefaultAPIStoreTimeout = 5 * time.Second

// Defaults of the acs rate limit: provisioning a subscriber takes a few
// requests, and acs provisions at the pace clients configure themselves.
const (
	DefaultACSRate  = 20
	DefaultACSBurst = 40
)

type acceptedToken struct {
	digest [sha256.Size]byte
	scope  Scope
	// slot is "current" or "next", for the audit log of a rotation.
	slot string
	// limit is the token's rate limit, nil for none.
	limit *bucket
}

// API is the HSS provisioning API under /v1/ (docs/api/hss.yaml).
type API struct {
	h              *HSS
	mux            *http.ServeMux
	tokens         []*acceptedToken
	configured     Scope
	notifier       Notifier
	defaultProfile string
	pushTimeout    time.Duration
	storeTimeout   time.Duration
	workers        int

	mu      sync.Mutex
	fanouts map[string]context.CancelFunc
	wg      sync.WaitGroup
	closing context.Context
	close   context.CancelFunc
}

// NewAPI returns the provisioning API of h.
func (h *HSS) NewAPI(o APIOptions) *API {
	a := &API{
		h: h, mux: http.NewServeMux(), notifier: o.Notifier, defaultProfile: o.DefaultProfile,
		pushTimeout: o.PushTimeout, workers: o.FanoutWorkers, fanouts: map[string]context.CancelFunc{},
	}
	if a.pushTimeout <= 0 {
		a.pushTimeout = DefaultPushTimeout
	}
	if a.workers <= 0 {
		a.workers = 8
	}
	a.storeTimeout = o.StoreTimeout
	if a.storeTimeout <= 0 {
		a.storeTimeout = DefaultAPIStoreTimeout
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	rate, burst := o.ACSRate, o.ACSBurst
	if rate <= 0 {
		rate = DefaultACSRate
	}
	if burst <= 0 {
		burst = DefaultACSBurst
	}
	a.closing, a.close = context.WithCancel(context.Background())
	add := func(scope Scope, list []string) {
		for i, t := range list {
			if t == "" {
				continue
			}
			at := &acceptedToken{digest: sha256.Sum256([]byte(t)), scope: scope, slot: "current"}
			if i > 0 {
				at.slot = "next"
			}
			if scope == ScopeACS {
				at.limit = newBucket(rate, burst, now)
			}
			a.tokens = append(a.tokens, at)
			a.configured |= scope
		}
	}
	add(ScopeAdmin, o.Tokens.Admin)
	add(ScopeACS, o.Tokens.ACS)
	add(ScopeFT, o.Tokens.FT)

	admin, acs, ft := ScopeAdmin, ScopeAdmin|ScopeACS, ScopeFT
	a.route("POST /v1/subscriptions", "create_subscription", admin, a.createSubscription)
	a.route("GET /v1/subscriptions/{impi}", "get_subscription", acs, a.getSubscription)
	a.route("PUT /v1/subscriptions/{impi}", "put_subscription", admin, a.putSubscription)
	a.route("DELETE /v1/subscriptions/{impi}", "delete_subscription", admin, a.deleteSubscription)
	a.route("PUT /v1/subscriptions/{impi}/aka", "put_aka", admin, a.putAKA)
	a.route("POST /v1/subscriptions/{impi}/digest-credential", "issue_ims_credential", acs, a.issueIMSCredential)
	a.route("POST /v1/subscriptions/{impi}/ft-credential", "issue_ft_credential", acs, a.issueFTCredential)
	a.route("GET /v1/subscriptions/{impi}/ft-credential", "get_ft_credential", ft, a.getFTCredential)
	a.route("POST /v1/service-profiles", "create_profile", admin, a.createProfile)
	a.route("GET /v1/service-profiles/{id}", "get_profile", admin, a.getProfile)
	a.route("PUT /v1/service-profiles/{id}", "put_profile", admin, a.putProfile)
	a.route("DELETE /v1/service-profiles/{id}", "delete_profile", admin, a.deleteProfile)
	return a
}

// ServeHTTP implements http.Handler.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	a.mux.ServeHTTP(w, r)
}

// Close stops the profile fan-outs still running and waits for them.
func (a *API) Close(ctx context.Context) error {
	a.close()
	done := make(chan struct{})
	go func() { a.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// apiError is an answer other than success. Messages say what is wrong
// with the request without quoting it: it holds subscriber identities.
type apiError struct {
	status  int
	message string
}

func (e *apiError) Error() string { return e.message }

func fail(status int, message string) error { return &apiError{status, message} }

type handler func(w http.ResponseWriter, r *http.Request, caller Scope) error

func (a *API) route(pattern, name string, allowed Scope, h handler) {
	a.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		ctx, cancel := context.WithTimeout(r.Context(), a.storeTimeout)
		defer cancel()
		r = r.WithContext(ctx)
		tok, err := a.authenticate(r, allowed)
		var caller Scope
		if tok != nil {
			caller = tok.scope
		}
		if err == nil {
			err = h(rec, r, caller)
		}
		if err != nil {
			a.writeError(rec, err)
		}
		a.h.metrics.Count("api."+name+"."+strconv.Itoa(rec.status), 1)
		a.h.metrics.Timing("api."+name, time.Since(start))
		a.audit(r, name, tok, rec.status)
	})
}

// audit logs who did what to which subscription (ADR 0007 §3): every
// request authenticated with a token, the token's slot, and the outcome.
// The IMPI is masked like every identifier; the path, the body and the
// token itself are never logged.
func (a *API) audit(r *http.Request, operation string, tok *acceptedToken, status int) {
	attrs := []slog.Attr{slog.String("operation", operation), slog.Int("status", status)}
	if tok != nil {
		attrs = append(attrs, slog.String("caller", tok.scope.String()), slog.String("token", tok.slot))
	} else {
		attrs = append(attrs, slog.String("caller", "unauthenticated"))
	}
	if impi := r.PathValue("impi"); impi != "" {
		attrs = append(attrs, pii.Identity("impi", impi))
	}
	if id := r.PathValue("id"); id != "" {
		attrs = append(attrs, slog.String("profile", pii.Redact(id)))
	}
	a.h.log.LogAttrs(r.Context(), slog.LevelInfo, "audit: provisioning request", attrs...)
}

// authenticate checks the bearer token (ADR 0007 §4): the presented token
// and every accepted one are compared as SHA-256 digests, in constant time
// and without stopping at a match, so neither the length nor the position of
// a token shows in the timing. It returns the matching token, if any, with
// the outcome: 503 when no token may use the operation, 401 for a missing or
// unknown token, 403 outside the token's scope and 429 over its rate limit.
func (a *API) authenticate(r *http.Request, allowed Scope) (*acceptedToken, error) {
	if a.configured&allowed == 0 {
		return nil, fail(http.StatusServiceUnavailable, "no token is configured for this operation")
	}
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return nil, fail(http.StatusUnauthorized, "a bearer token is required")
	}
	presented := sha256.Sum256([]byte(token))
	matched := -1
	for i, t := range a.tokens {
		match := subtle.ConstantTimeCompare(presented[:], t.digest[:])
		matched = subtle.ConstantTimeSelect(match, i, matched)
	}
	if matched < 0 {
		return nil, fail(http.StatusUnauthorized, "the bearer token is not accepted")
	}
	tok := a.tokens[matched]
	if tok.scope&allowed == 0 {
		return tok, fail(http.StatusForbidden, "the token's caller may not use this operation")
	}
	if tok.limit != nil && !tok.limit.allow() {
		a.h.metrics.Count("api.rate_limited", 1)
		return tok, &apiError{http.StatusTooManyRequests, "the token's rate limit is exceeded"}
	}
	return tok, nil
}

// bucket is a token bucket: rate requests per second, up to burst at once.
type bucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newBucket(rate float64, burst int, now func() time.Time) *bucket {
	return &bucket{rate: rate, burst: float64(burst), tokens: float64(burst), last: now(), now: now}
}

func (b *bucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.now()
	if elapsed := t.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(b.burst, b.tokens+elapsed*b.rate)
	}
	b.last = t
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// managedByACS refuses acs access to a subscription the operator has not
// handed to it (ADR 0007 §3). The admin token is not limited.
//
// acs gets the same answer for such a subscription as for one that does not
// exist: a different one would let an acs token enumerate which IMSI-based
// IMPIs the operator provisions outside acs.
func managedByACS(caller Scope, s *store.Subscription) error {
	if caller == ScopeACS && !s.ACSManaged {
		return errNotFound
	}
	return nil
}

// errNotFound is the answer for a subscription or profile that does not
// exist, and what classify gives store.ErrNotFound.
var errNotFound = &apiError{http.StatusNotFound, "not found"}

// writeError answers err. Errors the API has no specific answer for are
// store failures: 503, so that callers retry (an outage, throttling or a
// timeout is transient), with the cause logged, redacted. Unusable stored
// data is 500 instead (classify).
func (a *API) writeError(w http.ResponseWriter, err error) {
	var ae *apiError
	if !errors.As(err, &ae) {
		ae = a.classify(err)
	}
	if ae.status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="hss"`)
	}
	if ae.status == http.StatusServiceUnavailable || ae.status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "1")
	}
	writeJSON(w, ae.status, map[string]string{"error": ae.message})
}

func (a *API) classify(err error) *apiError {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return errNotFound
	case errors.Is(err, store.ErrExists):
		return &apiError{http.StatusConflict, "already exists"}
	case errors.Is(err, store.ErrIdentityInUse):
		return &apiError{http.StatusConflict, "a public identity belongs to another subscription"}
	case errors.Is(err, store.ErrProfileMissing):
		return &apiError{http.StatusUnprocessableEntity, "the service profile does not exist"}
	case errors.Is(err, store.ErrProfileInUse):
		return &apiError{http.StatusConflict, "the service profile is in use"}
	case errors.Is(err, errPrecondition):
		return &apiError{http.StatusPreconditionFailed, "the version does not match If-Match"}
	case errors.Is(err, errBusy), errors.Is(err, errContention):
		return &apiError{http.StatusServiceUnavailable, "the subscription is busy; retry"}
	case errors.Is(err, store.ErrInvalid), errors.Is(err, keyring.ErrCorrupt), errors.Is(err, keyring.ErrUnknownKey):
		// A record that does not decode or a secret that does not open will
		// not get better by retrying: 500, without Retry-After, counted
		// apart from store outages.
		a.h.metrics.Count("api.data_error", 1)
		a.h.log.Error("provisioning request found unusable data", slog.String("error", pii.Redact(err.Error())))
		return &apiError{http.StatusInternalServerError, "the stored subscription cannot be used; see the HSS log"}
	}
	a.h.metrics.Count("api.store_failure", 1)
	a.h.log.Error("provisioning request failed", slog.String("error", pii.Redact(err.Error())))
	return &apiError{http.StatusServiceUnavailable, "the subscriber store is unavailable; retry"}
}

var errPrecondition = errors.New("hss: If-Match does not match the stored version")

// ifMatch reads an If-Match header of the form the API's ETags take
// ("<version>"): 0 when absent.
func ifMatch(r *http.Request) (int64, error) {
	v := r.Header.Get("If-Match")
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(strings.Trim(v, `"`), 10, 64)
	if err != nil || n <= 0 || len(v) < 3 || v[0] != '"' || v[len(v)-1] != '"' {
		return 0, fail(http.StatusBadRequest, "If-Match is not an entity tag of this API")
	}
	return n, nil
}

func etag(version int64) string { return `"` + strconv.FormatInt(version, 10) + `"` }

// decodeBody reads a JSON request body of at most limit bytes strictly.
func decodeBody(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || ct != "application/json" {
		return fail(http.StatusUnsupportedMediaType, "the body must be application/json")
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return fail(http.StatusRequestEntityTooLarge, "the body is larger than "+strconv.FormatInt(limit, 10)+" bytes")
	}
	if err != nil {
		return fail(http.StatusBadRequest, "the body could not be read")
	}
	if err := ifcjson.DecodeStrict(body, v); err != nil {
		return fail(http.StatusBadRequest, "the body is not valid: "+err.Error())
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

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

// pushContext is the context of the S-CSCF requests a change causes: they
// run after the change is stored, so a client that goes away does not cut
// them short.
func (a *API) pushContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), a.pushTimeout)
}
