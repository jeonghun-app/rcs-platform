package msrprelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/store"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// maxControlBody bounds a control request body. The largest valid one is two
// one-URI paths and a number, well under 2 KiB.
const maxControlBody = 4 << 10

// coreLocalPort is the port of every core_path_local. The relay connects
// toward rcs-as and never listens on the core side, so it offers active
// with port 9 there (ADR 0004, RFC 6135 §4.2.2); RFC 4975 §8.1 makes the
// URI's port match the m= line's.
const coreLocalPort = 9

// controlOptions configure a control API handler.
type controlOptions struct {
	Store        store.Store
	StoreTimeout time.Duration
	// Public is the client-facing authority; CoreHost the core-side address.
	Public   msrp.URI
	CoreHost netip.Addr
	// CoreNetworks, Namespace and CorePorts say which core_path hosts and
	// ports are allowed.
	CoreNetworks []netip.Prefix
	CorePorts    []uint16
	Namespace    string
	MaxExpiresIn time.Duration
	Tokens       []string
	Clock        msrp.Clock
	Rand         io.Reader
	Log          *slog.Logger
	Metrics      *counters
}

// control is the control API pcscf allocates bindings through (ADR 0004;
// docs/api/msrp-relay.yaml).
type control struct {
	o    controlOptions
	auth *authorizer
	mux  *http.ServeMux
}

func newControl(o controlOptions) *control {
	c := &control{o: o, auth: newAuthorizer(o.Tokens), mux: http.NewServeMux()}
	c.mux.HandleFunc("POST /v1/bindings", c.scoped(opCreate, c.create))
	c.mux.HandleFunc("PATCH /v1/bindings/{id}", c.scoped(opUpdate, c.update))
	c.mux.HandleFunc("DELETE /v1/bindings/{id}", c.scoped(opDelete, c.remove))
	// The mux's own 404 and 405 answers are plain text; these keep every
	// answer JSON.
	c.mux.HandleFunc("/v1/bindings", notAllowed("POST"))
	c.mux.HandleFunc("/v1/bindings/{id}", notAllowed("PATCH, DELETE"))
	c.mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { writeError(w, http.StatusNotFound, "no such resource") })
	return c
}

func notAllowed(allow string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", allow)
		writeError(w, http.StatusMethodNotAllowed, "allowed methods: "+allow)
	}
}

// ServeHTTP authenticates before routing, so a caller without a token
// learns nothing about the API, not even which paths exist.
func (c *control) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if len(c.auth.callers) == 0 {
		writeError(w, http.StatusServiceUnavailable, "no control token is configured")
		return
	}
	who := c.auth.authenticate(r)
	if who == nil {
		c.o.Metrics.refuse(reasonUnauthorized)
		w.Header().Set("WWW-Authenticate", `Bearer realm="msrp-relay"`)
		writeError(w, http.StatusUnauthorized, "a valid bearer token is required")
		return
	}
	c.mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, who)))
}

type callerKey struct{}

// scoped refuses a caller whose token does not cover op (ADR 0007 §3).
func (c *control) scoped(op string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		who, _ := r.Context().Value(callerKey{}).(*caller)
		if who == nil || !who.allows(op) {
			c.o.Metrics.refuse(reasonForbidden)
			writeError(w, http.StatusForbidden, "this token does not allow "+op)
			return
		}
		h(w, r)
	}
}

// bindingRequest is the body of POST and PATCH. A path is a list of URIs,
// as in a=path; nil means "not given".
type bindingRequest struct {
	CorePath           []string `json:"core_path"`
	ClientEndpointPath []string `json:"client_endpoint_path"`
	ExpiresIn          *int64   `json:"expires_in"`
}

type bindingResponse struct {
	ID            string `json:"id"`
	ClientPath    string `json:"client_path,omitempty"`
	CorePathLocal string `json:"core_path_local,omitempty"`
	ExpiresAt     string `json:"expires_at"`
}

func (c *control) create(w http.ResponseWriter, r *http.Request) {
	req, ok := c.decode(w, r)
	if !ok {
		return
	}
	if req.ExpiresIn == nil {
		c.invalid(w, "expires_in is required")
		return
	}
	u, ok := c.validate(w, req)
	if !ok {
		return
	}
	clientSID, err := msrp.NewSessionID(c.o.Rand)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "no randomness")
		return
	}
	coreSID, err := msrp.NewSessionID(c.o.Rand)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "no randomness")
		return
	}
	clientURI := c.o.Public
	clientURI.SessionID = clientSID
	coreLocal := msrp.URI{Host: c.o.CoreHost.String(), Port: coreLocalPort, SessionID: coreSID, Transport: "tcp"}
	b := store.Binding{
		ID:                 BindingID(clientSID),
		CorePath:           u.CorePath,
		ClientEndpointPath: u.ClientEndpointPath,
		CoreLocal:          coreLocal.String(),
		ExpiresAt:          u.ExpiresAt,
	}
	ctx, cancel := context.WithTimeout(r.Context(), c.o.StoreTimeout)
	defer cancel()
	// A taken id would need a SHA-256 collision between two 160-bit random
	// session ids; it is an error, not something to retry.
	if err := c.o.Store.Create(ctx, b); err != nil {
		c.storeFailed(w, "create", err)
		return
	}
	c.o.Metrics.add(mBindingsCreated, 1)
	c.o.Log.Debug("binding created", slog.String("binding", b.ID))
	w.Header().Set("Location", "/v1/bindings/"+b.ID)
	writeJSON(w, http.StatusCreated, bindingResponse{
		ID:            b.ID,
		ClientPath:    clientURI.String(),
		CorePathLocal: b.CoreLocal,
		ExpiresAt:     formatTime(b.ExpiresAt),
	})
}

func (c *control) update(w http.ResponseWriter, r *http.Request) {
	id, ok := c.bindingID(w, r)
	if !ok {
		return
	}
	req, ok := c.decode(w, r)
	if !ok {
		return
	}
	if req.ExpiresIn == nil && req.CorePath == nil && req.ClientEndpointPath == nil {
		c.invalid(w, "nothing to change: give expires_in, core_path or client_endpoint_path")
		return
	}
	u, ok := c.validate(w, req)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), c.o.StoreTimeout)
	defer cancel()
	b, err := c.o.Store.Update(ctx, id, u, c.o.Clock.Now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such binding, or it has expired")
		return
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "a path is already set to another value; a new path needs a new binding")
		return
	case err != nil:
		c.storeFailed(w, "update", err)
		return
	}
	writeJSON(w, http.StatusOK, bindingResponse{ID: b.ID, ExpiresAt: formatTime(b.ExpiresAt)})
}

func (c *control) remove(w http.ResponseWriter, r *http.Request) {
	id, ok := c.bindingID(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), c.o.StoreTimeout)
	defer cancel()
	err := c.o.Store.Delete(ctx, id, c.o.Clock.Now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such binding, or it has expired")
		return
	case err != nil:
		c.storeFailed(w, "delete", err)
		return
	}
	c.o.Metrics.add(mBindingsReleased, 1)
	c.o.Log.Debug("binding released", slog.String("binding", id))
	w.WriteHeader(http.StatusNoContent)
}

// bindingID reads the {id} of the path. One that cannot be an id is
// answered like a missing binding, without a store call.
func (c *control) bindingID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !validBindingID(id) {
		writeError(w, http.StatusNotFound, "no such binding, or it has expired")
		return "", false
	}
	return id, true
}

// decode reads one JSON object with no unknown fields.
func (c *control) decode(w http.ResponseWriter, r *http.Request) (bindingRequest, bool) {
	var req bindingRequest
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		c.o.Metrics.refuse(reasonInvalid)
		writeError(w, http.StatusUnsupportedMediaType, "the body must be application/json")
		return req, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxControlBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			c.o.Metrics.refuse(reasonInvalid)
			writeError(w, http.StatusRequestEntityTooLarge, "the body is too large")
			return req, false
		}
		writeError(w, http.StatusBadRequest, "the body could not be read")
		return req, false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		c.invalid(w, "the body is not a binding request: "+jsonProblem(err))
		return req, false
	}
	if dec.More() {
		c.invalid(w, "the body holds more than one JSON value")
		return req, false
	}
	// encoding/json matches field names regardless of case; the API's
	// names are exact (docs/api/msrp-relay.yaml).
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		c.invalid(w, "the body is not a binding request: malformed JSON")
		return req, false
	}
	for name := range fields {
		switch name {
		case "core_path", "client_endpoint_path", "expires_in":
		default:
			c.invalid(w, "the body is not a binding request: unknown field "+strconv.Quote(name))
			return req, false
		}
	}
	return req, true
}

// jsonProblem describes a decoding error without echoing the body, which
// may hold session ids.
func jsonProblem(err error) string {
	var typeErr *json.UnmarshalTypeError
	var syntaxErr *json.SyntaxError
	switch {
	case errors.As(err, &typeErr):
		return "wrong type for " + typeErr.Field
	case errors.As(err, &syntaxErr):
		return "malformed JSON"
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		return "unknown field " + strings.TrimPrefix(err.Error(), "json: unknown field ")
	}
	return "malformed JSON"
}

// validate turns a request into a store update, answering the caller when it
// is invalid.
func (c *control) validate(w http.ResponseWriter, req bindingRequest) (store.Update, bool) {
	var u store.Update
	if req.ExpiresIn != nil {
		n := *req.ExpiresIn
		if n < 1 || n > int64(c.o.MaxExpiresIn/time.Second) {
			c.invalid(w, "expires_in must be from 1 to "+formatSeconds(c.o.MaxExpiresIn))
			return u, false
		}
		u.ExpiresAt = c.o.Clock.Now().Add(time.Duration(n) * time.Second)
	}
	if req.CorePath != nil {
		p, problem := c.corePath(req.CorePath)
		if problem != "" {
			c.invalid(w, "core_path: "+problem)
			return u, false
		}
		u.CorePath = p
	}
	if req.ClientEndpointPath != nil {
		p, problem := clientEndpointPath(req.ClientEndpointPath)
		if problem != "" {
			c.invalid(w, "client_endpoint_path: "+problem)
			return u, false
		}
		u.ClientEndpointPath = p
	}
	return u, true
}

// onePath parses a path of exactly one URI with a session id. A longer path
// would put RFC 4976 relays between the relay and that endpoint, which this
// relay does not support.
func onePath(path []string) (msrp.URI, string) {
	if len(path) != 1 {
		return msrp.URI{}, "must hold exactly one URI (RFC 4976 relays are not supported)"
	}
	u, err := msrp.ParseURI(path[0])
	if err != nil {
		return msrp.URI{}, "not an MSRP URI"
	}
	// The relay speaks MSRP over TCP only (TLS on TCP included, §6).
	if !strings.EqualFold(u.Transport, "tcp") {
		return msrp.URI{}, "the transport must be tcp"
	}
	if u.SessionID == "" || u.Port == 0 {
		return msrp.URI{}, "the URI needs a port and a session id (RFC 4975 §8.2)"
	}
	return u, ""
}

// corePath checks rcs-as's path. The relay will connect to its host, so a
// pcscf that is compromised, or that copies a path it should not, must not
// be able to make the relay connect anywhere but rcs-as's port on a private
// address in the VPC (ADR 0007 §5); the dialer checks again after name
// resolution.
func (c *control) corePath(path []string) (string, string) {
	u, problem := onePath(path)
	if problem != "" {
		return "", problem
	}
	if u.Secure {
		return "", "msrps toward rcs-as is not supported (ADR 0007)"
	}
	if !slices.Contains(c.o.CorePorts, uint16(u.Port)) {
		return "", "the port is not in RELAY_CORE_PORTS"
	}
	if a, err := netip.ParseAddr(u.Host); err == nil {
		if !inNetworks(a, c.o.CoreNetworks) {
			return "", "the host is outside RELAY_CORE_NETWORKS"
		}
	} else if !inNamespace(u.Host, c.o.Namespace) {
		return "", "the host is neither an address in RELAY_CORE_NETWORKS nor a name in RCS_SERVICE_NAMESPACE"
	}
	return u.String(), ""
}

// clientEndpointPath checks the client's path. The relay never connects to
// it (ADR 0004); it is only the To-Path of what goes to the client, so any
// host is accepted.
func clientEndpointPath(path []string) (string, string) {
	u, problem := onePath(path)
	if problem != "" {
		return "", problem
	}
	return u.String(), ""
}

func inNetworks(a netip.Addr, networks []netip.Prefix) bool {
	a = a.Unmap()
	for _, p := range networks {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// inNamespace matches whole labels, so "evil-ns.internal" is not inside
// "ns.internal" (ADR 0007 §5).
func inNamespace(host, namespace string) bool {
	namespace = strings.TrimSuffix(strings.ToLower(namespace), ".")
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return namespace != "" && strings.HasSuffix(host, "."+namespace)
}

func (c *control) invalid(w http.ResponseWriter, problem string) {
	c.o.Metrics.refuse(reasonInvalid)
	writeError(w, http.StatusBadRequest, problem)
}

// storeFailed answers a store failure with 503: pcscf can retry, or fail the
// session setup, which is what it would do without a relay.
func (c *control) storeFailed(w http.ResponseWriter, op string, err error) {
	c.o.Metrics.add(mStoreErrors, 1)
	c.o.Log.Warn("binding store failed", slog.String("op", op), slog.String("error", pii.Redact(err.Error())))
	writeError(w, http.StatusServiceUnavailable, "the binding store is unavailable")
}

func formatTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z07:00") }

func formatSeconds(d time.Duration) string { return strconv.FormatInt(int64(d/time.Second), 10) }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
