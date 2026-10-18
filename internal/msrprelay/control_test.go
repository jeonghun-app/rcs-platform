package msrprelay

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/store"
)

const nextToken = "next-token-0123456789-0123456789-0123456789"

// newTestControl is a control API over a memory store, with pcscf's current
// and next tokens.
func newTestControl(t *testing.T, st store.Store) (*control, *fakeClock, *counters) {
	t.Helper()
	clock := newFakeClock()
	m := newCounters()
	return newControl(controlOptions{
		Store: st, StoreTimeout: time.Second,
		Public:       msrp.URI{Secure: true, Host: publicHost, Port: DefaultPublicPort, Transport: "tcp"},
		CoreHost:     coreHostAddr,
		CoreNetworks: privateRanges, Namespace: "rcs.internal",
		MaxExpiresIn: DefaultMaxExpiresIn, Tokens: []string{testToken, nextToken},
		Clock: clock, Rand: &sequence{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Metrics: m,
	}), clock, m
}

const asPath = "msrp://10.0.1.5:2855/as5e55ion;tcp"

func TestCreateReturnsTheRelayPathsAndStoresTheBinding(t *testing.T) {
	st := store.NewMemory()
	c, clock, m := newTestControl(t, st)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/bindings", strings.NewReader(`{"core_path":["`+asPath+`"],"expires_in":1800}`))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+testToken)
	c.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST = %d %s", rec.Code, rec.Body)
	}
	_, out := callControl(t, c, "POST", "/v1/bindings", testToken, map[string]any{"core_path": []string{asPath}, "expires_in": 1800})
	first, err := decodeBinding(rec.Body.String())
	if err != nil {
		t.Fatal(err)
	}

	client := mustURI(t, first.ClientPath)
	if !client.Secure || client.Host != publicHost || client.Port != DefaultPublicPort || client.Transport != "tcp" || len(client.SessionID) != 32 {
		t.Fatalf("client_path %s", first.ClientPath)
	}
	core := mustURI(t, first.CorePathLocal)
	if core.Secure || core.Host != coreHostAddr.String() || core.Port != coreLocalPort || len(core.SessionID) != 32 {
		t.Fatalf("core_path_local %s", first.CorePathLocal)
	}
	// The two sides have separate session ids: the core one passes through
	// the core's SIP and logs, and must not let anyone in as the client.
	if core.SessionID == client.SessionID || out["client_path"] == first.ClientPath {
		t.Fatal("session ids are reused")
	}
	if first.ID != BindingID(client.SessionID) || rec.Header().Get("Location") != "/v1/bindings/"+first.ID {
		t.Fatalf("id %s, Location %s", first.ID, rec.Header().Get("Location"))
	}
	if strings.Contains(first.ID, client.SessionID) {
		t.Fatal("the id reveals the session id")
	}
	if first.ExpiresAt != clock.Now().Add(1800*time.Second).UTC().Format("2006-01-02T15:04:05.000Z07:00") {
		t.Fatalf("expires_at %s", first.ExpiresAt)
	}
	b, err := st.Get(context.Background(), first.ID, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if b.CorePath != asPath || b.ClientEndpointPath != "" || b.CoreLocal != first.CorePathLocal || b.ClaimedBy != "" {
		t.Fatalf("stored %+v", b)
	}
	if got := m.count(mBindingsCreated); got != 2 {
		t.Fatalf("BindingsCreated = %d", got)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("an answer with session ids may be cached")
	}
}

type decodedBinding struct {
	ID, ClientPath, CorePathLocal, ExpiresAt string
}

func decodeBinding(body string) (decodedBinding, error) {
	var out struct {
		ID            string `json:"id"`
		ClientPath    string `json:"client_path"`
		CorePathLocal string `json:"core_path_local"`
		ExpiresAt     string `json:"expires_at"`
	}
	err := jsonUnmarshal(body, &out)
	return decodedBinding{out.ID, out.ClientPath, out.CorePathLocal, out.ExpiresAt}, err
}

func TestControlRequiresPcscfsToken(t *testing.T) {
	c, _, m := newTestControl(t, store.NewMemory())
	for _, tt := range []struct {
		name   string
		header []string
		want   int
	}{
		{"no header", nil, http.StatusUnauthorized},
		{"wrong token", []string{"Bearer " + strings.Repeat("x", 43)}, http.StatusUnauthorized},
		{"another scheme", []string{"Basic " + testToken}, http.StatusUnauthorized},
		{"no token", []string{"Bearer "}, http.StatusUnauthorized},
		{"two headers", []string{"Bearer " + testToken, "Bearer " + testToken}, http.StatusUnauthorized},
		{"a prefix of the token", []string{"Bearer " + testToken[:42]}, http.StatusUnauthorized},
		{"characters outside b64token", []string{"Bearer " + testToken + "!"}, http.StatusUnauthorized},
		{"padding inside", []string{"Bearer ab=cd"}, http.StatusUnauthorized},
		{"only padding", []string{"Bearer =="}, http.StatusUnauthorized},
		{"too long", []string{"Bearer " + strings.Repeat("t", maxTokenLength+1)}, http.StatusUnauthorized},
		{"current token", []string{"Bearer " + testToken}, http.StatusCreated},
		{"next token, during rotation", []string{"Bearer " + nextToken}, http.StatusCreated},
		{"scheme in another case", []string{"bearer " + testToken}, http.StatusCreated},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/v1/bindings", strings.NewReader(`{"expires_in":60}`))
			req.Header.Set("Content-Type", "application/json")
			for _, h := range tt.header {
				req.Header.Add("Authorization", h)
			}
			rec := httptest.NewRecorder()
			c.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status %d, want %d: %s", rec.Code, tt.want, rec.Body)
			}
			if tt.want == http.StatusUnauthorized && !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer") {
				t.Fatal("401 without a Bearer challenge")
			}
		})
	}
	if m.count(mRefusedPrefix+reasonUnauthorized) != 10 {
		t.Fatalf("Refused.ControlUnauthorized = %d", m.count(mRefusedPrefix+reasonUnauthorized))
	}
}

func TestUnauthenticatedCallersLearnNothingAboutRoutes(t *testing.T) {
	c, _, _ := newTestControl(t, store.NewMemory())
	for _, path := range []string{"/v1/bindings", "/nope", "/v1/bindings/x"} {
		if code, _ := callControl(t, c, "GET", path, "", nil); code != http.StatusUnauthorized {
			t.Fatalf("GET %s = %d, want 401", path, code)
		}
	}
	if code, _ := callControl(t, c, "GET", "/nope", testToken, nil); code != http.StatusNotFound {
		t.Fatalf("authenticated GET /nope = %d", code)
	}
	if code, _ := callControl(t, c, "GET", "/v1/bindings", testToken, nil); code != http.StatusMethodNotAllowed {
		t.Fatalf("authenticated GET /v1/bindings = %d", code)
	}
	if code, _ := callControl(t, c, "POST", "/v1/bindings/"+BindingID("x"), testToken, nil); code != http.StatusMethodNotAllowed {
		t.Fatalf("authenticated POST /v1/bindings/{id} = %d", code)
	}
}

func TestControlWithoutATokenRefusesEveryCall(t *testing.T) {
	c := newControl(controlOptions{Metrics: newCounters()})
	if code, out := callControl(t, c, "POST", "/v1/bindings", testToken, map[string]any{"expires_in": 60}); code != http.StatusServiceUnavailable {
		t.Fatalf("POST = %d %v, want 503 rather than an open API", code, out)
	}
}

func TestTokenOutsideItsScopeIsForbidden(t *testing.T) {
	// pcscf's scope covers every operation, so scope is checked with a
	// caller that holds only one (ADR 0007 §3).
	c, _, m := newTestControl(t, store.NewMemory())
	reader := "reader-token-0123456789-0123456789-01234567"
	c.auth.callers = append(c.auth.callers, caller{
		name: "reader", digests: newAuthorizer([]string{reader}).callers[0].digests, scope: map[string]bool{opDelete: true},
	})
	if code, _ := callControl(t, c, "POST", "/v1/bindings", reader, map[string]any{"expires_in": 60}); code != http.StatusForbidden {
		t.Fatalf("POST with a delete-only token = %d, want 403", code)
	}
	if code, _ := callControl(t, c, "PATCH", "/v1/bindings/"+BindingID("x"), reader, map[string]any{"expires_in": 60}); code != http.StatusForbidden {
		t.Fatalf("PATCH with a delete-only token = %d, want 403", code)
	}
	if code, _ := callControl(t, c, "DELETE", "/v1/bindings/"+BindingID("x"), reader, nil); code != http.StatusNotFound {
		t.Fatalf("DELETE with a delete-only token = %d, want it allowed (404)", code)
	}
	if m.count(mRefusedPrefix+reasonForbidden) != 2 {
		t.Fatalf("Refused.ControlForbidden = %d", m.count(mRefusedPrefix+reasonForbidden))
	}
}

func TestInvalidCreateRequestsAreRefused(t *testing.T) {
	c, _, m := newTestControl(t, store.NewMemory())
	for _, tt := range []struct {
		name string
		body string
		want int
	}{
		{"no expires_in", `{}`, 400},
		{"expires_in zero", `{"expires_in":0}`, 400},
		{"expires_in negative", `{"expires_in":-1}`, 400},
		{"expires_in above the maximum", `{"expires_in":7201}`, 400},
		{"expires_in not whole", `{"expires_in":1.5}`, 400},
		{"expires_in a string", `{"expires_in":"60"}`, 400},
		{"unknown field", `{"expires_in":60,"core":"x"}`, 400},
		{"two values", `{"expires_in":60}{"expires_in":60}`, 400},
		{"not JSON", `expires_in=60`, 400},
		{"core path of two URIs", `{"expires_in":60,"core_path":["msrp://10.0.1.5:2855/a;tcp","msrp://10.0.1.6:2855/b;tcp"]}`, 400},
		{"empty core path", `{"expires_in":60,"core_path":[]}`, 400},
		{"core path not MSRP", `{"expires_in":60,"core_path":["sip:as@10.0.1.5"]}`, 400},
		{"core path without a session", `{"expires_in":60,"core_path":["msrp://10.0.1.5:2855;tcp"]}`, 400},
		{"core path over TLS", `{"expires_in":60,"core_path":["msrps://10.0.1.5:2856/a;tcp"]}`, 400},
		{"core path to a public address", `{"expires_in":60,"core_path":["msrp://192.0.2.10:2855/a;tcp"]}`, 400},
		{"core path to the metadata address", `{"expires_in":60,"core_path":["msrp://169.254.169.254:80/a;tcp"]}`, 400},
		{"core path to loopback", `{"expires_in":60,"core_path":["msrp://127.0.0.1:2855/a;tcp"]}`, 400},
		{"core path to a public name", `{"expires_in":60,"core_path":["msrp://as.example.com:2855/a;tcp"]}`, 400},
		{"core path to a lookalike namespace", `{"expires_in":60,"core_path":["msrp://as.evilrcs.internal:2855/a;tcp"]}`, 400},
		{"client path of two URIs", `{"expires_in":60,"client_endpoint_path":["` + clientURI + `","` + clientURI + `"]}`, 400},
		{"client path without a port", `{"expires_in":60,"client_endpoint_path":["msrp://client.invalid/x;tcp"]}`, 400},
		{"core path to a namespace name", `{"expires_in":60,"core_path":["msrp://rcs-as.rcs.internal:2855/a;tcp"]}`, 201},
		{"core path to a ULA", `{"expires_in":60,"core_path":["msrp://[fd00::5]:2855/a;tcp"]}`, 201},
		{"both paths", `{"expires_in":7200,"core_path":["` + asPath + `"],"client_endpoint_path":["` + clientURI + `"]}`, 201},
	} {
		t.Run(tt.name, func(t *testing.T) {
			code, out := callControl(t, c, "POST", "/v1/bindings", testToken, tt.body)
			if code != tt.want {
				t.Fatalf("POST %s = %d %v, want %d", tt.body, code, out, tt.want)
			}
			if code == 400 {
				if msg, _ := out["error"].(string); msg == "" || strings.Contains(msg, "10.0.1") || strings.Contains(msg, "cl1ent") {
					t.Fatalf("error %q is empty or echoes the request", msg)
				}
			}
		})
	}
	if m.count(mRefusedPrefix+reasonInvalid) != 21 {
		t.Fatalf("Refused.ControlInvalid = %d", m.count(mRefusedPrefix+reasonInvalid))
	}
}

func TestBodyMustBeSmallJSON(t *testing.T) {
	c, _, _ := newTestControl(t, store.NewMemory())
	req := httptest.NewRequest("POST", "/v1/bindings", strings.NewReader(`{"expires_in":60}`))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	c.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain = %d", rec.Code)
	}
	big := `{"expires_in":60,"core_path":["msrp://10.0.1.5:2855/` + strings.Repeat("a", maxControlBody) + `;tcp"]}`
	if code, _ := callControl(t, c, "POST", "/v1/bindings", testToken, big); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body = %d", code)
	}
	req = httptest.NewRequest("POST", "/v1/bindings", errReader{})
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	c.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unreadable body = %d", rec.Code)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("reset") }

func TestPatchExtendsAndCompletesABinding(t *testing.T) {
	st := store.NewMemory()
	c, clock, _ := newTestControl(t, st)
	_, out := callControl(t, c, "POST", "/v1/bindings", testToken, map[string]any{"client_endpoint_path": []string{clientURI}, "expires_in": 60})
	id := out["id"].(string)

	clock.Advance(30 * time.Second)
	code, out := callControl(t, c, "PATCH", "/v1/bindings/"+id, testToken, map[string]any{"core_path": []string{asPath}, "expires_in": 1800})
	if code != http.StatusOK || out["id"] != id || out["expires_at"] != formatTime(clock.Now().Add(1800*time.Second)) {
		t.Fatalf("PATCH = %d %v", code, out)
	}
	if _, has := out["client_path"]; has {
		t.Fatal("PATCH repeats a session id it has no need to")
	}
	b, err := st.Get(context.Background(), id, clock.Now())
	if err != nil || b.CorePath != asPath || b.ClientEndpointPath != clientURI {
		t.Fatalf("stored %+v, %v", b, err)
	}
	// The same path again is fine; another is a different session
	// (RFC 4975 §8.4).
	if code, _ := callControl(t, c, "PATCH", "/v1/bindings/"+id, testToken, map[string]any{"core_path": []string{asPath}}); code != http.StatusOK {
		t.Fatalf("idempotent PATCH = %d", code)
	}
	if code, _ := callControl(t, c, "PATCH", "/v1/bindings/"+id, testToken, map[string]any{"core_path": []string{"msrp://10.0.1.6:2855/other;tcp"}}); code != http.StatusConflict {
		t.Fatalf("conflicting PATCH = %d", code)
	}
}

func TestPatchRefusals(t *testing.T) {
	c, clock, _ := newTestControl(t, store.NewMemory())
	_, out := callControl(t, c, "POST", "/v1/bindings", testToken, map[string]any{"expires_in": 60})
	id := out["id"].(string)
	for _, tt := range []struct {
		name, path string
		body       any
		want       int
	}{
		{"nothing to change", "/v1/bindings/" + id, map[string]any{}, 400},
		{"invalid expiry", "/v1/bindings/" + id, map[string]any{"expires_in": 0}, 400},
		{"invalid path", "/v1/bindings/" + id, map[string]any{"client_endpoint_path": []string{"x"}}, 400},
		{"unknown id", "/v1/bindings/" + BindingID("other"), map[string]any{"expires_in": 60}, 404},
		{"malformed id", "/v1/bindings/NOT-AN-ID", map[string]any{"expires_in": 60}, 404},
		{"not JSON", "/v1/bindings/" + id, "{", 400},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if code, out := callControl(t, c, "PATCH", tt.path, testToken, tt.body); code != tt.want {
				t.Fatalf("PATCH = %d %v, want %d", code, out, tt.want)
			}
		})
	}
	// An expired binding cannot be revived.
	clock.Advance(60 * time.Second)
	if code, _ := callControl(t, c, "PATCH", "/v1/bindings/"+id, testToken, map[string]any{"expires_in": 60}); code != http.StatusNotFound {
		t.Fatalf("PATCH of an expired binding = %d", code)
	}
}

func TestDeleteReleasesABindingOnce(t *testing.T) {
	st := store.NewMemory()
	c, clock, m := newTestControl(t, st)
	_, out := callControl(t, c, "POST", "/v1/bindings", testToken, map[string]any{"expires_in": 60})
	id := out["id"].(string)
	if code, _ := callControl(t, c, "DELETE", "/v1/bindings/"+id, testToken, nil); code != http.StatusNoContent {
		t.Fatalf("DELETE = %d", code)
	}
	if _, err := st.Get(context.Background(), id, clock.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after DELETE: %v", err)
	}
	if code, _ := callControl(t, c, "DELETE", "/v1/bindings/"+id, testToken, nil); code != http.StatusNotFound {
		t.Fatalf("second DELETE = %d", code)
	}
	if code, _ := callControl(t, c, "DELETE", "/v1/bindings/short", testToken, nil); code != http.StatusNotFound {
		t.Fatalf("DELETE of a malformed id = %d", code)
	}
	if m.count(mBindingsReleased) != 1 {
		t.Fatalf("BindingsReleased = %d", m.count(mBindingsReleased))
	}
}

// brokenStore fails every call, as an unreachable DynamoDB does.
type brokenStore struct{ store.Store }

var errBroken = errors.New("dynamostore: get: RequestTimeout")

func (brokenStore) Create(context.Context, store.Binding) error { return errBroken }
func (brokenStore) Update(context.Context, string, store.Update, time.Time) (store.Binding, error) {
	return store.Binding{}, errBroken
}
func (brokenStore) Delete(context.Context, string, time.Time) error { return errBroken }

func TestStoreFailuresAreAnswered503(t *testing.T) {
	c, _, m := newTestControl(t, brokenStore{})
	id := BindingID("x")
	for _, call := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/v1/bindings", map[string]any{"expires_in": 60}},
		{"PATCH", "/v1/bindings/" + id, map[string]any{"expires_in": 60}},
		{"DELETE", "/v1/bindings/" + id, nil},
	} {
		if code, _ := callControl(t, c, call.method, call.path, testToken, call.body); code != http.StatusServiceUnavailable {
			t.Fatalf("%s = %d, want 503", call.method, code)
		}
	}
	if m.count(mStoreErrors) != 3 {
		t.Fatalf("StoreErrors = %d", m.count(mStoreErrors))
	}
}

// failingRand runs out of randomness.
type failingRand struct{ after int }

func (f *failingRand) Read(p []byte) (int, error) {
	if f.after <= 0 {
		return 0, errors.New("no entropy")
	}
	f.after--
	return len(p), nil
}

func TestCreateWithoutRandomnessFails(t *testing.T) {
	for _, after := range []int{0, 1} {
		c, _, _ := newTestControl(t, store.NewMemory())
		c.o.Rand = &failingRand{after: after}
		if code, _ := callControl(t, c, "POST", "/v1/bindings", testToken, map[string]any{"expires_in": 60}); code != http.StatusInternalServerError {
			t.Fatalf("POST = %d, want 500", code)
		}
	}
}

func TestBindingIDsAreDigestsInTheSessionIDAlphabet(t *testing.T) {
	id := BindingID("anything")
	if len(id) != bindingIDLen || !validBindingID(id) || id != BindingID("anything") || id == BindingID("anything else") {
		t.Fatalf("BindingID = %q", id)
	}
	for _, bad := range []string{"", strings.ToUpper(id), id[:51], id + "a", strings.Replace(id, id[:1], "1", 1)} {
		if validBindingID(bad) {
			t.Fatalf("validBindingID(%q)", bad)
		}
	}
}

func TestNamespaceMatchesWholeLabels(t *testing.T) {
	for _, tt := range []struct {
		host, ns string
		want     bool
	}{
		{"rcs-as.rcs.internal", "rcs.internal", true},
		{"RCS-AS.RCS.INTERNAL.", "rcs.internal.", true},
		{"rcs.internal", "rcs.internal", false},
		{"as.evilrcs.internal", "rcs.internal", false},
		{"as.rcs.internal", "", false},
	} {
		if got := inNamespace(tt.host, tt.ns); got != tt.want {
			t.Fatalf("inNamespace(%q, %q) = %v", tt.host, tt.ns, got)
		}
	}
	if !inNetworks(netip.MustParseAddr("::ffff:10.0.0.1"), privateRanges) {
		t.Fatal("an IPv4-mapped private address is not private")
	}
}

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }
