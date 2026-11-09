package maap

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

const nextToken = "operator-next-token-0123456789abcdefghijklmnopqrstuvwxyz"

// otherScope stands for a caller other than the operator, such as rcs-as
// once #683 adds it.
const otherScope = scopeOperator << 1

type testBody struct {
	Name string `json:"name" maxbytes:"64"`
}

// trackedBody is a request body that records whether it was read.
type trackedBody struct {
	io.Reader
	read bool
}

func (b *trackedBody) Read(p []byte) (int, error) { b.read = true; return b.Reader.Read(p) }

// testAPI is the internal API with the operator's two tokens, a decode cap
// of decodes, and two routes: POST /v1/test for the operator, which decodes
// an operator body, and GET /v1/other for another caller.
func testAPI(t *testing.T, decodes int) (*internalAPI, *runtimetest.Harness) {
	h := runtimetest.New(t, "maap")
	a := newInternalAPI(TokenPair{secret.NewString(operatorToken), secret.NewString(nextToken)}, newDecoder(decodes, h.Runtime.Metrics), h.Runtime)
	a.route("POST /v1/test", "test", scopeOperator, func(w http.ResponseWriter, r *http.Request) error {
		var b testBody
		release, err := a.decoder.decode(r, maxOperatorBody, &b)
		if err != nil {
			return err
		}
		defer release()
		_, _ = io.WriteString(w, b.Name)
		return nil
	})
	a.route("GET /v1/other", "other", otherScope, func(http.ResponseWriter, *http.Request) error { return nil })
	return a, h
}

// serve sends a request with body and the Authorization headers auth to a.
func serve(a *internalAPI, method, path string, body *trackedBody, auth ...string) *httptest.ResponseRecorder {
	var r io.Reader
	if body != nil {
		r = body
	}
	req := httptest.NewRequest(method, path, r)
	for _, v := range auth {
		req.Header.Add("Authorization", v)
	}
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	return rec
}

func body(s string) *trackedBody { return &trackedBody{Reader: strings.NewReader(s)} }

func TestOnlyTheOperatorTokensAreAcceptedAndTheRestGet401BeforeTheBody(t *testing.T) {
	a, h := testAPI(t, 1)
	for _, tc := range []struct {
		name string
		auth []string
		want int
	}{
		{"current", []string{"Bearer " + operatorToken}, http.StatusOK},
		{"next", []string{"bearer " + nextToken}, http.StatusOK},
		{"none", nil, http.StatusUnauthorized},
		{"unknown", []string{"Bearer " + operatorToken + "x"}, http.StatusUnauthorized},
		{"hss's", []string{"Bearer hss-admin-token-0123456789abcdefghijklmnopqrstuvwxyz"}, http.StatusUnauthorized},
		{"another scheme", []string{"Basic " + operatorToken}, http.StatusUnauthorized},
		{"two headers", []string{"Bearer " + operatorToken, "Bearer " + operatorToken}, http.StatusUnauthorized},
		{"empty", []string{"Bearer "}, http.StatusUnauthorized},
	} {
		b := body(`{"name":"ok"}`)
		rec := serve(a, "POST", "/v1/test", b, tc.auth...)
		switch {
		case rec.Code != tc.want:
			t.Errorf("%s: status %d, want %d (%s)", tc.name, rec.Code, tc.want, rec.Body)
		case tc.want == http.StatusUnauthorized && (b.read || rec.Header().Get("WWW-Authenticate") == ""):
			t.Errorf("%s: body read %v, WWW-Authenticate %q", tc.name, b.read, rec.Header().Get("WWW-Authenticate"))
		case rec.Header().Get("Cache-Control") != "no-store":
			t.Errorf("%s: Cache-Control %q", tc.name, rec.Header().Get("Cache-Control"))
		}
	}
	audits := h.Logs("audit: internal request")
	if len(audits) != 8 || audits[1]["caller"] != "operator" || audits[1]["token"] != "next" || audits[2]["caller"] != "unauthenticated" {
		t.Errorf("audit lines = %v", audits)
	}
	if strings.Contains(h.Output(), operatorToken) || strings.Contains(h.Output(), "/v1/test") {
		t.Error("a token or a path reached the log")
	}
}

func TestTheOperatorTokenReachesOperatorRoutesOnly(t *testing.T) {
	a, _ := testAPI(t, 1)
	if rec := serve(a, "GET", "/v1/other", nil, "Bearer "+operatorToken); rec.Code != http.StatusForbidden {
		t.Errorf("another caller's route: status %d, want 403", rec.Code)
	}
	for _, path := range []string{"/v1/unknown", "/v1/messages", "/healthz"} {
		if rec := serve(a, "GET", path, nil, "Bearer "+operatorToken); rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", path, rec.Code)
		}
	}
}

func TestWithoutATokenConfiguredTheAPIAnswers503(t *testing.T) {
	h := runtimetest.New(t, "maap")
	a := newInternalAPI(TokenPair{}, newDecoder(1, h.Runtime.Metrics), h.Runtime)
	a.route("GET /v1/test", "test", scopeOperator, func(http.ResponseWriter, *http.Request) error { return nil })
	if rec := serve(a, "GET", "/v1/test", nil, "Bearer "); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status %d, want 503", rec.Code)
	}
}

func TestOperatorBodiesAreDecodedStrictlyAt16KiB(t *testing.T) {
	a, _ := testAPI(t, 1)
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"name":"bot"}`, http.StatusOK},
		{`{"name":"` + strings.Repeat("a", 64) + `"}`, http.StatusOK},
		{`{"name":"x"}` + strings.Repeat(" ", maxOperatorBody-12), http.StatusOK},
		{`{"name":"x"}` + strings.Repeat(" ", maxOperatorBody-11), http.StatusRequestEntityTooLarge},
		{`{"name":"` + strings.Repeat("a", 65) + `"}`, http.StatusBadRequest},
		{`{"name":"x","extra":1}`, http.StatusBadRequest},
		{`{"Name":"x"}`, http.StatusBadRequest},
		{`{"name":"x"}{}`, http.StatusBadRequest},
	} {
		if rec := serve(a, "POST", "/v1/test", body(tc.body), "Bearer "+operatorToken); rec.Code != tc.want {
			t.Errorf("%.40q: status %d, want %d (%s)", tc.body, rec.Code, tc.want, rec.Body)
		}
	}
	// Every answer above released its slot, or the last ones would be 503.
}

func TestARequestOverTheDecodeCapGets503WithoutItsBodyRead(t *testing.T) {
	a, h := testAPI(t, 1)
	release, ok := a.decoder.tryAcquire()
	if !ok {
		t.Fatal("no free slot")
	}
	b := body(`{"name":"x"}`)
	rec := serve(a, "POST", "/v1/test", b, "Bearer "+operatorToken)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "1" || b.read {
		t.Fatalf("status %d, Retry-After %q, body read %v", rec.Code, rec.Header().Get("Retry-After"), b.read)
	}
	if n, _ := h.Metric("api.decode_busy"); n != 1 {
		t.Errorf("api.decode_busy = %v, want 1", n)
	}
	release()
	release() // a second call must not free a slot someone else holds
	if rec := serve(a, "POST", "/v1/test", body(`{"name":"x"}`), "Bearer "+operatorToken); rec.Code != http.StatusOK {
		t.Errorf("after the release: status %d", rec.Code)
	}
	if _, ok := a.decoder.tryAcquire(); !ok {
		t.Error("the handler kept its slot")
	}
	if _, ok := a.decoder.tryAcquire(); ok {
		t.Error("a double release freed a second slot")
	}
}

func TestRefuseControlsRefusesC0AndDELWithoutQuotingTheValue(t *testing.T) {
	for _, v := range []string{"a\r\nInjected: 1", "a\x00b", "\x1b[31m", "tab\there", "del\x7f", "\n"} {
		err := refuseControls("display_name", v)
		if err == nil || err.Error() != "display_name holds a control character" {
			t.Errorf("%q: %v", v, err)
		}
	}
	for _, v := range []string{"", "Pizza Bot", "피자 봇 ✓", "a\u0085b"} {
		if err := refuseControls("display_name", v); err != nil {
			t.Errorf("%q refused: %v", v, err)
		}
	}
}
