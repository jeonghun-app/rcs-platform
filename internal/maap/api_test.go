package maap

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

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
// of decodes, and routes for the operator: POST /v1/test decodes an operator
// body, /v1/panic panics after decoding, /v1/late errs after sending 201;
// and GET /v1/other for another caller.
func testAPI(t *testing.T, decodes int) (*internalAPI, *runtimetest.Harness) {
	h := runtimetest.New(t, "maap")
	a := newInternalAPI(TokenPair{secret.NewString(operatorToken), secret.NewString(nextToken)}, newDecoder(decodes, h.Runtime.Metrics), h.Runtime)
	a.route("POST /v1/test", "test", scopeOperator, func(c *call) error {
		var b testBody
		if err := a.decoder.decode(c, maxOperatorBody, &b); err != nil {
			return err
		}
		_, _ = io.WriteString(c.w, b.Name)
		return nil
	})
	a.route("POST /v1/panic", "panic", scopeOperator, func(c *call) error {
		var b testBody
		_ = a.decoder.decode(c, maxOperatorBody, &b)
		panic("handler bug")
	})
	a.route("POST /v1/late", "late", scopeOperator, func(c *call) error {
		c.w.WriteHeader(http.StatusCreated)
		return errors.New("after the answer")
	})
	a.route("GET /v1/other", "other", otherScope, func(*call) error { return nil })
	return a, h
}

// serve sends a request with body, as application/json, and the
// Authorization headers auth to a.
func serve(a *internalAPI, method, path string, body *trackedBody, auth ...string) *httptest.ResponseRecorder {
	var r io.Reader
	if body != nil {
		r = body
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Content-Type", "application/json")
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
		case tc.want == http.StatusUnauthorized && (b.read || rec.Header().Get("WWW-Authenticate") == "" || rec.Header().Get("Connection") != "close"):
			t.Errorf("%s: body read %v, headers %v", tc.name, b.read, rec.Header())
		case rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff":
			t.Errorf("%s: headers %v", tc.name, rec.Header())
		}
	}
	audits := h.Logs("audit: internal request")
	if len(audits) != 8 || audits[0]["token"] != "current" || audits[1]["caller"] != "operator" || audits[1]["token"] != "next" || audits[2]["caller"] != "unauthenticated" {
		t.Errorf("audit lines = %v", audits)
	}
	if ok, _ := h.Metric("api.test.200"); ok != 2 {
		t.Errorf("api.test.200 = %v, want 2", ok)
	}
	if refused, _ := h.Metric("api.test.401"); refused != 6 {
		t.Errorf("api.test.401 = %v, want 6", refused)
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
	a.route("GET /v1/test", "test", scopeOperator, func(*call) error { return nil })
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
		{`{"name":"x"}` + strings.Repeat(" ", 16384-12), http.StatusOK},
		{`{"name":"x"}` + strings.Repeat(" ", 16385-12), http.StatusRequestEntityTooLarge},
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
	for ct, want := range map[string]int{"application/json; charset=utf-8": 200, "text/plain": 415, "": 415} {
		req := httptest.NewRequest("POST", "/v1/test", strings.NewReader(`{"name":"x"}`))
		req.Header.Set("Content-Type", ct)
		req.Header.Set("Authorization", "Bearer "+operatorToken)
		rec := httptest.NewRecorder()
		if a.ServeHTTP(rec, req); rec.Code != want {
			t.Errorf("Content-Type %q: status %d, want %d", ct, rec.Code, want)
		}
	}
}

func TestARequestOverTheDecodeCapGets503WithoutItsBodyRead(t *testing.T) {
	a, h := testAPI(t, 1)
	release, ok := a.decoder.tryAcquire()
	if !ok {
		t.Fatal("no free slot")
	}
	b := body(`{"name":"x"}`)
	// (Over a real connection: TestRefusalsBeforeTheBodyDoNotWaitForIt.)
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

// TestRefusalsBeforeTheBodyDoNotWaitForIt runs over a connection, since
// what net/http does with an unread body after the handler returns is not
// in a ResponseRecorder (#723 tester's repro).
func TestRefusalsBeforeTheBodyDoNotWaitForIt(t *testing.T) {
	a, _ := testAPI(t, 1)
	srv := httptest.NewServer(a)
	defer srv.Close()
	release, _ := a.decoder.tryAcquire()
	defer release()
	for _, tc := range []struct {
		name, auth string
		want       int
	}{
		{"decode cap full", "Authorization: Bearer " + operatorToken + "\r\n", http.StatusServiceUnavailable},
		{"no token", "", http.StatusUnauthorized},
	} {
		c, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("POST /v1/test HTTP/1.1\r\nHost: maap\r\n" + tc.auth + "Content-Type: application/json\r\nContent-Length: 1000\r\n\r\n{\"name\":\""))
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		line, err := bufio.NewReader(c).ReadString('\n')
		_ = c.Close()
		if err != nil || !strings.Contains(line, http.StatusText(tc.want)) {
			t.Errorf("%s: status line %q, %v; want %d within 2 s", tc.name, line, err, tc.want)
		}
	}
}

// TestASlowBodyFreesItsDecodeSlotLongBeforeTheReadTimeout: the test server
// has no ReadTimeout, so without decode's own deadline a sender that
// trickles its body would hold the slot for good; with it, 16 KiB get 1.25 s.
func TestASlowBodyFreesItsDecodeSlotLongBeforeTheReadTimeout(t *testing.T) {
	a, _ := testAPI(t, 1)
	srv := httptest.NewServer(a)
	defer srv.Close()
	slow, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	_, _ = slow.Write([]byte("POST /v1/test HTTP/1.1\r\nHost: maap\r\nAuthorization: Bearer " + operatorToken +
		"\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{\"name\":\""))
	go func() {
		for _, err := slow.Write([]byte("a")); err == nil; _, err = slow.Write([]byte("a")) {
			time.Sleep(100 * time.Millisecond)
		}
	}()
	// The slot's own state, not answers to other requests: those may come
	// too late, under load, to see the slot taken.
	wait := func(held int, what string) {
		for deadline := time.Now().Add(10 * time.Second); len(a.decoder.slots) != held; time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal(what)
			}
		}
	}
	wait(1, "the slow sender never took the slot")
	wait(0, "the slot was still held 10 s after a trickled body took it")
}

func TestAPanickingHandlerFreesItsSlotAndIsAudited(t *testing.T) {
	a, h := testAPI(t, 1)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic was swallowed")
			}
		}()
		serve(a, "POST", "/v1/panic", body(`{"name":"x"}`), "Bearer "+operatorToken)
	}()
	if _, ok := a.decoder.tryAcquire(); !ok {
		t.Error("the panicking handler kept its slot")
	}
	if l := h.Logs("audit: internal request"); len(l) != 1 || l[0]["operation"] != "panic" || l[0]["status"] != 500.0 {
		t.Errorf("audit lines = %v", l)
	}
}

func TestTheAuditAndMetricKeepTheFirstStatusSent(t *testing.T) {
	a, h := testAPI(t, 1)
	if rec := serve(a, "POST", "/v1/late", nil, "Bearer "+operatorToken); rec.Code != http.StatusCreated {
		t.Fatalf("status %d", rec.Code)
	}
	if n, _ := h.Metric("api.late.201"); n != 1 || h.Logs("audit: internal request")[0]["status"] != 201.0 {
		t.Errorf("api.late.201 = %v, audit %v", n, h.Logs("audit: internal request"))
	}
}

func TestRefuseControlsRefusesC0AndDELWithoutQuotingTheValue(t *testing.T) {
	for _, v := range []string{"a\r\nInjected: 1", "a\x00b", "\x1b[31m", "tab\there", "del\x7f", "\n", "us\x1f"} {
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
