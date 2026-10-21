package pcscf

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	testRelayToken = "relay-token-for-tests-only-0123456789abcdefgh"
	testBindingID  = "iy5x5b2bhc2xeckdw7ercei27dwrmk4rxpybngwhlrnzm7x5halq"
	testClientPath = "msrps://msrp.example.net:2856/aebagbafaydqqcikbmga2dqpcaireeyu;tcp"
	testCoreLocal  = "msrp://10.0.2.9:9/culbogazdinryhi6d4qccirdeqssmjzi;tcp"
)

// fakeRelay answers the control API as answer says, recording each call.
type fakeRelay struct {
	calls  []relayCall
	answer func(method, path string) (int, string)
}

type relayCall struct {
	method, path, auth string
	body               map[string]any
}

func startFakeRelay(t *testing.T, answer func(method, path string) (int, string)) (*fakeRelay, *relayClient) {
	t.Helper()
	f := &fakeRelay{answer: answer}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := relayCall{method: r.Method, path: r.URL.Path, auth: r.Header.Get("Authorization")}
		if b, _ := io.ReadAll(r.Body); len(b) > 0 {
			if err := json.Unmarshal(b, &c.body); err != nil {
				t.Errorf("body %q: %v", b, err)
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("Content-Type %q", r.Header.Get("Content-Type"))
			}
		}
		f.calls = append(f.calls, c)
		code, body := f.answer(r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL)
	// waitFor, not a protocol bound: these tests read what the client makes
	// of an answer, which a loaded host may be slow to serve (#388).
	// TestTheRelayClientIsBounded times the client with its own.
	return f, newRelayClient(base, testRelayToken, waitFor, nil)
}

// createdJSON is the relay's 201 to POST.
const createdJSON = `{"id":"` + testBindingID + `","client_path":"` + testClientPath + `","core_path_local":"` + testCoreLocal + `","expires_at":"2026-01-02T03:34:05.000Z"}`

// The client calls the documented operations with the bearer token and the
// paths as lists, and reads the binding POST returns.
func TestTheRelayClientSpeaksTheControlAPI(t *testing.T) {
	f, c := startFakeRelay(t, func(method, _ string) (int, string) {
		switch method {
		case http.MethodPost:
			return 201, createdJSON
		case http.MethodPatch:
			return 200, `{"id":"` + testBindingID + `","expires_at":"2026-01-02T03:34:05.000Z"}`
		}
		return 204, ""
	})
	ctx := context.Background()
	b, err := c.create(ctx, relayPaths{ClientEndpointPath: []string{"msrp://client.invalid:7777/a1;tcp"}, ExpiresIn: 1800})
	if err != nil || b != (relayBinding{ID: testBindingID, ClientPath: testClientPath, CorePathLocal: testCoreLocal}) {
		t.Fatalf("create: %+v, %v", b, err)
	}
	if err := c.update(ctx, b.ID, relayPaths{CorePath: []string{"msrp://10.0.1.5:2855/r1;tcp"}}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := c.release(ctx, b.ID); err != nil {
		t.Fatalf("release: %v", err)
	}
	want := []relayCall{
		{http.MethodPost, "/v1/bindings", "Bearer " + testRelayToken, map[string]any{"client_endpoint_path": []any{"msrp://client.invalid:7777/a1;tcp"}, "expires_in": 1800.0}},
		{http.MethodPatch, "/v1/bindings/" + testBindingID, "Bearer " + testRelayToken, map[string]any{"core_path": []any{"msrp://10.0.1.5:2855/r1;tcp"}}},
		{http.MethodDelete, "/v1/bindings/" + testBindingID, "Bearer " + testRelayToken, nil},
	}
	if len(f.calls) != len(want) {
		t.Fatalf("calls %+v", f.calls)
	}
	for i, w := range want {
		g := f.calls[i]
		gb, _ := json.Marshal(g.body)
		wb, _ := json.Marshal(w.body)
		if g.method != w.method || g.path != w.path || g.auth != w.auth || string(gb) != string(wb) {
			t.Errorf("call %d: %+v, want %+v", i, g, w)
		}
	}
}

// Refusals and failures are errors that name the operation and the status
// alone; a 409 and a 404 are told apart, and releasing a binding already
// gone succeeds. An answer that is no binding is refused.
func TestTheRelayClientsErrorsSayLittle(t *testing.T) {
	for _, tt := range []struct {
		name string
		code int
		body string
		call func(c *relayClient) error
		want error
	}{
		{"409", 409, `{"error":"path already set"}`, func(c *relayClient) error {
			return c.update(context.Background(), testBindingID, relayPaths{ExpiresIn: 1})
		}, errRelayConflict},
		{"404 on update", 404, `{}`, func(c *relayClient) error {
			return c.update(context.Background(), testBindingID, relayPaths{ExpiresIn: 1})
		}, errRelayGone},
		{"404 on release", 404, `{}`, func(c *relayClient) error { return c.release(context.Background(), testBindingID) }, nil},
		{"503", 503, `{"error":"store"}`, func(c *relayClient) error {
			_, err := c.create(context.Background(), relayPaths{ExpiresIn: 1})
			return err
		}, errors.New("503")},
		{"not JSON", 201, `<html>`, func(c *relayClient) error {
			_, err := c.create(context.Background(), relayPaths{ExpiresIn: 1})
			return err
		}, errors.New("not a binding")},
		{"no client_path", 201, `{"id":"` + testBindingID + `","core_path_local":"` + testCoreLocal + `"}`, func(c *relayClient) error {
			_, err := c.create(context.Background(), relayPaths{ExpiresIn: 1})
			return err
		}, errors.New("incomplete")},
		{"a bad id", 201, strings.Replace(createdJSON, testBindingID, "../x", 1), func(c *relayClient) error {
			_, err := c.create(context.Background(), relayPaths{ExpiresIn: 1})
			return err
		}, errors.New("incomplete")},
		{"too large", 201, `{"id":"` + strings.Repeat("a", maxRelayResponse) + `"}`, func(c *relayClient) error {
			_, err := c.create(context.Background(), relayPaths{ExpiresIn: 1})
			return err
		}, errors.New("too large")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, c := startFakeRelay(t, func(string, string) (int, string) { return tt.code, tt.body })
			err := tt.call(c)
			switch {
			case tt.want == nil:
				if err != nil {
					t.Errorf("%v, want none", err)
				}
			case errors.Is(tt.want, errRelayConflict) || errors.Is(tt.want, errRelayGone):
				if !errors.Is(err, tt.want) {
					t.Errorf("%v, want %v", err, tt.want)
				}
			default:
				if err == nil || !strings.Contains(err.Error(), tt.want.Error()) {
					t.Errorf("%v, want one saying %q", err, tt.want)
				}
			}
			if err != nil && (strings.Contains(err.Error(), testRelayToken) || strings.Contains(err.Error(), "msrps://")) {
				t.Errorf("the error tells too much: %v", err)
			}
		})
	}
}

// A relay that does not answer in time fails the call within the timeout,
// and a redirect is not followed with the token.
func TestTheRelayClientIsBounded(t *testing.T) {
	block := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-block }))
	// Cleanups run last first: the handler is let go before Close waits
	// for it.
	t.Cleanup(slow.Close)
	t.Cleanup(func() { close(block) })
	base, _ := url.Parse(slow.URL)
	c := newRelayClient(base, testRelayToken, 100*time.Millisecond, nil)
	start := time.Now()
	if _, err := c.create(context.Background(), relayPaths{ExpiresIn: 1}); err == nil {
		t.Fatal("no error from a relay that does not answer")
	}
	if waited := time.Since(start); waited > 5*time.Second {
		t.Errorf("waited %v", waited)
	}

	var leaked bool
	target := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization") != ""
	}))
	t.Cleanup(target.Close)
	_, c = startFakeRelay(t, func(string, string) (int, string) { return 0, "" })
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/v1/bindings", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirect.Close)
	c.base, _ = url.Parse(redirect.URL)
	if _, err := c.create(context.Background(), relayPaths{ExpiresIn: 1}); err == nil || leaked {
		t.Errorf("redirect: %v, token sent on: %v", err, leaked)
	}
}
