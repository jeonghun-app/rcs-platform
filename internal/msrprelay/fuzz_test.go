package msrprelay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/store"
)

// FuzzControlRequest feeds the control API arbitrary bodies. Whatever
// arrives, the answer is one of the documented codes, and a binding it
// stores holds only paths the relay can use: one URI each, a core host in
// the allowed networks or namespace, never msrps toward the core.
func FuzzControlRequest(f *testing.F) {
	for _, seed := range []string{
		`{"core_path":["msrp://10.0.1.5:2855/as5e55ion;tcp"],"expires_in":1800}`,
		`{"client_endpoint_path":["msrp://client.invalid:7777/c;tcp"],"expires_in":60}`,
		`{"core_path":["msrp://rcs-as.rcs.internal:2855/a;tcp"],"client_endpoint_path":["msrps://[2001:db8::1]:1/x;tcp"],"expires_in":7200}`,
		`{"core_path":["msrp://169.254.169.254:80/a;tcp"],"expires_in":60}`,
		`{"expires_in":1e3}`, `{"expires_in":60}{}`, `[]`, `null`, `{"core_path":null,"expires_in":60}`,
	} {
		f.Add(seed, "POST")
		f.Add(seed, "PATCH")
	}
	f.Fuzz(func(t *testing.T, body, method string) {
		st := store.NewMemory()
		c, clock, _ := newTestControl(t, st)
		path := "/v1/bindings"
		if method != "POST" {
			method = "PATCH"
			_, out := callControl(t, c, "POST", path, testToken, map[string]any{"expires_in": 60})
			path += "/" + out["id"].(string)
		}
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+testToken)
		rec := httptest.NewRecorder()
		c.ServeHTTP(rec, req)
		switch rec.Code {
		case http.StatusCreated, http.StatusOK, http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusConflict:
		default:
			t.Fatalf("%s %q = %d %s", method, body, rec.Code, rec.Body)
		}
		if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
			return
		}
		id := strings.TrimPrefix(path, "/v1/bindings/")
		if rec.Code == http.StatusCreated {
			d, err := decodeBinding(rec.Body.String())
			if err != nil {
				t.Fatal(err)
			}
			id = d.ID
		}
		b, err := st.Get(context.Background(), id, clock.Now())
		if err != nil {
			t.Fatalf("answered %d but stored nothing: %v", rec.Code, err)
		}
		if b.CorePath != "" {
			u, err := msrp.ParseURI(b.CorePath)
			if err != nil || u.Secure || strings.Contains(b.CorePath, " ") {
				t.Fatalf("stored core path %q", b.CorePath)
			}
			if _, problem := c.corePath([]string{b.CorePath}); problem != "" {
				t.Fatalf("stored a core path the API refuses: %q: %s", b.CorePath, problem)
			}
		}
		if b.ClientEndpointPath != "" {
			if _, err := msrp.ParseURI(b.ClientEndpointPath); err != nil || strings.Contains(b.ClientEndpointPath, " ") {
				t.Fatalf("stored client path %q", b.ClientEndpointPath)
			}
		}
	})
}

// FuzzBearer checks the Authorization parser: it accepts exactly one
// "Bearer" credential in b64token syntax and nothing else.
func FuzzBearer(f *testing.F) {
	for _, seed := range []string{"Bearer abc", "bearer abc==", "Bearer ", "Basic abc", "Bearer a b", "Bearer ab=c", "Bearer \x00", "Bearer " + testToken} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, header string) {
		token, ok := bearer([]string{header})
		if !ok {
			return
		}
		if !strings.EqualFold(header[:7], "Bearer ") || header[7:] != token || token == "" || len(token) > maxTokenLength {
			t.Fatalf("bearer(%q) = %q", header, token)
		}
		body := strings.TrimRight(token, "=")
		for _, r := range body {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~+/", r)) {
				t.Fatalf("bearer(%q) accepted %q", header, r)
			}
		}
		if _, again := bearer([]string{"Bearer " + token}); !again {
			t.Fatalf("an accepted token %q does not round-trip", token)
		}
	})
}
