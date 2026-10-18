package digest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func lookupFor(password string) SecretLookup {
	return func(_ context.Context, username string, _ Algorithm) (Secret, error) {
		if username != "alice" {
			return Secret{}, errors.New("unknown user")
		}
		return Password([]byte(password)), nil
	}
}

func httpAnswer(t *testing.T, ch Challenge, method, uri string, nc uint32) string {
	t.Helper()
	c, err := Respond(ch, ClientParams{Username: "alice", Password: []byte(testPass), Method: method, URI: uri, CNonce: "http-cnonce", NC: nc})
	if err != nil {
		t.Fatal(err)
	}
	return c.String()
}

func TestHTTPChallengeOffersSHA256BeforeMD5(t *testing.T) {
	h := newHarness(t)
	w := httptest.NewRecorder()
	if err := h.server.ChallengeHTTP(w, false); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", w.Code)
	}
	values := w.Header().Values("WWW-Authenticate")
	if len(values) != 2 {
		t.Fatalf("WWW-Authenticate = %q", values)
	}
	for i, want := range []Algorithm{SHA256, MD5} {
		ch, err := ParseChallenge(values[i])
		if err != nil || ch.Algorithm != want || ch.Stale {
			t.Fatalf("challenge %d = %+v, %v; want %s", i, ch, err, want)
		}
	}
}

func TestHTTPStaleChallengeSaysStale(t *testing.T) {
	h := newHarness(t)
	w := httptest.NewRecorder()
	if err := h.server.ChallengeHTTP(w, true); err != nil {
		t.Fatal(err)
	}
	for _, v := range w.Header().Values("WWW-Authenticate") {
		if ch, err := ParseChallenge(v); err != nil || !ch.Stale {
			t.Fatalf("challenge %q is not stale", v)
		}
	}
}

func TestHTTPChallengeWritesNothingWithoutRandomness(t *testing.T) {
	h := newHarness(t)
	h.server.random = brokenReader{}
	w := httptest.NewRecorder()
	if err := h.server.ChallengeHTTP(w, false); err == nil {
		t.Fatal("challenge written without randomness")
	}
	if len(w.Header().Values("WWW-Authenticate")) != 0 {
		t.Fatal("a partial challenge was written")
	}
}

func TestHTTPRequestWithCorrectCredentialsIsAuthenticated(t *testing.T) {
	h := newHarness(t)
	ch := h.challenge(t, SHA256)
	r := httptest.NewRequest(http.MethodPost, "/files?upload=1", nil)
	r.Header.Add("Authorization", "Bearer something-else")
	r.Header.Add("Authorization", httpAnswer(t, ch, http.MethodPost, "/files?upload=1", 1))
	c, err := h.server.VerifyHTTP(r, lookupFor(testPass))
	if err != nil {
		t.Fatalf("VerifyHTTP: %v", err)
	}
	if c.Username != "alice" {
		t.Fatalf("username = %q", c.Username)
	}
}

func TestHTTPRequestWithoutURLRequestURIUsesTheURL(t *testing.T) {
	h := newHarness(t)
	ch := h.challenge(t, MD5)
	r, err := http.NewRequest(http.MethodGet, "https://ft.example/download/abc?x=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", httpAnswer(t, ch, http.MethodGet, "/download/abc?x=1", 1))
	if _, err := h.server.VerifyHTTP(r, lookupFor(testPass)); err != nil {
		t.Fatalf("VerifyHTTP: %v", err)
	}
}

func TestHTTPRequestFailures(t *testing.T) {
	h := newHarness(t)
	ch := h.challenge(t, SHA256)
	good := httpAnswer(t, ch, http.MethodGet, "/f", 1)
	cases := []struct {
		name    string
		target  string
		headers []string
		lookup  SecretLookup
		want    error
	}{
		{"no Authorization", "/f", nil, lookupFor(testPass), ErrNoCredentials},
		{"only another scheme", "/f", []string{"Basic YWxpY2U6cA=="}, lookupFor(testPass), ErrNoCredentials},
		{"two Digest fields", "/f", []string{good, good}, lookupFor(testPass), ErrMalformed},
		{"malformed", "/f", []string{"Digest username="}, lookupFor(testPass), ErrMalformed},
		{"uri for another resource", "/g", []string{good}, lookupFor(testPass), ErrURIMismatch},
		{"wrong password", "/f", []string{good}, lookupFor("other"), ErrWrongResponse},
		{"AKA over HTTP", "/f", []string{`Digest username="alice", realm="` + testRealm + `", nonce="n", uri="/f", response="", algorithm=AKAv1-MD5`}, lookupFor(testPass), ErrUnsupportedAlgorithm},
		{"forged nonce", "/f", []string{`Digest username="alice", realm="` + testRealm + `", nonce="n", uri="/f", response="", qop=auth, nc=00000001, cnonce="c"`}, nil, ErrInvalidNonce},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tc.target, nil)
			for _, v := range tc.headers {
				r.Header.Add("Authorization", v)
			}
			// A nil lookup proves the nonce is checked before any lookup.
			if _, err := h.server.VerifyHTTP(r, tc.lookup); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestHTTPUnknownUserFailsWithTheLookupError(t *testing.T) {
	h := newHarness(t)
	ch := h.challenge(t, SHA256)
	c, err := Respond(ch, ClientParams{Username: "mallory", Password: []byte("x"), Method: "GET", URI: "/f", CNonce: "c", NC: 1})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/f", nil)
	r.Header.Set("Authorization", c.String())
	if _, err := h.server.VerifyHTTP(r, lookupFor(testPass)); err == nil || errors.Is(err, ErrWrongResponse) {
		t.Fatalf("err = %v, want the lookup error", err)
	}
}

func TestHTTPReusedNonceWithIncreasingCountIsAccepted(t *testing.T) {
	// The HTTP pattern: one nonce for many requests, nc counting up.
	h := newHarness(t)
	ch := h.challenge(t, SHA256)
	for nc := uint32(1); nc <= 3; nc++ {
		r := httptest.NewRequest(http.MethodGet, "/f", nil)
		r.Header.Set("Authorization", httpAnswer(t, ch, http.MethodGet, "/f", nc))
		if _, err := h.server.VerifyHTTP(r, lookupFor(testPass)); err != nil {
			t.Fatalf("nc %d: %v", nc, err)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/f", nil)
	r.Header.Set("Authorization", httpAnswer(t, ch, http.MethodGet, "/f", 2))
	if _, err := h.server.VerifyHTTP(r, lookupFor(testPass)); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replayed nc: err = %v, want ErrReplayed", err)
	}
}
