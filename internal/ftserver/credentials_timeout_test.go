package ftserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// backstop bounds each test below whatever the code under test does.
const backstop = 10 * time.Second

// stallingHSS accepts every request and stalls it until the test ends:
// before any answer, or, with headers set, after sending 200 headers and
// before the body.
func stallingHSS(t *testing.T, headers bool) *hss {
	release := make(chan struct{})
	h := newHSS(t, func(w http.ResponseWriter, _ *http.Request) {
		if headers {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
		}
		<-release
	})
	// Registered after newHSS's own cleanup, so it runs first: the server
	// cannot close while a handler still waits.
	t.Cleanup(func() { close(release) })
	return h
}

// wiredSource is the credential source ft-server builds from its
// configuration (credentialSource), with FT_HSS_TIMEOUT set to timeout. It
// checks that the setting reaches the client: a test that called
// NewHSSCredentials itself would pass with the setting dropped or replaced
// by the default (QA on #138).
func wiredSource(t *testing.T, h *hss, timeout time.Duration) *HSSCredentials {
	t.Helper()
	cfg := Config{Credentials: CredentialsHSS, HSSURL: mustURL(h.URL), HSSToken: secret{"t"}, Realm: realm, HSSTimeout: timeout, MaxLookups: 4}
	src, ok := credentialSource(cfg, false).(*HSSCredentials)
	if !ok {
		t.Fatalf("credentialSource gave %T, want *HSSCredentials", credentialSource(cfg, false))
	}
	if src.client.Timeout != cfg.HSSTimeout {
		t.Fatalf("HSS client timeout = %v, want FT_HSS_TIMEOUT %v", src.client.Timeout, cfg.HSSTimeout)
	}
	return src
}

// The HSS client's timeout (FT_HSS_TIMEOUT) is what keeps an HSS that stops
// answering from holding every upload that needs a credential (#134). The
// other credential tests allow far more than they need, so these prove the
// timeout applies, whether the HSS stalls before its answer or in its body.
func TestAnHSSThatStopsAnsweringTimesOutAsABackendFailure(t *testing.T) {
	const timeout = 50 * time.Millisecond
	for name, headers := range map[string]bool{"no answer": false, "body stalls": true} {
		t.Run(name, func(t *testing.T) {
			src := wiredSource(t, stallingHSS(t, headers), timeout)
			// backstop ends the lookup if the client's timeout does not, so
			// a regression fails here instead of hanging until go test's
			// timeout.
			ctx, cancel := context.WithTimeout(t.Context(), backstop)
			defer cancel()
			start := time.Now()
			_, err := src.Lookup(ctx, alice, digest.SHA256)
			took := time.Since(start)
			// Far above the timeout, so a loaded host cannot fail it.
			if took >= backstop/2 {
				t.Fatalf("Lookup took %v with a %v timeout", took, timeout)
			}
			if err == nil || !strings.Contains(err.Error(), "Timeout") {
				t.Fatalf("Lookup = %v, want the client's timeout", err)
			}
			if isUnknown, isRecord := errors.Is(err, ErrUnknownUser), errors.Is(err, ErrBadCredentialRecord); isUnknown || isRecord {
				t.Fatalf("a timeout counted as the user's fault (unknown %v, unusable record %v)", isUnknown, isRecord)
			}
		})
	}
}

// The same through ft-server: a signed upload whose credential lookup times
// out is answered 503 with Retry-After, so the client tries again later,
// and not 401, which would tell it its password is wrong.
func TestAnUploadWhoseLookupTimesOutIsAnsweredServiceUnavailable(t *testing.T) {
	src := wiredSource(t, stallingHSS(t, false), 50*time.Millisecond)
	e := newEnv(t, func(o *Options) { o.Credentials = src })
	u := e.user(alice)
	u.challenge()
	answered := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		answered <- u.upload(multipartBody(tidPart("slow-hss"), filePart("a.bin", "application/octet-stream", "x")))
	}()
	var rec *httptest.ResponseRecorder
	select {
	case rec = <-answered:
	case <-time.After(backstop):
		t.Fatalf("no answer within %v: the lookup did not time out", backstop)
	}
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("upload = %d, Retry-After %q; want 503 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
}
