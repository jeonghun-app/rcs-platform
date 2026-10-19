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

// silentHSS accepts every request and never answers it, until the test ends.
func silentHSS(t *testing.T) *hss {
	release := make(chan struct{})
	h := newHSS(t, func(http.ResponseWriter, *http.Request) { <-release })
	// Registered after newHSS's own cleanup, so it runs first: the server
	// cannot close while a handler still waits.
	t.Cleanup(func() { close(release) })
	return h
}

// The HSS client's timeout (FT_HSS_TIMEOUT) is what keeps an HSS that stops
// answering from holding every upload that needs a credential (#134). The
// other credential tests allow far more than they need, so this one alone
// proves the timeout applies.
func TestAnHSSThatDoesNotAnswerTimesOutAsABackendFailure(t *testing.T) {
	const timeout = 50 * time.Millisecond
	h := silentHSS(t)
	src := NewHSSCredentials(mustURL(h.URL), "t", realm, timeout, 4, nil)
	// backstop ends the lookup if the client's timeout does not, so a
	// regression fails here instead of hanging until go test's timeout.
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
		t.Fatalf("Lookup = %v, want a timeout", err)
	}
	if isUnknown, isRecord := errors.Is(err, ErrUnknownUser), errors.Is(err, ErrBadCredentialRecord); isUnknown || isRecord {
		t.Fatalf("a timeout counted as the user's fault (unknown %v, unusable record %v)", isUnknown, isRecord)
	}
}

// The same through ft-server: a signed upload whose credential lookup times
// out is answered 503 with Retry-After, so the client tries again later,
// and not 401, which would tell it its password is wrong.
func TestAnUploadWhoseLookupTimesOutIsAnsweredServiceUnavailable(t *testing.T) {
	h := silentHSS(t)
	src := NewHSSCredentials(mustURL(h.URL), "t", realm, 50*time.Millisecond, 4, nil)
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
