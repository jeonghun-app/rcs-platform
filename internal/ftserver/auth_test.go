package ftserver

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/secret"
	secretkey "github.com/jeonghun-app/rcs-platform/internal/secret"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// failure strips what differs between two 401s by design (the nonce and
// opaque of each fresh challenge), leaving what a client could compare.
func failure(rec *httptest.ResponseRecorder) string {
	var b strings.Builder
	b.WriteString(strconv.Itoa(rec.Code) + "|" + rec.Body.String())
	for _, v := range rec.Header().Values("WWW-Authenticate") {
		ch, _ := digest.ParseChallenge(v)
		b.WriteString("|" + string(ch.Algorithm) + " " + ch.Realm + " " + strconv.FormatBool(ch.Stale))
	}
	for _, name := range slices.Sorted(maps.Keys(rec.Header())) {
		b.WriteString("|" + name)
	}
	return b.String()
}

func TestEveryAuthenticationFailureLooksTheSame(t *testing.T) {
	e := newEnv(t)
	post := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/ft", strings.NewReader(multipartBody(tidPart("x"), filePart("a", "text/plain", "x"))))
		r.Header.Set("Content-Type", formType)
		return r
	}
	wrong := e.user(alice)
	wrong.password = "wrong"
	unknown := e.user("001010000000003@ims.mnc001.mcc001.3gppnetwork.org")
	replayed := e.user(alice)
	first := replayed.sign(post())
	e.do(first)
	replay := post()
	replay.Header.Set("Authorization", first.Header.Get("Authorization"))
	otherURI := e.user(alice)
	misdirected := otherURI.sign(httptest.NewRequest(http.MethodPost, "/ft?x=1", nil))
	misdirected.URL.RawQuery = ""
	misdirected.RequestURI = "/ft"

	cases := map[string]*http.Request{
		"no credentials": post(),
		"wrong password": wrong.sign(post()),
		"unknown user":   unknown.sign(post()),
		"replayed":       replay,
		"other uri":      misdirected,
		"garbage":        func() *http.Request { r := post(); r.Header.Set("Authorization", "Digest ???"); return r }(),
	}
	var want string
	for name, r := range cases {
		got := failure(e.do(r))
		if want == "" {
			want = got
		}
		if got != want {
			t.Errorf("%s answered\n%s\nwhere another failure answered\n%s", name, got, want)
		}
		if !strings.HasPrefix(got, "401|") {
			t.Errorf("%s: %s", name, got)
		}
	}
	// Each upload sent with credentials that did not verify; not the one
	// without credentials, nor the empty POST.
	if got := e.metric("upload.failed.auth"); got != 4 {
		t.Errorf("upload.failed.auth = %v, want 4", got)
	}
}

func TestExpiredNonceGetsAStaleChallenge(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	u.challenge()
	e.clock.Advance(digest.DefaultNonceLifetime + time.Second)
	rec := e.do(u.sign(httptest.NewRequest(http.MethodPost, "/ft", nil)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	for _, v := range rec.Header().Values("WWW-Authenticate") {
		if ch, err := digest.ParseChallenge(v); err != nil || !ch.Stale {
			t.Fatalf("challenge %q is not stale", v)
		}
	}
	if e.metric("auth.stale") != 1 {
		t.Fatal("stale nonce not counted")
	}
	// The client retries with the new nonce without asking the user.
	u.takeChallenge(rec.Header())
	if rec := e.do(u.sign(httptest.NewRequest(http.MethodPost, "/ft", nil))); rec.Code != http.StatusNoContent {
		t.Fatalf("retry with the stale challenge's nonce = %d", rec.Code)
	}
}

func TestMD5CredentialsAreAccepted(t *testing.T) {
	e := newEnv(t)
	rec := e.do(httptest.NewRequest(http.MethodPost, "/ft", nil))
	var ch digest.Challenge
	for _, v := range rec.Header().Values("WWW-Authenticate") {
		if c, _ := digest.ParseChallenge(v); c.Algorithm == digest.MD5 {
			ch = c
		}
	}
	c, err := digest.Respond(ch, digest.ClientParams{Username: alice, Password: secret.NewKey([]byte(password)), Method: "POST", URI: "/ft", CNonce: "c", NC: 1})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/ft", nil)
	r.Header.Set("Authorization", c.Header())
	if rec := e.do(r); rec.Code != http.StatusNoContent {
		t.Fatalf("MD5 pre-check = %d", rec.Code)
	}
}

// failingSource fails every lookup like an HSS that is down.
type failingSource struct{}

func (failingSource) Lookup(context.Context, string, digest.Algorithm) (Credential, error) {
	return Credential{}, errors.New("hss unreachable")
}

func TestCredentialBackendFailureIsServiceUnavailableAndLogged(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.Credentials = failingSource{} })
	u := e.user(alice)
	rec := e.do(u.sign(httptest.NewRequest(http.MethodPost, "/ft", nil)))
	// Not 401: the failure says nothing about the user, and RCS clients
	// retry a 503 but give up after a second 401.
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" || rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("status = %d, headers %v", rec.Code, rec.Header())
	}
	if e.metric("auth.backend_error") != 1 || len(e.h.Logs("credential lookup failed")) != 1 {
		t.Fatal("backend failure not reported")
	}
	if strings.Contains(e.h.Output(), "001010000000001") {
		t.Fatal("the user name reached the log")
	}
}

// blockingSource holds every lookup until released, counting how many are
// in progress at once.
type blockingSource struct {
	release chan struct{}
	mu      sync.Mutex
	now     int
	peak    int
}

func (b *blockingSource) Lookup(context.Context, string, digest.Algorithm) (Credential, error) {
	b.mu.Lock()
	b.now++
	b.peak = max(b.peak, b.now)
	b.mu.Unlock()
	<-b.release
	b.mu.Lock()
	b.now--
	b.mu.Unlock()
	return Credential{}, ErrUnknownUser
}

func TestCredentialLookupsPerTaskAreBounded(t *testing.T) {
	src := &blockingSource{release: make(chan struct{})}
	e := newEnv(t, func(o *Options) { o.Credentials = src; o.MaxConcurrentLookups = 2 })
	// Requests from anyone with a nonce and a made-up user name.
	const requests = 10
	var wg sync.WaitGroup
	codes := make(chan int, requests)
	for i := range requests {
		u := e.user("nobody-" + strconv.Itoa(i))
		r := u.sign(httptest.NewRequest(http.MethodPost, "/ft", nil))
		wg.Go(func() { codes <- e.do(r).Code })
	}
	// Every request beyond the limit is answered at once.
	for range requests - 2 {
		if code := <-codes; code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503 beyond the lookup limit", code)
		}
	}
	close(src.release)
	wg.Wait()
	for range 2 {
		if code := <-codes; code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 for the looked-up unknown users", code)
		}
	}
	if src.peak > 2 || e.metric("auth.lookup_busy") != requests-2 {
		t.Fatalf("peak lookups %d, lookup_busy %v", src.peak, e.metric("auth.lookup_busy"))
	}
}

func TestChallengeWithoutRandomnessIsAnInternalError(t *testing.T) {
	ds, err := digest.NewServer(digest.ServerConfig{
		Realm: realm, NonceKey: secretkey.NewKey(make([]byte, 32)), NonceCounts: digest.NewMemoryNonceCounts(nil),
		Random: errReader{io.ErrUnexpectedEOF},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, func(o *Options) { o.Digest = ds })
	if rec := e.do(httptest.NewRequest(http.MethodPost, "/ft", nil)); rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestUploadBodyReadsRunUnderDeadlines(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.IdleTimeout = 30 * time.Second })
	u := e.user(alice)
	r := httptest.NewRequest(http.MethodPost, "/ft", strings.NewReader(multipartBody(tidPart("dl"), filePart("a", "text/plain", pattern(3*testPart)))))
	r.Header.Set("Content-Type", formType)
	before := time.Now()
	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	e.srv.ServeHTTP(rec, u.sign(r))
	if rec.Code != http.StatusOK || len(rec.reads) == 0 {
		t.Fatalf("status %d, %d read deadlines", rec.Code, len(rec.reads))
	}
	end := before.Add(e.opts.UploadTimeout)
	for _, d := range rec.reads {
		if d.Before(before.Add(30*time.Second)) || d.After(end.Add(time.Second)) {
			t.Fatalf("read deadline %v outside the idle and upload timeouts", d)
		}
	}
}

func TestUploadPastTheUploadTimeoutIsEnded(t *testing.T) {
	e := newEnv(t, func(o *Options) {
		o.IdleTimeout = time.Second
		o.UploadTimeout = time.Nanosecond
	})
	u := e.user(alice)
	r := httptest.NewRequest(http.MethodPost, "/ft", strings.NewReader(multipartBody(tidPart("slow"), filePart("a", "text/plain", "x"))))
	r.Header.Set("Content-Type", formType)
	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	e.srv.ServeHTTP(rec, u.sign(r))
	if rec.Code != http.StatusRequestTimeout || e.metric("upload.failed.timeout") != 1 {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestStalledUploadIsCutOffAtTheIdleTimeout(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.IdleTimeout = 100 * time.Millisecond })
	srv := e.serve()
	u := e.user(alice)
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/ft", nil)
	u.sign(req)
	body := multipartBody(tidPart("stall"), filePart("a", "text/plain", pattern(testPart)))
	head := "POST /ft HTTP/1.1\r\nHost: ft\r\nContent-Type: " + formType +
		"\r\nAuthorization: " + req.Header.Get("Authorization") +
		"\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
	// Half the body, then nothing: the connection stays open.
	if _, err := io.WriteString(conn, head+body[:len(body)/2]); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer to a stalled upload: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want 408", resp.StatusCode)
	}
}

// The 408 still reaches the client when the handler, having seen the idle
// timeout, does not get to write it for longer than the idle timeout again,
// as on a loaded host: the answer's write deadline is set just before the
// write, not before the hold (#211). The handler is held three idle
// timeouts, a lower bound only.
func TestAStalledUploadsAnswerSurvivesASlowHandler(t *testing.T) {
	const idle = 100 * time.Millisecond
	hold := func() { time.Sleep(3 * idle) }
	answeringFailure.Store(&hold)
	t.Cleanup(func() { answeringFailure.Store(nil) })
	e := newEnv(t, func(o *Options) { o.IdleTimeout = idle })
	srv := e.serve()
	u := e.user(alice)
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/ft", nil)
	u.sign(req)
	body := multipartBody(tidPart("stall"), filePart("a", "text/plain", pattern(testPart)))
	head := "POST /ft HTTP/1.1\r\nHost: ft\r\nContent-Type: " + formType +
		"\r\nAuthorization: " + req.Header.Get("Authorization") +
		"\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
	if _, err := io.WriteString(conn, head+body[:len(body)/2]); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer to a stalled upload whose handler was slow: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want 408", resp.StatusCode)
	}
}

// A failed upload's answer is written while the handler runs, under a
// write deadline of IdleTimeout set just before the write, and flushed at
// once: its write is bounded, and no deadline set earlier can pass before
// it (#211). The writer records what is done to it, in order.
func TestAFailedUploadsAnswerIsWrittenUnderAFreshDeadline(t *testing.T) {
	const idle = 100 * time.Millisecond
	e := newEnv(t, func(o *Options) { o.IdleTimeout = idle })
	wall := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	e.srv.wallNow = func() time.Time { return wall }
	w := &recordingWriter{ResponseRecorder: httptest.NewRecorder()}
	e.srv.uploadFailed(w, "timeout", http.StatusRequestTimeout)
	want := []string{"read deadline " + time.Unix(1, 0).UTC().Format(time.RFC3339Nano), "deadline " + wall.Add(idle).Format(time.RFC3339Nano), "write", "flush"}
	if got := w.events(); !slices.Equal(got, want) {
		t.Fatalf("the writer saw %q, want %q", got, want)
	}
	if w.Code != http.StatusRequestTimeout {
		t.Errorf("status = %d, want 408", w.Code)
	}
}

// recordingWriter records the write deadlines, writes and flushes done to
// it through http.ResponseController.
type recordingWriter struct {
	*httptest.ResponseRecorder
	mu  sync.Mutex
	log []string
}

func (w *recordingWriter) add(e string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.log) == 0 || w.log[len(w.log)-1] != e {
		w.log = append(w.log, e)
	}
}

func (w *recordingWriter) events() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.log)
}

func (w *recordingWriter) SetReadDeadline(d time.Time) error {
	w.add("read deadline " + d.UTC().Format(time.RFC3339Nano))
	return nil
}

func (w *recordingWriter) SetWriteDeadline(d time.Time) error {
	w.add("deadline " + d.Format(time.RFC3339Nano))
	return nil
}

func (w *recordingWriter) Write(b []byte) (int, error) {
	w.add("write")
	return w.ResponseRecorder.Write(b)
}

func (w *recordingWriter) FlushError() error {
	w.add("flush")
	w.ResponseRecorder.Flush()
	return nil
}

// A resume that fails before its body is read, here for an unknown tid,
// is answered, and frees the user's upload slot, though the client never
// sends the body it announced: the failure answer's whole flush is bounded,
// net/http's discard of the unread body included (#497). The slot must be
// free within IdleTimeout; the wait is only a hang guard, since nothing
// else would end that read.
func TestAFailedResumeWithItsBodyUnsentFreesItsSlot(t *testing.T) {
	const idle = 30 * time.Second
	e := newEnv(t, func(o *Options) { o.IdleTimeout = idle; o.MaxUploadsPerUser = 1 })
	srv := e.serve()
	u := e.user(alice)
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/ft/unknown-tid", nil)
	u.sign(req)
	head := "PUT /ft/unknown-tid HTTP/1.1\r\nHost: ft\r\nContent-Type: text/plain" +
		"\r\nAuthorization: " + req.Header.Get("Authorization") +
		"\r\nContent-Range: bytes 0-99/100\r\nContent-Length: 100\r\n\r\n"
	if _, err := io.WriteString(conn, head); err != nil { // and no body
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(idle)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer to a resume whose body was never sent: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	held := func() int {
		e.srv.perUser.mu.Lock()
		defer e.srv.perUser.mu.Unlock()
		n := 0
		for _, k := range e.srv.perUser.n {
			n += k
		}
		return n
	}
	for deadline := time.Now().Add(idle); held() != 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the user still holds %d upload slots %v after the answer", held(), idle)
		}
	}
}

// badRecordSource answers like an HSS whose record for the user is
// unusable.
type badRecordSource struct{}

func (badRecordSource) Lookup(context.Context, string, digest.Algorithm) (Credential, error) {
	return Credential{}, fmt.Errorf("%w: credential for another realm", ErrBadCredentialRecord)
}

func TestUnusableCredentialRecordLooksLikeAnUnknownUser(t *testing.T) {
	post := func() *http.Request { return httptest.NewRequest(http.MethodPost, "/ft", nil) }
	bad := newEnv(t, func(o *Options) { o.Credentials = badRecordSource{} })
	unknown := newEnv(t)
	got := failure(bad.do(bad.user(alice).sign(post())))
	want := failure(unknown.do(unknown.user("001010000000003@ims.mnc001.mcc001.3gppnetwork.org").sign(post())))
	if got != want {
		t.Fatalf("an unusable record answered\n%s\nan unknown user\n%s", got, want)
	}
	if bad.metric("auth.bad_credential_record") != 1 || bad.metric("auth.backend_error") != 0 || len(bad.h.Logs("credential record unusable")) != 1 {
		t.Fatal("the unusable record was not reported on its own")
	}
	if strings.Contains(bad.h.Output(), "001010000000001") {
		t.Fatal("the user name reached the log")
	}
}
