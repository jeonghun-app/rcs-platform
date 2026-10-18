package ftserver

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
)

// stalledBody delivers its prefix, signals, then blocks until released,
// like a client that stops sending in the middle of a body.
type stalledBody struct {
	prefix  *strings.Reader
	stalled chan struct{}
	release chan struct{}
	once    sync.Once
}

func newStalledBody(prefix string) *stalledBody {
	return &stalledBody{prefix: strings.NewReader(prefix), stalled: make(chan struct{}), release: make(chan struct{})}
}

func (s *stalledBody) Read(p []byte) (int, error) {
	if s.prefix.Len() > 0 {
		return s.prefix.Read(p)
	}
	s.once.Do(func() { close(s.stalled) })
	<-s.release
	return 0, io.ErrUnexpectedEOF
}

func TestOneUserCannotHoldEveryUploadSlot(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.MaxUploadsPerUser = 2 })
	a, b := e.user(alice), e.user(bob)
	a.challenge()
	var wg sync.WaitGroup
	var stalls []*stalledBody
	for i := range 2 {
		body := multipartBody(tidPart("hold-"+strconv.Itoa(i)), filePart("a", "text/plain", pattern(testPart)))
		s := newStalledBody(body[:len(body)/2])
		stalls = append(stalls, s)
		r := a.sign(httptest.NewRequest(http.MethodPost, "/ft", s))
		r.Header.Set("Content-Type", formType)
		wg.Go(func() { e.do(r) })
		<-s.stalled
	}
	rec := a.upload(multipartBody(tidPart("third"), filePart("a", "text/plain", "x")))
	if rec.Code != http.StatusServiceUnavailable || e.metric("upload.failed.user_busy") != 1 {
		t.Fatalf("alice's third upload = %d, user_busy %v", rec.Code, e.metric("upload.failed.user_busy"))
	}
	b.uploadFile("bobs", "x")
	for _, s := range stalls {
		close(s.release)
	}
	wg.Wait()
	a.uploadFile("after", "x")
}

func TestUploadSlowerThanTheMinimumRateIsCutOff(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.MinUploadRate = 100; o.UploadTimeout = time.Hour })
	wall := time.Unix(1_800_000_000, 0)
	e.srv.wallNow = func() time.Time { return wall }
	u := e.user(alice)
	body := multipartBody(tidPart("slow"), filePart("a", "text/plain", pattern(3*testPart)))
	// Every read moves the wall clock on by ten seconds: 4096 bytes and
	// more per read, the first minute passes at well over 100 bytes/s ...
	fast := &clockedReader{r: strings.NewReader(body), step: 10 * time.Second, now: &wall, chunk: 4096}
	r := u.sign(httptest.NewRequest(http.MethodPost, "/ft", fast))
	r.Header.Set("Content-Type", formType)
	if rec := e.do(r); rec.Code != http.StatusOK {
		t.Fatalf("upload at a good rate = %d", rec.Code)
	}
	// ... but at 100 bytes per ten seconds the next minute falls short.
	slow := &clockedReader{r: strings.NewReader(strings.Replace(body, "slow", "slow2", 1)), step: 10 * time.Second, now: &wall, chunk: 100}
	r = u.sign(httptest.NewRequest(http.MethodPost, "/ft", slow))
	r.Header.Set("Content-Type", formType)
	if rec := e.do(r); rec.Code != http.StatusRequestTimeout || e.metric("upload.failed.too_slow") != 1 {
		t.Fatalf("upload below the minimum rate = %d", rec.Code)
	}
}

// clockedReader returns at most chunk bytes per read and moves *now on by
// step each time.
type clockedReader struct {
	r     io.Reader
	step  time.Duration
	now   *time.Time
	chunk int
}

func (c *clockedReader) Read(p []byte) (int, error) {
	*c.now = c.now.Add(c.step)
	if len(p) > c.chunk {
		p = p[:c.chunk]
	}
	return c.r.Read(p)
}

func TestDownloadsBeyondTheTaskLimitAreTurnedAway(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.MaxConcurrentDownloads = 1 })
	file, _ := uploaded(t, e, "data")
	release, _ := acquireSlot(e.srv.downloads)
	rec := get(e, file)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" || e.metric("download.failed.busy") != 1 {
		t.Fatalf("status = %d", rec.Code)
	}
	release()
	if rec := get(e, file); rec.Code != http.StatusOK {
		t.Fatalf("after the slot freed = %d", rec.Code)
	}
}

func TestEmptyPrecheckWithAFormContentTypeIsAPrecheckAndUsesNoToken(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.UploadsPerMinute = 1 })
	u := e.user(alice)
	for range 3 {
		r := httptest.NewRequest(http.MethodPost, "/ft", nil)
		r.Header.Set("Content-Type", formType)
		if rec := e.do(u.sign(r)); rec.Code != http.StatusNoContent {
			t.Fatalf("pre-check with a form Content-Type = %d", rec.Code)
		}
	}
	// Chunked with no data, as a streaming client sends it.
	r := httptest.NewRequest(http.MethodPost, "/ft", struct{ io.Reader }{strings.NewReader("")})
	r.ContentLength = -1
	r.Header.Set("Content-Type", formType)
	if rec := e.do(u.sign(r)); rec.Code != http.StatusNoContent {
		t.Fatalf("chunked empty pre-check = %d", rec.Code)
	}
	if e.metric("upload.precheck") != 4 {
		t.Fatalf("upload.precheck = %v", e.metric("upload.precheck"))
	}
	u.uploadFile("after-prechecks", "x")
}

func TestEveryAnswerSaysNosniff(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	u.uploadFile("sniff", "x")
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"file-info":   u.upload(multipartBody(tidPart("sniff2"), filePart("a", "text/html", "<p>"))),
		"upload-info": u.get("/ft?tid=sniff&get_upload_info"),
		"401":         e.do(httptest.NewRequest(http.MethodPost, "/ft", nil)),
		"404":         e.do(httptest.NewRequest(http.MethodGet, "/nowhere", nil)),
	} {
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s (%d) lacks nosniff", name, rec.Code)
		}
	}
}

func TestLeaseIsRenewedWhileContentFlowsAndLapsesWithoutIt(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	breakUpload(t, e, u, "renew", pattern(4*testPart), testPart+1)
	rec, _ := e.meta.GetByTID(t.Context(), alice, "renew")
	rec, err := e.srv.acquireLease(t.Context(), rec, nil)
	if err != nil {
		t.Fatal(err)
	}
	w, err := e.srv.newWriter(rec)
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	// A slow body: the manual clock moves a third of the lease on per read,
	// so the lease would lapse twice over without renewal.
	src := &clockAdvancer{r: strings.NewReader(pattern(testPart / 2)), c: e.clock, step: e.srv.leaseTTL / 3, chunk: 64}
	if err := w.copy(t.Context(), src); err != nil {
		t.Fatal(err)
	}
	stored, _ := e.meta.Get(t.Context(), rec.ID)
	if !e.clock.Now().Before(stored.LeaseUntil) || e.metric("upload.lease_renewed") == 0 {
		t.Fatalf("lease until %v at %v, renewals %v", stored.LeaseUntil, e.clock.Now(), e.metric("upload.lease_renewed"))
	}
	// A lease nobody renews is free again after leaseTTL.
	e.clock.Advance(e.srv.leaseTTL)
	if _, err := e.srv.acquireLease(t.Context(), stored, nil); err != nil {
		t.Fatalf("an unrenewed lease did not lapse: %v", err)
	}
}

// clockAdvancer moves a manual clock on by step on every read.
type clockAdvancer struct {
	r     io.Reader
	c     *clock
	step  time.Duration
	chunk int
}

func (c *clockAdvancer) Read(p []byte) (int, error) {
	c.c.Advance(c.step)
	if len(p) > c.chunk {
		p = p[:c.chunk]
	}
	return c.r.Read(p)
}

// signalBlobs signals each stored part.
type signalBlobs struct {
	store.Blobs
	parts chan struct{}
}

func (s *signalBlobs) UploadPart(ctx context.Context, key, id string, n int32, body []byte) (store.Part, error) {
	p, err := s.Blobs.UploadPart(ctx, key, id, n, body)
	s.parts <- struct{}{}
	return p, err
}

func TestShutdownCutsRunningUploadsAndReleasesTheirLeases(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.IdleTimeout = time.Minute })
	signal := &signalBlobs{Blobs: e.blobs, parts: make(chan struct{}, 8)}
	e.srv.o.Blobs = signal
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: e.srv}
	go hs.Serve(ln)
	u := e.user(alice)

	// An upload that has stored a part and then waits for more.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	data := pattern(3 * testPart)
	body := multipartBody(tidPart("cut"), filePart("a.bin", "application/octet-stream", data))
	req, _ := http.NewRequest(http.MethodPost, "http://"+ln.Addr().String()+"/ft", nil)
	u.sign(req)
	head := "POST /ft HTTP/1.1\r\nHost: ft\r\nContent-Type: " + formType + "\r\nAuthorization: " +
		req.Header.Get("Authorization") + "\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
	if _, err := io.WriteString(conn, head+body[:strings.Index(body, data)+testPart+10]); err != nil {
		t.Fatal(err)
	}
	<-signal.parts

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err := drain(ctx, hs, e.srv, 50*time.Millisecond); err != nil {
		t.Fatalf("drain = %v", err)
	}
	if _, err := http.ReadResponse(bufio.NewReader(conn), nil); err == nil {
		// The connection was closed under the handler; any answer it
		// managed to write is fine, a hung one is not.
		t.Log("the cut upload was answered")
	}
	rec, _ := e.meta.GetByTID(t.Context(), alice, "cut")
	if rec.Lease != "" || rec.Received != testPart {
		t.Fatalf("after shutdown: lease %q, received %d", rec.Lease, rec.Received)
	}
	// Another task takes over at once, without waiting for a lease.
	if put := u.put("/ft/cut", rangeHeader(testPart, len(data)), data[testPart:]); put.Code != http.StatusOK {
		t.Fatalf("resume after shutdown = %d", put.Code)
	}
}

func TestBreakAfterTheLastByteOfAPartMultipleCanStillComplete(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	data := pattern(2 * testPart)
	breakUpload(t, e, u, "edge", data, len(data)) // every content byte, then the link breaks
	d := parseResumeDocument(t, u.get("/ft?tid=edge&get_upload_info").Body.Bytes())
	end, _ := strconv.Atoi(d.Range.End)
	if end >= len(data)-1 {
		t.Fatalf("incomplete upload reported as fully held (end=%d)", end)
	}
	if put := u.put("/ft/edge", rangeHeader(end+1, len(data)), data[end+1:]); put.Code != http.StatusOK {
		t.Fatalf("resume = %d", put.Code)
	}
}

// flakyComplete fails the first CompleteMultipart with a transient error.
type flakyComplete struct {
	store.Blobs
	n atomic.Int32
}

func (f *flakyComplete) CompleteMultipart(ctx context.Context, key, id string, parts []store.Part) error {
	if f.n.Add(1) == 1 {
		return errors.New("SlowDown")
	}
	return f.Blobs.CompleteMultipart(ctx, key, id, parts)
}

func TestTransientCompletionFailureOfAPartMultipleCanBeResumed(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	data := pattern(3 * testPart)
	breakUpload(t, e, u, "flaky", data, testPart+10)
	e.srv.o.Blobs = &flakyComplete{Blobs: e.blobs}
	if put := u.put("/ft/flaky", rangeHeader(testPart, len(data)), data[testPart:]); put.Code != http.StatusInternalServerError {
		t.Fatalf("first resume = %d, want 500", put.Code)
	}
	d := parseResumeDocument(t, u.get("/ft?tid=flaky&get_upload_info").Body.Bytes())
	end, _ := strconv.Atoi(d.Range.End)
	if put := u.put("/ft/flaky", rangeHeader(end+1, len(data)), data[end+1:]); put.Code != http.StatusOK {
		t.Fatalf("resume after a transient failure = %d (end=%d)", put.Code, end)
	}
}

func TestDownloadURIWithTrailingSlashIsRefused(t *testing.T) {
	base := newEnv(t).opts
	for _, uris := range [][2]string{
		{"https://ft.example.test/ft/", "https://ft.example.test/dl"},
		{"https://ft.example.test/ft", "https://ft.example.test/dl/"},
	} {
		o := base
		o.UploadURI, o.DownloadURI = mustURL(uris[0]), mustURL(uris[1])
		if _, err := New(o); err == nil {
			t.Errorf("New accepted %v", uris)
		}
	}
}

func TestSweepReportsItsDuration(t *testing.T) {
	e := newEnv(t)
	if _, err := e.srv.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.h.Metric("sweep.duration"); !ok {
		t.Fatal("no sweep.duration")
	}
}
