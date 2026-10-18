package ftserver

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

func TestEmptyPostIsChallengedWithSHA256BeforeMD5(t *testing.T) {
	e := newEnv(t)
	rec := e.do(httptest.NewRequest(http.MethodPost, "/ft", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	values := rec.Header().Values("WWW-Authenticate")
	if len(values) != 2 {
		t.Fatalf("WWW-Authenticate = %q", values)
	}
	for i, want := range []digest.Algorithm{digest.SHA256, digest.MD5} {
		ch, err := digest.ParseChallenge(values[i])
		if err != nil || ch.Algorithm != want || ch.Realm != realm {
			t.Fatalf("challenge %d = %+v, %v", i, ch, err)
		}
	}
	if e.metric("auth.challenged") != 1 {
		t.Fatal("challenge not counted")
	}
}

func TestAuthenticatedEmptyPostIsAnsweredNoContent(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	rec := e.do(u.sign(httptest.NewRequest(http.MethodPost, "/ft", nil)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if e.metric("upload.precheck") != 1 {
		t.Fatal("pre-check not counted")
	}
}

func TestChunkedEmptyPostIsAPrecheck(t *testing.T) {
	e := newEnv(t)
	srv := e.serve()
	u := e.user(alice)
	// A chunked request with no data, as RCS clients streaming the
	// pre-check send it: no Content-Length, zero chunks.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/ft", struct{ *strings.Reader }{strings.NewReader("")})
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	u.sign(req)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
}

func TestNonMultipartBodyIsUnsupported(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	r := httptest.NewRequest(http.MethodPost, "/ft", strings.NewReader("hello"))
	r.Header.Set("Content-Type", "text/plain")
	if rec := e.do(u.sign(r)); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", rec.Code)
	}
}

func TestUploadReturnsFileInfoForFileAndThumbnail(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	data := pattern(3*testPart + 17)
	rec := u.upload(multipartBody(tidPart("f81d4fae-7dec-11d0-a765-00a0c91e6bf6"), thumbPart("JPEGDATA"),
		filePart("holiday <1> & 'two'.jpg", "image/jpeg", data)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != ContentType {
		t.Fatalf("Content-Type = %q", ct)
	}
	doc := parseFileDocument(t, rec.Body.Bytes())
	if len(doc.Infos) != 2 || doc.Infos[0].Type != infoTypeThumbnail || doc.Infos[1].Type != infoTypeFile {
		t.Fatalf("file-info elements = %+v, want thumbnail then file", doc.Infos)
	}
	until := formatUntil(e.clock.Now().Add(e.opts.Validity))
	th, f := doc.Infos[0], doc.Infos[1]
	if th.Size != 8 || th.ContentType != "image/jpeg" || th.Name != "" || th.Data.Until != until {
		t.Fatalf("thumbnail info = %+v", th)
	}
	if f.Size != int64(len(data)) || f.ContentType != "image/jpeg" || f.Name != "holiday <1> & 'two'.jpg" || f.Data.Until != until {
		t.Fatalf("file info = %+v", f)
	}
	if !strings.HasPrefix(f.Data.URL, "https://ft.example.test/dl?id=") || th.Data.URL != f.Data.URL+thumbnailSuffix {
		t.Fatalf("data URLs = %q, %q", f.Data.URL, th.Data.URL)
	}
	if f.BrandedURL != "" {
		t.Fatalf("branded-url without FT_BRANDED_URI: %q", f.BrandedURL)
	}
	id, _, _ := parseDownloadID(strings.TrimPrefix(f.Data.URL, "https://ft.example.test/dl?id="))
	stored, ok := e.blobs.Object(id)
	if !ok || string(stored) != data {
		t.Fatalf("stored object is %d bytes, want %d", len(stored), len(data))
	}
	r, err := e.meta.Get(t.Context(), id)
	if err != nil || r.State != store.Complete || !bytes.Equal(r.SHA256, sha(data)) || r.Lease != "" {
		t.Fatalf("record = %+v, %v", r, err)
	}
	if e.metric("upload.completed") != 1 || e.metric("upload.bytes") != float64(len(data)) || e.metric("upload.parts") != 3 {
		t.Fatalf("metrics: completed %v bytes %v parts %v", e.metric("upload.completed"), e.metric("upload.bytes"), e.metric("upload.parts"))
	}
}

func TestSmallFileIsStoredWithoutMultipart(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	u.uploadFile("small", "tiny")
	if e.metric("upload.parts") != 0 || e.blobs.OpenUploads() != 0 {
		t.Fatal("a file below one part used a multipart upload")
	}
}

func TestFileOfExactlyOnePartIsStoredWhole(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	data := pattern(testPart)
	doc := u.uploadFile("one-part", data)
	if got := u.get(downloadTarget(t, fileOf(t, doc).Data.URL)).Body.String(); got != data {
		t.Fatalf("download is %d bytes, want %d", len(got), len(data))
	}
}

func TestEmptyFileUploadsAndDownloads(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	doc := u.uploadFile("empty", "")
	f := fileOf(t, doc)
	rec := e.do(httptest.NewRequest(http.MethodGet, downloadTarget(t, f.Data.URL), nil))
	if f.Size != 0 || rec.Code != http.StatusOK || rec.Body.Len() != 0 || rec.Header().Get("Content-Length") != "0" {
		t.Fatalf("empty file: size %d, download %d %q", f.Size, rec.Code, rec.Body)
	}
}

func TestBrandedURLUsesTheSameID(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.BrandedURI = mustURL("https://files.example.test/view") })
	f := fileOf(t, e.user(alice).uploadFile("branded", "x"))
	id := strings.TrimPrefix(f.Data.URL, "https://ft.example.test/dl?id=")
	if f.BrandedURL != "https://files.example.test/view?id="+id {
		t.Fatalf("branded-url = %q", f.BrandedURL)
	}
}

func TestDeclaredFileLengthMustMatch(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	p := filePart("a.bin", "application/octet-stream", "12345")
	p.header += "Content-Length: 9\r\n"
	if rec := u.upload(multipartBody(tidPart("len"), p)); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e.metric("upload.failed.length_mismatch") != 1 {
		t.Fatal("mismatch not counted")
	}
}

func TestFileLargerThanTheMaximumIsRefusedAndDiscarded(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	data := pattern(int(e.opts.MaxSize) + 1)
	rec := u.upload(multipartBody(tidPart("big"), filePart("a.bin", "application/octet-stream", data)))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	r, err := e.meta.GetByTID(t.Context(), alice, "big")
	if err != nil {
		t.Fatal(err)
	}
	if r.Received != 0 || r.MultipartID != "" || r.Lease != "" || e.blobs.OpenUploads() != 0 {
		t.Fatalf("a too large upload kept content: %+v, open uploads %d", r, e.blobs.OpenUploads())
	}
}

func TestOversizedRequestIsRefusedBeforeReading(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	r := httptest.NewRequest(http.MethodPost, "/ft", strings.NewReader("x"))
	r.Header.Set("Content-Type", formType)
	r.ContentLength = e.opts.MaxSize + e.opts.MaxThumbnailSize + maxFormOverhead + 1
	if rec := e.do(u.sign(r)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestUploadWithoutCredentialsIsChallengedWithoutStoringAnything(t *testing.T) {
	e := newEnv(t)
	r := httptest.NewRequest(http.MethodPost, "/ft", strings.NewReader(multipartBody(tidPart("x"), filePart("a", "text/plain", "x"))))
	r.Header.Set("Content-Type", formType)
	if rec := e.do(r); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if _, err := e.meta.GetByTID(t.Context(), alice, "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("an unauthenticated upload created a record")
	}
}

func TestCompletedTIDCannotBeUploadedAgain(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	u.uploadFile("done", "first")
	rec := u.upload(multipartBody(tidPart("done"), filePart("a.bin", "text/plain", "second")))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

func TestSameTIDOfAnotherUserIsAnotherUpload(t *testing.T) {
	e := newEnv(t)
	a := fileOf(t, e.user(alice).uploadFile("shared-tid", "alice's"))
	b := fileOf(t, e.user(bob).uploadFile("shared-tid", "bob's"))
	if a.Data.URL == b.Data.URL {
		t.Fatal("two users' uploads with one tid share a link")
	}
}

func TestIncompleteTIDStartsAgainFromTheFirstByte(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	breakUpload(t, e, u, "restart", pattern(3*testPart), 2*testPart+10)
	before, _ := e.meta.GetByTID(t.Context(), alice, "restart")
	data := pattern(2*testPart + 5)
	doc := u.uploadFile("restart", data)
	f := fileOf(t, doc)
	if f.Size != int64(len(data)) {
		t.Fatalf("size = %d", f.Size)
	}
	if got := u.get(downloadTarget(t, f.Data.URL)).Body.String(); got != data {
		t.Fatal("restarted upload stored other content")
	}
	if e.blobs.OpenUploads() != 0 {
		t.Fatalf("the first attempt's multipart upload was left open (%s)", before.MultipartID)
	}
	if e.metric("upload.restarted") != 1 {
		t.Fatal("restart not counted")
	}
}

func TestUploadsOverTheRateLimitAreTurnedAway(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.UploadsPerMinute = 2 })
	u := e.user(alice)
	u.uploadFile("r1", "x")
	u.uploadFile("r2", "x")
	rec := u.upload(multipartBody(tidPart("r3"), filePart("a", "text/plain", "x")))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("third upload in a minute = %d, want 503", rec.Code)
	}
	if ra, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || ra < 1 || ra > 30 {
		t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
	// Another user has their own bucket.
	e.user(bob).uploadFile("r3", "x")
	e.clock.Advance(30 * time.Second)
	u.uploadFile("r3", "x")
}

func TestRateLimitForgetsIdleUsers(t *testing.T) {
	now := time.Unix(0, 0)
	l := newLimiter(1, func() time.Time { return now })
	if ok, _ := l.allow("a"); !ok {
		t.Fatal("first upload refused")
	}
	if ok, wait := l.allow("a"); ok || wait <= 0 || wait > time.Minute {
		t.Fatalf("second upload = %v, wait %v", ok, wait)
	}
	now = now.Add(2 * time.Minute)
	l.allow("b")
	l.mu.Lock()
	_, kept := l.buckets["a"]
	l.mu.Unlock()
	if kept {
		t.Fatal("a refilled bucket was kept")
	}
}

func TestUploadsBeyondTheTaskLimitAreTurnedAway(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.MaxConcurrentUploads = 1 })
	release, ok := e.srv.acquireSlot()
	if !ok {
		t.Fatal("no slot")
	}
	defer release()
	u := e.user(alice)
	rec := u.upload(multipartBody(tidPart("busy"), filePart("a", "text/plain", "x")))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("status = %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	put := u.put("/ft/busy", "bytes 0-0/1", "x")
	if put.Code != http.StatusServiceUnavailable {
		t.Fatalf("resume status = %d", put.Code)
	}
}

func TestStorageFailureIsAnInternalErrorThatNamesNoFile(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	u.challenge()
	e.blobs.SetFailure(errors.New("s3 is down for https://bucket.example/secret-file-id"))
	rec := u.upload(multipartBody(tidPart("fails"), filePart("secret-name.jpg", "image/jpeg", pattern(2*testPart))))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if e.metric("upload.failed.storage") != 1 {
		t.Fatal("storage failure not counted")
	}
	out := e.h.Output()
	if len(e.h.Logs("storage failed")) != 1 || strings.Contains(out, "secret-name") || strings.Contains(out, "001010000000001") {
		t.Fatalf("log lines: %s", out)
	}
	r, _ := e.meta.GetByTID(t.Context(), alice, "fails")
	if r.Lease != "" {
		t.Fatal("a failed upload kept its lease")
	}
}

func TestThumbnailStorageFailureReleasesTheLease(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	u.challenge()
	e.blobs.SetFailure(errors.New("down"))
	rec := u.upload(multipartBody(tidPart("thumb-fails"), thumbPart("JPEG"), filePart("a", "text/plain", "x")))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	r, _ := e.meta.GetByTID(t.Context(), alice, "thumb-fails")
	if r.Lease != "" {
		t.Fatal("lease kept")
	}
	e.blobs.SetFailure(nil)
	u.upload(multipartBody(tidPart("thumb-fails"), thumbPart("JPEG"), filePart("a", "text/plain", "x")))
}

func TestUploadOfALeasedTIDIsBusy(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	breakUpload(t, e, u, "leased", pattern(2*testPart), testPart+1)
	r, _ := e.meta.GetByTID(t.Context(), alice, "leased")
	r.Lease, r.LeaseUntil = "someone", e.clock.Now().Add(time.Hour)
	if _, err := e.meta.Update(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	rec := u.upload(multipartBody(tidPart("leased"), filePart("a", "text/plain", "x")))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	// A lease whose holder died lapses.
	e.clock.Advance(2 * time.Hour)
	u.challenge()
	u.uploadFile("leased", "x")
}

func TestConcurrentCompletionOfOneTIDSucceedsOnce(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	rec, err := e.meta.Create(ctx, store.Record{
		ID: "concurrent-file-id-00000", Owner: alice, TID: "race", State: store.Uploading,
		DeclaredSize: -1, Created: e.clock.Now(), Expires: e.clock.Now().Add(time.Hour),
		Lease: "held", LeaseUntil: e.clock.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Two tasks that both believe they hold the record at this version: the
	// conditional update lets exactly one complete it.
	const writers = 2
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := range writers {
		wg.Go(func() {
			w, err := e.srv.newWriter(rec)
			if err != nil {
				errs[i] = err
				return
			}
			defer w.close()
			if err := w.copy(ctx, strings.NewReader("content "+strconv.Itoa(i))); err != nil {
				errs[i] = err
				return
			}
			_, errs[i] = w.complete(ctx)
		})
	}
	wg.Wait()
	ok, lost := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, errLostLease):
			lost++
		default:
			t.Fatalf("complete = %v", err)
		}
	}
	if ok != 1 || lost != 1 {
		t.Fatalf("%d completions succeeded and %d lost, want 1 and 1", ok, lost)
	}
}

func TestConcurrentResumesOfOneTIDHaveOneWriter(t *testing.T) {
	e := newEnv(t)
	u, v := e.user(alice), e.user(alice)
	data := pattern(3 * testPart)
	breakUpload(t, e, u, "race", data, testPart+5)
	u.challenge()
	v.challenge()
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i, c := range []*user{u, v} {
		r := c.sign(httptest.NewRequest(http.MethodPut, "/ft/race", strings.NewReader(data[testPart:])))
		r.Header.Set("Content-Range", "bytes "+strconv.Itoa(testPart)+"-"+strconv.Itoa(len(data)-1)+"/"+strconv.Itoa(len(data)))
		wg.Go(func() { codes[i] = e.do(r).Code })
	}
	wg.Wait()
	if !(codes[0] == http.StatusOK && codes[1] == http.StatusConflict || codes[0] == http.StatusConflict && codes[1] == http.StatusOK) {
		t.Fatalf("racing resumes answered %v, want one 200 and one 409", codes)
	}
	doc := parseFileDocument(t, u.get("/ft?tid=race&get_download_info").Body.Bytes())
	if got := u.get(downloadTarget(t, fileOf(t, doc).Data.URL)).Body.String(); got != data {
		t.Fatal("racing resumes corrupted the file")
	}
}

func TestUnknownPathsAndMethodsAreRefused(t *testing.T) {
	e := newEnv(t)
	for _, c := range []struct {
		method, target string
		code           int
		allow          string
	}{
		{http.MethodGet, "/other", http.StatusNotFound, ""},
		{http.MethodDelete, "/ft", http.StatusMethodNotAllowed, "GET, POST"},
		{http.MethodPost, "/dl?id=x", http.StatusMethodNotAllowed, "GET, HEAD"},
		{http.MethodPost, "/ft/some-tid", http.StatusMethodNotAllowed, "PUT"},
		{http.MethodPut, "/ft/a%2Fb", http.StatusNotFound, ""},
		{http.MethodPut, "/ft/..", http.StatusNotFound, ""},
	} {
		rec := e.do(httptest.NewRequest(c.method, c.target, nil))
		if rec.Code != c.code || rec.Header().Get("Allow") != c.allow {
			t.Errorf("%s %s = %d Allow %q, want %d %q", c.method, c.target, rec.Code, rec.Header().Get("Allow"), c.code, c.allow)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s %s may be cached", c.method, c.target)
		}
	}
}

func TestNewRefusesInconsistentOptions(t *testing.T) {
	base := newEnv(t).opts
	for name, change := range map[string]func(*Options){
		"no URIs":               func(o *Options) { o.UploadURI = nil },
		"no stores":             func(o *Options) { o.Blobs = nil },
		"no logger":             func(o *Options) { o.Metrics = nil },
		"zero size":             func(o *Options) { o.MaxSize = 0 },
		"too many parts":        func(o *Options) { o.PartSize = 1 },
		"zero validity":         func(o *Options) { o.Validity = 0 },
		"no slots":              func(o *Options) { o.MaxConcurrentUploads = 0 },
		"root upload path":      func(o *Options) { o.UploadURI = mustURL("https://ft.example.test/") },
		"same paths":            func(o *Options) { o.DownloadURI = mustURL("https://other.example.test/ft/") },
		"download below upload": func(o *Options) { o.DownloadURI = mustURL("https://ft.example.test/ft/dl") },
	} {
		o := base
		change(&o)
		if _, err := New(o); err == nil {
			t.Errorf("%s: New accepted the options", name)
		}
	}
}

// failingUpdates fails every record update after the first n, like a table
// that starts throttling in the middle of an upload.
type failingUpdates struct {
	store.Metadata
	mu sync.Mutex
	n  int
}

func (f *failingUpdates) Update(ctx context.Context, r store.Record) (store.Record, error) {
	f.mu.Lock()
	f.n--
	fail := f.n < 0
	f.mu.Unlock()
	if fail {
		return store.Record{}, errors.New("throttled")
	}
	return f.Metadata.Update(ctx, r)
}

func TestFailedPartRecordAbortsTheNewMultipartUpload(t *testing.T) {
	meta := &failingUpdates{Metadata: store.NewMemory()}
	e := newEnv(t, func(o *Options) { o.Metadata = meta })
	u := e.user(alice)
	rec := u.upload(multipartBody(tidPart("throttled"), filePart("a", "text/plain", pattern(3*testPart))))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	if e.blobs.OpenUploads() != 0 {
		t.Fatal("a multipart upload no record names was left open")
	}
	if !strings.Contains(e.h.Output(), "update record") {
		t.Fatalf("log does not say which step failed: %s", e.h.Output())
	}
}

func TestLogsAndMetricsCarryNoFileDataOrIdentity(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	const name, tid, content = "private-name.jpg", "private-tid-0001", "private-content"
	rec := u.upload(multipartBody(tidPart(tid), thumbPart("private-thumb"), filePart(name, "image/jpeg", content)))
	f := fileOf(t, parseFileDocument(t, rec.Body.Bytes()))
	id := strings.TrimPrefix(f.Data.URL, "https://ft.example.test/dl?id=")
	get(e, downloadTarget(t, f.Data.URL))
	breakUpload(t, e, u, "private-tid-0002", pattern(2*testPart), testPart+3)
	u.get("/ft?tid=private-tid-0002&get_upload_info")
	e.blobs.SetFailure(errors.New("storage down"))
	u.put("/ft/private-tid-0002", rangeHeader(testPart, 2*testPart), pattern(2 * testPart)[testPart:])

	out := e.h.Output()
	if len(e.h.Logs("upload completed")) != 1 {
		t.Fatalf("no completion log line:\n%s", out)
	}
	for _, secret := range []string{name, tid, "private-tid-0002", content, "private-thumb", id, "001010000000001", password} {
		if strings.Contains(out, secret) {
			t.Errorf("output contains %q:\n%s", secret, out)
		}
	}
}
