package ftserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// Test identities: IMPIs of the reserved test network (MCC 001 / MNC 01),
// listed in .github/allowed-test-identifiers.txt.
const (
	alice    = "001010000000001@ims.mnc001.mcc001.3gppnetwork.org"
	bob      = "001010000000002@ims.mnc001.mcc001.3gppnetwork.org"
	password = "correct horse battery staple"
	realm    = "ft.ims.mnc001.mcc001.3gppnetwork.org"
	testPart = 1024
)

// clock is a manual clock for validity, leases and nonces.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// seeded is a deterministic, concurrency-safe randomness source.
type seeded struct {
	mu sync.Mutex
	r  *rand.ChaCha8
}

func (s *seeded) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.r.Read(p)
}

// env is one ft-server under test with its stores, clock and output.
type env struct {
	t       *testing.T
	h       *runtimetest.Harness
	srv     *Server
	meta    *store.Memory
	blobs   *store.MemoryBlobs
	clock   *clock
	opts    Options
	httpSrv *httptest.Server
}

func newEnv(t *testing.T, change ...func(*Options)) *env {
	t.Helper()
	h := runtimetest.New(t, "ft-server")
	c := &clock{now: time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)}
	ds, err := digest.NewServer(digest.ServerConfig{
		Realm:       realm,
		NonceKey:    bytes.Repeat([]byte("k"), 32),
		NonceCounts: digest.NewMemoryNonceCounts(c.Now),
		Now:         c.Now,
		Random:      &seeded{r: rand.NewChaCha8([32]byte{1})},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, h: h, meta: store.NewMemory(), blobs: store.NewMemoryBlobs(testPart), clock: c}
	e.opts = Options{
		UploadURI:            mustURL("https://ft.example.test/ft"),
		DownloadURI:          mustURL("https://ft.example.test/dl"),
		Digest:               ds,
		Credentials:          NewStaticCredentials(map[string]string{alice: password, bob: password}),
		Metadata:             e.meta,
		Blobs:                e.blobs,
		Logger:               h.Runtime.Logger,
		Metrics:              h.Runtime.Metrics,
		MaxSize:              64 * testPart,
		MaxThumbnailSize:     2 * testPart,
		PartSize:             testPart,
		Validity:             7 * 24 * time.Hour,
		UploadsPerMinute:     100,
		MaxConcurrentUploads: 8,
		UploadTimeout:        time.Minute,
		StorageTimeout:       time.Minute,
		Now:                  c.Now,
		Random:               &seeded{r: rand.NewChaCha8([32]byte{2})},
	}
	for _, f := range change {
		f(&e.opts)
	}
	e.srv, err = New(e.opts)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// serve starts a real HTTP server, for flows that need connections:
// chunked bodies, broken uploads, deadlines.
func (e *env) serve() *httptest.Server {
	if e.httpSrv == nil {
		e.httpSrv = httptest.NewServer(e.srv)
		e.t.Cleanup(e.httpSrv.Close)
	}
	return e.httpSrv
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// metric returns the sum of metric name, 0 if never written.
func (e *env) metric(name string) float64 {
	v, _ := e.h.Metric(name)
	return v
}

// user is a Digest client for one user: it holds the challenge and the
// nonce-count, like an RCS client reusing a nonce.
type user struct {
	e        *env
	name     string
	password string
	ch       digest.Challenge
	nc       uint32
}

func (e *env) user(name string) *user {
	return &user{e: e, name: name, password: password}
}

// challenge gets a fresh SHA-256 challenge with the pre-check POST.
func (u *user) challenge() {
	u.e.t.Helper()
	rec := u.e.do(httptest.NewRequest(http.MethodPost, "/ft", nil))
	if rec.Code != http.StatusUnauthorized {
		u.e.t.Fatalf("pre-check without credentials = %d, want 401", rec.Code)
	}
	u.takeChallenge(rec.Header())
}

func (u *user) takeChallenge(h http.Header) {
	u.e.t.Helper()
	for _, v := range h.Values("WWW-Authenticate") {
		ch, err := digest.ParseChallenge(v)
		if err == nil && ch.Algorithm == digest.SHA256 {
			u.ch, u.nc = ch, 0
			return
		}
	}
	u.e.t.Fatalf("no SHA-256 challenge in %q", h.Values("WWW-Authenticate"))
}

// sign adds credentials for r to it, using the next nonce-count.
func (u *user) sign(r *http.Request) *http.Request {
	u.e.t.Helper()
	if u.ch.Nonce == "" {
		u.challenge()
	}
	u.nc++
	c, err := digest.Respond(u.ch, digest.ClientParams{
		Username: u.name, Password: []byte(u.password), Method: r.Method,
		URI: r.URL.RequestURI(), CNonce: fmt.Sprintf("cnonce-%d", u.nc), NC: u.nc,
	})
	if err != nil {
		u.e.t.Fatal(err)
	}
	r.Header.Set("Authorization", c.Header())
	return r
}

// do serves r on the handler directly.
func (e *env) do(r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, r)
	return rec
}

// part is one part of a hand-built multipart body.
type part struct {
	header string // raw header lines, each ending in CRLF
	body   string
}

func tidPart(tid string) part {
	return part{header: "Content-Disposition: form-data; name=\"tid\"\r\nContent-Type: text/plain\r\n", body: tid}
}

func thumbPart(data string) part {
	return part{header: "Content-Disposition: form-data; name=\"Thumbnail\"; filename=\"thumb.jpg\"\r\nContent-Type: image/jpeg\r\n", body: data}
}

func filePart(name, contentType, data string) part {
	return part{header: "Content-Disposition: form-data; name=\"File\"; filename=\"" + name + "\"\r\nContent-Type: " + contentType + "\r\n", body: data}
}

const boundary = "boundary1"

// multipartBody writes parts the way RCS clients do, closing delimiter
// included.
func multipartBody(parts ...part) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString("--" + boundary + "\r\n" + p.header + "\r\n" + p.body + "\r\n")
	}
	b.WriteString("--" + boundary + "--\r\n")
	return b.String()
}

const formType = "multipart/form-data; boundary=" + boundary

// upload posts a multipart body as u and returns the recorder.
func (u *user) upload(body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/ft", strings.NewReader(body))
	r.Header.Set("Content-Type", formType)
	return u.e.do(u.sign(r))
}

// uploadFile uploads data under tid with no thumbnail and returns the
// parsed file-info document.
func (u *user) uploadFile(tid, data string) fileDocument {
	u.e.t.Helper()
	rec := u.upload(multipartBody(tidPart(tid), filePart("a.bin", "application/octet-stream", data)))
	if rec.Code != http.StatusOK {
		u.e.t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	return parseFileDocument(u.e.t, rec.Body.Bytes())
}

func (u *user) get(target string) *httptest.ResponseRecorder {
	return u.e.do(u.sign(httptest.NewRequest(http.MethodGet, target, nil)))
}

func (u *user) put(target, contentRange, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPut, target, strings.NewReader(body))
	r.Header.Set("Content-Range", contentRange)
	return u.e.do(u.sign(r))
}

func parseFileDocument(t *testing.T, body []byte) fileDocument {
	t.Helper()
	var d fileDocument
	if err := xml.Unmarshal(body, &d); err != nil {
		t.Fatalf("file-info document does not parse: %v\n%s", err, body)
	}
	if d.XMLName.Space != namespace || d.XMLName.Local != "file" {
		t.Fatalf("root element = %v", d.XMLName)
	}
	return d
}

func parseResumeDocument(t *testing.T, body []byte) resumeDocument {
	t.Helper()
	var d resumeDocument
	if err := xml.Unmarshal(body, &d); err != nil {
		t.Fatalf("upload-info document does not parse: %v\n%s", err, body)
	}
	return d
}

// fileOf returns the info of type file.
func fileOf(t *testing.T, d fileDocument) fileInfo {
	t.Helper()
	for _, i := range d.Infos {
		if i.Type == infoTypeFile {
			return i
		}
	}
	t.Fatalf("no file info in %+v", d)
	return fileInfo{}
}

// downloadTarget turns a data URL into the request target on the test
// server.
func downloadTarget(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	return u.RequestURI()
}

// pattern returns n bytes that differ by position, so a misplaced range or
// part shows up.
func pattern(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + i%26 + i/26%3)
	}
	return string(b)
}

func sha(data string) []byte {
	s := sha256.Sum256([]byte(data))
	return s[:]
}

func readAllString(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
