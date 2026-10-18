package ftserver

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// minPartSize is the smallest part S3 accepts in a multipart upload other
// than the last.
const minPartSize = 5 << 20

// maxParts bounds the parts of one upload. S3 allows 10000, but every part is
// listed in the record, and a DynamoDB item (400 KB) holds about 7000 part
// entries; 5000 leaves room for the rest of the record.
const maxParts = 5000

// retryAfter is the Retry-After of a 503 for a full task, a user at their
// limits, a credential backend that is down, and a tid that another request
// is creating.
const retryAfter = 10 * time.Second

// rateWindow is the interval over which FT_MIN_UPLOAD_RATE is measured.
const rateWindow = time.Minute

// Options configures a Server. Every field without a stated default is
// required.
type Options struct {
	// UploadURI is the public ftHTTPCSURI and DownloadURI the public
	// ftHTTPDLURI (what acs provisions). The server answers on their paths,
	// which must not end in '/'; the documents it returns link to them.
	UploadURI, DownloadURI *url.URL
	// BrandedURI, when set, adds a branded-url to each file's file-info: the
	// same id on an operator's web page, for recipients without RCS.
	BrandedURI *url.URL

	// Digest verifies credentials. It should accept a path-only uri
	// (digest.ServerConfig.HTTPPathOnlyURI) for the info requests of RCS
	// clients that sign only the path.
	Digest      *digest.Server
	Credentials CredentialSource
	Metadata    store.Metadata
	Blobs       store.Blobs

	Logger  *slog.Logger
	Metrics *runtime.Metrics

	// MaxSize bounds a file and MaxThumbnailSize a thumbnail, in bytes.
	MaxSize, MaxThumbnailSize int64
	// PartSize is the size of each stored part, and so the memory one
	// upload holds; at least 5 MiB for S3.
	PartSize int64
	// Validity is how long download links work after an upload completes,
	// and how long an incomplete upload may be resumed.
	Validity time.Duration
	// DownloadAuth requires Digest authentication on downloads.
	DownloadAuth bool
	// UploadsPerMinute limits new uploads per user and task; 0 disables it.
	UploadsPerMinute int
	// MaxConcurrentUploads bounds uploads and resumes in progress on this
	// task, and MaxUploadsPerUser those of one user on it.
	MaxConcurrentUploads, MaxUploadsPerUser int
	// MaxConcurrentDownloads bounds downloads in progress on this task.
	MaxConcurrentDownloads int
	// MaxConcurrentLookups bounds credential lookups in progress on this
	// task, so requests from the internet cannot load the HSS without limit.
	MaxConcurrentLookups int
	// MaxDownloadsPerFile bounds downloads of one file in progress on this
	// task, sized for a group chat whose members all fetch one link at once,
	// and MaxDownloadsPerUploader those of all the files of one uploader, so
	// that one subscriber's links cannot take every slot of the task.
	MaxDownloadsPerFile, MaxDownloadsPerUploader int
	// MinUploadRate is the slowest an upload body may arrive and
	// MinDownloadRate the slowest a download may be read, in bytes per
	// second over each minute; 0 disables the check.
	MinUploadRate, MinDownloadRate int64
	// MinDownloadRateUnderPressure replaces MinDownloadRate while more
	// than DownloadPressurePercent of the task's download slots are taken.
	// A slow mobile link must be able to finish a large file while slots
	// are plentiful; when they run short, slow readers make room for others.
	// A MinDownloadRate of 0 turns the floor off in both regimes, and a
	// DownloadPressurePercent of 0 means DefaultDownloadPressurePercent.
	MinDownloadRateUnderPressure int64
	DownloadPressurePercent      int
	// IdleTimeout ends a transfer that moves no byte for that long; zero
	// disables connection deadlines (tests with a ResponseRecorder).
	// UploadTimeout bounds one upload request end to end.
	IdleTimeout, UploadTimeout time.Duration
	// StorageTimeout bounds each storage call.
	StorageTimeout time.Duration

	// Now is the clock for validity and leases; time.Now when nil.
	// Connection deadlines and the transfer rate use the wall clock.
	Now func() time.Time
	// Random supplies file ids, object keys and lease tokens; crypto/rand
	// when nil.
	Random io.Reader
}

// Server is the FT via HTTP content server: an http.Handler for the upload
// and download paths. It is safe for concurrent use.
type Server struct {
	o            Options
	uploadPath   string
	downloadPath string
	now          func() time.Time
	wallNow      func() time.Time
	random       io.Reader
	log          *slog.Logger
	metrics      *runtime.Metrics
	limiter      *limiter
	slots        chan struct{}
	downloads    chan struct{}
	lookups      chan struct{}
	perUser      *userSlots
	perFile      *userSlots
	perUploader  *userSlots
	// retryWait is the pause before retry attempt n of a completing update.
	retryWait func(attempt int) time.Duration
	writers   activity
	buffers   sync.Pool
	// leaseTTL is how long a lease lasts without renewal: twice the longest
	// a live writer can go without renewing (a read waiting IdleTimeout and
	// a storage call taking StorageTimeout), so that it never lapses under
	// one, and short enough that a dead task's lease lapses in minutes.
	leaseTTL time.Duration
}

// New validates o and returns a Server.
func New(o Options) (*Server, error) {
	switch {
	case o.UploadURI == nil || o.DownloadURI == nil:
		return nil, errors.New("ftserver: upload and download URIs are required")
	case o.Digest == nil || o.Credentials == nil || o.Metadata == nil || o.Blobs == nil:
		return nil, errors.New("ftserver: digest server, credentials and stores are required")
	case o.Logger == nil || o.Metrics == nil:
		return nil, errors.New("ftserver: logger and metrics are required")
	case o.MaxSize <= 0 || o.MaxThumbnailSize <= 0 || o.PartSize <= 0:
		return nil, errors.New("ftserver: sizes must be positive")
	case (o.MaxSize+o.PartSize-1)/o.PartSize >= maxParts:
		return nil, errors.New("ftserver: the maximum size needs too many parts")
	case o.Validity <= 0 || o.UploadTimeout <= 0 || o.StorageTimeout <= 0 || o.IdleTimeout < 0:
		return nil, errors.New("ftserver: validity and timeouts must be positive")
	case o.MaxConcurrentUploads <= 0 || o.MaxUploadsPerUser <= 0 || o.MaxConcurrentDownloads <= 0 ||
		o.MaxDownloadsPerFile <= 0 || o.MaxDownloadsPerUploader <= 0 || o.MaxConcurrentLookups <= 0 || o.UploadsPerMinute < 0 ||
		o.MinUploadRate < 0 || o.MinDownloadRate < 0 || o.MinDownloadRateUnderPressure < 0 ||
		o.DownloadPressurePercent < 0 || o.DownloadPressurePercent > 100:
		return nil, errors.New("ftserver: concurrency limits must be positive")
	}
	up, down := o.UploadURI.Path, o.DownloadURI.Path
	switch {
	case up == "" || up == "/" || down == "":
		// Resume URLs live below the upload path, so it cannot be the root.
		return nil, errors.New("ftserver: the upload and download URIs need a path")
	case strings.HasSuffix(up, "/") || strings.HasSuffix(down, "/"):
		// Links are built from the URI as given and requests are routed on
		// the exact path, so a trailing '/' would make the server's own
		// links miss it.
		return nil, errors.New("ftserver: the upload and download paths must not end in '/'")
	case up == down || strings.HasPrefix(down, up+"/"):
		return nil, errors.New("ftserver: the download path must not be the upload path or below it")
	}
	s := &Server{
		o:            o,
		uploadPath:   up,
		downloadPath: down,
		now:          o.Now,
		wallNow:      time.Now,
		random:       o.Random,
		log:          o.Logger,
		metrics:      o.Metrics,
		slots:        make(chan struct{}, o.MaxConcurrentUploads),
		downloads:    make(chan struct{}, o.MaxConcurrentDownloads),
		lookups:      make(chan struct{}, o.MaxConcurrentLookups),
		perUser:      &userSlots{max: o.MaxUploadsPerUser, n: map[string]int{}},
		perFile:      &userSlots{max: o.MaxDownloadsPerFile, n: map[string]int{}},
		perUploader:  &userSlots{max: o.MaxDownloadsPerUploader, n: map[string]int{}},
		leaseTTL:     2 * (o.IdleTimeout + o.StorageTimeout),
		retryWait:    func(n int) time.Duration { return time.Duration(50<<n) * time.Millisecond },
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.random == nil {
		s.random = rand.Reader
	}
	if s.o.DownloadPressurePercent == 0 {
		// The zero value must not mean "always under pressure".
		s.o.DownloadPressurePercent = DefaultDownloadPressurePercent
	}
	s.limiter = newLimiter(o.UploadsPerMinute, s.now)
	// One byte more than a part: a full part is stored only once the next
	// byte has arrived (see writer).
	size := o.PartSize + 1
	s.buffers.New = func() any { b := make([]byte, 0, size); return &b }
	return s, nil
}

// ServeHTTP routes the upload path (POST upload, GET upload and download
// info), resume URLs below it (PUT) and the download path (GET, HEAD).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Every answer is about one user's transfer; none may be cached on the
	// way, and none is to be sniffed into something else. Downloads replace
	// the cache rule (see handleDownload).
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.extendWrite(w)
	switch p := r.URL.Path; {
	case p == s.downloadPath:
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w, "GET, HEAD")
			return
		}
		s.handleDownload(w, r)
	case p == s.uploadPath:
		switch r.Method {
		case http.MethodPost:
			defer s.writers.start()()
			s.handleUpload(w, r)
		case http.MethodGet:
			s.handleInfo(w, r)
		default:
			methodNotAllowed(w, "GET, POST")
		}
	case strings.HasPrefix(p, s.uploadPath+"/"):
		tid := p[len(s.uploadPath)+1:]
		if !validTID(tid) {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPut {
			methodNotAllowed(w, "PUT")
			return
		}
		defer s.writers.start()()
		s.handleResume(w, r, tid)
	default:
		http.NotFound(w, r)
	}
}

// WaitWriters returns once no upload or resume handler is running, or when
// ctx ends. At shutdown, after the listener has closed their connections, it
// lets those handlers release their leases before the process exits.
func (s *Server) WaitWriters(ctx context.Context) error {
	return s.writers.wait(ctx)
}

// activity counts running handlers. A sync.WaitGroup is not used because
// new requests may still arrive while shutdown waits.
type activity struct {
	mu   sync.Mutex
	n    int
	idle chan struct{} // closed while n == 0; nil means closed
}

func (a *activity) start() (done func()) {
	a.mu.Lock()
	if a.n == 0 {
		a.idle = make(chan struct{})
	}
	a.n++
	a.mu.Unlock()
	return func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.n--; a.n == 0 {
			close(a.idle)
		}
	}
}

func (a *activity) wait(ctx context.Context) error {
	a.mu.Lock()
	idle := a.idle
	n := a.n
	a.mu.Unlock()
	if n == 0 {
		return nil
	}
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
}

// identity is an authenticated user.
type identity struct {
	owner string
}

// errLookupBusy fails a credential lookup when the task already has
// MaxConcurrentLookups in progress.
var errLookupBusy = errors.New("ftserver: too many credential lookups in progress")

// authenticate verifies the request's Digest credentials (RFC 7616 via
// internal/sip/digest). On failure it has answered.
//
// Every credential failure (no credentials, an unknown user, an unusable
// credential record, a wrong password, a replay, a wrong uri) gets the same
// 401 with a fresh challenge,
// stale=true only for a correct response with an expired nonce, so a client
// cannot learn which user names exist. A failure of the credential backend
// itself, or a task at its lookup limit, gets 503 with Retry-After instead:
// it says nothing about the user, and RCS clients retry a 503 but give up
// after a second 401.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (identity, bool) {
	var cred Credential
	var lookupErr error
	c, err := s.o.Digest.VerifyHTTP(r, func(ctx context.Context, username string, alg digest.Algorithm) (digest.Secret, error) {
		select {
		case s.lookups <- struct{}{}:
			defer func() { <-s.lookups }()
		default:
			lookupErr = errLookupBusy
			return digest.Secret{}, lookupErr
		}
		found, err := s.o.Credentials.Lookup(ctx, username, alg)
		if err != nil {
			lookupErr = err
			return digest.Secret{}, err
		}
		cred = found
		return found.Secret, nil
	})
	if err == nil {
		if digest.PathOnlyURI(r, c) {
			// A deviation accepted for interoperability, counted
			// (docs/architecture.md §8) so it can be withdrawn on evidence.
			s.metrics.Count("auth.uri_path_only", 1)
		}
		return identity{owner: cred.Owner}, true
	}
	stale := errors.Is(err, digest.ErrStaleNonce)
	switch {
	case errors.Is(lookupErr, errLookupBusy):
		s.metrics.Count("auth.lookup_busy", 1)
		serviceUnavailable(w, time.Second)
		return identity{}, false
	case errors.Is(lookupErr, ErrBadCredentialRecord):
		// Answered like an unknown user, below; only the operator learns.
		s.metrics.Count("auth.bad_credential_record", 1)
		s.log.Warn("credential record unusable", slog.String("error", pii.Redact(lookupErr.Error())))
	case lookupErr != nil && !errors.Is(lookupErr, ErrUnknownUser):
		s.metrics.Count("auth.backend_error", 1)
		s.log.Warn("credential lookup failed", slog.String("error", pii.Redact(lookupErr.Error())))
		serviceUnavailable(w, retryAfter)
		return identity{}, false
	case errors.Is(err, digest.ErrNoCredentials):
		s.metrics.Count("auth.challenged", 1)
	case stale:
		s.metrics.Count("auth.stale", 1)
	default:
		s.metrics.Count("auth.failed", 1)
	}
	if err := s.o.Digest.ChallengeHTTP(w, stale); err != nil {
		s.log.Error("cannot issue a digest challenge", slog.String("error", err.Error()))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
	return identity{}, false
}

// serviceUnavailable answers 503 with Retry-After, which RCS clients honour
// before retrying an upload.
func serviceUnavailable(w http.ResponseWriter, after time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int((after+time.Second-1)/time.Second))))
	http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
}

// acquireSlot reserves one of the task's slots in slots (uploads, each of
// which holds a part buffer, or downloads).
func acquireSlot(slots chan struct{}) (release func(), ok bool) {
	select {
	case slots <- struct{}{}:
		return func() { <-slots }, true
	default:
		return nil, false
	}
}

// acquireUpload reserves an upload slot on the task and one of owner's,
// so that one user cannot hold every slot of a task. reason names the limit
// that refused it.
func (s *Server) acquireUpload(owner string) (release func(), reason string) {
	task, ok := acquireSlot(s.slots)
	if !ok {
		return nil, "busy"
	}
	user, ok := s.perUser.acquire(owner)
	if !ok {
		task()
		return nil, "user_busy"
	}
	return func() { user(); task() }, ""
}

// userSlots counts transfers in progress per key: uploads per owner,
// downloads per file id and per uploader.
type userSlots struct {
	max int
	mu  sync.Mutex
	n   map[string]int
}

func (u *userSlots) acquire(owner string) (release func(), ok bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.n[owner] >= u.max {
		return nil, false
	}
	u.n[owner]++
	return func() {
		u.mu.Lock()
		defer u.mu.Unlock()
		if u.n[owner]--; u.n[owner] == 0 {
			delete(u.n, owner)
		}
	}, true
}

// completeBudget bounds the completion of an upload: storing the last part,
// closing the object, every try of the completing update and the read-back.
// Two thirds of a lease, so that a writer that renews its lease at the start
// of completion is done while it still holds it.
func (s *Server) completeBudget() time.Duration { return s.leaseTTL * 2 / 3 }

// minDownloadRate is the download rate floor now: the stricter one while
// the task's download slots are under pressure.
func (s *Server) minDownloadRate() int64 {
	if s.o.MinDownloadRate == 0 {
		// Turned off, in both regimes.
		return 0
	}
	if used, total := len(s.downloads), cap(s.downloads); used*100 > s.o.DownloadPressurePercent*total {
		return s.o.MinDownloadRateUnderPressure
	}
	return s.o.MinDownloadRate
}

// storageContext bounds one storage call. It does not end with the request:
// bytes already received are worth storing even if the client has gone, so
// that it can resume after them.
func (s *Server) storageContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), s.o.StorageTimeout)
}

// extendWrite gives the response IdleTimeout to make progress. The public
// listener has no WriteTimeout, because a download may take far longer than
// any fixed one; deadlines per write keep a stalled reader from holding the
// connection instead.
func (s *Server) extendWrite(w http.ResponseWriter) {
	if s.o.IdleTimeout > 0 {
		_ = http.NewResponseController(w).SetWriteDeadline(s.wallNow().Add(s.o.IdleTimeout))
	}
}

// bodyReader returns r's body with its limits: the whole body must arrive
// within UploadTimeout and, measured over each minute, at MinUploadRate or
// faster; with IdleTimeout, each read must also make progress within it.
func (s *Server) bodyReader(w http.ResponseWriter, r *http.Request) io.Reader {
	now := s.wallNow()
	d := &deadlineReader{
		r:    r.Body,
		now:  s.wallNow,
		end:  now.Add(s.o.UploadTimeout),
		idle: s.o.IdleTimeout,
		rate: newRateCheck(func() int64 { return s.o.MinUploadRate }, s.wallNow),
	}
	if s.o.IdleTimeout > 0 {
		d.rc = http.NewResponseController(w)
	}
	return d
}

// Errors of a transfer that moves too slowly; an upload gets 408 for
// either.
var (
	errUploadTimeout = errors.New("ftserver: upload took longer than the upload timeout")
	errTooSlow       = errors.New("ftserver: transfer slower than the minimum rate")
)

// rateCheck enforces a minimum transfer rate, measured over each rateWindow.
// It is what stops a client from holding a slot for hours by moving a byte
// just often enough to beat the idle deadline.
type rateCheck struct {
	min    func() int64 // bytes per second, asked at the end of each window; 0 disables the check
	now    func() time.Time
	window time.Time // start of the current window
	bytes  int64     // moved in the current window
}

func newRateCheck(min func() int64, now func() time.Time) rateCheck {
	return rateCheck{min: min, now: now, window: now()}
}

// check fails once a window has passed with fewer bytes than the rate asks
// for, and otherwise starts the next window when one is over.
func (r *rateCheck) check() error {
	now := r.now()
	if elapsed := now.Sub(r.window); elapsed >= rateWindow {
		if min := r.min(); min > 0 && float64(r.bytes) < float64(min)*elapsed.Seconds() {
			return errTooSlow
		}
		r.window, r.bytes = now, 0
	}
	return nil
}

func (r *rateCheck) add(n int) { r.bytes += int64(n) }

// deadlineReader enforces bodyReader's limits.
type deadlineReader struct {
	r    io.Reader
	rc   *http.ResponseController
	now  func() time.Time
	end  time.Time
	idle time.Duration
	rate rateCheck
}

func (d *deadlineReader) Read(p []byte) (int, error) {
	now := d.now()
	if !now.Before(d.end) {
		return 0, errUploadTimeout
	}
	if err := d.rate.check(); err != nil {
		return 0, err
	}
	if d.rc != nil {
		// Not every ResponseWriter supports deadlines (http.ErrNotSupported);
		// the read then simply has none.
		deadline := now.Add(d.idle)
		if deadline.After(d.end) {
			deadline = d.end
		}
		_ = d.rc.SetReadDeadline(deadline)
	}
	n, err := d.r.Read(p)
	d.rate.add(n)
	return n, err
}

// limiter is a token bucket per owner: perMinute new uploads, refilled
// continuously, with a burst of the same size. It lives in task memory, so a
// user spread over N tasks can make up to N times as many; it stops a
// runaway client, not a determined one, for which AWS WAF rate-based rules
// in front of the ALB are the tool.
type limiter struct {
	perMinute float64
	now       func() time.Time

	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newLimiter(perMinute int, now func() time.Time) *limiter {
	return &limiter{perMinute: float64(perMinute), now: now, buckets: map[string]*bucket{}, lastSweep: now()}
}

// allow takes a token for key, or reports how long until one is available.
func (l *limiter) allow(key string) (bool, time.Duration) {
	if l.perMinute == 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	refill := func(b *bucket) {
		b.tokens = min(l.perMinute, b.tokens+now.Sub(b.at).Minutes()*l.perMinute)
		b.at = now
	}
	if now.Sub(l.lastSweep) >= time.Minute {
		// A bucket that has refilled is the same as no bucket.
		for k, b := range l.buckets {
			if refill(b); b.tokens >= l.perMinute {
				delete(l.buckets, k)
			}
		}
		l.lastSweep = now
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.perMinute, at: now}
		l.buckets[key] = b
	}
	refill(b)
	if b.tokens < 1 {
		wait := time.Duration((1 - b.tokens) / l.perMinute * float64(time.Minute))
		return false, wait
	}
	b.tokens--
	return true, 0
}
