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

// maxParts is the most parts an S3 multipart upload may have.
const maxParts = 10000

// leaseMargin is added to a writer's lease beyond the longest a request can
// last, so that a lease never expires under a live writer even with some clock
// difference between tasks.
const leaseMargin = time.Minute

// retryAfter is the Retry-After of a 503: when a task is at its upload limit
// or a user at their rate limit.
const retryAfter = 10 * time.Second

// Options configures a Server. Every field without a stated default is
// required.
type Options struct {
	// UploadURI is the public ftHTTPCSURI and DownloadURI the public
	// ftHTTPDLURI (what acs provisions). The server answers on their paths;
	// the documents it returns link to them.
	UploadURI, DownloadURI *url.URL
	// BrandedURI, when set, adds a branded-url to each file's file-info: the
	// same id on an operator's web page, for recipients without RCS.
	BrandedURI *url.URL

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
	// MaxConcurrentUploads bounds uploads in progress on this task.
	MaxConcurrentUploads int
	// IdleTimeout ends a transfer that moves no byte for that long; zero
	// disables connection deadlines (tests with a ResponseRecorder).
	// UploadTimeout bounds one upload request end to end.
	IdleTimeout, UploadTimeout time.Duration
	// StorageTimeout bounds each storage call.
	StorageTimeout time.Duration

	// Now is the clock for validity and leases; time.Now when nil.
	// Connection deadlines always use the wall clock.
	Now func() time.Time
	// Random supplies file ids and lease tokens; crypto/rand when nil.
	Random io.Reader
}

// Server is the FT via HTTP content server: an http.Handler for the upload
// and download paths. It is safe for concurrent use.
type Server struct {
	o            Options
	uploadPath   string
	downloadPath string
	now          func() time.Time
	random       io.Reader
	log          *slog.Logger
	metrics      *runtime.Metrics
	limiter      *limiter
	slots        chan struct{}
	buffers      sync.Pool
	leaseTTL     time.Duration
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
	case (o.MaxSize+o.PartSize-1)/o.PartSize > maxParts:
		return nil, errors.New("ftserver: the maximum size needs more than 10000 parts")
	case o.Validity <= 0 || o.UploadTimeout <= 0 || o.StorageTimeout <= 0 || o.IdleTimeout < 0:
		return nil, errors.New("ftserver: validity and timeouts must be positive")
	case o.MaxConcurrentUploads <= 0 || o.UploadsPerMinute < 0:
		return nil, errors.New("ftserver: upload limits must be positive")
	}
	up, down := cleanPath(o.UploadURI), cleanPath(o.DownloadURI)
	switch {
	case up == "/":
		// Resume URLs live below the upload path, so it cannot be the root.
		return nil, errors.New("ftserver: the upload URI needs a path")
	case up == down || strings.HasPrefix(down, up+"/"):
		return nil, errors.New("ftserver: the download path must not be the upload path or below it")
	}
	s := &Server{
		o:            o,
		uploadPath:   up,
		downloadPath: down,
		now:          o.Now,
		random:       o.Random,
		log:          o.Logger,
		metrics:      o.Metrics,
		slots:        make(chan struct{}, o.MaxConcurrentUploads),
		// A request lasts at most UploadTimeout, and its last storage call
		// at most StorageTimeout beyond; see acquireLease.
		leaseTTL: o.UploadTimeout + o.StorageTimeout + leaseMargin,
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.random == nil {
		s.random = rand.Reader
	}
	s.limiter = newLimiter(o.UploadsPerMinute, s.now)
	partSize := o.PartSize
	s.buffers.New = func() any { b := make([]byte, 0, partSize); return &b }
	return s, nil
}

func cleanPath(u *url.URL) string {
	p := strings.TrimSuffix(u.Path, "/")
	if p == "" {
		return "/"
	}
	return p
}

// ServeHTTP routes the upload path (POST upload, GET upload and download
// info), resume URLs below it (PUT) and the download path (GET, HEAD).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Every answer is about one user's transfer; none may be cached on the
	// way. Downloads replace this (see handleDownload).
	w.Header().Set("Cache-Control", "no-store")
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
		s.handleResume(w, r, tid)
	default:
		http.NotFound(w, r)
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

// authenticate verifies the request's Digest credentials (RFC 7616 via
// internal/sip/digest). On failure it has answered 401 with a fresh
// challenge, stale=true only for a correct response with an expired nonce,
// and the same answer for every other failure: no credentials, an unknown
// user, a wrong password, a replay, a failed lookup. A client therefore
// cannot learn which user names exist.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (identity, bool) {
	var cred Credential
	var lookupErr error
	_, err := s.o.Digest.VerifyHTTP(r, func(ctx context.Context, username string, alg digest.Algorithm) (digest.Secret, error) {
		c, err := s.o.Credentials.Lookup(ctx, username, alg)
		if err != nil {
			lookupErr = err
			return digest.Secret{}, err
		}
		cred = c
		return c.Secret, nil
	})
	if err == nil {
		return identity{owner: cred.Owner}, true
	}
	stale := errors.Is(err, digest.ErrStaleNonce)
	switch {
	case errors.Is(err, digest.ErrNoCredentials):
		s.metrics.Count("auth.challenged", 1)
	case stale:
		s.metrics.Count("auth.stale", 1)
	case lookupErr != nil && !errors.Is(lookupErr, ErrUnknownUser):
		// The client still gets the uniform 401; the operator gets the
		// cause, which names no user.
		s.metrics.Count("auth.backend_error", 1)
		s.log.Warn("credential lookup failed", slog.String("error", pii.Redact(lookupErr.Error())))
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
	w.Header().Set("Retry-After", strconv.Itoa(int((after+time.Second-1)/time.Second)))
	http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
}

// acquireSlot reserves one of the task's concurrent upload slots, each of
// which holds a part buffer.
func (s *Server) acquireSlot() (release func(), ok bool) {
	select {
	case s.slots <- struct{}{}:
		return func() { <-s.slots }, true
	default:
		return nil, false
	}
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
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(s.o.IdleTimeout))
	}
}

// bodyReader returns r's body with deadlines: each read must make progress
// within IdleTimeout, and the whole body must arrive within UploadTimeout.
func (s *Server) bodyReader(w http.ResponseWriter, r *http.Request) io.Reader {
	if s.o.IdleTimeout == 0 {
		return r.Body
	}
	return &deadlineReader{
		r:   r.Body,
		rc:  http.NewResponseController(w),
		end: time.Now().Add(s.o.UploadTimeout),
		idl: s.o.IdleTimeout,
	}
}

// errUploadTimeout ends a request body that took longer than UploadTimeout.
var errUploadTimeout = errors.New("ftserver: upload took longer than the upload timeout")

type deadlineReader struct {
	r   io.Reader
	rc  *http.ResponseController
	end time.Time
	idl time.Duration
}

func (d *deadlineReader) Read(p []byte) (int, error) {
	now := time.Now()
	if !now.Before(d.end) {
		return 0, errUploadTimeout
	}
	deadline := now.Add(d.idl)
	if deadline.After(d.end) {
		deadline = d.end
	}
	// Not every ResponseWriter supports deadlines (http.ErrNotSupported);
	// the read then simply has none.
	_ = d.rc.SetReadDeadline(deadline)
	return d.r.Read(p)
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
