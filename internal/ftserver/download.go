package ftserver

import (
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// handleDownload serves GET and HEAD on the download URI: ?id=<file id> for
// the file, ?id=<file id>.t for its thumbnail (RCC.07 FT via HTTP, download),
// with single byte ranges so a client can resume a broken download (RFC 9110
// §14).
//
// Anything that is not a live, complete file is 404: an unknown id, an
// upload still in progress, a file past its validity. Telling them apart
// would only help someone guessing ids.
//
// The declared type is sent as is and never sniffed; Content-Disposition
// attachment, nosniff and a sandboxing CSP keep a browser from rendering
// uploaded HTML or script under the content server's origin.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	if s.o.DownloadAuth {
		if _, ok := s.authenticate(w, r); !ok {
			return
		}
	}
	// Each download holds a goroutine, a copy buffer and an open storage
	// stream for as long as its reader keeps up with the write deadline,
	// which for a slow reader can be hours.
	release, ok := acquireSlot(s.downloads)
	if !ok {
		s.metrics.Count("download.failed.busy", 1)
		serviceUnavailable(w, retryAfter)
		return
	}
	defer release()
	q := r.URL.Query()
	id, thumbnail, ok := parseDownloadID(q.Get("id"))
	if !ok || len(q["id"]) != 1 {
		s.notFound(w, r)
		return
	}
	sctx, cancel := s.storageContext(r.Context())
	rec, err := s.o.Metadata.Get(sctx, id)
	cancel()
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.notFound(w, r)
		return
	case err != nil:
		s.downloadFailed(w, "read record", err)
		return
	case rec.State != store.Complete || !s.now().Before(rec.Expires):
		s.notFound(w, r)
		return
	}
	// Neither one link nor all the links of one uploader may take every
	// download slot of the task: with FT_DOWNLOAD_AUTH off, anyone holding
	// a link can open connections.
	releaseUploader, ok := s.perUploader.acquire(rec.Owner)
	if !ok {
		s.metrics.Count("download.failed.uploader_busy", 1)
		serviceUnavailable(w, retryAfter)
		return
	}
	defer releaseUploader()
	releaseFile, ok := s.perFile.acquire(rec.ID)
	if !ok {
		s.metrics.Count("download.failed.file_busy", 1)
		serviceUnavailable(w, retryAfter)
		return
	}
	defer releaseFile()
	key, size, contentType, name := rec.Object, rec.Size, rec.ContentType, rec.FileName
	etag := `"` + hex.EncodeToString(rec.SHA256) + `"`
	if thumbnail {
		if rec.Thumbnail == nil {
			s.notFound(w, r)
			return
		}
		key, size, contentType, name = rec.Thumbnail.Key, rec.Thumbnail.Size, rec.Thumbnail.ContentType, ""
		// The thumbnail is not hashed; its validator is the file's plus a
		// marker, which changes whenever the file does.
		etag = `"t` + etag[1:]
	}

	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Content-Disposition", attachment(name))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Referrer-Policy", "no-referrer")
	// The URL is a capability: shared caches must not keep the content.
	h.Set("Cache-Control", "private, no-store")
	h.Set("Accept-Ranges", "bytes")
	h.Set("ETag", etag)
	h.Set("Last-Modified", rec.Completed.UTC().Format(http.TimeFormat))

	status, rng := http.StatusOK, byteRange{start: 0, length: size}
	if v := r.Header.Get("Range"); v != "" && r.Method == http.MethodGet && ifRangeHolds(r, etag) {
		parsed, result := parseRange(v, size)
		switch result {
		case rangeSatisfiable:
			status, rng = http.StatusPartialContent, parsed
			h.Set("Content-Range", "bytes "+strconv.FormatInt(rng.start, 10)+"-"+
				strconv.FormatInt(rng.start+rng.length-1, 10)+"/"+strconv.FormatInt(size, 10))
		case rangeUnsatisfiable:
			s.metrics.Count("download.unsatisfiable", 1)
			h.Del("Content-Type")
			h.Set("Content-Range", "bytes */"+strconv.FormatInt(size, 10))
			http.Error(w, http.StatusText(http.StatusRequestedRangeNotSatisfiable), http.StatusRequestedRangeNotSatisfiable)
			return
		}
	}
	h.Set("Content-Length", strconv.FormatInt(rng.length, 10))
	if r.Method == http.MethodHead || rng.length == 0 {
		w.WriteHeader(status)
		return
	}

	// The read follows the request: once the client has gone there is no
	// point fetching the rest.
	body, err := s.o.Blobs.Open(r.Context(), key, rng.start, rng.length)
	if err != nil {
		for _, name := range []string{"Content-Length", "Content-Range", "Content-Disposition", "ETag", "Last-Modified"} {
			h.Del(name)
		}
		if errors.Is(err, store.ErrNotFound) {
			// A valid file whose object is gone: a lifecycle rule shorter
			// than the validity. The client gets what any missing file
			// gets; operators get a metric of its own and a log line,
			// because this one should never happen.
			s.metrics.Count("download.failed.missing_object", 1)
			s.log.Warn("download object missing", slog.Bool("thumbnail", thumbnail))
			http.NotFound(w, r)
			return
		}
		s.downloadFailed(w, "open", err)
		return
	}
	defer body.Close()
	w.WriteHeader(status)
	n, err := io.Copy(&deadlineWriter{s: s, w: w, rate: newRateCheck(s.o.MinDownloadRate, s.wallNow)}, body)
	s.metrics.Count("download.bytes", n)
	if err != nil || n != rng.length {
		// The status line is out; all that is left is to cut the response
		// short, which the client sees as a broken download it can resume.
		if errors.Is(err, errTooSlow) {
			s.metrics.Count("download.failed.too_slow", 1)
		} else {
			s.metrics.Count("download.failed.interrupted", 1)
		}
		return
	}
	if status == http.StatusPartialContent {
		s.metrics.Count("download.partial", 1)
	} else {
		s.metrics.Count("download.served", 1)
	}
}

// ifRangeHolds evaluates If-Range (RFC 9110 §13.1.5). Only an entity tag
// can hold: a date never matches strongly enough to splice ranges by, so a
// date-form If-Range gets the whole file, as a failed condition would.
func ifRangeHolds(r *http.Request, etag string) bool {
	v := r.Header.Get("If-Range")
	return v == "" || v == etag
}

// attachment is the download's Content-Disposition (RFC 6266 §4): always
// attachment, with the declared file name when it can be encoded.
func attachment(name string) string {
	if name != "" {
		if v := mime.FormatMediaType("attachment", map[string]string{"filename": name}); v != "" {
			return v
		}
	}
	return "attachment"
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.metrics.Count("download.not_found", 1)
	http.NotFound(w, r)
}

func (s *Server) downloadFailed(w http.ResponseWriter, op string, err error) {
	s.metrics.Count("download.failed.storage", 1)
	s.log.Warn("download failed", slog.String("op", op), slog.String("error", pii.Redact(err.Error())))
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

// deadlineWriter gives each write of a download IdleTimeout, so a reader
// that stops reading releases the connection, and cuts off a reader slower
// than MinDownloadRate, so one that reads just enough to beat the deadline
// cannot hold a download slot for hours.
type deadlineWriter struct {
	s    *Server
	w    http.ResponseWriter
	rate rateCheck
}

func (d *deadlineWriter) Write(p []byte) (int, error) {
	if err := d.rate.check(); err != nil {
		return 0, err
	}
	d.s.extendWrite(d.w)
	n, err := d.w.Write(p)
	d.rate.add(n)
	return n, err
}
