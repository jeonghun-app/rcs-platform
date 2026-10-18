package ftserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// maxFormOverhead is what an upload form may carry besides the file and the
// thumbnail: part headers, boundaries and the tid.
const maxFormOverhead = 64 << 10

// handleUpload serves POST to the upload URI (RCC.07 FT via HTTP, upload).
// An empty POST is the client's authentication pre-check: 401 with a
// challenge until it authenticates, then 204. A multipart/form-data POST
// uploads: tid, optional Thumbnail, File, answered with the file-info
// document once the whole file is stored.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	// The pre-check is recognised by its empty body, whatever Content-Type
	// a client copies onto it, and before any upload limit is applied.
	body, empty := peekEmpty(r, s.bodyReader(w, r))
	if empty {
		s.metrics.Count("upload.precheck", 1)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	ct := r.Header.Get("Content-Type")
	if mt, _, _ := mime.ParseMediaType(ct); mt != "multipart/form-data" {
		s.uploadFailed(w, "not_multipart", http.StatusUnsupportedMediaType)
		return
	}
	if ok, wait := s.limiter.allow(id.owner); !ok {
		s.metrics.Count("upload.failed.rate_limited", 1)
		serviceUnavailable(w, wait)
		return
	}
	release, reason := s.acquireUpload(id.owner)
	if release == nil {
		s.metrics.Count("upload.failed."+reason, 1)
		serviceUnavailable(w, retryAfter)
		return
	}
	defer release()
	if r.ContentLength > s.o.MaxSize+s.o.MaxThumbnailSize+maxFormOverhead {
		s.uploadFailed(w, "too_large", http.StatusRequestEntityTooLarge)
		return
	}

	form, err := readUploadHead(ct, body, formLimits{maxFile: s.o.MaxSize, maxThumbnail: s.o.MaxThumbnailSize})
	if err != nil {
		s.formFailed(w, err)
		return
	}
	rec, err := s.beginUpload(r.Context(), id, form)
	if err != nil {
		s.failUpload(w, err)
		return
	}
	s.metrics.Count("upload.started", 1)
	wr, err := s.newWriter(rec)
	if err != nil {
		s.releaseLease(r.Context(), rec)
		s.failUpload(w, err)
		return
	}
	defer wr.close()
	if err := wr.copy(r.Context(), form.file.body); err != nil {
		s.abandon(r.Context(), wr, err)
		s.failUpload(w, err)
		return
	}
	if err := form.finish(); err != nil {
		wr.release(r.Context())
		s.formFailed(w, err)
		return
	}
	s.finishUpload(w, r, wr)
}

// peekEmpty reports whether the request has no body, and returns the body
// to read otherwise. A pre-check POST may be sent chunked, with no
// Content-Length, so the first byte is tried and handed back.
func peekEmpty(r *http.Request, body io.Reader) (io.Reader, bool) {
	if r.ContentLength == 0 {
		return body, true
	}
	var b [1]byte
	n, err := io.ReadFull(body, b[:])
	if n == 0 && err == io.EOF {
		return body, true
	}
	if n == 0 {
		return errorReader{err}, false
	}
	return io.MultiReader(bytes.NewReader(b[:n]), body), false
}

// errorReader fails every read with err: a body that broke on its first
// byte.
type errorReader struct{ err error }

func (e errorReader) Read([]byte) (int, error) { return 0, e.err }

// beginUpload finds or creates owner's record for the form's tid and takes
// its lease. A tid that is still uploading starts again from the first byte:
// that is what a client does when it cannot resume (RCC.07 FT via HTTP), and
// the lease keeps it from cutting into a request still writing. A completed
// or expired tid is not reused.
func (s *Server) beginUpload(ctx context.Context, id identity, form *uploadForm) (store.Record, error) {
	sctx, cancel := s.storageContext(ctx)
	defer cancel()
	rec, err := s.o.Metadata.GetByTID(sctx, id.owner, form.tid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return s.createUpload(sctx, id, form)
	case err != nil:
		return store.Record{}, storageErr("read record", err)
	case rec.State != store.Uploading:
		return store.Record{}, errTIDUsed
	}
	previousKey, previous := rec.Object, rec.MultipartID
	thumbKey, err := s.thumbnailKey(rec.ID, form)
	if err != nil {
		return store.Record{}, err
	}
	now := s.now()
	rec, err = s.acquireLease(ctx, rec, func(r *store.Record) {
		clearContent(r)
		describe(r, form, thumbKey)
		r.Expires = now.Add(s.o.Validity)
	})
	if err != nil {
		return store.Record{}, err
	}
	if previous != "" {
		_ = s.o.Blobs.AbortMultipart(sctx, previousKey, previous)
	}
	s.metrics.Count("upload.restarted", 1)
	return s.storeThumbnail(ctx, rec, form)
}

// errTIDUsed means the owner's tid names a completed or expired upload.
var errTIDUsed = errors.New("ftserver: the transaction id has been used")

func (s *Server) createUpload(ctx context.Context, id identity, form *uploadForm) (store.Record, error) {
	fileID, err := newID(s.random)
	if err != nil {
		return store.Record{}, err
	}
	lease, err := newID(s.random)
	if err != nil {
		return store.Record{}, err
	}
	thumbKey, err := s.thumbnailKey(fileID, form)
	if err != nil {
		return store.Record{}, err
	}
	now := s.now()
	r := store.Record{
		ID:         fileID,
		Owner:      id.owner,
		TID:        form.tid,
		State:      store.Uploading,
		Created:    now,
		Expires:    now.Add(s.o.Validity),
		Lease:      lease,
		LeaseUntil: now.Add(s.leaseTTL),
	}
	describe(&r, form, thumbKey)
	rec, err := s.o.Metadata.Create(ctx, r)
	switch {
	case errors.Is(err, store.ErrExists):
		// The same tid raced in through another request or task.
		return store.Record{}, &busyError{wait: retryAfter}
	case err != nil:
		return store.Record{}, storageErr("create record", err)
	}
	return s.storeThumbnail(ctx, rec, form)
}

// describe copies what the form declares about the file into r; the
// thumbnail, if any, goes to thumbKey.
func describe(r *store.Record, form *uploadForm, thumbKey string) {
	r.FileName = form.file.name
	r.ContentType = form.file.contentType
	r.DeclaredSize = form.file.declaredSize
	r.Thumbnail = nil
	if t := form.thumbnail; t != nil {
		r.Thumbnail = &store.Thumbnail{Key: thumbKey, Size: int64(len(t.data)), ContentType: t.contentType}
	}
}

// thumbnailKey returns a fresh key for the form's thumbnail, or "" without
// one. Each attempt has its own, like the file content, so a restart never
// overwrites a thumbnail another attempt committed.
func (s *Server) thumbnailKey(id string, form *uploadForm) (string, error) {
	if form.thumbnail == nil {
		return "", nil
	}
	key, err := s.newObjectKey(id)
	if err != nil {
		return "", err
	}
	return key + thumbnailSuffix, nil
}

// storeThumbnail stores the form's thumbnail, if any, before the file
// content arrives. The record already describes it; it becomes downloadable
// only with the file.
func (s *Server) storeThumbnail(ctx context.Context, rec store.Record, form *uploadForm) (store.Record, error) {
	if form.thumbnail == nil {
		return rec, nil
	}
	sctx, cancel := s.storageContext(ctx)
	defer cancel()
	if err := s.o.Blobs.Put(sctx, rec.Thumbnail.Key, form.thumbnail.data, form.thumbnail.contentType); err != nil {
		s.releaseLease(ctx, rec)
		return store.Record{}, storageErr("put thumbnail", err)
	}
	return rec, nil
}

// abandon ends a writer whose copy failed: a file found too large is
// discarded, anything else keeps its durable parts for a resume.
func (s *Server) abandon(ctx context.Context, wr *writer, err error) {
	if errors.Is(err, errFileTooLarge) {
		wr.reset(ctx)
		return
	}
	wr.release(ctx)
}

// finishUpload completes the writer's content and answers with the
// file-info document.
func (s *Server) finishUpload(w http.ResponseWriter, r *http.Request, wr *writer) {
	rec, err := wr.complete(r.Context())
	if err != nil {
		wr.release(r.Context())
		s.failUpload(w, err)
		return
	}
	s.metrics.Count("upload.completed", 1)
	s.metrics.Count("upload.bytes", rec.Size)
	s.log.Info("upload completed", pii.Identity("owner", rec.Owner), slog.Int64("size", rec.Size))
	s.writeFileDocument(w, rec)
}

// handleResume serves PUT to a resume URL: the rest of an upload, from the
// first byte the server does not have to the last, with Content-Range
// (RCC.07 FT via HTTP, resume upload; RFC 9110 §14.5). A range starting
// anywhere else than at the bytes held gets 409, so the client asks for the
// upload info again; one ending before the last byte gets 400, because only
// the end of a file can complete it.
func (s *Server) handleResume(w http.ResponseWriter, r *http.Request, tid string) {
	id, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	cr, ok := parseContentRange(r.Header.Get("Content-Range"))
	switch {
	case !ok || cr.last != cr.total-1:
		s.uploadFailed(w, "bad_content_range", http.StatusBadRequest)
		return
	case cr.total > s.o.MaxSize:
		s.uploadFailed(w, "too_large", http.StatusRequestEntityTooLarge)
		return
	case r.ContentLength >= 0 && r.ContentLength != cr.last-cr.first+1:
		s.uploadFailed(w, "bad_content_range", http.StatusBadRequest)
		return
	}
	release, reason := s.acquireUpload(id.owner)
	if release == nil {
		s.metrics.Count("upload.failed."+reason, 1)
		serviceUnavailable(w, retryAfter)
		return
	}
	defer release()

	sctx, cancel := s.storageContext(r.Context())
	rec, err := s.o.Metadata.GetByTID(sctx, id.owner, tid)
	cancel()
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.uploadFailed(w, "not_found", http.StatusNotFound)
		return
	case err != nil:
		s.failUpload(w, storageErr("read record", err))
		return
	case rec.State != store.Uploading || !s.now().Before(rec.Expires):
		s.uploadFailed(w, "not_resumable", http.StatusConflict)
		return
	case rec.DeclaredSize >= 0 && rec.DeclaredSize != cr.total, cr.first != rec.Received:
		s.uploadFailed(w, "range_conflict", http.StatusConflict)
		return
	}
	rec, err = s.acquireLease(r.Context(), rec, func(r *store.Record) { r.DeclaredSize = cr.total })
	if err != nil {
		s.failUpload(w, err)
		return
	}
	s.metrics.Count("upload.resumed", 1)
	wr, err := s.newWriter(rec)
	if err != nil {
		s.releaseLease(r.Context(), rec)
		s.failUpload(w, err)
		return
	}
	defer wr.close()
	if err := wr.copy(r.Context(), s.bodyReader(w, r)); err != nil {
		s.abandon(r.Context(), wr, err)
		s.failUpload(w, err)
		return
	}
	s.finishUpload(w, r, wr)
}

// handleInfo serves GET on the upload URI with tid and get_upload_info or
// get_download_info (RCC.07 FT via HTTP, resume upload). Only the owner of
// the tid gets an answer; anyone else's tid is simply not found.
//
// get_upload_info answers with the bytes held and the resume URL, or 404 if
// none are held, in which case the client posts the file again. A complete
// upload reports every byte held, which tells the client to ask for the
// download info instead.
func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	_, upload := q["get_upload_info"]
	_, download := q["get_download_info"]
	if err != nil || len(q["tid"]) != 1 || !validTID(q.Get("tid")) || upload == download {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	sctx, cancel := s.storageContext(r.Context())
	rec, err := s.o.Metadata.GetByTID(sctx, id.owner, q.Get("tid"))
	cancel()
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.failUpload(w, storageErr("read record", err))
		return
	}
	live := err == nil && s.now().Before(rec.Expires)
	switch {
	case download && live && rec.State == store.Complete:
		s.writeFileDocument(w, rec)
	case upload && live && rec.State == store.Complete:
		s.writeDocument(w, newResumeDocument(rec.Size, s.resumeURL(rec.TID)))
	case upload && live && rec.State == store.Uploading && rec.Received > 0:
		s.writeDocument(w, newResumeDocument(rec.Received, s.resumeURL(rec.TID)))
	default:
		http.NotFound(w, r)
	}
}

// resumeURL is where the rest of tid's upload is PUT: below the upload URI,
// path only, because some clients sign only the path in their Digest uri.
func (s *Server) resumeURL(tid string) string {
	return s.o.UploadURI.JoinPath(tid).String()
}

// downloadURL is the public download link for id.
func (s *Server) downloadURL(base *url.URL, id string) string {
	u := *base
	u.RawQuery = url.Values{"id": {id}}.Encode()
	return u.String()
}

func (s *Server) writeFileDocument(w http.ResponseWriter, rec store.Record) {
	until := formatUntil(rec.Expires)
	var doc fileDocument
	if t := rec.Thumbnail; t != nil {
		doc.Infos = append(doc.Infos, fileInfo{
			Type:        infoTypeThumbnail,
			Size:        t.Size,
			ContentType: t.ContentType,
			Data:        dataLink{URL: s.downloadURL(s.o.DownloadURI, rec.ID+thumbnailSuffix), Until: until},
		})
	}
	info := fileInfo{
		Type:        infoTypeFile,
		Size:        rec.Size,
		Name:        rec.FileName,
		ContentType: rec.ContentType,
		Data:        dataLink{URL: s.downloadURL(s.o.DownloadURI, rec.ID), Until: until},
	}
	if s.o.BrandedURI != nil {
		info.BrandedURL = s.downloadURL(s.o.BrandedURI, rec.ID)
	}
	doc.Infos = append(doc.Infos, info)
	s.writeDocument(w, doc)
}

func (s *Server) writeDocument(w http.ResponseWriter, doc any) {
	body, err := marshalDocument(doc)
	if err != nil {
		s.log.Error("cannot marshal a document", slog.String("error", err.Error()))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	s.extendWrite(w)
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// formFailed answers a rejected upload form.
func (s *Server) formFailed(w http.ResponseWriter, err error) {
	var fe *formError
	if errors.As(err, &fe) {
		s.uploadFailed(w, fe.reason, fe.status)
		return
	}
	s.failUpload(w, err)
}

// failUpload answers an upload or resume that failed after it started.
func (s *Server) failUpload(w http.ResponseWriter, err error) {
	var se *storageError
	var ne net.Error
	var busy *busyError
	switch {
	case errors.As(err, &busy):
		// A request still holds the lease, often one whose connection has
		// gone half-open after the client changed networks; RCS clients
		// retry a 503 after Retry-After but give up on a 409.
		s.metrics.Count("upload.failed.leased", 1)
		serviceUnavailable(w, busy.wait)
	case errors.Is(err, errFileTooLarge):
		s.uploadFailed(w, "too_large", http.StatusRequestEntityTooLarge)
	case errors.Is(err, errLengthMismatch):
		s.uploadFailed(w, "length_mismatch", http.StatusBadRequest)
	case errors.Is(err, errTIDUsed):
		s.uploadFailed(w, "tid_used", http.StatusConflict)
	case errors.Is(err, errLostLease), errors.Is(err, errUploadGone):
		s.uploadFailed(w, "conflict", http.StatusConflict)
	case errors.As(err, &se):
		s.log.Warn("storage failed", slog.String("op", se.op), slog.String("error", pii.Redact(se.err.Error())))
		s.uploadFailed(w, "storage", http.StatusInternalServerError)
	case errors.Is(err, errTooManyParts):
		s.uploadFailed(w, "too_large", http.StatusRequestEntityTooLarge)
	case errors.Is(err, errTooSlow):
		s.uploadFailed(w, "too_slow", http.StatusRequestTimeout)
	case errors.Is(err, errUploadTimeout), errors.Is(err, os.ErrDeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		s.uploadFailed(w, "timeout", http.StatusRequestTimeout)
	case errors.Is(err, context.Canceled):
		s.uploadFailed(w, "interrupted", http.StatusBadRequest)
	default:
		var fe *formError
		if errors.As(err, &fe) {
			s.uploadFailed(w, fe.reason, fe.status)
			return
		}
		// The body broke off: the connection went or the framing was bad.
		s.uploadFailed(w, "interrupted", http.StatusBadRequest)
	}
}

// uploadFailed counts the failure under reason and answers status.
func (s *Server) uploadFailed(w http.ResponseWriter, reason string, status int) {
	s.metrics.Count("upload.failed."+reason, 1)
	s.extendWrite(w)
	http.Error(w, http.StatusText(status), status)
}

// sweepBatch bounds the records one sweep handles.
const sweepBatch = 100

// Sweep marks the records whose validity has ended as expired and aborts the
// multipart uploads of incomplete ones. Downloads already refuse an expired
// file whatever its mark (they compare Expires with the clock); the mark
// keeps the table honest for operators and lets the incomplete content go at
// once rather than when the bucket's lifecycle rule gets to it. Deleting
// complete content is the lifecycle rule's job (docs/ft-server.md).
func (s *Server) Sweep(ctx context.Context) (int, error) {
	start := s.wallNow()
	defer func() { s.metrics.Timing("sweep.duration", s.wallNow().Sub(start)) }()
	now := s.now()
	// Each call has its own deadline: a request that never answers must not
	// stop the sweeper silently.
	lctx, cancel := context.WithTimeout(ctx, s.o.StorageTimeout)
	list, err := s.o.Metadata.ListExpired(lctx, now, sweepBatch)
	cancel()
	if err != nil {
		return 0, err
	}
	marked := 0
	for _, rec := range list {
		if ctx.Err() != nil {
			break
		}
		if rec.State == store.Uploading && rec.Lease != "" && now.Before(rec.LeaseUntil) {
			continue // a request is still writing; the next sweep gets it
		}
		key, multipart := rec.Object, rec.MultipartID
		rec.State = store.Expired
		if multipart != "" {
			clearContent(&rec)
		}
		rec.Lease, rec.LeaseUntil = "", time.Time{}
		uctx, cancel := context.WithTimeout(ctx, s.o.StorageTimeout)
		_, err := s.o.Metadata.Update(uctx, rec)
		if err == nil && multipart != "" {
			_ = s.o.Blobs.AbortMultipart(uctx, key, multipart)
		}
		cancel()
		if err != nil {
			continue // changed meanwhile; the next sweep sees the new version
		}
		marked++
	}
	s.metrics.Count("sweep.expired", int64(marked))
	return marked, nil
}
