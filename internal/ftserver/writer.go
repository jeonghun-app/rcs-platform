package ftserver

import (
	"context"
	"crypto/sha256"
	"encoding"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
)

// Errors of the content path, mapped to answers in failUpload.
var (
	// errLostLease means the record changed under a writer that held the
	// lease: the sweeper expired it, or the lease ran out.
	errLostLease = errors.New("ftserver: the upload changed while being written")
	// errUploadGone means the open multipart upload behind a record no
	// longer exists (completed or aborted after a failure) or no longer
	// matches it; the record has been reset so the client starts again.
	errUploadGone = errors.New("ftserver: the stored upload is gone")
	// errLengthMismatch means the content ended at another length than
	// the client declared.
	errLengthMismatch = errors.New("ftserver: content length does not match the declared size")
)

// writer streams one request's file content into storage. It holds the
// record's lease, keeps at most one part in memory and makes each full part
// durable, with the hash state up to it, before reading on: whatever arrives
// after the last durable part is lost if the request breaks, and the client
// resumes from Received (RCC.07 FT via HTTP, resume upload).
type writer struct {
	s     *Server
	rec   store.Record
	hash  hash.Hash
	buf   *[]byte
	total int64 // the size the content must have, or -1
}

// newWriter starts writing after rec.Received bytes. The record must hold
// this request's lease.
func (s *Server) newWriter(rec store.Record) (*writer, error) {
	h := sha256.New()
	if rec.Received > 0 {
		if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(rec.HashState); err != nil {
			return nil, fmt.Errorf("ftserver: restoring the hash state: %w", err)
		}
	}
	buf := s.buffers.Get().(*[]byte)
	*buf = (*buf)[:0]
	return &writer{s: s, rec: rec, hash: h, buf: buf, total: rec.DeclaredSize}, nil
}

// close returns the part buffer. Call it once, last.
func (w *writer) close() {
	w.s.buffers.Put(w.buf)
	w.buf = nil
}

// copy reads src to its end, storing every full part on the way. On nil the
// content after the last stored part is in the buffer, for complete. An error
// from src is returned as is: the client stopped or broke off.
func (w *writer) copy(ctx context.Context, src io.Reader) error {
	for {
		b := *w.buf
		if len(b) == cap(b) {
			if err := w.flush(ctx); err != nil {
				return err
			}
			b = *w.buf
		}
		n, err := src.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		*w.buf = b
		size := w.rec.Received + int64(len(b))
		switch {
		case size > w.s.o.MaxSize:
			return errFileTooLarge
		case w.total >= 0 && size > w.total:
			return errLengthMismatch
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		}
	}
}

// flush stores the full buffer as the next part and records it. w.rec
// changes only once the record update has succeeded, so that after a failure
// it still describes what is stored.
func (w *writer) flush(ctx context.Context) error {
	ctx, cancel := w.s.storageContext(ctx)
	defer cancel()
	b := *w.buf
	key := w.rec.ID
	r := w.rec.Clone()
	// A multipart upload created here is named by no record until the
	// update below succeeds; on any failure before that it is aborted, not
	// left for the lifecycle rule.
	orphan := r.MultipartID == ""
	if orphan {
		id, err := w.s.o.Blobs.CreateMultipart(ctx, key, r.ContentType)
		if err != nil {
			return storageErr("create multipart", err)
		}
		r.MultipartID = id
	}
	abortOrphan := func() {
		if orphan {
			_ = w.s.o.Blobs.AbortMultipart(ctx, key, r.MultipartID)
		}
	}
	number := int32(len(r.Parts) + 1)
	etag, err := w.s.o.Blobs.UploadPart(ctx, key, r.MultipartID, number, b)
	if err != nil {
		if orphan {
			abortOrphan()
			return storageErr("upload part", err)
		}
		return w.storageFailure(ctx, "upload part", err)
	}
	// The hash runs ahead of w.rec if the update fails, but the writer is
	// abandoned then and its hash never stored.
	w.hash.Write(b)
	state, err := w.hash.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		abortOrphan()
		return fmt.Errorf("ftserver: saving the hash state: %w", err)
	}
	r.Parts = append(r.Parts, store.Part{Number: number, ETag: etag, Size: int64(len(b))})
	r.Received += int64(len(b))
	r.HashState = state
	rec, err := w.s.o.Metadata.Update(ctx, r)
	if err != nil {
		abortOrphan()
		return metadataErr(err)
	}
	w.rec = rec
	w.s.metrics.Count("upload.parts", 1)
	*w.buf = b[:0]
	return nil
}

// complete stores the rest of the content, closes the object and marks the
// record complete, giving the file its validity from now. Only the request
// holding the lease gets here, and the conditional update lets only one of
// two racing completions win.
func (w *writer) complete(ctx context.Context) (store.Record, error) {
	ctx, cancel := w.s.storageContext(ctx)
	defer cancel()
	tail := *w.buf
	size := w.rec.Received + int64(len(tail))
	if w.total >= 0 && size != w.total {
		return store.Record{}, errLengthMismatch
	}
	key := w.rec.ID
	if w.rec.MultipartID == "" {
		if err := w.s.o.Blobs.Put(ctx, key, tail, w.rec.ContentType); err != nil {
			return store.Record{}, storageErr("put", err)
		}
	} else {
		parts := slices.Clone(w.rec.Parts)
		if len(tail) > 0 {
			number := int32(len(parts) + 1)
			etag, err := w.s.o.Blobs.UploadPart(ctx, key, w.rec.MultipartID, number, tail)
			if err != nil {
				return store.Record{}, w.storageFailure(ctx, "upload part", err)
			}
			parts = append(parts, store.Part{Number: number, ETag: etag, Size: int64(len(tail))})
		}
		if err := w.s.o.Blobs.CompleteMultipart(ctx, key, w.rec.MultipartID, parts); err != nil {
			return store.Record{}, w.storageFailure(ctx, "complete multipart", err)
		}
	}
	w.hash.Write(tail)
	now := w.s.now()
	r := w.rec
	r.State = store.Complete
	r.Size, r.Received, r.DeclaredSize = size, size, size
	r.SHA256 = w.hash.Sum(nil)
	r.HashState, r.MultipartID, r.Parts = nil, "", nil
	r.Lease, r.LeaseUntil = "", time.Time{}
	r.Completed = now
	r.Expires = now.Add(w.s.o.Validity)
	rec, err := w.s.o.Metadata.Update(ctx, r)
	if err != nil {
		return store.Record{}, metadataErr(err)
	}
	w.rec = rec
	return rec, nil
}

// release gives up the lease after a request that did not complete, keeping
// the durable progress. It must run even when the client has gone, hence its
// own context.
func (w *writer) release(ctx context.Context) {
	w.s.releaseLease(ctx, w.rec)
}

// reset discards everything stored for the upload, after a file turned out
// too large, so the record cannot be resumed past the limit.
func (w *writer) reset(ctx context.Context) {
	ctx, cancel := w.s.storageContext(ctx)
	defer cancel()
	if w.rec.MultipartID != "" {
		_ = w.s.o.Blobs.AbortMultipart(ctx, w.rec.ID, w.rec.MultipartID)
	}
	r := w.rec
	clearContent(&r)
	r.Lease, r.LeaseUntil = "", time.Time{}
	if rec, err := w.s.o.Metadata.Update(ctx, r); err == nil {
		w.rec = rec
	}
}

// storageFailure handles a failed part or completion call. ErrNotFound
// means the multipart upload is gone and ErrInvalidParts that its parts no
// longer match the record; a record in either state can never complete. It
// is reset so that the client starts again instead of resuming into the same
// failure.
func (w *writer) storageFailure(ctx context.Context, op string, err error) error {
	if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrInvalidParts) {
		return storageErr(op, err)
	}
	w.reset(ctx)
	return errUploadGone
}

// clearContent forgets the stored content of an incomplete record.
func clearContent(r *store.Record) {
	r.Received = 0
	r.HashState, r.MultipartID, r.Parts = nil, "", nil
}

// storageError is a failed storage call; the cause is logged, not sent.
type storageError struct {
	op  string
	err error
}

func (e *storageError) Error() string { return "ftserver: storage " + e.op + ": " + e.err.Error() }
func (e *storageError) Unwrap() error { return e.err }

func storageErr(op string, err error) error { return &storageError{op: op, err: err} }

// metadataErr turns a failed record update into errLostLease when another
// writer changed the record, and a storage error otherwise.
func metadataErr(err error) error {
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
		return errLostLease
	}
	return storageErr("update record", err)
}

// errBusy means another request holds the upload's lease.
var errBusy = errors.New("ftserver: another request is writing this upload")

// acquireLease makes this request the upload's only writer, or fails with
// errBusy while another holds it. A lease outlives the longest request can
// last (UploadTimeout, plus one StorageTimeout for its last call, plus a
// margin), so it only lapses when its holder has died; then a resume can take
// over. Without it two requests for one upload could both store part N, and
// whichever S3 kept last might not be the one the record names.
func (s *Server) acquireLease(ctx context.Context, rec store.Record, change func(*store.Record)) (store.Record, error) {
	now := s.now()
	if rec.Lease != "" && now.Before(rec.LeaseUntil) {
		return store.Record{}, errBusy
	}
	lease, err := newID(s.random)
	if err != nil {
		return store.Record{}, err
	}
	rec.Lease, rec.LeaseUntil = lease, now.Add(s.leaseTTL)
	if change != nil {
		change(&rec)
	}
	ctx, cancel := s.storageContext(ctx)
	defer cancel()
	out, err := s.o.Metadata.Update(ctx, rec)
	if errors.Is(err, store.ErrConflict) {
		return store.Record{}, errBusy
	}
	if err != nil {
		return store.Record{}, storageErr("update record", err)
	}
	return out, nil
}

// releaseLease clears rec's lease, best effort: if it fails the lease simply
// lapses later.
func (s *Server) releaseLease(ctx context.Context, rec store.Record) {
	if rec.Lease == "" || rec.State != store.Uploading {
		return
	}
	ctx, cancel := s.storageContext(ctx)
	defer cancel()
	rec.Lease, rec.LeaseUntil = "", time.Time{}
	_, _ = s.o.Metadata.Update(ctx, rec)
}
