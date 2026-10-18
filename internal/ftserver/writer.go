package ftserver

import (
	"bytes"
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
	// lease: the sweeper expired it, or the lease lapsed and another
	// request took over.
	errLostLease = errors.New("ftserver: the upload changed while being written")
	// errUploadGone means the open multipart upload behind a record no
	// longer exists (completed or aborted after a failure) or no longer
	// matches it; the record has been reset so the client starts again.
	errUploadGone = errors.New("ftserver: the stored upload is gone")
	// errLengthMismatch means the content ended at another length than
	// the client declared.
	errLengthMismatch = errors.New("ftserver: content length does not match the declared size")
	// errTooManyParts means the file would need more parts than a record
	// can list.
	errTooManyParts = errors.New("ftserver: the file needs too many parts")
)

// writer streams one request's file content into storage. It holds the
// record's lease, keeps at most one part (plus one byte) in memory and makes
// each full part durable, with the hash state up to it, before reading on:
// whatever arrives after the last durable part is lost if the request breaks,
// and the client resumes from Received (RCC.07 FT via HTTP, resume upload).
//
// A full part is stored only once a byte after it has arrived. The last part
// of a file therefore always stays in memory until the request completes, so
// an incomplete record always has Received below the file's size: a client
// whose upload breaks after the last byte, or whose completion fails, has a
// non-empty rest to send again rather than a record that claims every byte
// and cannot be completed.
type writer struct {
	s       *Server
	rec     store.Record
	hash    hash.Hash
	buf     *[]byte // capacity PartSize+1
	total   int64   // the size the content must have, or -1
	renewed time.Time
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
	// The lease was taken (or last renewed) leaseTTL before it ends, which
	// may be well before now if a thumbnail was stored in between.
	renewed := rec.LeaseUntil.Add(-s.leaseTTL)
	return &writer{s: s, rec: rec, hash: h, buf: buf, total: rec.DeclaredSize, renewed: renewed}, nil
}

// close returns the part buffer. Call it once, last.
func (w *writer) close() {
	w.s.buffers.Put(w.buf)
	w.buf = nil
}

// copy reads src to its end, storing every part that is followed by more
// content. On nil the content after the last stored part is in the buffer,
// for complete. An error from src is returned as is: the client stopped or
// broke off.
func (w *writer) copy(ctx context.Context, src io.Reader) error {
	part := int(w.s.o.PartSize)
	for {
		b := *w.buf
		if len(b) == cap(b) {
			if err := w.flush(ctx, part); err != nil {
				return err
			}
			b = *w.buf
		}
		if err := w.renew(ctx); err != nil {
			return err
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

// renew extends the lease while content flows, once a quarter of its
// lifetime has passed. A lease is short (see Server.leaseTTL) so that one
// left by a task that died lapses within minutes; renewing it is what keeps
// it from lapsing under a writer that is merely slow.
func (w *writer) renew(ctx context.Context) error {
	now := w.s.now()
	if now.Sub(w.renewed) < w.s.leaseTTL/4 {
		return nil
	}
	ctx, cancel := w.s.storageContext(ctx)
	defer cancel()
	r := w.rec
	r.LeaseUntil = now.Add(w.s.leaseTTL)
	rec, err := w.s.o.Metadata.Update(ctx, r)
	if err != nil {
		return metadataErr(err)
	}
	w.rec, w.renewed = rec, now
	w.s.metrics.Count("upload.lease_renewed", 1)
	return nil
}

// flush stores the first n bytes of the buffer as the next part, records
// it, and keeps the rest of the buffer. w.rec changes only once the record
// update has succeeded, so that after a failure it still describes what is
// stored.
func (w *writer) flush(ctx context.Context, n int) error {
	ctx, cancel := w.s.storageContext(ctx)
	defer cancel()
	b := (*w.buf)[:n]
	r := w.rec.Clone()
	if len(r.Parts)+1 >= maxParts {
		return errTooManyParts
	}
	// A multipart upload created here is named by no record until the
	// update below succeeds; on any failure before that it is aborted, not
	// left for the lifecycle rule.
	orphan := r.MultipartID == ""
	if orphan {
		key, err := w.s.newObjectKey(r.ID)
		if err != nil {
			return err
		}
		id, err := w.s.o.Blobs.CreateMultipart(ctx, key, r.ContentType)
		if err != nil {
			return storageErr("create multipart", err)
		}
		r.Object, r.MultipartID = key, id
	}
	abortOrphan := func() {
		if orphan {
			_ = w.s.o.Blobs.AbortMultipart(ctx, r.Object, r.MultipartID)
		}
	}
	part, err := w.s.o.Blobs.UploadPart(ctx, r.Object, r.MultipartID, int32(len(r.Parts)+1), b)
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
	r.Parts = append(r.Parts, part)
	r.Received += int64(n)
	r.HashState = state
	// Storing a part renews the lease too.
	now := w.s.now()
	r.LeaseUntil = now.Add(w.s.leaseTTL)
	rec, err := w.s.o.Metadata.Update(ctx, r)
	if err != nil {
		abortOrphan()
		return metadataErr(err)
	}
	w.rec, w.renewed = rec, now
	w.s.metrics.Count("upload.parts", 1)
	rest := copy(*w.buf, (*w.buf)[n:])
	*w.buf = (*w.buf)[:rest]
	return nil
}

// complete stores the rest of the content, closes the object and marks the
// record complete, giving the file its validity from now.
//
// Only the request holding the lease should get here; if a lease was broken
// all the same (a writer stalled past it, clocks far apart), the two
// completions cannot spoil each other's content: a single-object file goes to
// a key of its own for every completion, a multipart one is joined by S3 only
// from parts whose ETags match the list given, and the conditional record
// update commits exactly one of them.
func (w *writer) complete(parent context.Context) (store.Record, error) {
	ctx, cancel := w.s.storageContext(parent)
	defer cancel()
	tail := *w.buf
	size := w.rec.Received + int64(len(tail))
	if w.total >= 0 && size != w.total {
		return store.Record{}, errLengthMismatch
	}
	r := w.rec
	if r.MultipartID == "" {
		key, err := w.s.newObjectKey(r.ID)
		if err != nil {
			return store.Record{}, err
		}
		if err := w.s.o.Blobs.Put(ctx, key, tail, r.ContentType); err != nil {
			return store.Record{}, storageErr("put", err)
		}
		r.Object = key
	} else {
		parts := slices.Clone(r.Parts)
		if len(tail) > 0 {
			part, err := w.s.o.Blobs.UploadPart(ctx, r.Object, r.MultipartID, int32(len(parts)+1), tail)
			if err != nil {
				return store.Record{}, w.storageFailure(ctx, "upload part", err)
			}
			parts = append(parts, part)
		}
		if err := w.s.o.Blobs.CompleteMultipart(ctx, r.Object, r.MultipartID, parts); err != nil {
			return store.Record{}, w.storageFailure(ctx, "complete multipart", err)
		}
	}
	w.hash.Write(tail)
	now := w.s.now()
	r.State = store.Complete
	r.Size, r.Received, r.DeclaredSize = size, size, size
	r.SHA256 = w.hash.Sum(nil)
	r.HashState, r.MultipartID, r.Parts = nil, "", nil
	r.Lease, r.LeaseUntil = "", time.Time{}
	r.Completed = now
	r.Expires = now.Add(w.s.o.Validity)
	rec, err := w.commit(parent, r)
	if err != nil {
		return store.Record{}, metadataErr(err)
	}
	w.rec = rec
	return rec, nil
}

// commitAttempts bounds the tries of the update that completes an upload.
const commitAttempts = 4

// commit writes the record that completes an upload. By then the content
// is committed in storage and the multipart upload closed, so if this update
// failed for good the upload could only start over; a transient failure (a
// throttled table, a timed-out call) is therefore retried, with backoff. The
// update is conditional on the version this writer holds, so a retry can
// only ever write it once: a conflict ends the retries at once.
//
// Each attempt gets a storage context of its own (FT_STORAGE_TIMEOUT is per
// call), so that one attempt timing out leaves time for the next. An update
// can be applied and its answer lost: our own deadline ends the call after
// DynamoDB wrote, or the SDK's retry of a lost answer meets the write as
// ConditionalCheckFailed. So a conflict, and every failure that leaves the
// outcome unknown, is checked against the stored record before it is
// answered: if the record is complete with this completion's object key and
// hash, the upload did complete and is reported as such (#50).
func (w *writer) commit(ctx context.Context, r store.Record) (store.Record, error) {
	var err error
	for attempt := range commitAttempts {
		if attempt > 0 {
			// The request may have ended; the commit is worth finishing
			// anyway, so the wait does not follow it.
			<-time.After(w.s.retryWait(attempt))
		}
		actx, cancel := w.s.storageContext(ctx)
		var rec store.Record
		rec, err = w.s.o.Metadata.Update(actx, r)
		cancel()
		switch {
		case err == nil, errors.Is(err, store.ErrNotFound):
			return rec, err
		case errors.Is(err, store.ErrConflict):
			if mine, ok := w.committed(ctx, r); ok {
				return mine, nil
			}
			return rec, err
		}
		w.s.metrics.Count("upload.commit_retried", 1)
	}
	// Every attempt failed without saying whether it wrote: look once more.
	if mine, ok := w.committed(ctx, r); ok {
		return mine, nil
	}
	return store.Record{}, err
}

// committed reads the record back, with a context of its own, and reports
// whether it holds this completion, r.
//
// The object key and the hash together identify r. A single-object file is
// written under a new key for every completion, so no other completion can
// share it. Writers resuming one multipart upload do share its key, but S3
// completes a multipart upload only once, and the hash covers the content.
func (w *writer) committed(ctx context.Context, r store.Record) (store.Record, bool) {
	gctx, cancel := w.s.storageContext(ctx)
	defer cancel()
	stored, err := w.s.o.Metadata.Get(gctx, r.ID)
	if err != nil || stored.State != store.Complete || stored.Object != r.Object || !bytes.Equal(stored.SHA256, r.SHA256) {
		return store.Record{}, false
	}
	w.s.metrics.Count("upload.commit_recovered", 1)
	return stored, true
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
		_ = w.s.o.Blobs.AbortMultipart(ctx, w.rec.Object, w.rec.MultipartID)
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
	r.HashState, r.Object, r.MultipartID, r.Parts = nil, "", "", nil
}

// newObjectKey returns a key for one attempt at storing file id's content:
// the id and a random suffix, so that no two attempts share an object.
func (s *Server) newObjectKey(id string) (string, error) {
	suffix, err := newID(s.random)
	if err != nil {
		return "", err
	}
	return id + "." + suffix, nil
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

// busyError means another request holds the upload's lease, which it will
// renew or release within wait.
type busyError struct{ wait time.Duration }

func (e *busyError) Error() string { return "ftserver: another request is writing this upload" }

// acquireLease makes this request the upload's only writer, or fails with a
// *busyError while another holds it. A lease lasts leaseTTL and is renewed
// while content flows (writer.renew), so a live writer keeps it and a dead
// one's lapses within minutes; then a resume can take over. Without it two
// requests for one upload could both store part N, and whichever S3 kept
// last might not be the one the record names.
func (s *Server) acquireLease(ctx context.Context, rec store.Record, change func(*store.Record)) (store.Record, error) {
	now := s.now()
	if rec.Lease != "" && now.Before(rec.LeaseUntil) {
		return store.Record{}, &busyError{wait: min(rec.LeaseUntil.Sub(now), s.leaseTTL)}
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
		return store.Record{}, &busyError{wait: retryAfter}
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
