package ftserver

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
)

// lostAnswer applies the first completing update but reports it as timed
// out, as when DynamoDB commits and the response is lost.
type lostAnswer struct {
	store.Metadata
	done atomic.Bool
}

func (l *lostAnswer) Update(ctx context.Context, r store.Record) (store.Record, error) {
	rec, err := l.Metadata.Update(ctx, r)
	if err == nil && r.State == store.Complete && l.done.CompareAndSwap(false, true) {
		return store.Record{}, context.DeadlineExceeded
	}
	return rec, err
}

func TestCommitThatSucceededButTimedOutIsReportedAsSuccess(t *testing.T) {
	for _, size := range []int{20, 3*testPart + 5} {
		meta := &lostAnswer{Metadata: store.NewMemory()}
		e := newEnv(t, func(o *Options) { o.Metadata = meta })
		e.srv.retryWait = func(int) time.Duration { return 0 }
		data := pattern(size)
		// The retry meets its own earlier write as a conflict; the record
		// names this attempt's object, so the upload did complete.
		doc := e.user(alice).uploadFile("lost", data)
		if got := get(e, downloadTarget(t, fileOf(t, doc).Data.URL)).Body.String(); got != data {
			t.Fatalf("%d bytes: the download differs", size)
		}
		if !meta.done.Load() || e.metric("upload.commit_recovered") != 1 {
			t.Fatalf("%d bytes: commit_recovered = %v", size, e.metric("upload.commit_recovered"))
		}
	}
}

// otherWriter completes the record under another object key the first time
// a completing update arrives, then fails that update as timed out: a
// conflict the retry must not mistake for its own success.
type otherWriter struct {
	store.Metadata
	done atomic.Bool
}

func (o *otherWriter) Update(ctx context.Context, r store.Record) (store.Record, error) {
	if r.State == store.Complete && o.done.CompareAndSwap(false, true) {
		theirs := r.Clone()
		theirs.Object = r.Object + ".theirs"
		if _, err := o.Metadata.Update(ctx, theirs); err != nil {
			return store.Record{}, err
		}
		return store.Record{}, context.DeadlineExceeded
	}
	return o.Metadata.Update(ctx, r)
}

func TestConflictWithAnotherWritersCommitIsStillAFailure(t *testing.T) {
	meta := &otherWriter{Metadata: store.NewMemory()}
	e := newEnv(t, func(o *Options) { o.Metadata = meta })
	e.srv.retryWait = func(int) time.Duration { return 0 }
	rec := e.user(alice).upload(multipartBody(tidPart("theirs"), filePart("a", "text/plain", "mine")))
	if rec.Code != http.StatusConflict || e.metric("upload.commit_recovered") != 0 {
		t.Fatalf("status = %d, recovered %v", rec.Code, e.metric("upload.commit_recovered"))
	}
}

// appliedThenTimedOut applies completing updates, then holds the call until
// its context ends and reports the context's error, as when DynamoDB writes
// and FT_STORAGE_TIMEOUT expires before the answer arrives. With every set,
// it does so on every completing update; otherwise only on the first.
type appliedThenTimedOut struct {
	store.Metadata
	every bool
	calls atomic.Int32
}

func (a *appliedThenTimedOut) Update(ctx context.Context, r store.Record) (store.Record, error) {
	if r.State != store.Complete || !a.every && a.calls.Load() > 0 {
		return a.Metadata.Update(ctx, r)
	}
	a.calls.Add(1)
	_, _ = a.Metadata.Update(ctx, r) // applied, or a conflict on a retry
	<-ctx.Done()
	return store.Record{}, ctx.Err()
}

func TestCommitAppliedBeforeItsDeadlineExpiredIsRecovered(t *testing.T) {
	for name, every := range map[string]bool{"retry conflicts": false, "every attempt times out": true} {
		t.Run(name, func(t *testing.T) {
			meta := &appliedThenTimedOut{Metadata: store.NewMemory(), every: every}
			e := newEnv(t, func(o *Options) { o.Metadata = meta; o.StorageTimeout = 300 * time.Millisecond })
			e.srv.retryWait = func(int) time.Duration { return 0 }
			data := pattern(20)
			// The first attempt really expires; a later attempt meets the
			// applied write as a conflict, or, if every attempt expires,
			// the final read-back finds it.
			u := e.user(alice)
			u.challenge()
			start := time.Now()
			rec := u.upload(multipartBody(tidPart("expired"), filePart("a", "text/plain", data)))
			if rec.Code != http.StatusOK || e.metric("upload.commit_recovered") != 1 {
				t.Fatalf("status = %d, recovered %v, retried %v", rec.Code, e.metric("upload.commit_recovered"), e.metric("upload.commit_retried"))
			}
			// However many attempts time out, completion ends within its
			// budget, while the writer still holds the lease.
			if took := time.Since(start); took > e.srv.completeBudget()+time.Second {
				t.Fatalf("completion took %v, budget %v", took, e.srv.completeBudget())
			}
		})
	}
}

// sameKeyOtherContent commits, the first time a completing update arrives,
// a record with the same object key but another hash, as a writer resuming
// the same multipart upload with other content would, then reports a
// timeout.
type sameKeyOtherContent struct {
	store.Metadata
	done atomic.Bool
}

func (o *sameKeyOtherContent) Update(ctx context.Context, r store.Record) (store.Record, error) {
	if r.State == store.Complete && o.done.CompareAndSwap(false, true) {
		theirs := r.Clone()
		theirs.SHA256 = sha("other content")
		if _, err := o.Metadata.Update(ctx, theirs); err != nil {
			return store.Record{}, err
		}
		return store.Record{}, context.DeadlineExceeded
	}
	return o.Metadata.Update(ctx, r)
}

func TestCommitUnderTheSameKeyWithAnotherHashIsNotMistakenForOurs(t *testing.T) {
	meta := &sameKeyOtherContent{Metadata: store.NewMemory()}
	e := newEnv(t, func(o *Options) { o.Metadata = meta })
	e.srv.retryWait = func(int) time.Duration { return 0 }
	rec := e.user(alice).upload(multipartBody(tidPart("same-key"), filePart("a", "text/plain", "mine")))
	if rec.Code != http.StatusConflict || e.metric("upload.commit_recovered") != 0 {
		t.Fatalf("status = %d, recovered %v", rec.Code, e.metric("upload.commit_recovered"))
	}
}

func TestCompletionRenewsALeaseWithLessThanItsBudgetLeft(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	data := pattern(2*testPart + 1)
	breakUpload(t, e, u, "late", data, testPart+1)
	rec, _ := e.meta.GetByTID(t.Context(), alice, "late")
	rec, err := e.srv.acquireLease(t.Context(), rec, nil)
	if err != nil {
		t.Fatal(err)
	}
	w, err := e.srv.newWriter(rec)
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	if err := w.copy(t.Context(), strings.NewReader(data[testPart:])); err != nil {
		t.Fatal(err)
	}
	// Most of the lease is gone by the time the content has arrived.
	e.clock.Advance(e.srv.leaseTTL - e.srv.completeBudget()/2)
	renewals := e.metric("upload.lease_renewed")
	done, err := w.complete(t.Context())
	if err != nil || done.State != store.Complete {
		t.Fatalf("complete = %+v, %v", done, err)
	}
	if e.metric("upload.lease_renewed") != renewals+1 {
		t.Fatal("the lease was not renewed before completing")
	}
}
