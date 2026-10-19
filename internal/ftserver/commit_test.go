package ftserver

import (
	"context"
	"net/http"
	"strings"
	"sync"
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

// appliedThenTimedOut applies completing updates, then reports them as timed
// out, as when DynamoDB writes and FT_STORAGE_TIMEOUT expires before the
// answer arrives. With every set, it does so on every completing update;
// otherwise only on the first. With expire set, it holds the call until its
// context ends and reports the context's error; otherwise it reports
// context.DeadlineExceeded at once.
type appliedThenTimedOut struct {
	store.Metadata
	every, expire bool
	calls         atomic.Int32

	mu sync.Mutex
	// updates and reads are the completing updates and the reads after
	// the first, with when each was called and its context's deadline.
	updates, reads []timedCall
}

type timedCall struct{ at, deadline time.Time }

func (a *appliedThenTimedOut) record(calls *[]timedCall, ctx context.Context) {
	deadline, _ := ctx.Deadline()
	a.mu.Lock()
	*calls = append(*calls, timedCall{time.Now(), deadline})
	a.mu.Unlock()
}

func (a *appliedThenTimedOut) Get(ctx context.Context, id string) (store.Record, error) {
	if a.calls.Load() > 0 {
		a.record(&a.reads, ctx)
	}
	return a.Metadata.Get(ctx, id)
}

func (a *appliedThenTimedOut) Update(ctx context.Context, r store.Record) (store.Record, error) {
	if r.State == store.Complete {
		a.record(&a.updates, ctx)
	}
	if r.State != store.Complete || !a.every && a.calls.Load() > 0 {
		return a.Metadata.Update(ctx, r)
	}
	a.calls.Add(1)
	_, _ = a.Metadata.Update(ctx, r) // applied, or a conflict on a retry
	if !a.expire {
		return store.Record{}, context.DeadlineExceeded
	}
	<-ctx.Done()
	return store.Record{}, ctx.Err()
}

func TestCommitAppliedBeforeItsDeadlineExpiredIsRecovered(t *testing.T) {
	for _, tt := range []struct {
		name          string
		every, expire bool
	}{
		{"retry conflicts", false, false},
		{"every attempt times out", true, false},
		{"the attempts really expire", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			meta := &appliedThenTimedOut{Metadata: store.NewMemory(), every: tt.every, expire: tt.expire}
			e := newEnv(t, func(o *Options) {
				o.Metadata = meta
				if tt.expire {
					// The lease is 900 ms and the completion budget 600 ms,
					// of which 450 ms are for the commit attempts: the first
					// expires after 300 ms, and whether a second starts
					// before the budget ends depends on how the host runs
					// the test, so only the budget is checked.
					o.StorageTimeout = 300 * time.Millisecond
					o.IdleTimeout = 150 * time.Millisecond
				} else {
					// The attempts report their timeout at once, so none
					// waits on the clock. With no idle timeout, the budget
					// less the reserve is one StorageTimeout: an attempt
					// whose deadline ignored the budget would end past it,
					// as each starts at least one retryWait after the first
					// (review of #131).
					o.StorageTimeout = 10 * time.Second
					o.IdleTimeout = 0
				}
			})
			e.srv.retryWait = func(int) time.Duration { return 10 * time.Millisecond }
			data := pattern(20)
			// A retry meets the applied write as a conflict, or, if every
			// attempt times out, the final read back finds it.
			u := e.user(alice)
			u.challenge()
			rec := u.upload(multipartBody(tidPart("expired"), filePart("a", "text/plain", data)))
			if rec.Code != http.StatusOK || e.metric("upload.commit_recovered") != 1 {
				t.Fatalf("status = %d, recovered %v, retried %v", rec.Code, e.metric("upload.commit_recovered"), e.metric("upload.commit_retried"))
			}
			// However many attempts time out, completion ends within its
			// budget, while the writer still holds the lease. That is
			// shown by the deadlines completion gives its calls, not by
			// the time a loaded host takes to run them (#130): every
			// attempt ends within the budget less the reserve, counted
			// from the first, which began after the budget did, and each
			// read back within the reserve.
			budget := e.srv.completeBudget()
			reserve := min(e.srv.o.StorageTimeout, budget/4)
			meta.mu.Lock()
			defer meta.mu.Unlock()
			if len(meta.updates) == 0 || !tt.expire && (len(meta.updates) < 2 || len(meta.reads) != 1) {
				t.Fatalf("%d completing updates and %d reads back, want at least 2 and 1", len(meta.updates), len(meta.reads))
			}
			for i, c := range meta.updates {
				if c.deadline.IsZero() || c.deadline.After(meta.updates[0].at.Add(budget-reserve)) {
					t.Errorf("attempt %d has deadline %v, past %v of budget after the first", i, c.deadline.Sub(meta.updates[0].at), budget-reserve)
				}
			}
			for i, c := range meta.reads {
				if c.deadline.IsZero() || c.deadline.After(c.at.Add(reserve)) {
					t.Errorf("read back %d has deadline %v after it began, past the %v reserve", i, c.deadline.Sub(c.at), reserve)
				}
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
