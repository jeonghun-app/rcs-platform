package ftserver

import (
	"context"
	"net/http"
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
