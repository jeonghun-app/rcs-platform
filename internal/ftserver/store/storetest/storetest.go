// Package storetest is the contract every ft-server storage backend meets.
// The memory backends run it in unit tests and the S3 and DynamoDB backends
// run it against local containers (make test-integration), so a behaviour
// ft-server relies on, such as a conditional update losing a race, is tested
// once and holds for both.
package storetest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
)

// T0 is the time the records in the contract are created at.
var T0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// Record returns an uploading record for owner and tid with file id id.
func Record(id, owner, tid string) store.Record {
	return store.Record{
		ID:           id,
		Owner:        owner,
		TID:          tid,
		State:        store.Uploading,
		FileName:     "holiday photo.jpg",
		ContentType:  "image/jpeg",
		DeclaredSize: -1,
		Created:      T0,
		Expires:      T0.Add(7 * 24 * time.Hour),
	}
}

// Metadata runs the Metadata contract. newStore returns an empty store; ids
// and owners in the contract are unique per call, so a shared table is fine.
func Metadata(t *testing.T, newStore func(t *testing.T) store.Metadata) {
	ctx := context.Background()
	seq := 0
	ids := func(t *testing.T) (id, owner string) {
		seq++
		n := strconv.Itoa(seq)
		return "file-" + t.Name() + "-" + n, "sip:owner-" + n + "@ims.mnc001.mcc001.3gppnetwork.org"
	}

	t.Run("CreatedRecordReadsBackByIDAndByTID", func(t *testing.T) {
		s := newStore(t)
		id, owner := ids(t)
		in := Record(id, owner, "tid-1")
		in.Thumbnail = &store.Thumbnail{Size: 10, ContentType: "image/png"}
		got, err := s.Create(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		if got.Version != 1 {
			t.Fatalf("version = %d, want 1", got.Version)
		}
		for name, read := range map[string]func() (store.Record, error){
			"Get":      func() (store.Record, error) { return s.Get(ctx, id) },
			"GetByTID": func() (store.Record, error) { return s.GetByTID(ctx, owner, "tid-1") },
		} {
			r, err := read()
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if !Equal(r, got) {
				t.Fatalf("%s = %+v, want %+v", name, r, got)
			}
		}
	})

	t.Run("SecondRecordForTheSameTIDIsRefused", func(t *testing.T) {
		s := newStore(t)
		id, owner := ids(t)
		if _, err := s.Create(ctx, Record(id, owner, "tid-1")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Create(ctx, Record(id+"-other", owner, "tid-1")); !errors.Is(err, store.ErrExists) {
			t.Fatalf("second Create = %v, want ErrExists", err)
		}
		if _, err := s.Get(ctx, id+"-other"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("refused record was stored: %v", err)
		}
	})

	t.Run("SameTIDOfAnotherOwnerIsSeparate", func(t *testing.T) {
		s := newStore(t)
		id, owner := ids(t)
		id2, owner2 := ids(t)
		if _, err := s.Create(ctx, Record(id, owner, "tid-1")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Create(ctx, Record(id2, owner2, "tid-1")); err != nil {
			t.Fatalf("another owner's tid-1: %v", err)
		}
		r, err := s.GetByTID(ctx, owner2, "tid-1")
		if err != nil || r.ID != id2 {
			t.Fatalf("GetByTID = %v, %v", r.ID, err)
		}
	})

	t.Run("MissingRecordsAreNotFound", func(t *testing.T) {
		s := newStore(t)
		_, owner := ids(t)
		if _, err := s.Get(ctx, "no-such-file"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Get = %v", err)
		}
		if _, err := s.GetByTID(ctx, owner, "no-such-tid"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("GetByTID = %v", err)
		}
		r := Record("no-such-file", owner, "x")
		r.Version = 1
		if _, err := s.Update(ctx, r); !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrConflict) {
			t.Fatalf("Update = %v", err)
		}
	})

	t.Run("UpdateStoresEveryFieldAndBumpsTheVersion", func(t *testing.T) {
		s := newStore(t)
		id, owner := ids(t)
		r, err := s.Create(ctx, Record(id, owner, "tid-1"))
		if err != nil {
			t.Fatal(err)
		}
		r.State = store.Complete
		r.DeclaredSize = 12
		r.Received = 12
		r.Size = 12
		r.SHA256 = bytes.Repeat([]byte{0xab}, 32)
		r.HashState = []byte{1, 2, 3}
		r.Object = id + ".attempt"
		r.MultipartID = "upload-1"
		r.Parts = []store.Part{{Number: 1, ETag: `"e1"`, Size: 5, Checksum: "AAAAAA=="}, {Number: 2, ETag: `"e2"`, Size: 7}}
		r.Thumbnail = &store.Thumbnail{Key: id + ".attempt.t", Size: 3, ContentType: "image/png"}
		r.Completed = T0.Add(time.Minute)
		r.Expires = T0.Add(time.Hour)
		r.Lease = "lease-1"
		r.LeaseUntil = T0.Add(2 * time.Minute)
		got, err := s.Update(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		if got.Version != 2 {
			t.Fatalf("version = %d, want 2", got.Version)
		}
		read, err := s.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		want := r
		want.Version = 2
		if !Equal(read, want) {
			t.Fatalf("read back %+v, want %+v", read, want)
		}
	})

	t.Run("UpdateWithAStaleVersionConflicts", func(t *testing.T) {
		s := newStore(t)
		id, owner := ids(t)
		r, err := s.Create(ctx, Record(id, owner, "tid-1"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Update(ctx, r); err != nil {
			t.Fatal(err)
		}
		r.Received = 99
		if _, err := s.Update(ctx, r); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("stale Update = %v, want ErrConflict", err)
		}
		if got, _ := s.Get(ctx, id); got.Received == 99 {
			t.Fatal("stale update was written")
		}
	})

	t.Run("ConcurrentUpdatesOfOneVersionHaveOneWinner", func(t *testing.T) {
		s := newStore(t)
		id, owner := ids(t)
		r, err := s.Create(ctx, Record(id, owner, "tid-1"))
		if err != nil {
			t.Fatal(err)
		}
		const writers = 8
		var wg sync.WaitGroup
		results := make([]error, writers)
		for i := range writers {
			wg.Go(func() {
				c := r.Clone()
				c.State = store.Complete
				c.Lease = "writer-" + strconv.Itoa(i)
				_, results[i] = s.Update(ctx, c)
			})
		}
		wg.Wait()
		wins := 0
		for _, err := range results {
			switch {
			case err == nil:
				wins++
			case !errors.Is(err, store.ErrConflict):
				t.Fatalf("Update = %v", err)
			}
		}
		if wins != 1 {
			t.Fatalf("%d writers completed the same version, want 1", wins)
		}
	})

	t.Run("ExpiredRecordsAreListedUntilMarked", func(t *testing.T) {
		s := newStore(t)
		id, owner := ids(t)
		old := Record(id, owner, "old")
		old.Expires = T0.Add(-time.Hour)
		fresh := Record(id+"-fresh", owner, "fresh")
		fresh.Expires = T0.Add(time.Hour)
		r, err := s.Create(ctx, old)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Create(ctx, fresh); err != nil {
			t.Fatal(err)
		}
		list, err := s.ListExpired(ctx, T0, 1000)
		if err != nil {
			t.Fatal(err)
		}
		if !containsID(list, id) || containsID(list, id+"-fresh") {
			t.Fatalf("ListExpired = %v, want only %s", idsOf(list), id)
		}
		r.State = store.Expired
		if _, err := s.Update(ctx, r); err != nil {
			t.Fatal(err)
		}
		list, err = s.ListExpired(ctx, T0, 1000)
		if err != nil {
			t.Fatal(err)
		}
		if containsID(list, id) {
			t.Fatal("a record marked expired is listed again")
		}
	})

	t.Run("ListExpiredHonoursTheLimit", func(t *testing.T) {
		s := newStore(t)
		id, owner := ids(t)
		for i := range 3 {
			r := Record(id+"-"+strconv.Itoa(i), owner, "tid-"+strconv.Itoa(i))
			r.Expires = T0.Add(-time.Hour)
			if _, err := s.Create(ctx, r); err != nil {
				t.Fatal(err)
			}
		}
		list, err := s.ListExpired(ctx, T0, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 2 {
			t.Fatalf("ListExpired returned %d records, want 2", len(list))
		}
	})
}

// Blobs runs the Blobs contract against a store whose minimum part size is
// minPart. Keys are unique per call.
func Blobs(t *testing.T, b store.Blobs, minPart int) {
	ctx := context.Background()
	seq := 0
	key := func() string {
		seq++
		return "contract-" + strconv.Itoa(seq)
	}
	read := func(t *testing.T, k string, off, n int64) []byte {
		t.Helper()
		rc, err := b.Open(ctx, k, off, n)
		if err != nil {
			t.Fatalf("Open(%d, %d): %v", off, n, err)
		}
		defer rc.Close()
		data, err := io.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	t.Run("PutObjectReadsBackInRanges", func(t *testing.T) {
		k := key()
		body := []byte("0123456789")
		if err := b.Put(ctx, k, body, "text/plain"); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct{ off, n int64 }{{0, 10}, {3, 4}, {9, 1}, {0, 0}} {
			if got := read(t, k, c.off, c.n); !bytes.Equal(got, body[c.off:c.off+c.n]) {
				t.Fatalf("Open(%d, %d) = %q", c.off, c.n, got)
			}
		}
	})

	t.Run("MissingObjectIsNotFound", func(t *testing.T) {
		if _, err := b.Open(ctx, key(), 0, 1); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Open = %v, want ErrNotFound", err)
		}
	})

	t.Run("MultipartPartsJoinInOrder", func(t *testing.T) {
		k := key()
		id, err := b.CreateMultipart(ctx, k, "application/octet-stream")
		if err != nil {
			t.Fatal(err)
		}
		p1 := bytes.Repeat([]byte{'a'}, minPart)
		p2 := []byte("tail")
		part1, err := b.UploadPart(ctx, k, id, 1, p1)
		if err != nil {
			t.Fatal(err)
		}
		part2, err := b.UploadPart(ctx, k, id, 2, p2)
		if err != nil {
			t.Fatal(err)
		}
		if part1.Number != 1 || part1.Size != int64(len(p1)) || part1.ETag == "" || part2.Number != 2 {
			t.Fatalf("parts = %+v, %+v", part1, part2)
		}
		parts := []store.Part{part1, part2}
		if err := b.CompleteMultipart(ctx, k, id, parts); err != nil {
			t.Fatal(err)
		}
		want := append(bytes.Clone(p1), p2...)
		if got := read(t, k, 0, int64(len(want))); !bytes.Equal(got, want) {
			t.Fatalf("object is %d bytes, want %d", len(got), len(want))
		}
		if got := read(t, k, int64(minPart)-1, 3); string(got) != "ata" {
			t.Fatalf("range across the part boundary = %q", got)
		}
	})

	t.Run("ReplacedPartFailsCompletionWithTheOldETag", func(t *testing.T) {
		k := key()
		id, err := b.CreateMultipart(ctx, k, "application/octet-stream")
		if err != nil {
			t.Fatal(err)
		}
		first, err := b.UploadPart(ctx, k, id, 1, []byte("first writer"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.UploadPart(ctx, k, id, 1, []byte("second writer")); err != nil {
			t.Fatal(err)
		}
		if err := b.CompleteMultipart(ctx, k, id, []store.Part{first}); !errors.Is(err, store.ErrInvalidParts) {
			t.Fatalf("completion with the replaced part's ETag = %v, want ErrInvalidParts", err)
		}
		_ = b.AbortMultipart(ctx, k, id)
	})

	t.Run("AbortedUploadTakesNoMoreParts", func(t *testing.T) {
		k := key()
		id, err := b.CreateMultipart(ctx, k, "application/octet-stream")
		if err != nil {
			t.Fatal(err)
		}
		if err := b.AbortMultipart(ctx, k, id); err != nil {
			t.Fatal(err)
		}
		if _, err := b.UploadPart(ctx, k, id, 1, []byte("late")); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("UploadPart after abort = %v, want ErrNotFound", err)
		}
		if err := b.AbortMultipart(ctx, k, id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("second abort = %v, want ErrNotFound", err)
		}
	})
}

// Equal compares records the way a backend round trip must preserve them:
// times to the millisecond, nil and empty slices alike.
func Equal(a, b store.Record) bool {
	sameTime := func(x, y time.Time) bool { return x.UnixMilli() == y.UnixMilli() }
	sameThumb := (a.Thumbnail == nil) == (b.Thumbnail == nil) &&
		(a.Thumbnail == nil || *a.Thumbnail == *b.Thumbnail)
	sameParts := len(a.Parts) == len(b.Parts)
	for i := 0; sameParts && i < len(a.Parts); i++ {
		sameParts = a.Parts[i] == b.Parts[i]
	}
	return a.ID == b.ID && a.Owner == b.Owner && a.TID == b.TID && a.State == b.State &&
		a.FileName == b.FileName && a.ContentType == b.ContentType &&
		a.DeclaredSize == b.DeclaredSize && a.Received == b.Received && a.Size == b.Size &&
		bytes.Equal(a.SHA256, b.SHA256) && bytes.Equal(a.HashState, b.HashState) &&
		a.Object == b.Object && a.MultipartID == b.MultipartID && sameParts && sameThumb &&
		sameTime(a.Created, b.Created) && sameTime(a.Completed, b.Completed) &&
		sameTime(a.Expires, b.Expires) && a.Lease == b.Lease &&
		sameTime(a.LeaseUntil, b.LeaseUntil) && a.Version == b.Version
}

func containsID(list []store.Record, id string) bool {
	for _, r := range list {
		if r.ID == id {
			return true
		}
	}
	return false
}

func idsOf(list []store.Record) []string {
	out := make([]string, len(list))
	for i, r := range list {
		out[i] = r.ID
	}
	return out
}
