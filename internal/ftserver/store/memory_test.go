package store_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store/storetest"
)

func TestMemoryMeetsTheMetadataContract(t *testing.T) {
	storetest.Metadata(t, func(*testing.T) store.Metadata { return store.NewMemory() })
}

func TestMemoryBlobsMeetTheBlobsContract(t *testing.T) {
	storetest.Blobs(t, store.NewMemoryBlobs(8), 8)
}

func TestMemoryReturnsCopiesCallersCannotChange(t *testing.T) {
	m := store.NewMemory()
	ctx := context.Background()
	r := storetest.Record("id-1", "owner", "tid")
	r.Parts = []store.Part{{Number: 1, ETag: "a", Size: 1}}
	r.Thumbnail = &store.Thumbnail{Size: 1, ContentType: "image/png"}
	if _, err := m.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.Parts[0].ETag = "changed"
	r.Thumbnail.Size = 99
	got, err := m.Get(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Parts[0].ETag != "a" || got.Thumbnail.Size != 1 {
		t.Fatalf("stored record changed through the caller's slices: %+v", got)
	}
	got.Parts[0].ETag = "changed again"
	again, _ := m.Get(ctx, "id-1")
	if again.Parts[0].ETag != "a" {
		t.Fatal("stored record changed through a returned record")
	}
}

func TestMemoryRefusesToChangeTheOwner(t *testing.T) {
	m := store.NewMemory()
	ctx := context.Background()
	r, err := m.Create(ctx, storetest.Record("id-1", "owner", "tid"))
	if err != nil {
		t.Fatal(err)
	}
	r.Owner = "someone else"
	if _, err := m.Update(ctx, r); err == nil {
		t.Fatal("owner changed")
	}
}

func TestMemoryRefusesAReusedFileID(t *testing.T) {
	m := store.NewMemory()
	ctx := context.Background()
	if _, err := m.Create(ctx, storetest.Record("id-1", "owner", "tid-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(ctx, storetest.Record("id-1", "owner", "tid-2")); !errors.Is(err, store.ErrExists) {
		t.Fatalf("Create = %v, want ErrExists", err)
	}
}

func TestMemoryBlobsEnforceThePartRules(t *testing.T) {
	b := store.NewMemoryBlobs(4)
	ctx := context.Background()
	id, err := b.CreateMultipart(ctx, "k", "")
	if err != nil {
		t.Fatal(err)
	}
	e1, _ := b.UploadPart(ctx, "k", id, 1, []byte("ab"))
	e2, _ := b.UploadPart(ctx, "k", id, 2, []byte("cd"))
	small := []store.Part{{Number: 1, ETag: e1}, {Number: 2, ETag: e2}}
	if err := b.CompleteMultipart(ctx, "k", id, small); !errors.Is(err, store.ErrInvalidParts) {
		t.Fatalf("a non-last part below the minimum: %v", err)
	}
	unordered := []store.Part{{Number: 2, ETag: e2}, {Number: 1, ETag: e1}}
	if err := b.CompleteMultipart(ctx, "k", id, unordered); !errors.Is(err, store.ErrInvalidParts) {
		t.Fatalf("parts out of order: %v", err)
	}
	if err := b.CompleteMultipart(ctx, "k", id, nil); !errors.Is(err, store.ErrInvalidParts) {
		t.Fatalf("completion without parts: %v", err)
	}
	if _, err := b.UploadPart(ctx, "k", id, 0, []byte("x")); err == nil {
		t.Fatal("part number 0 was accepted")
	}
	if _, err := b.UploadPart(ctx, "other", id, 1, []byte("x")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("part for another key = %v", err)
	}
	if b.OpenUploads() != 1 {
		t.Fatalf("open uploads = %d", b.OpenUploads())
	}
	if err := b.CompleteMultipart(ctx, "k", "nope", small); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown upload = %v", err)
	}
}

func TestMemoryBlobsRefuseARangeOutsideTheObject(t *testing.T) {
	b := store.NewMemoryBlobs(4)
	ctx := context.Background()
	if err := b.Put(ctx, "k", []byte("abc"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open(ctx, "k", 2, 2); err == nil {
		t.Fatal("range past the end was opened")
	}
	if got, ok := b.Object("k"); !ok || !bytes.Equal(got, []byte("abc")) {
		t.Fatalf("Object = %q, %v", got, ok)
	}
}

func TestMemoryBlobsFailEveryCallWhenToldTo(t *testing.T) {
	b := store.NewMemoryBlobs(4)
	ctx := context.Background()
	boom := errors.New("boom")
	b.SetFailure(boom)
	checks := []error{
		b.Put(ctx, "k", nil, ""),
		func() error { _, err := b.CreateMultipart(ctx, "k", ""); return err }(),
		func() error { _, err := b.UploadPart(ctx, "k", "id", 1, nil); return err }(),
		b.CompleteMultipart(ctx, "k", "id", nil),
		b.AbortMultipart(ctx, "k", "id"),
		func() error { _, err := b.Open(ctx, "k", 0, 0); return err }(),
	}
	for i, err := range checks {
		if !errors.Is(err, boom) {
			t.Fatalf("call %d = %v, want the injected failure", i, err)
		}
	}
	b.SetFailure(nil)
	if err := b.Put(ctx, "k", []byte("x"), ""); err != nil {
		t.Fatal(err)
	}
	rc, err := b.Open(ctx, "k", 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rc)
	if string(data) != "x" {
		t.Fatalf("read %q", data)
	}
}
