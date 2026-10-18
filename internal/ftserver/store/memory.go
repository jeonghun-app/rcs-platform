package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"sync"
	"time"
)

// Memory is a Metadata in process memory, for tests and local runs. Instances
// do not share it, so a deployment with several tasks needs DynamoDB instead
// (ft-server refuses FT_STORE=memory in staging and prod).
type Memory struct {
	mu      sync.Mutex
	records map[string]Record
	byTID   map[tidKey]string
}

type tidKey struct{ owner, tid string }

// NewMemory returns an empty Memory.
func NewMemory() *Memory {
	return &Memory{records: map[string]Record{}, byTID: map[tidKey]string{}}
}

// Create implements Metadata.
func (m *Memory) Create(_ context.Context, r Record) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := tidKey{r.Owner, r.TID}
	if _, ok := m.byTID[k]; ok {
		return Record{}, ErrExists
	}
	if _, ok := m.records[r.ID]; ok {
		return Record{}, ErrExists
	}
	r = r.Clone()
	r.Version = 1
	m.records[r.ID] = r
	m.byTID[k] = r.ID
	return r.Clone(), nil
}

// Get implements Metadata.
func (m *Memory) Get(_ context.Context, id string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	return r.Clone(), nil
}

// GetByTID implements Metadata.
func (m *Memory) GetByTID(_ context.Context, owner, tid string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byTID[tidKey{owner, tid}]
	if !ok {
		return Record{}, ErrNotFound
	}
	return m.records[id].Clone(), nil
}

// Update implements Metadata.
func (m *Memory) Update(_ context.Context, r Record) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.records[r.ID]
	switch {
	case !ok:
		return Record{}, ErrNotFound
	case cur.Version != r.Version:
		return Record{}, ErrConflict
	case cur.Owner != r.Owner || cur.TID != r.TID:
		return Record{}, errors.New("store: owner and transaction id cannot change")
	}
	r = r.Clone()
	r.Version++
	m.records[r.ID] = r
	return r.Clone(), nil
}

// ListExpired implements Metadata. Records come in file id order, so a test
// sees the same order every run.
func (m *Memory) ListExpired(_ context.Context, now time.Time, limit int) ([]Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Record
	for _, id := range slices.Sorted(maps.Keys(m.records)) {
		if len(out) == limit {
			break
		}
		if r := m.records[id]; r.State != Expired && r.Expires.Before(now) {
			out = append(out, r.Clone())
		}
	}
	return out, nil
}

// MemoryBlobs is a Blobs in process memory, for tests and local runs. It
// enforces the part rules S3 does, with a configurable minimum part size, so a
// test with small parts exercises the same paths as production.
type MemoryBlobs struct {
	minPart int64

	mu      sync.Mutex
	objects map[string][]byte
	uploads map[string]*memUpload
	nextID  int
	// fail, when set, makes every call fail, so tests can exercise storage
	// errors.
	fail error
}

type memUpload struct {
	key   string
	parts map[int32][]byte
}

// NewMemoryBlobs returns an empty MemoryBlobs whose multipart uploads refuse
// a part other than the last below minPart bytes, as S3 does at 5 MiB.
func NewMemoryBlobs(minPart int64) *MemoryBlobs {
	return &MemoryBlobs{minPart: minPart, objects: map[string][]byte{}, uploads: map[string]*memUpload{}}
}

// SetFailure makes every later call return err, or behave normally again when
// err is nil.
func (b *MemoryBlobs) SetFailure(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fail = err
}

// Object returns a copy of the stored object key, for tests.
func (b *MemoryBlobs) Object(key string) ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	o, ok := b.objects[key]
	return bytes.Clone(o), ok
}

// OpenUploads counts multipart uploads that are neither completed nor
// aborted, for tests.
func (b *MemoryBlobs) OpenUploads() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.uploads)
}

// Put implements Blobs.
func (b *MemoryBlobs) Put(_ context.Context, key string, body []byte, _ string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail != nil {
		return b.fail
	}
	b.objects[key] = bytes.Clone(body)
	return nil
}

// CreateMultipart implements Blobs.
func (b *MemoryBlobs) CreateMultipart(_ context.Context, key, _ string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail != nil {
		return "", b.fail
	}
	b.nextID++
	id := "mpu-" + strconv.Itoa(b.nextID)
	b.uploads[id] = &memUpload{key: key, parts: map[int32][]byte{}}
	return id, nil
}

// UploadPart implements Blobs.
func (b *MemoryBlobs) UploadPart(_ context.Context, key, uploadID string, number int32, body []byte) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail != nil {
		return "", b.fail
	}
	u, ok := b.uploads[uploadID]
	if !ok || u.key != key {
		return "", ErrNotFound
	}
	if number < 1 || number > 10000 {
		return "", fmt.Errorf("store: part number %d out of range", number)
	}
	u.parts[number] = bytes.Clone(body)
	return etag(body), nil
}

// CompleteMultipart implements Blobs.
func (b *MemoryBlobs) CompleteMultipart(_ context.Context, key, uploadID string, parts []Part) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail != nil {
		return b.fail
	}
	u, ok := b.uploads[uploadID]
	if !ok || u.key != key {
		return ErrNotFound
	}
	if len(parts) == 0 {
		return fmt.Errorf("%w: no parts", ErrInvalidParts)
	}
	var obj []byte
	for i, p := range parts {
		data, ok := u.parts[p.Number]
		switch {
		case !ok || etag(data) != p.ETag:
			return fmt.Errorf("%w: part %d differs", ErrInvalidParts, p.Number)
		case i > 0 && p.Number <= parts[i-1].Number:
			return fmt.Errorf("%w: not in ascending order", ErrInvalidParts)
		case i < len(parts)-1 && int64(len(data)) < b.minPart:
			return fmt.Errorf("%w: part %d is below the minimum size", ErrInvalidParts, p.Number)
		}
		obj = append(obj, data...)
	}
	b.objects[key] = obj
	delete(b.uploads, uploadID)
	return nil
}

// AbortMultipart implements Blobs.
func (b *MemoryBlobs) AbortMultipart(_ context.Context, key, uploadID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail != nil {
		return b.fail
	}
	if u, ok := b.uploads[uploadID]; !ok || u.key != key {
		return ErrNotFound
	}
	delete(b.uploads, uploadID)
	return nil
}

// Open implements Blobs.
func (b *MemoryBlobs) Open(_ context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail != nil {
		return nil, b.fail
	}
	o, ok := b.objects[key]
	if !ok {
		return nil, ErrNotFound
	}
	if offset < 0 || length < 0 || offset+length > int64(len(o)) {
		return nil, errors.New("store: range outside the object")
	}
	return io.NopCloser(bytes.NewReader(bytes.Clone(o[offset : offset+length]))), nil
}

// etag stands in for the S3 ETag: any value that changes with the content
// lets CompleteMultipart catch a part replaced behind the writer's back.
func etag(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}
