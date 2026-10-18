// Package store defines what ft-server keeps about a file transfer and where:
// a metadata record per upload (owner, transaction id, progress, validity) and
// the content itself as objects. ft-server talks only to the interfaces here,
// so its upload, resume and download logic runs against the memory backends in
// unit tests and against S3 and DynamoDB (internal/ftserver/awsstore) in
// production; the contract both must meet is checked by
// internal/ftserver/store/storetest.
//
// Records are written with optimistic concurrency: every Update names the
// version it read and fails with ErrConflict if another writer got there
// first. That is what stops two ft-server tasks from completing the same
// upload twice or interleaving their writes (ADR 0005: any task may serve any
// request).
package store

import (
	"context"
	"errors"
	"io"
	"slices"
	"time"
)

// Errors every backend returns, possibly wrapped.
var (
	// ErrNotFound means no record or object exists under the key, or a
	// multipart upload is no longer open.
	ErrNotFound = errors.New("store: not found")
	// ErrExists means Create found a record for the same owner and
	// transaction id.
	ErrExists = errors.New("store: record exists")
	// ErrConflict means Update was given a version that is no longer the
	// stored one.
	ErrConflict = errors.New("store: version conflict")
	// ErrInvalidParts means CompleteMultipart was given parts that do not
	// match what the upload holds: a wrong ETag, a missing part, parts out of
	// order or too small. Completing those parts can never succeed.
	ErrInvalidParts = errors.New("store: parts do not match the upload")
)

// State is where an upload is in its life.
type State string

// The states. An upload starts Uploading, becomes Complete once all its bytes
// are stored, and is marked Expired by the sweeper when its validity ends.
const (
	Uploading State = "uploading"
	Complete  State = "complete"
	Expired   State = "expired"
)

// Part is one stored part of a multipart object, in the S3 sense: parts are
// numbered from 1 and every part but the last has the backend's minimum size.
type Part struct {
	Number int32
	ETag   string
	Size   int64
}

// Thumbnail describes the optional thumbnail stored with a file.
type Thumbnail struct {
	Size        int64
	ContentType string
}

// Record is the metadata of one upload, keyed by its file id and, for the
// owner, by the transaction id the client chose.
//
// FileName, Owner and TID identify a subscriber or reveal what they sent; they
// never reach a log except through internal/pii (docs/architecture.md §8).
type Record struct {
	// ID is the file id: at least 128 random bits, the secret part of the
	// download URL.
	ID string
	// Owner is the identity that uploaded the file (the IMPU given by the
	// credential source).
	Owner string
	// TID is the client's transaction id (RCC.07 FT via HTTP upload), unique
	// per owner.
	TID   string
	State State

	FileName    string
	ContentType string
	// DeclaredSize is the size the client announced, or -1 until it has.
	DeclaredSize int64
	// Received counts the bytes stored durably, the point a resumed upload
	// continues from.
	Received int64
	// Size and SHA256 describe the complete content.
	Size   int64
	SHA256 []byte
	// HashState is the marshalled SHA-256 state over the first Received
	// bytes, so a resume on another task continues the same hash.
	HashState []byte
	// MultipartID is the open multipart upload holding Parts, or empty while
	// no part has been stored.
	MultipartID string
	Parts       []Part
	Thumbnail   *Thumbnail

	Created   time.Time
	Completed time.Time
	// Expires ends the validity: of the upload while it is incomplete, of the
	// download links once it is complete.
	Expires time.Time

	// Lease names the request currently writing content; LeaseUntil is when
	// another request may take over if the holder vanished.
	Lease      string
	LeaseUntil time.Time

	// Version is the stored version. Update writes only if it still matches
	// and returns the record with the next version.
	Version int64
}

// Clone returns a deep copy, so a caller can change it without touching a
// record a backend still holds.
func (r Record) Clone() Record {
	r.SHA256 = slices.Clone(r.SHA256)
	r.HashState = slices.Clone(r.HashState)
	r.Parts = slices.Clone(r.Parts)
	if r.Thumbnail != nil {
		t := *r.Thumbnail
		r.Thumbnail = &t
	}
	return r
}

// Metadata stores upload records. Implementations are safe for concurrent use
// and every read is strongly consistent.
type Metadata interface {
	// Create stores a new record with version 1. It fails with ErrExists if
	// the owner already has a record for r.TID, or one with r.ID exists.
	Create(ctx context.Context, r Record) (Record, error)
	// Get returns the record with file id id, or ErrNotFound.
	Get(ctx context.Context, id string) (Record, error)
	// GetByTID returns owner's record for tid, or ErrNotFound.
	GetByTID(ctx context.Context, owner, tid string) (Record, error)
	// Update replaces the record if its stored version is r.Version and
	// returns it with the next version; otherwise it fails with ErrConflict
	// (or ErrNotFound). ID, Owner and TID cannot change.
	Update(ctx context.Context, r Record) (Record, error)
	// ListExpired returns up to limit records whose Expires is before now and
	// whose state is not Expired yet.
	ListExpired(ctx context.Context, now time.Time, limit int) ([]Record, error)
}

// Blobs stores content. Keys are file ids (plus a suffix for thumbnails).
// Implementations are safe for concurrent use.
type Blobs interface {
	// Put stores body as the whole object key.
	Put(ctx context.Context, key string, body []byte, contentType string) error
	// CreateMultipart opens a multipart upload for key and returns its id.
	CreateMultipart(ctx context.Context, key, contentType string) (string, error)
	// UploadPart stores part number of an open multipart upload and returns
	// its ETag. Storing a number again replaces the part. A closed or unknown
	// upload gives ErrNotFound.
	UploadPart(ctx context.Context, key, uploadID string, number int32, body []byte) (string, error)
	// CompleteMultipart joins parts, in order, into object key. It fails
	// with ErrInvalidParts if a part's ETag does not match the part stored
	// under its number, or the parts break the size and order rules.
	CompleteMultipart(ctx context.Context, key, uploadID string, parts []Part) error
	// AbortMultipart discards an open multipart upload; an unknown one gives
	// ErrNotFound.
	AbortMultipart(ctx context.Context, key, uploadID string) error
	// Open returns length bytes of object key starting at offset. The range
	// must lie inside the object; a missing object gives ErrNotFound.
	Open(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error)
}
