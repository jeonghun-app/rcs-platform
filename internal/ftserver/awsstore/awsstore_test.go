package awsstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	dtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go/logging"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store/storetest"
)

func fakeStores(t *testing.T) (*Stores, *fakeS3, *fakeDynamo) {
	s3c, ddb := newFakeS3(), newFakeDynamo(t)
	now := storetest.T0
	return NewWithClients(Config{Bucket: "files", Prefix: "ft/", Table: "files", SSE: "aws:kms", KMSKeyID: "alias/ft",
		Now: func() time.Time { return now }}, s3c, ddb), s3c, ddb
}

func TestDynamoMetadataMeetsTheContract(t *testing.T) {
	storetest.Metadata(t, func(t *testing.T) store.Metadata {
		s, _, _ := fakeStores(t)
		return s.Metadata
	})
}

func TestS3BlobsMeetTheContract(t *testing.T) {
	s, _, _ := fakeStores(t)
	storetest.Blobs(t, s.Blobs, 1)
}

func TestObjectsAreEncryptedAndPrefixed(t *testing.T) {
	s, s3c, _ := fakeStores(t)
	ctx := t.Context()
	if err := s.Blobs.Put(ctx, "id", []byte("x"), "text/plain"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Blobs.CreateMultipart(ctx, "id2", "text/plain"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s3c.objects["ft/id"]; !ok {
		t.Fatalf("objects = %v, want the key under the prefix", s3c.objects)
	}
	for _, sse := range s3c.sse {
		if sse != "aws:kms/alias/ft" {
			t.Fatalf("encryption = %q", sse)
		}
	}
	plain := NewWithClients(Config{Bucket: "b", SSE: "AES256", KMSKeyID: "ignored"}, s3c, nil)
	if err := plain.Blobs.Put(ctx, "id3", nil, ""); err != nil {
		t.Fatal(err)
	}
	if got := s3c.sse[len(s3c.sse)-1]; got != "AES256/" {
		t.Fatalf("SSE-S3 object asked for %q", got)
	}
}

func TestNonceCountsOnlyAdvance(t *testing.T) {
	s, _, _ := fakeStores(t)
	ctx := t.Context()
	n := s.NonceCounts
	later := storetest.T0.Add(time.Minute)
	for i, c := range []struct {
		user, nonce string
		nc          uint32
		want        bool
	}{
		{"alice", "n1", 1, true},
		{"alice", "n1", 1, false},
		{"alice", "n1", 3, true},
		{"alice", "n1", 2, false},
		{"bob", "n1", 1, true},
		{"alice", "n2", 1, true},
	} {
		got, err := n.Advance(ctx, c.user, c.nonce, c.nc, later)
		if err != nil || got != c.want {
			t.Fatalf("step %d: Advance = %v, %v; want %v", i, got, err, c.want)
		}
	}
	// Once the entry has expired the nonce cannot verify anyway, so the
	// slot may be reused.
	n.now = func() time.Time { return later.Add(time.Second) }
	if ok, err := n.Advance(ctx, "alice", "n1", 1, later.Add(time.Hour)); err != nil || !ok {
		t.Fatalf("Advance after expiry = %v, %v", ok, err)
	}
}

func TestKeysOfDifferentOwnersCannotCollide(t *testing.T) {
	if tidKey("a1", "x") == tidKey("a", "1x") || nonceKey("u#1", "n") == nonceKey("u", "#1n") {
		t.Fatal("length-prefixed keys collide")
	}
}

func TestReadyChecksBucketAndTable(t *testing.T) {
	s, s3c, ddb := fakeStores(t)
	if err := s.Ready(t.Context()); err != nil {
		t.Fatal(err)
	}
	ddb.status = dtypes.TableStatusCreating
	if err := s.Ready(t.Context()); err == nil {
		t.Fatal("a table being created is ready")
	}
	s3c.fail = &fakeAPIError{code: "AccessDenied"}
	if err := s.Ready(t.Context()); err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("Ready = %v", err)
	}
	s3c.fail = nil
	ddb.fail = &fakeAPIError{code: "ResourceNotFoundException"}
	if err := s.Ready(t.Context()); err == nil {
		t.Fatal("a missing table is ready")
	}
}

func TestErrorsNameNoObjectKey(t *testing.T) {
	s, s3c, ddb := fakeStores(t)
	ctx := t.Context()
	leak := &url.Error{Op: "Put", URL: "https://files.s3.example/ft/secret-file-id?partNumber=1", Err: errors.New("dial tcp: connection refused")}
	for _, f := range []error{leak, &fakeAPIError{code: "SlowDown"}, fmt.Errorf("wrapped: %w", context.DeadlineExceeded), errors.New("https://files/secret-file-id")} {
		s3c.fail, ddb.fail = f, f
		errs := []error{
			s.Blobs.Put(ctx, "secret-file-id", nil, ""),
			func() error { _, err := s.Blobs.CreateMultipart(ctx, "secret-file-id", ""); return err }(),
			func() error { _, err := s.Blobs.UploadPart(ctx, "secret-file-id", "u", 1, nil); return err }(),
			s.Blobs.CompleteMultipart(ctx, "secret-file-id", "u", nil),
			s.Blobs.AbortMultipart(ctx, "secret-file-id", "u"),
			func() error { _, err := s.Blobs.Open(ctx, "secret-file-id", 0, 1); return err }(),
			func() error { _, err := s.Metadata.Get(ctx, "secret-file-id"); return err }(),
			func() error {
				_, err := s.Metadata.Create(ctx, storetest.Record("secret-file-id", "o", "t"))
				return err
			}(),
			func() error {
				_, err := s.Metadata.Update(ctx, storetest.Record("secret-file-id", "o", "t"))
				return err
			}(),
			func() error { _, err := s.Metadata.ListExpired(ctx, storetest.T0, 1); return err }(),
			func() error { _, err := s.NonceCounts.Advance(ctx, "u", "n", 1, storetest.T0); return err }(),
		}
		for i, err := range errs {
			if err == nil || strings.Contains(err.Error(), "secret-file-id") {
				t.Errorf("%T call %d: %v", f, i, err)
			}
		}
	}
	s3c.fail = fmt.Errorf("wrapped: %w", context.DeadlineExceeded)
	if err := s.Blobs.Put(ctx, "k", nil, ""); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a timeout is no longer recognisable: %v", err)
	}
}

func TestMissingUploadAndObjectAreNotFound(t *testing.T) {
	s, _, _ := fakeStores(t)
	ctx := t.Context()
	if _, err := s.Blobs.UploadPart(ctx, "k", "nope", 1, []byte("x")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UploadPart = %v", err)
	}
	if err := s.Blobs.CompleteMultipart(ctx, "k", "nope", nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Complete = %v", err)
	}
}

func TestMalformedItemsAreErrors(t *testing.T) {
	good := encodeRecord(storetest.Record("id", "o", "t"))
	good[attrParts] = &dtypes.AttributeValueMemberL{Value: []dtypes.AttributeValue{
		&dtypes.AttributeValueMemberM{Value: map[string]dtypes.AttributeValue{"n": num(1), "etag": str("e"), "size": num(5)}},
	}}
	if _, err := decodeRecord(good); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(map[string]dtypes.AttributeValue){
		"missing owner":    func(m map[string]dtypes.AttributeValue) { delete(m, attrOwner) },
		"owner not string": func(m map[string]dtypes.AttributeValue) { m[attrOwner] = num(1) },
		"size not number":  func(m map[string]dtypes.AttributeValue) { m[attrSize] = str("x") },
		"bad number":       func(m map[string]dtypes.AttributeValue) { m[attrSize] = &dtypes.AttributeValueMemberN{Value: "1.5"} },
		"missing expiry":   func(m map[string]dtypes.AttributeValue) { delete(m, attrExpires) },
		"hash not binary":  func(m map[string]dtypes.AttributeValue) { m[attrSHA256] = str("x") },
		"parts not list":   func(m map[string]dtypes.AttributeValue) { m[attrParts] = str("x") },
		"part not map": func(m map[string]dtypes.AttributeValue) {
			m[attrParts] = &dtypes.AttributeValueMemberL{Value: []dtypes.AttributeValue{str("x")}}
		},
		"part without etag": func(m map[string]dtypes.AttributeValue) {
			m[attrParts] = &dtypes.AttributeValueMemberL{Value: []dtypes.AttributeValue{&dtypes.AttributeValueMemberM{Value: map[string]dtypes.AttributeValue{"n": num(1)}}}}
		},
		"thumbnail without size": func(m map[string]dtypes.AttributeValue) { m[attrThumbType] = str("image/png") },
	} {
		item := encodeRecord(storetest.Record("id", "o", "t"))
		change(item)
		if _, err := decodeRecord(item); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

func TestTIDItemPointingElsewhereIsAnError(t *testing.T) {
	s, _, ddb := fakeStores(t)
	ctx := t.Context()
	if _, err := s.Metadata.Create(ctx, storetest.Record("id-1", "alice", "tid")); err != nil {
		t.Fatal(err)
	}
	ddb.rows[tidKey("bob", "tid")] = map[string]dtypes.AttributeValue{attrPK: str(tidKey("bob", "tid")), attrID: str("id-1")}
	if _, err := s.Metadata.GetByTID(ctx, "bob", "tid"); err == nil {
		t.Fatal("bob's tid item led to alice's record")
	}
	ddb.rows[tidKey("carol", "tid")] = map[string]dtypes.AttributeValue{attrPK: str(tidKey("carol", "tid"))}
	if _, err := s.Metadata.GetByTID(ctx, "carol", "tid"); err == nil {
		t.Fatal("a tid item without an id was followed")
	}
}

func TestNewBuildsClientsWithLocalEndpoints(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")
	s, err := New(t.Context(), Config{Bucket: "b", Table: "t", SSE: "AES256", S3Endpoint: "http://127.0.0.1:1", DynamoDBEndpoint: "http://127.0.0.1:1"})
	if err != nil || s.Blobs == nil || s.Metadata == nil || s.NonceCounts == nil {
		t.Fatalf("New = %+v, %v", s, err)
	}
}

func TestSDKWarningsGoToTheServiceLog(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(prev)
	sdkLogger{}.Logf(logging.Debug, "noise %d", 1)
	sdkLogger{}.Logf(logging.Warn, "retry for %s", "sip:+15550100001@example.test")
	out := buf.String()
	if strings.Contains(out, "noise") || !strings.Contains(out, "aws sdk warning") || strings.Contains(out, "15550100001") {
		t.Fatalf("log = %s", out)
	}
}
