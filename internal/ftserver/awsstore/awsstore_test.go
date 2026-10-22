package awsstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go/logging"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store/storetest"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
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

func TestNonceCountsAcceptEachCountOnceInsideTheWindow(t *testing.T) {
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
		{"alice", "n1", 2, true}, // late, inside the window
		{"alice", "n1", 2, false},
		{"bob", "n1", 1, true},
		{"alice", "n2", 1, true},
		{"alice", "n1", 4 + digest.NonceCountWindow, true},
		{"alice", "n1", 4, false}, // never used, but below the window
		{"alice", "n1", 5, true},  // the lowest count inside it
		{"alice", "n1", 5, false},
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

func TestNonceCountsAcceptEachCountOnceUnderConcurrency(t *testing.T) {
	// maxNonceCountAttempts requests in flight on one nonce, each sent
	// twice: every count is accepted exactly once, and none runs out of
	// attempts, since each lost race is a win for another count.
	s, _, _ := fakeStores(t)
	var accepted [maxNonceCountAttempts + 1]atomic.Int32
	var wg sync.WaitGroup
	for nc := uint32(1); nc <= maxNonceCountAttempts; nc++ {
		for range 2 {
			wg.Go(func() {
				ok, err := s.NonceCounts.Advance(context.Background(), "alice", "n", nc, storetest.T0.Add(time.Minute))
				if err != nil {
					t.Errorf("Advance(%d): %v", nc, err)
				}
				if ok {
					accepted[nc].Add(1)
				}
			})
		}
	}
	wg.Wait()
	for nc := 1; nc <= maxNonceCountAttempts; nc++ {
		if got := accepted[nc].Load(); got != 1 {
			t.Errorf("nc %d accepted %d times", nc, got)
		}
	}
}

// racingDynamo records another count with the same nonce, through other,
// before each of the next races updates reaches the table, as a request
// verified on another task at that moment would.
type racingDynamo struct {
	*fakeDynamo
	other *NonceCounts
	races int
	nc    uint32
}

func (r *racingDynamo) UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	if r.races > 0 {
		r.races--
		r.nc++
		if ok, err := r.other.Advance(ctx, "alice", "n", r.nc, storetest.T0.Add(time.Minute)); !ok || err != nil {
			r.t.Fatalf("the racing Advance(%d) = %v, %v", r.nc, ok, err)
		}
	}
	return r.fakeDynamo.UpdateItem(ctx, in, opts...)
}

func TestNonceCountsReadAgainAfterLosingARace(t *testing.T) {
	s, _, ddb := fakeStores(t)
	racing := &racingDynamo{fakeDynamo: ddb, other: s.NonceCounts, races: 3, nc: 100}
	var waits []time.Duration
	contended := 0
	n := &NonceCounts{api: racing, table: s.NonceCounts.table, now: s.NonceCounts.now,
		contended: func() { contended++ },
		sleep:     func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }}
	ctx := t.Context()
	exp := storetest.T0.Add(time.Minute)
	if ok, err := n.Advance(ctx, "alice", "n", 90, exp); !ok || err != nil {
		t.Fatalf("Advance after losing 3 races = %v, %v", ok, err)
	}
	// A random wait before each read after a lost write, below a bound
	// that doubles; each lost write counted.
	if len(waits) != 3 || contended != 3 {
		t.Fatalf("waits %v, contended %d; want 3 of each", waits, contended)
	}
	for i, d := range waits {
		if limit := nonceBackoffBase << i; d < 0 || d >= limit {
			t.Fatalf("wait %d is %v, want below %v", i, d, limit)
		}
	}
	// The window the winners and this request left: 101-103 and 90 used.
	for _, nc := range []uint32{90, 101, 103} {
		if ok, err := s.NonceCounts.Advance(ctx, "alice", "n", nc, exp); ok || err != nil {
			t.Fatalf("nc %d again = %v, %v", nc, ok, err)
		}
	}
	if ok, err := s.NonceCounts.Advance(ctx, "alice", "n", 91, exp); !ok || err != nil {
		t.Fatalf("unused nc 91 = %v, %v", ok, err)
	}

	// Losing every attempt is an error, not a replay: the count is unused.
	racing.races = maxNonceCountAttempts
	waits = nil
	if ok, err := n.Advance(ctx, "alice", "n", 92, exp); ok || !errors.Is(err, errNonceCountContended) {
		t.Fatalf("Advance losing every race = %v, %v", ok, err)
	}
	// Random: 15 waits all of zero would mean no backoff at all.
	if len(waits) != maxNonceCountAttempts-1 || slices.Max(waits) >= nonceBackoffMax || slices.Max(waits) == 0 {
		t.Fatalf("waits %v", waits)
	}
	if ok, err := n.Advance(ctx, "alice", "n", 92, exp); !ok || err != nil {
		t.Fatalf("nc 92 once the races stop = %v, %v", ok, err)
	}
}

// resendingDynamo applies each update and then sends it again, as the SDK
// does when the answer to a write that landed is lost, and answers with the
// second outcome.
type resendingDynamo struct{ *fakeDynamo }

func (r resendingDynamo) UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	_, _ = r.fakeDynamo.UpdateItem(ctx, in, opts...)
	return r.fakeDynamo.UpdateItem(ctx, in, opts...)
}

func TestNonceCountResentAfterItLandedIsAccepted(t *testing.T) {
	s, _, ddb := fakeStores(t)
	resent := &NonceCounts{api: resendingDynamo{ddb}, table: s.NonceCounts.table, now: s.NonceCounts.now}
	ctx := t.Context()
	exp := storetest.T0.Add(time.Minute)
	if ok, err := resent.Advance(ctx, "alice", "n", 3, exp); !ok || err != nil {
		t.Fatalf("Advance whose write was resent = %v, %v; want the count it recorded", ok, err)
	}
	// The count is recorded: another request with it is a replay, resent
	// or not.
	for _, n := range []*NonceCounts{s.NonceCounts, resent} {
		if ok, err := n.Advance(ctx, "alice", "n", 3, exp); ok || err != nil {
			t.Fatalf("nc 3 again = %v, %v", ok, err)
		}
	}
	if ok, err := resent.Advance(ctx, "alice", "n", 2, exp); !ok || err != nil {
		t.Fatalf("nc 2 = %v, %v", ok, err)
	}
}

func TestNonceCountResentBySDKAfterItLandedIsAccepted(t *testing.T) {
	// Over the SDK: the first UpdateItem lands but answers 500, the resend
	// fails its condition and gets back the item the first one wrote.
	var mu sync.Mutex
	var item map[string]any
	updates := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var in struct {
			ExpressionAttributeValues           map[string]map[string]string
			ReturnValuesOnConditionCheckFailure string
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		switch r.Header.Get("X-Amz-Target") {
		case "DynamoDB_20120810.GetItem":
			_, _ = io.WriteString(w, `{}`)
		case "DynamoDB_20120810.UpdateItem":
			updates++
			if updates == 1 {
				v := in.ExpressionAttributeValues
				item = map[string]any{"pk": map[string]string{"S": "n"}, "nc": v[":nc"], "nc_window": v[":w"],
					"nc_window_at": v[":nc"], "expires": v[":e"], "ttl": v[":ttl"], "nc_writer": v[":by"]}
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = io.WriteString(w, `{"__type":"com.amazonaws.dynamodb.v20120810#InternalServerError","message":"lost"}`)
				return
			}
			body := map[string]any{"__type": "com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException", "message": "The conditional request failed"}
			if in.ReturnValuesOnConditionCheckFailure == "ALL_OLD" {
				body["Item"] = item
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(body)
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"__type":"com.amazonaws.dynamodb.v20120810#ValidationException","message":"unexpected"}`)
		}
	}))
	defer srv.Close()
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "local")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "local")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	stores, err := New(t.Context(), Config{Table: "files", DynamoDBEndpoint: srv.URL, Now: func() time.Time { return storetest.T0 }})
	if err != nil {
		t.Fatal(err)
	}
	ok, err := stores.NonceCounts.Advance(t.Context(), "alice", "n", 1, storetest.T0.Add(time.Minute))
	if !ok || err != nil {
		t.Fatalf("Advance = %v, %v; want the count that landed", ok, err)
	}
	if updates != 2 {
		t.Fatalf("%d UpdateItem calls, want the original and one resend", updates)
	}
}

func TestNonceCountsWrittenByThePreviousVersionCountAsUsedUpToTheirHighest(t *testing.T) {
	// The version before #66 stores only nc and advances it alone; the
	// window is trusted only where it was written for the nc stored.
	s, _, ddb := fakeStores(t)
	ctx := t.Context()
	exp := storetest.T0.Add(time.Minute)
	advance := func(nonce string, nc uint32, want bool) {
		t.Helper()
		if ok, err := s.NonceCounts.Advance(ctx, "alice", nonce, nc, exp); ok != want || err != nil {
			t.Fatalf("Advance(%s, %d) = %v, %v; want %v", nonce, nc, ok, err, want)
		}
	}
	old := nonceKey("alice", "old")
	ddb.rows[old] = map[string]dtypes.AttributeValue{
		attrPK: str(old), attrNC: num(5), attrExpires: num(exp.UnixMilli()), attrTTL: num(exp.Add(time.Hour).Unix()),
	}
	advance("old", 4, false)
	advance("old", 6, true)
	advance("old", 3, false)

	advance("mixed", 10, true)
	advance("mixed", 8, true)
	// The previous version accepts 12 and moves nc, not the window.
	ddb.rows[nonceKey("alice", "mixed")][attrNC] = num(12)
	advance("mixed", 9, false)
	advance("mixed", 11, false)
	advance("mixed", 13, true)

	// Nor is a window without the highest count's bit, which no version
	// writes.
	odd := nonceKey("alice", "odd")
	ddb.rows[odd] = map[string]dtypes.AttributeValue{
		attrPK: str(odd), attrNC: num(5), attrNCWindow: num(0), attrNCWindowAt: num(5),
		attrExpires: num(exp.UnixMilli()), attrTTL: num(exp.Add(time.Hour).Unix()),
	}
	advance("odd", 5, false)
	advance("odd", 4, false)
}

func TestMalformedNonceCountItemIsAnError(t *testing.T) {
	s, _, ddb := fakeStores(t)
	k := nonceKey("alice", "n")
	exp := storetest.T0.Add(time.Minute)
	for name, item := range map[string]map[string]dtypes.AttributeValue{
		"no expiry":       {attrPK: str(k), attrNC: num(1)},
		"no count":        {attrPK: str(k), attrExpires: num(exp.UnixMilli())},
		"count too large": {attrPK: str(k), attrNC: num(1 << 32), attrExpires: num(exp.UnixMilli())},
		"negative window": {attrPK: str(k), attrNC: num(1), attrNCWindow: num(-1), attrNCWindowAt: num(1), attrExpires: num(exp.UnixMilli())},
		"string count":    {attrPK: str(k), attrNC: str("1"), attrExpires: num(exp.UnixMilli())},
	} {
		ddb.rows[k] = item
		if ok, err := s.NonceCounts.Advance(t.Context(), "alice", "n", 2, exp); ok || err == nil {
			t.Errorf("%s: Advance = %v, %v", name, ok, err)
		}
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
