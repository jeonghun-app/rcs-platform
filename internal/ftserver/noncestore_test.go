package ftserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/awsstore"
	secretkey "github.com/jeonghun-app/rcs-platform/internal/secret"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// faultyTable is a DynamoDB that throttles every read, or one whose every
// conditional write loses to another request.
type faultyTable struct {
	awsstore.DynamoAPI
	throttle bool
}

func (f faultyTable) GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	if f.throttle {
		return nil, &smithy.GenericAPIError{Code: "ProvisionedThroughputExceededException", Message: "throttled"}
	}
	return &dynamodb.GetItemOutput{}, nil
}

func (f faultyTable) UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	return nil, &types.ConditionalCheckFailedException{}
}

// badItemTable is a DynamoDB whose first nonce-count item read is
// malformed for good; every other item is empty and every write lands.
type badItemTable struct {
	awsstore.DynamoAPI
	mu  sync.Mutex
	bad string
}

func (f *badItemTable) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	pk := in.Key["pk"].(*types.AttributeValueMemberS).Value
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bad == "" {
		f.bad = pk
	}
	if pk == f.bad {
		return &dynamodb.GetItemOutput{Item: map[string]types.AttributeValue{"nc": &types.AttributeValueMemberS{Value: "x"}}}, nil
	}
	return &dynamodb.GetItemOutput{}, nil
}

func (f *badItemTable) UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	return &dynamodb.UpdateItemOutput{}, nil
}

// namingCounts is a nonce-count store whose error names the user, as one
// that does not sanitise its errors might.
type namingCounts struct{}

func (namingCounts) Advance(_ context.Context, username, _ string, _ uint32, _ time.Time) (bool, error) {
	return false, errors.New("cannot reach the table for sip:" + username)
}

// withNonceCounts makes o's digest server keep its nonce-counts in counts.
func withNonceCounts(t *testing.T, counts func(o *Options) digest.NonceCountStore) func(*Options) {
	return func(o *Options) {
		ds, err := digest.NewServer(digest.ServerConfig{
			Realm: realm, NonceKey: secretkey.NewKey(bytes.Repeat([]byte("k"), 32)),
			NonceCounts: counts(o), Now: o.Now, Random: &seeded{r: rand.NewChaCha8([32]byte{1})},
			HTTPPathOnlyURI: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		o.Digest = ds
	}
}

// overTable keeps nonce-counts in the real awsstore over table.
func overTable(table awsstore.DynamoAPI) func(o *Options) digest.NonceCountStore {
	return func(o *Options) digest.NonceCountStore {
		return awsstore.NewWithClients(awsstore.Config{Table: "files", Now: o.Now}, nil, table).NonceCounts
	}
}

// uploadRequest is a small upload, sent under credentials.
func uploadRequest() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/ft", strings.NewReader(multipartBody(tidPart("t"), filePart("a.bin", "text/plain", "x"))))
	r.Header.Set("Content-Type", formType)
	return r
}

func TestANonceCountStoreFailureIsServiceUnavailable(t *testing.T) {
	// #621: the response was right, so the client gets 503, which it
	// retries, not a second 401, which it gives up on; operators see a
	// backend error, not an auth failure.
	for name, counts := range map[string]func(o *Options) digest.NonceCountStore{
		"throttled":   overTable(faultyTable{throttle: true}),
		"contended":   overTable(faultyTable{}),
		"unsanitised": func(*Options) digest.NonceCountStore { return namingCounts{} },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, withNonceCounts(t, counts))
			rec := e.do(e.user(alice).sign(uploadRequest()))
			if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
				t.Fatalf("upload with the store failing = %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
			}
			if rec.Header().Get("WWW-Authenticate") != "" {
				t.Fatal("a store failure was answered with a challenge")
			}
			for metric, want := range map[string]float64{"auth.backend_error": 1, "auth.failed": 0, "upload.failed.auth": 0} {
				if got := e.metric(metric); got != want {
					t.Errorf("%s = %v, want %v", metric, got, want)
				}
			}
			if n := len(e.h.Logs("nonce count store failed")); n != 1 {
				t.Errorf("%d log lines for the store failure, want 1", n)
			}
			if strings.Contains(e.h.Output(), "001010000000001") {
				t.Error("the user name reached the log")
			}
		})
	}
}

// namingUnusableCounts keeps counts in memory, but its record of the first
// nonce it sees is unusable, and says so naming the user.
type namingUnusableCounts struct {
	*digest.MemoryNonceCounts
	mu  sync.Mutex
	bad string
}

func (c *namingUnusableCounts) Advance(ctx context.Context, username, nonce string, nc uint32, expires time.Time) (bool, error) {
	c.mu.Lock()
	if c.bad == "" {
		c.bad = nonce
	}
	bad := c.bad == nonce
	c.mu.Unlock()
	if bad {
		return false, fmt.Errorf("%w: item of sip:%s is malformed", digest.ErrNonceCountUnusable, username)
	}
	return c.MemoryNonceCounts.Advance(ctx, username, nonce, nc, expires)
}

func TestAnUnusableNonceCountRecordGetsANewNonceAtOnce(t *testing.T) {
	// #621, QA on the first version: the record stays bad until the nonce
	// expires, so a 503 brought the client back to it for five minutes. A
	// stale challenge sends it to a new nonce, as before #621, without
	// being counted as an auth failure. It is counted apart from expired
	// nonces, so that FtAuthBackendError sees a table whose records cannot
	// be read, after a rollback say (#641).
	for name, counts := range map[string]func(o *Options) digest.NonceCountStore{
		"malformed item": overTable(&badItemTable{}),
		"unsanitised": func(o *Options) digest.NonceCountStore {
			return &namingUnusableCounts{MemoryNonceCounts: digest.NewMemoryNonceCounts(o.Now)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, withNonceCounts(t, counts))
			u := e.user(alice)
			rec := e.do(u.sign(uploadRequest()))
			if rec.Code != http.StatusUnauthorized || rec.Header().Get("Retry-After") != "" {
				t.Fatalf("upload over an unusable record = %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
			}
			for _, v := range rec.Header().Values("WWW-Authenticate") {
				if ch, err := digest.ParseChallenge(v); err != nil || !ch.Stale {
					t.Fatalf("challenge %q is not stale", v)
				}
			}
			u.takeChallenge(rec.Header())
			if rec := e.do(u.sign(uploadRequest())); rec.Code != http.StatusOK {
				t.Fatalf("upload with the new nonce = %d", rec.Code)
			}
			for metric, want := range map[string]float64{"auth.nonce_count_unusable": 1, "auth.stale": 0, "auth.backend_error": 0, "auth.failed": 0} {
				if got := e.metric(metric); got != want {
					t.Errorf("%s = %v, want %v", metric, got, want)
				}
			}
			logs := e.h.Logs("nonce count record unusable")
			if n := len(logs); n != 1 {
				t.Errorf("%d log lines for the unusable record, want 1", n)
			}
			for _, l := range logs {
				if msg, _ := l["error"].(string); !strings.HasPrefix(msg, digest.ErrNonceCountUnusable.Error()) || strings.Contains(msg, "expired") {
					t.Errorf("the unusable record logged as %q", msg)
				}
			}
			if n := len(e.h.Logs("nonce count store failed")); n != 0 {
				t.Errorf("an unusable record logged as a store failure %d times", n)
			}
			if strings.Contains(e.h.Output(), "001010000000001") {
				t.Error("the user name reached the log")
			}
		})
	}
}
