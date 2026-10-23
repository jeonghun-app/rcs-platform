package ftserver

import (
	"bytes"
	"context"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func TestANonceCountStoreFailureIsServiceUnavailable(t *testing.T) {
	// #621: the response was right, so the client gets 503, which it
	// retries, not a second 401, which it gives up on; operators see a
	// backend error, not an auth failure.
	for name, throttle := range map[string]bool{"throttled": true, "contended": false} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, func(o *Options) {
				counts := awsstore.NewWithClients(awsstore.Config{Table: "files", Now: o.Now}, nil, faultyTable{throttle: throttle}).NonceCounts
				ds, err := digest.NewServer(digest.ServerConfig{
					Realm: realm, NonceKey: secretkey.NewKey(bytes.Repeat([]byte("k"), 32)),
					NonceCounts: counts, Now: o.Now, Random: &seeded{r: rand.NewChaCha8([32]byte{1})},
					HTTPPathOnlyURI: true,
				})
				if err != nil {
					t.Fatal(err)
				}
				o.Digest = ds
			})
			u := e.user(alice)
			r := httptest.NewRequest(http.MethodPost, "/ft", strings.NewReader(multipartBody(tidPart("t"), filePart("a.bin", "text/plain", "x"))))
			r.Header.Set("Content-Type", formType)
			rec := e.do(u.sign(r))
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
		})
	}
}
