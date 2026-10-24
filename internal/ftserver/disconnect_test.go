package ftserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/smithy-go"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/awsstore"
	secretkey "github.com/jeonghun-app/rcs-platform/internal/secret"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// hangUp sends r to e over a real HTTP server on a connection of its own,
// closes the connection once held says the request has reached the backend,
// and returns once the handler has returned. r has no body: only then does
// net/http watch the connection while the handler runs, and cancel the
// request's context when it closes.
func (e *env) hangUp(r *http.Request, held <-chan struct{}) {
	e.t.Helper()
	served := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { served <- struct{}{} }()
		e.srv.ServeHTTP(w, r)
	}))
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		e.t.Fatal(err)
	}
	defer conn.Close()
	if err := r.Write(conn); err != nil {
		e.t.Fatal(err)
	}
	select {
	case <-held:
	case <-time.After(backstop):
		e.t.Fatalf("the request did not reach the backend within %v", backstop)
	}
	conn.Close()
	select {
	case <-served:
	case <-time.After(backstop):
		e.t.Fatalf("the handler did not return within %v of the client hanging up", backstop)
	}
}

// heldHSS takes each credential request and holds it until the ft-server
// side gives up on it, sending on held when one arrives.
func heldHSS(t *testing.T, held chan<- struct{}) *hss {
	release := make(chan struct{})
	h := newHSS(t, func(_ http.ResponseWriter, r *http.Request) {
		held <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	// Runs before newHSS's own cleanup, so that the server never waits
	// for a held handler.
	t.Cleanup(func() { close(release) })
	return h
}

// heldTable is a DynamoDB whose every read is held until the caller's
// context ends, answering then as the SDK does. It sends on held when a
// read arrives.
type heldTable struct {
	awsstore.DynamoAPI
	held chan<- struct{}
}

func (f heldTable) GetItem(ctx context.Context, _ *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.held <- struct{}{}
	<-ctx.Done()
	return nil, &smithy.OperationError{ServiceID: "DynamoDB", OperationName: "GetItem", Err: &smithy.CanceledError{Err: ctx.Err()}}
}

func TestAClientThatHangsUpIsNotABackendError(t *testing.T) {
	// #641: a client that went away while the HSS or the nonce-count
	// store worked for it is no sign that either fails, and must not
	// page through FtAuthBackendError.
	for name, backend := range map[string]func(t *testing.T, held chan struct{}) func(*Options){
		"hss lookup": func(t *testing.T, held chan struct{}) func(*Options) {
			return func(o *Options) {
				o.Credentials = NewHSSCredentials(mustURL(heldHSS(t, held).URL), secretkey.NewString("t"), realm, lookupTimeout, 4, nil)
			}
		},
		"nonce count": func(t *testing.T, held chan struct{}) func(*Options) {
			return withNonceCounts(t, overTable(heldTable{held: held}))
		},
	} {
		t.Run(name, func(t *testing.T) {
			held := make(chan struct{}, 1)
			e := newEnv(t, backend(t, held))
			u := e.user(alice)
			u.challenge()
			r, err := http.NewRequest(http.MethodPost, "http://ft/ft", nil)
			if err != nil {
				t.Fatal(err)
			}
			e.hangUp(u.sign(r), held)
			for metric, want := range map[string]float64{"auth.backend_error": 0, "auth.interrupted": 1, "auth.failed": 0} {
				if got := e.metric(metric); got != want {
					t.Errorf("%s = %v, want %v", metric, got, want)
				}
			}
			for _, msg := range []string{"credential lookup failed", "nonce count store failed"} {
				if n := len(e.h.Logs(msg)); n != 0 {
					t.Errorf("%d warnings %q for a client that hung up", n, msg)
				}
			}
		})
	}
}

// cancelledSource fails every lookup with a cancellation of its own, as a
// backend client that gave up for its own reasons might.
type cancelledSource struct{}

func (cancelledSource) Lookup(context.Context, string, digest.Algorithm) (Credential, error) {
	return Credential{}, fmt.Errorf("ftserver: hss: %w", context.Canceled)
}

// cancelledCounts fails every update with a cancellation of its own.
type cancelledCounts struct{}

func (cancelledCounts) Advance(context.Context, string, string, uint32, time.Time) (bool, error) {
	return false, errors.Join(errors.New("table"), context.Canceled)
}

func TestACancellationThatIsNotTheRequestsIsABackendError(t *testing.T) {
	// #641: only the request's own context tells that the client went;
	// a backend that reports a cancellation while the request still runs
	// has failed.
	for name, backend := range map[string]func(t *testing.T) func(*Options){
		"hss lookup": func(*testing.T) func(*Options) {
			return func(o *Options) { o.Credentials = cancelledSource{} }
		},
		"nonce count": func(t *testing.T) func(*Options) {
			return withNonceCounts(t, func(*Options) digest.NonceCountStore { return cancelledCounts{} })
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, backend(t))
			rec := e.do(e.user(alice).sign(httptest.NewRequest(http.MethodPost, "/ft", nil)))
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503", rec.Code)
			}
			for metric, want := range map[string]float64{"auth.backend_error": 1, "auth.interrupted": 0} {
				if got := e.metric(metric); got != want {
					t.Errorf("%s = %v, want %v", metric, got, want)
				}
			}
			if strings.Contains(e.h.Output(), "001010000000001") {
				t.Error("the user name reached the log")
			}
		})
	}
}
