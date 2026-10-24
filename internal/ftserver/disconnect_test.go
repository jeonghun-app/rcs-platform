package ftserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
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
			// As Run builds it, with the update's own timeout far off: the
			// hang-up comes first.
			return func(o *Options) {
				ds, err := newDigest(Config{Realm: realm, HSSTimeout: time.Minute}, bytes.Repeat([]byte("k"), 32),
					awsstore.NewWithClients(awsstore.Config{Table: "files"}, nil, heldTable{held: held}).NonceCounts)
				if err != nil {
					t.Fatal(err)
				}
				o.Digest = ds
			}
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

// silentDynamo is a DynamoDB endpoint that takes connections and requests
// and never answers. It closes them when the test ends.
func silentDynamo(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go func() { _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	return "http://" + ln.Addr().String()
}

// deadlineTable is the real SDK client, recording how long the context of
// each read has left when the read starts.
type deadlineTable struct {
	*dynamodb.Client
	left chan<- time.Duration
}

func (d deadlineTable) GetItem(ctx context.Context, in *dynamodb.GetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	left := time.Duration(-1)
	if deadline, ok := ctx.Deadline(); ok {
		left = max(0, time.Until(deadline))
	}
	select {
	case d.left <- left:
	default:
	}
	return d.Client.GetItem(ctx, in, opts...)
}

func TestAStalledNonceCountStoreTimesOutAsABackendError(t *testing.T) {
	// #641 reviews: under the request's context alone, a DynamoDB that
	// does not answer held the request until the client gave up, and the
	// hang-up was counted in auth.interrupted, which does not page and
	// logs nothing. Under FT_HSS_TIMEOUT the update fails first, as a
	// backend error. The real SDK client, as the QA probe ran it.
	const timeout = 50 * time.Millisecond
	if DefaultHSSTimeout <= timeout {
		t.Fatalf("DefaultHSSTimeout %v is not above the %v this test uses", DefaultHSSTimeout, timeout)
	}
	left := make(chan time.Duration, 1)
	client := dynamodb.New(dynamodb.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(silentDynamo(t)),
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
		}),
	})
	e := newEnv(t, func(o *Options) {
		// As Run builds it, so that the setting is shown to reach the
		// store rather than a default (QA on #138).
		ds, err := newDigest(Config{Realm: realm, HSSTimeout: timeout}, bytes.Repeat([]byte("k"), 32),
			awsstore.NewWithClients(awsstore.Config{Table: "files"}, nil, deadlineTable{Client: client, left: left}).NonceCounts)
		if err != nil {
			t.Fatal(err)
		}
		o.Digest = ds
	})
	srv := e.serve()
	u := e.user(alice)
	u.challenge()
	r, err := http.NewRequest(http.MethodPost, srv.URL+"/ft", nil)
	if err != nil {
		t.Fatal(err)
	}
	// A client that waits 5 s, far beyond the timeout, then gives up.
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(u.sign(r))
	if err != nil {
		t.Fatalf("no answer before the client gave up: %v", err)
	}
	resp.Body.Close()
	// Set before the read, so it can only have shrunk on the way: more
	// than the setting left, or none, means another deadline.
	if got := <-left; got < 0 || got > timeout {
		t.Fatalf("the read had %v left on its context, want at most FT_HSS_TIMEOUT %v", got, timeout)
	}
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("upload = %d, Retry-After %q; want 503 with Retry-After", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	for metric, want := range map[string]float64{"auth.backend_error": 1, "auth.interrupted": 0} {
		if got := e.metric(metric); got != want {
			t.Errorf("%s = %v, want %v", metric, got, want)
		}
	}
	if n := len(e.h.Logs("nonce count store failed")); n != 1 {
		t.Errorf("%d warnings for the stalled store, want 1", n)
	}
}

// lateFailures fail a lookup or an update, with an error that is not a
// cancellation, only once the request's context has ended: an answer that
// came back as the client hung up. held says the call has started.
type lateFailures struct {
	held chan<- struct{}
	err  error
}

func (f lateFailures) wait(ctx context.Context) {
	f.held <- struct{}{}
	<-ctx.Done()
}

func (f lateFailures) Lookup(ctx context.Context, _ string, _ digest.Algorithm) (Credential, error) {
	f.wait(ctx)
	return Credential{}, f.err
}

func (f lateFailures) Advance(ctx context.Context, _, _ string, _ uint32, _ time.Time) (bool, error) {
	f.wait(ctx)
	return false, f.err
}

func TestABackendFailureAfterTheClientHungUpIsStillCounted(t *testing.T) {
	// #641 QA: a hang-up hides only the cancellation it causes. A failure
	// the backend reported meanwhile is still the backend's, or the
	// record's, and keeps its own count.
	for name, c := range map[string]struct {
		backend func(t *testing.T, f lateFailures) func(*Options)
		err     error
		metric  string
	}{
		"hss lookup fails": {
			backend: func(_ *testing.T, f lateFailures) func(*Options) { return func(o *Options) { o.Credentials = f } },
			err:     errors.New("ftserver: hss answered 500"), metric: "auth.backend_error",
		},
		"hss record unusable": {
			backend: func(_ *testing.T, f lateFailures) func(*Options) { return func(o *Options) { o.Credentials = f } },
			err:     fmt.Errorf("%w: hss response is not an ft-credential", ErrBadCredentialRecord), metric: "auth.bad_credential_record",
		},
		"nonce count fails": {
			backend: func(t *testing.T, f lateFailures) func(*Options) {
				return withNonceCounts(t, func(*Options) digest.NonceCountStore { return f })
			},
			err: errors.New("awsstore: advance nonce count: InternalServerError"), metric: "auth.backend_error",
		},
	} {
		t.Run(name, func(t *testing.T) {
			held := make(chan struct{}, 1)
			e := newEnv(t, c.backend(t, lateFailures{held: held, err: c.err}))
			u := e.user(alice)
			u.challenge()
			r, err := http.NewRequest(http.MethodPost, "http://ft/ft", nil)
			if err != nil {
				t.Fatal(err)
			}
			e.hangUp(u.sign(r), held)
			for metric, want := range map[string]float64{c.metric: 1, "auth.interrupted": 0} {
				if got := e.metric(metric); got != want {
					t.Errorf("%s = %v, want %v", metric, got, want)
				}
			}
		})
	}
}
