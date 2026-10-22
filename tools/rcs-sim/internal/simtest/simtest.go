// Package simtest starts the services the simulator talks to inside a test
// process: ft-server on memory stores and msrp-relay on its memory store,
// both on loopback, so the simulator's packages are tested against the real
// service code without containers. make e2e runs the built binaries
// instead (tools/rcs-sim/e2e).
package simtest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver"
	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// The test identities: an IMPI in the MCC 001 test network (on
// .github/allowed-test-identifiers.txt) and a password made up here.
const (
	FTUser     = "001010000000001@ims.mnc001.mcc001.3gppnetwork.org"
	FTPassword = "sim-test-password"
	FTRealm    = "ft.ims.mnc001.mcc001.3gppnetwork.org"
	// RelayToken is pcscf's control token in tests: 43 characters, the
	// shortest production accepts.
	RelayToken = "simtest-relay-token-0123456789-0123456789ab"
)

// FT is an ft-server in the test process.
type FT struct {
	UploadURL *url.URL
	Server    *httptest.Server
	// Harness holds ft-server's log and metric lines.
	Harness *runtimetest.Harness

	// inFlight is how many requests ft-server is still handling, and
	// brokenDelay how long a request body's read error is held back.
	inFlight    atomic.Int64
	brokenDelay atomic.Int64
}

// SetBrokenUploadDelay makes ft-server notice a broken upload d late: the
// read that fails returns only after d, with the parts read so far stored
// and the upload still leased. A loaded host does the same (#176).
func (f *FT) SetBrokenUploadDelay(d time.Duration) { f.brokenDelay.Store(int64(d)) }

// lateError is a request body whose read errors come late; see
// SetBrokenUploadDelay.
type lateError struct {
	io.ReadCloser
	delay time.Duration
}

func (l lateError) Read(p []byte) (int, error) {
	n, err := l.ReadCloser.Read(p)
	if err != nil && err != io.EOF {
		time.Sleep(l.delay)
	}
	return n, err
}

// StartFT starts ft-server with memory stores and parts of partSize, so a
// resume test needs a file of only a few parts.
func StartFT(t testing.TB, partSize int64) *FT {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	upload, _ := url.Parse(base + "/ft")
	download, _ := url.Parse(base + "/dl")
	h := runtimetest.New(t, "ft-server")
	ds, err := digest.NewServer(digest.ServerConfig{
		Realm: FTRealm, NonceKey: secret.NewKey(bytes.Repeat([]byte("k"), digest.MinNonceKeySize)),
		NonceCounts: digest.NewMemoryNonceCounts(nil), HTTPPathOnlyURI: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := ftserver.New(ftserver.Options{
		UploadURI: upload, DownloadURI: download, Digest: ds,
		Credentials: ftserver.NewStaticCredentials(map[string]string{FTUser: FTPassword}),
		Metadata:    store.NewMemory(), Blobs: store.NewMemoryBlobs(partSize),
		Logger: h.Runtime.Logger, Metrics: h.Runtime.Metrics,
		MaxSize: 64 * partSize, MaxThumbnailSize: partSize, PartSize: partSize,
		Validity: time.Hour, UploadsPerMinute: 1000,
		MaxConcurrentUploads: 16, MaxUploadsPerUser: 16, MaxConcurrentDownloads: 16, MaxConcurrentLookups: 16,
		MaxDownloadsPerFile: 16, MaxDownloadsPerUploader: 16,
		IdleTimeout: 10 * time.Second, UploadTimeout: time.Minute, StorageTimeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &FT{UploadURL: upload, Harness: h}
	// A get_upload_info is answered only once ft-server is done with every
	// request before it, the broken upload above all: its parts stored and
	// its lease released. A device asks seconds after the break, once it is
	// back on a network, and a deployed server is done by then; a test asks
	// at once, and a server still storing could answer the same bytes for
	// the whole quiet time and then refuse the resume 503 (#176). The
	// request's context bounds the wait.
	counted := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "get_upload_info") {
			for f.inFlight.Load() > 0 {
				select {
				case <-r.Context().Done():
					return
				case <-time.After(5 * time.Millisecond):
				}
			}
		}
		f.inFlight.Add(1)
		defer f.inFlight.Add(-1)
		if d := time.Duration(f.brokenDelay.Load()); d > 0 && r.Body != nil {
			r.Body = lateError{r.Body, d}
		}
		srv.ServeHTTP(w, r)
	})
	f.Server = &httptest.Server{Listener: ln, Config: &http.Server{Handler: counted, ErrorLog: runtime.HTTPErrorLog(slog.Default())}}
	f.Server.Start()
	t.Cleanup(f.Server.Close)
	return f
}

// Relay is an msrp-relay in the test process.
type Relay struct {
	Control *url.URL
	Harness *runtimetest.Harness
	// TLSRoots trusts the certificate of the TLS terminator in front of a
	// relay from StartRelayBehindTLS; nil otherwise.
	TLSRoots *x509.CertPool
}

// StartRelay starts msrp-relay with its memory store, a plain public
// listener on loopback (no NLB, so no PROXY header and no TLS), and the
// core side limited to loopback and corePorts. It is configured through
// msrprelay.Configure from the environment it would get in a test stack.
//
// The relay must be told its ports before it listens, so they come from
// FreePorts, which gives two different ones. Something can still take one
// before the relay listens on it. Then the relay stops at once, and
// StartRelay tries again with fresh ports, up to three times.
func StartRelay(t testing.TB, corePorts ...int) *Relay {
	t.Helper()
	return startRelayRetrying(t, corePorts, nil)
}

// StartRelayBehindTLS is StartRelay with a TLS terminator in front of the
// relay's public listener, as the NLB is in AWS (ADR 0003): client_path is
// msrps: on the terminator's port, and the relay listens plain behind it.
// Clients trust Relay.TLSRoots.
func StartRelayBehindTLS(t testing.TB, corePorts ...int) *Relay {
	t.Helper()
	ts := httptest.NewTLSServer(http.NotFoundHandler()) // only for its certificate
	t.Cleanup(ts.Close)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", ts.TLS.Clone())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	front := &tlsFront{ln: ln}
	r := startRelayRetrying(t, corePorts, front)
	r.TLSRoots = ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	go front.serve()
	return r
}

// tlsFront is a TLS terminator: it takes TLS on ln and copies each
// connection, in the clear, to the relay's public listener.
type tlsFront struct {
	ln     net.Listener
	public int
}

func (f *tlsFront) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *tlsFront) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			b, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(f.public))
			if err != nil {
				return
			}
			defer b.Close()
			go func() { _, _ = io.Copy(b, c); _ = b.(*net.TCPConn).CloseWrite() }()
			_, _ = io.Copy(c, b)
		}()
	}
}

// startRelayRetrying starts the relay, trying again with fresh ports, up to
// three times, when it stopped because one was taken.
func startRelayRetrying(t testing.TB, corePorts []int, front *tlsFront) *Relay {
	t.Helper()
	for attempt := 1; ; attempt++ {
		ports := freePorts(t, 2)
		r, err := startRelay(t, ports[0], ports[1], corePorts, front)
		switch {
		case err == nil:
			return r
		case !errors.Is(err, syscall.EADDRINUSE) || attempt == 3:
			t.Fatalf("msrp-relay stopped: %v", err)
		}
	}
}

// startRelay starts the relay on the given ports and waits until it is
// ready. With front, client_path names the terminator's msrps: port, and
// the terminator forwards to public. If the relay stops first, it returns
// the error the relay stopped with; the relay's cleanup does not wait for
// it a second time.
func startRelay(t testing.TB, public, control int, corePorts []int, front *tlsFront) (*Relay, error) {
	t.Helper()
	advertised, secure := public, "false"
	if front != nil {
		front.public = public
		advertised, secure = front.port(), "true"
	}
	ports := make([]string, len(corePorts))
	for i, p := range corePorts {
		ports[i] = strconv.Itoa(p)
	}
	env := map[string]string{
		"RCS_ENV":                  "test",
		"RELAY_LISTEN_ADDR":        "127.0.0.1:" + strconv.Itoa(public),
		"RELAY_CONTROL_ADDR":       "127.0.0.1:" + strconv.Itoa(control),
		"RELAY_PUBLIC_HOST":        "127.0.0.1",
		"RELAY_PUBLIC_PORT":        strconv.Itoa(advertised),
		"RELAY_PUBLIC_TLS":         secure,
		"RELAY_CORE_HOST":          "127.0.0.1",
		"RELAY_CORE_NETWORKS":      "127.0.0.0/8",
		"RELAY_CORE_PORTS":         strings.Join(ports, ","),
		"RELAY_STORE":              "memory",
		"RELAY_PCSCF_TOKEN":        RelayToken,
		"RELAY_KEEPALIVE_INTERVAL": "10s",
		"RELAY_IDLE_TIMEOUT":       "60s",
		// chat-core-originated sends the PATCH 300 ms after the client
		// connects, and checks that the relay waits for it, not for how
		// long. On a loaded host those 300 ms have taken over 2 s, the
		// default wait (#204).
		"RELAY_PATH_WAIT": "10s",
	}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	shared := runtime.NewEnv("RCS_", lookup)
	cfg := msrprelay.Configure(&runtime.Settings{Env: shared.WithPrefix("RELAY_"), Shared: shared, Environment: runtime.Test})
	if err := shared.Err(); err != nil {
		t.Fatal(err)
	}
	h := runtimetest.New(t, "msrp-relay")
	ctx, cancel := context.WithCancel(context.Background())
	// Closed when Run returns, with runErr set: both the wait for
	// readiness and the cleanup can see it. A channel holding the one
	// value let the readiness wait take it, and the cleanup then waited
	// for ever (#107).
	stopped := make(chan struct{})
	var runErr error
	go func() {
		runErr = msrprelay.Run(ctx, h.Runtime, cfg)
		close(stopped)
	}()
	t.Cleanup(func() {
		cancel()
		<-stopped
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		if code, _ := h.Get("/readyz"); code == http.StatusOK {
			break
		}
		select {
		case <-stopped:
			return nil, runErr
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("msrp-relay did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	u, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(control))
	return &Relay{Control: u, Harness: h}, nil
}

// FreePort returns a loopback port nothing listens on at the moment, for a
// service under test that must be told its port before it listens. Nothing
// stops another socket from taking it before the service listens on it.
// A caller that needs several ports at once takes them from FreePorts,
// since two calls in a row can return the same port.
func FreePort(t testing.TB) int {
	t.Helper()
	return FreePorts(t, 1)[0]
}

// FreePorts returns n different loopback ports nothing listens on at the
// moment. It holds a listener on each until it has all of them: a port
// closed before the next is picked can be the next, which made StartRelay
// give its public and control listeners the same port (QA on #127).
func FreePorts(t testing.TB, n int) []int {
	t.Helper()
	ports := make([]int, n)
	for i := range ports {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		ports[i] = ln.Addr().(*net.TCPAddr).Port
	}
	return ports
}

// freePorts is where StartRelay takes its ports from; a test replaces it to
// hand out a taken one.
var freePorts = FreePorts
