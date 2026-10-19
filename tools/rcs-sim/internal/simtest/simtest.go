// Package simtest starts the services the simulator talks to inside a test
// process: ft-server on memory stores and msrp-relay on its memory store,
// both on loopback, so the simulator's packages are tested against the real
// service code without containers. make e2e runs the built binaries
// instead (tools/rcs-sim/e2e).
package simtest

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver"
	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
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
		Realm: FTRealm, NonceKey: bytes.Repeat([]byte("k"), digest.MinNonceKeySize),
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
	hs := &httptest.Server{Listener: ln, Config: &http.Server{Handler: srv}}
	hs.Start()
	t.Cleanup(hs.Close)
	return &FT{UploadURL: upload, Server: hs, Harness: h}
}

// Relay is an msrp-relay in the test process.
type Relay struct {
	Control *url.URL
	Harness *runtimetest.Harness
}

// StartRelay starts msrp-relay with its memory store, a plain public
// listener on loopback (no NLB, so no PROXY header and no TLS), and the
// core side limited to loopback and corePorts. It is configured through
// msrprelay.Configure from the environment it would get in a test stack.
func StartRelay(t testing.TB, corePorts ...int) *Relay {
	t.Helper()
	public, control := FreePort(t), FreePort(t)
	ports := make([]string, len(corePorts))
	for i, p := range corePorts {
		ports[i] = strconv.Itoa(p)
	}
	env := map[string]string{
		"RCS_ENV":                  "test",
		"RELAY_LISTEN_ADDR":        "127.0.0.1:" + strconv.Itoa(public),
		"RELAY_CONTROL_ADDR":       "127.0.0.1:" + strconv.Itoa(control),
		"RELAY_PUBLIC_HOST":        "127.0.0.1",
		"RELAY_PUBLIC_PORT":        strconv.Itoa(public),
		"RELAY_PUBLIC_TLS":         "false",
		"RELAY_CORE_HOST":          "127.0.0.1",
		"RELAY_CORE_NETWORKS":      "127.0.0.0/8",
		"RELAY_CORE_PORTS":         strings.Join(ports, ","),
		"RELAY_STORE":              "memory",
		"RELAY_PCSCF_TOKEN":        RelayToken,
		"RELAY_KEEPALIVE_INTERVAL": "10s",
		"RELAY_IDLE_TIMEOUT":       "60s",
	}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	shared := runtime.NewEnv("RCS_", lookup)
	cfg := msrprelay.Configure(&runtime.Settings{Env: shared.WithPrefix("RELAY_"), Shared: shared, Environment: runtime.Test})
	if err := shared.Err(); err != nil {
		t.Fatal(err)
	}
	h := runtimetest.New(t, "msrp-relay")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- msrprelay.Run(ctx, h.Runtime, cfg) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		if code, _ := h.Get("/readyz"); code == http.StatusOK {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("msrp-relay stopped: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("msrp-relay did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	u, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(control))
	return &Relay{Control: u, Harness: h}
}

// FreePort returns a loopback port nothing listens on at the moment. A
// service under test that must be told its port before it listens needs
// one; another process could take it in between, which on a test host is
// rare enough.
func FreePort(t testing.TB) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
