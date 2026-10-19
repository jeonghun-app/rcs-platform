package safeerr_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/safeerr"
)

func TestNetworkFailuresLoseTheirAddresses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := &http.Client{}
	for _, tt := range []struct {
		url  string
		want []error
	}{
		{"http://127.0.0.1:" + port + "/ft", []error{safeerr.ErrRefused}},
		// Without a resolver to ask, the lookup times out instead.
		{"http://ft.rcs-sim-test.invalid/ft", []error{safeerr.ErrNoSuchHost, safeerr.ErrTimeout}},
	} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, tt.url, nil)
		_, err := client.Do(req)
		got := safeerr.Reason(err)
		if !slices.Contains(tt.want, got) {
			t.Fatalf("%s: Reason(%v) = %v, want one of %v", tt.url, err, got, tt.want)
		}
		if s := got.Error(); strings.Contains(s, port) || strings.Contains(s, "invalid") || strings.Contains(s, "127.0.0.1") {
			t.Fatalf("the reason names where: %s", s)
		}
	}
}

func TestOtherErrorsAndContextErrorsAreKept(t *testing.T) {
	plain := errors.New("ft: upload: HTTP 409")
	if safeerr.Reason(plain) != plain || safeerr.Reason(nil) != nil {
		t.Fatal("a non-network error was changed")
	}
	if !errors.Is(safeerr.Reason(fmt.Errorf("x: %w", context.DeadlineExceeded)), context.DeadlineExceeded) {
		t.Fatal("a deadline is no longer recognisable")
	}
	if !errors.Is(safeerr.Reason(fmt.Errorf("x: %w", context.Canceled)), context.Canceled) {
		t.Fatal("a cancellation is no longer recognisable")
	}
	op := &net.OpError{Op: "read", Net: "tcp", Err: errors.New("weird failure at 10.1.2.3:4")}
	if got := safeerr.Reason(op); got != safeerr.ErrNetwork {
		t.Fatalf("Reason(%v) = %v", op, got)
	}
}

// timeout is a network error that reports a timeout without being one of
// the standard deadline errors.
type timeout struct{}

func (timeout) Error() string { return "i/o timeout at 10.1.2.3:4" }
func (timeout) Timeout() bool { return true }

func TestEachFailureHasItsReason(t *testing.T) {
	op := func(err error) error {
		return &url.Error{Op: "Get", URL: "http://10.1.2.3/ft", Err: &net.OpError{Op: "dial", Net: "tcp", Err: err}}
	}
	for _, tt := range []struct {
		err  error
		want error
	}{
		{&net.DNSError{Name: "ft.example.invalid", Server: "10.0.0.2:53", IsTimeout: true}, safeerr.ErrTimeout},
		{op(&net.DNSError{Name: "ft.example.invalid", Server: "10.0.0.2:53", IsNotFound: true}), safeerr.ErrNoSuchHost},
		{&tls.CertificateVerificationError{Err: errors.New("bad")}, safeerr.ErrCertificate},
		{x509.HostnameError{Certificate: &x509.Certificate{}, Host: "10.1.2.3"}, safeerr.ErrCertificate},
		{x509.UnknownAuthorityError{}, safeerr.ErrCertificate},
		{tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, safeerr.ErrTLS},
		{op(os.NewSyscallError("connect", syscall.ECONNREFUSED)), safeerr.ErrRefused},
		{op(os.NewSyscallError("read", syscall.ECONNRESET)), safeerr.ErrReset},
		{op(os.NewSyscallError("write", syscall.EPIPE)), safeerr.ErrReset},
		{op(os.NewSyscallError("connect", syscall.ENETUNREACH)), safeerr.ErrUnreachable},
		{op(os.NewSyscallError("connect", syscall.EHOSTUNREACH)), safeerr.ErrUnreachable},
		{op(os.ErrDeadlineExceeded), safeerr.ErrTimeout},
		{op(net.ErrClosed), safeerr.ErrClosed},
		{op(timeout{}), safeerr.ErrTimeout},
	} {
		if got := safeerr.Reason(tt.err); got != tt.want {
			t.Errorf("Reason(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

func TestAnUntrustedServerIsACertificateFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	// The default client does not trust the test server's certificate.
	_, err := (&http.Client{Transport: &http.Transport{}}).Get(srv.URL)
	if got := safeerr.Reason(err); got != safeerr.ErrCertificate {
		t.Fatalf("Reason(%v) = %v", err, got)
	}
}
