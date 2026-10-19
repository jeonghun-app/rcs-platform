package safeerr_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
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
	// The lookup goes to a resolver that cannot be reached, which fails at
	// once with a *net.DNSError, as an unknown name does. The host's own
	// resolver (none in the toolchain container) answered in its own time,
	// and on a loaded host after the test's deadline (#130).
	noResolver := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("no resolver here")
	}}
	client := &http.Client{Transport: &http.Transport{
		DialContext: (&net.Dialer{Resolver: noResolver}).DialContext,
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, tt := range []struct {
		url  string
		want []error
	}{
		{"http://127.0.0.1:" + port + "/ft", []error{safeerr.ErrRefused}},
		{"http://ft.rcs-sim-test.invalid/ft", []error{safeerr.ErrNoSuchHost}},
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

// answering listens on loopback and answers every request with reply,
// once it has read the request: a reply sent earlier would reach a client
// that has not asked yet, which Go reports differently.
func answering(t *testing.T, reply string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = http.ReadRequest(bufio.NewReader(c))
			_, _ = c.Write([]byte(reply))
			_ = c.Close()
		}
	}()
	return "http://" + ln.Addr().String() + "/ft"
}

func TestAnAnswerThatIsNotHTTPIsNotQuoted(t *testing.T) {
	for _, reply := range []string{
		"SSH-2.0-OpenSSH secret-host.example 10.9.8.7\r\n",
		"HTTP/1.1 2x0 secret-host.example\r\n\r\n",
		"HTTP/1.1 200 OK\r\nsecret-host.example 10.9.8.7\r\n\r\n",
	} {
		_, err := http.Get(answering(t, reply))
		got := safeerr.Reason(err)
		if got != safeerr.ErrNotHTTP {
			t.Errorf("%q: Reason(%v) = %v", reply, err, got)
		}
	}
}

func TestEveryOtherHTTPFailureIsAFixedReason(t *testing.T) {
	for _, tt := range []struct {
		reply string
		want  error
	}{
		{"HTTP/1.1 200 OK\r\nContent-Length: secret-host.example\r\n\r\n", safeerr.ErrHTTP},
		{"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2 secret-host.example\r\n\r\n", safeerr.ErrHTTP},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: secret-host.example\r\n\r\n", safeerr.ErrHTTP},
		// The server closes without answering.
		{"", safeerr.ErrClosed},
	} {
		_, err := http.Get(answering(t, tt.reply))
		if got := safeerr.Reason(err); got != tt.want {
			t.Errorf("%q: Reason(%v) = %v, want %v", tt.reply, err, got, tt.want)
		}
	}
	// A link with another scheme, taken from a server's document.
	_, err := http.Get("ftp://secret-host.example/x")
	if got := safeerr.Reason(err); got != safeerr.ErrHTTP {
		t.Errorf("Reason(%v) = %v", err, got)
	}
}

func TestABodyThatCannotBeReadIsAFixedReason(t *testing.T) {
	for _, tt := range []struct {
		reply string
		want  error
	}{
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nsecret-host\r\n", safeerr.ErrBadBody},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nasecret-host\r\n0\r\n\r\n", safeerr.ErrBadBody},
		{"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", safeerr.ErrClosed},
	} {
		resp, err := http.Get(answering(t, tt.reply))
		if err != nil {
			t.Fatalf("%q: %v", tt.reply, err)
		}
		_, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if got := safeerr.Body(err); got != tt.want || strings.Contains(got.Error(), "secret") {
			t.Errorf("%q: Body(%v) = %v, want %v", tt.reply, err, got, tt.want)
		}
	}
	if safeerr.Body(nil) != nil || !errors.Is(safeerr.Body(fmt.Errorf("x: %w", context.Canceled)), context.Canceled) {
		t.Fatal("Body changed nil or a cancellation")
	}
	op := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}
	if got := safeerr.Body(op); got != safeerr.ErrReset {
		t.Fatalf("Body(%v) = %v", op, got)
	}
}
