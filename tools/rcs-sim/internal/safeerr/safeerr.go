// Package safeerr reduces network errors to fixed reasons. The simulator's
// results go to CI logs, and a Go network error names the addresses, the
// host and even the resolver it used; against a deployed stack those are an
// operator's hosts. What a result needs is why the step failed, not where.
package safeerr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/textproto"
	"net/url"
	"os"
	"strings"
	"syscall"
)

// Reasons a network failure is reduced to.
var (
	ErrRefused     = errors.New("connection refused")
	ErrReset       = errors.New("connection reset")
	ErrUnreachable = errors.New("network unreachable")
	ErrNoSuchHost  = errors.New("host name not resolved")
	ErrTimeout     = errors.New("timed out")
	ErrTLS         = errors.New("TLS handshake failed")
	ErrCertificate = errors.New("server certificate not accepted")
	ErrClosed      = errors.New("connection closed")
	ErrNetwork     = errors.New("network error")
	// ErrNotHTTP is an answer that is not HTTP, from something else
	// listening on the port, say. Go's error would quote its bytes.
	ErrNotHTTP = errors.New("the answer is not HTTP")
)

// Reason returns err as a fixed reason when it is a network failure, and err
// itself otherwise. Context errors are kept, so callers can still tell a
// deadline with errors.Is.
func Reason(err error) error {
	if err == nil {
		return nil
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var (
		dns  *net.DNSError
		op   *net.OpError
		cert *tls.CertificateVerificationError
		hn   x509.HostnameError
		ua   x509.UnknownAuthorityError
		rec  tls.RecordHeaderError
		hdr  textproto.ProtocolError
	)
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		if errors.Is(err, context.Canceled) {
			return context.Canceled
		}
		return context.DeadlineExceeded
	case errors.As(err, &dns):
		if dns.IsTimeout {
			return ErrTimeout
		}
		return ErrNoSuchHost
	case errors.As(err, &cert), errors.As(err, &hn), errors.As(err, &ua):
		return ErrCertificate
	case errors.As(err, &rec):
		return ErrTLS
	case errors.Is(err, syscall.ECONNREFUSED):
		return ErrRefused
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return ErrReset
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return ErrUnreachable
	case errors.Is(err, os.ErrDeadlineExceeded):
		return ErrTimeout
	case errors.Is(err, net.ErrClosed):
		return ErrClosed
	case errors.As(err, &op):
		if op.Timeout() {
			return ErrTimeout
		}
		return ErrNetwork
	case errors.As(err, &hdr), ue != nil && strings.Contains(err.Error(), "malformed HTTP"):
		// net/http's own parse errors have no exported type; inside a
		// *url.Error, "malformed HTTP" names only them.
		return ErrNotHTTP
	}
	return err
}
