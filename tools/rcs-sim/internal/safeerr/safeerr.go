// Package safeerr reduces network and HTTP errors to fixed reasons. The
// simulator's results go to CI logs, and a Go network error names the
// addresses, the host and even the resolver it used; against a deployed
// stack those are an operator's hosts. net/http's own errors may quote what
// the server sent. What a result needs is why the step failed, not where.
package safeerr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
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
	// ErrHTTP is any other failure net/http reports for a request: a bad
	// Content-Length, a link with another scheme. Several of its messages
	// quote what the server sent.
	ErrHTTP = errors.New("the HTTP exchange failed")
	// ErrBadBody is an answer's body that could not be read: a broken
	// chunked encoding, a bad trailer. Some of those messages quote the
	// server's bytes too.
	ErrBadBody = errors.New("the answer's body could not be read")
)

// Reason returns err as a fixed reason when it is a network failure, and err
// itself otherwise. Context errors are kept, so callers can still tell a
// deadline with errors.Is.
//
// An error inside a *url.Error, which only http.Client returns, is net/http's
// own when it is none of the network failures: an answer it could not parse
// is ErrNotHTTP and anything else ErrHTTP, because net/http has no exported
// types for them and several quote what the server sent.
func Reason(err error) error {
	if err == nil {
		return nil
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if r := network(err); r != nil {
		return r
	}
	var hdr textproto.ProtocolError
	switch {
	case errors.As(err, &hdr), ue != nil && strings.Contains(err.Error(), "malformed HTTP"):
		return ErrNotHTTP
	case ue != nil:
		return ErrHTTP
	}
	return err
}

// Body is Reason for an error reading an answer's body: a network failure
// gets its fixed reason, a context error is kept, and anything else is
// ErrBadBody, since the reader is net/http's and so is the error.
func Body(err error) error {
	if err == nil {
		return nil
	}
	if r := network(err); r != nil {
		return r
	}
	return ErrBadBody
}

// network returns the fixed reason of a network failure or a context
// error, and nil for anything else.
func network(err error) error {
	var (
		dns  *net.DNSError
		op   *net.OpError
		cert *tls.CertificateVerificationError
		hn   x509.HostnameError
		ua   x509.UnknownAuthorityError
		rec  tls.RecordHeaderError
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
	case errors.Is(err, net.ErrClosed), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		// The server closed the connection before or while answering.
		return ErrClosed
	case errors.As(err, &op):
		if op.Timeout() {
			return ErrTimeout
		}
		return ErrNetwork
	}
	return nil
}
