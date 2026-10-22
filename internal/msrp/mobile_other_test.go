//go:build !linux

package msrp

import "net"

// mobileDialer is a plain dialer where the socket options are not
// available; the slow-reader test is then only as faithful as loopback.
func mobileDialer() *net.Dialer { return &net.Dialer{} }

// rigListenConfig is a plain listener where the socket options are not
// available.
func rigListenConfig() net.ListenConfig { return net.ListenConfig{} }
