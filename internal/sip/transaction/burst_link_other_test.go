//go:build !linux

package transaction

import "github.com/jeonghun-app/rcs-platform/internal/sip/transport"

// linkDialer is the transport's own dialer where TCP_MAXSEG is not set.
func linkDialer() transport.Dialer { return nil }
