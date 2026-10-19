//go:build !linux

package msrprelay

import (
	"net"
	"time"
)

// setUserTimeout is a no-op where TCP_USER_TIMEOUT is not available; the
// service runs on Linux (Fargate).
func setUserTimeout(net.Conn, time.Duration) error { return nil }
