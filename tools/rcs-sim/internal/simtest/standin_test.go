package simtest

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"
)

func TestStandInPortsLieOutsideTheEphemeralRange(t *testing.T) {
	for _, tt := range []struct {
		contents string
		readErr  error
		lo, hi   int
		fails    string
	}{
		{contents: "32768\t60999\n", lo: 10000, hi: 32767},
		// No room below: above the range.
		{contents: "10000 60999", lo: 61000, hi: 65535},
		{contents: "1024 60000", lo: 60001, hi: 65535},
		// No room on either side: an error naming the range.
		{contents: "1024 65535", fails: "1024-65535 leaves no room"},
		{contents: "10000 65535", fails: "10000-65535 leaves no room"},
		// Not a range.
		{contents: "", fails: "not a port range"},
		{contents: "60999 32768", fails: "not a port range"},
		{contents: "32768", fails: "not a port range"},
		// Only an unreadable file means Linux's default.
		{readErr: os.ErrNotExist, lo: 10000, hi: 32767},
	} {
		lo, hi, err := standInPorts(tt.contents, tt.readErr)
		switch {
		case tt.fails != "" && (err == nil || !strings.Contains(err.Error(), tt.fails)):
			t.Errorf("%q: %d-%d, %v; want an error with %q", tt.contents, lo, hi, err, tt.fails)
		case tt.fails == "" && (err != nil || lo != tt.lo || hi != tt.hi):
			t.Errorf("%q, %v: %d-%d, %v; want %d-%d", tt.contents, tt.readErr, lo, hi, err, tt.lo, tt.hi)
		}
	}
}

// A stand-in port is never one the kernel can give a "127.0.0.1:0" listener
// in another package, an outgoing connection or a FreePorts pick, which
// together took it about once in 700 runs (#133).
func TestStandInPortsAreOutsideThisHostsEphemeralRange(t *testing.T) {
	b, err := os.ReadFile(ephemeralRangeFile)
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("no ", ephemeralRangeFile)
	}
	lo, hi, err := standInPorts(string(b), err)
	if err != nil {
		t.Fatal(err)
	}
	for range 200 {
		if p := StandInPort(t); p < lo || p > hi {
			t.Fatalf("StandInPort = %d, want %d to %d", p, lo, hi)
		}
	}
}

// One of what took the port: an outgoing connection's local port blocks a
// listener on it, and every such port is in the ephemeral range. The other,
// a ":0" listener in a parallel package, is in the same range by definition.
func TestAnOutgoingConnectionsPortIsInTheEphemeralRange(t *testing.T) {
	b, err := os.ReadFile(ephemeralRangeFile)
	if err != nil {
		t.Skip("no ", ephemeralRangeFile)
	}
	f := strings.Fields(string(b))
	low, high := atoi(t, f[0]), atoi(t, f[1])
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	for range 50 {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		p := c.LocalAddr().(*net.TCPAddr).Port
		if l, err := net.Listen("tcp", c.LocalAddr().String()); err == nil {
			_ = l.Close()
			t.Fatalf("a listener could take port %d of an open connection", p)
		}
		_ = c.Close()
		if p < low || p > high {
			t.Fatalf("an outgoing connection got port %d, outside %d to %d", p, low, high)
		}
	}
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("%q is not a number", s)
		}
		n = n*10 + int(c-'0')
	}
	return n
}
