package simtest

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
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

// accept is ln.Accept with a bound, so that a stand-in listener that loses
// or withholds a connection fails the test at once, with what was waited
// for, instead of hanging it (code review on #358).
func accept(t *testing.T, ln net.Listener, what string) (net.Conn, error) {
	t.Helper()
	type result struct {
		c   net.Conn
		err error
	}
	got := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		got <- result{c, err}
	}()
	select {
	case r := <-got:
		return r.c, r.err
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: Accept did not return", what)
		return nil, nil
	}
}

func TestTheStandInListenerHoldsItsPortBetweenScenarios(t *testing.T) {
	// #186: the port the relay is told about stays taken by the test from
	// the first scenario to the last, and each scenario's stand-in gets the
	// connections made while it listens, including one made before its
	// Accept is called.
	s := ListenStandIn(t)
	addr := "127.0.0.1:" + strconv.Itoa(s.Port())
	for round := range 2 {
		ln, err := s.Lend()
		if err != nil {
			t.Fatal(err)
		}
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("round %d: dial %v", round, err)
		}
		got, err := accept(t, ln, fmt.Sprintf("round %d: a connection made before Accept", round))
		if err != nil {
			t.Fatalf("round %d: accept %v", round, err)
		}
		_ = got.Close()
		_ = c.Close()
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := accept(t, ln, fmt.Sprintf("round %d: Accept after Close", round)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("round %d: Accept after Close = %v", round, err)
		}
		// Between two scenarios nobody else can listen on it.
		if other, err := net.Listen("tcp", addr); err == nil {
			_ = other.Close()
			t.Fatalf("round %d: the port was free between scenarios", round)
		}
	}
}

func TestClosingALentStandInListenerWakesItsAccept(t *testing.T) {
	// chat.Core.Close closes its listener to end the Accept its goroutine
	// is waiting in; a lent listener must end it too.
	s := ListenStandIn(t)
	ln, err := s.Lend()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		done <- err
	}()
	time.Sleep(10 * time.Millisecond) // most likely waiting by now; if not, it finds the listener closed
	_ = ln.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("the waiting Accept returned %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not wake the waiting Accept")
	}
}

func TestTheStandInListenerIsLentToOneStandInAtATime(t *testing.T) {
	s := ListenStandIn(t)
	ln, err := s.Lend()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lend(); err == nil {
		t.Fatal("lent twice at once")
	}
	_ = ln.Close()
	again, err := s.Lend()
	if err != nil {
		t.Fatalf("Lend after Close = %v", err)
	}
	_ = again.Close()
}
