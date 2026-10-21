package simtest

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// StandInPort returns a loopback port for the rcs-as stand-in, which a
// chat scenario listens on and the relay is told about (RELAY_CORE_PORTS).
//
// FreePort's ports come from the kernel's ephemeral range, so they cannot
// be held for the stand-in: the kernel hands the same range out to
// everything else on the host. About once in 700 runs the stand-in's listen
// failed with "address already in use" (#133). On this kernel the port was
// mostly taken by a "127.0.0.1:0" listener of another test package running
// at the same time (Linux gives those odd ports), and otherwise by the local
// port of an outgoing connection (even ports), of which the test process
// makes many. The relay's own FreePorts picks can return it too. A test in
// the process holds the port with StandInListener instead; StandInPort is
// for a stand-in in another process, which listens itself.
//
// StandInPort picks outside the ephemeral range, which none of those ever
// uses: below it, or above it when the range leaves no room below, and it
// fails when there is no room on either side. It reserves nothing, so two
// test packages that call it at the same time can, rarely, get the same
// port.
func StandInPort(t testing.TB) int {
	t.Helper()
	b, err := os.ReadFile(ephemeralRangeFile)
	lo, hi, err := standInPorts(string(b), err)
	if err != nil {
		t.Fatal(err)
	}
	for range 100 {
		port := lo + rand.IntN(hi-lo+1)
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			continue
		}
		_ = ln.Close()
		return port
	}
	t.Fatalf("no free port in %d-%d, outside the ephemeral range", lo, hi)
	return 0
}

// ephemeralRangeFile holds the kernel's range of local ports for outgoing
// connections (net.ipv4.ip_local_port_range).
const ephemeralRangeFile = "/proc/sys/net/ipv4/ip_local_port_range"

// The stand-in's ports stay clear of the registered ports most services
// default to, and need this many ports of room on one side of the
// ephemeral range.
const (
	minStandInPort = 10000
	maxPort        = 65535
	minRoom        = 100
)

// defaultEphemeralLow and defaultEphemeralHigh are Linux's default range,
// assumed only when the file cannot be read (another system, or a sandbox
// without /proc). A file that can be read but leaves no room is an error,
// not a reason to assume the default.
const defaultEphemeralLow, defaultEphemeralHigh = 32768, 60999

// standInPorts returns the range StandInPort picks from, given the contents
// of ephemeralRangeFile or the error reading it: below the ephemeral range
// if it leaves room, else above it. A range that leaves no room on either
// side, or contents that are not a range, is an error naming the range, not
// a silent fall back to a default the host does not use.
func standInPorts(contents string, readErr error) (lo, hi int, err error) {
	low, high := defaultEphemeralLow, defaultEphemeralHigh
	if readErr == nil {
		f := strings.Fields(contents)
		var err1, err2 error
		if len(f) == 2 {
			low, err1 = strconv.Atoi(f[0])
			high, err2 = strconv.Atoi(f[1])
		}
		if len(f) != 2 || err1 != nil || err2 != nil || low < 1 || high > maxPort || high < low {
			return 0, 0, fmt.Errorf("simtest: %s holds %q, not a port range", ephemeralRangeFile, strings.TrimSpace(contents))
		}
	}
	switch {
	case low-minStandInPort >= minRoom:
		return minStandInPort, low - 1, nil
	case maxPort-high >= minRoom:
		return max(high+1, minStandInPort), maxPort, nil
	}
	return 0, 0, fmt.Errorf("simtest: the ephemeral range %d-%d leaves no room for the rcs-as stand-in's port (%d-%d)", low, high, minStandInPort, maxPort)
}

// StandInListener holds one loopback listener on port 0 for the rcs-as
// stand-in, from before the relay starts until the test ends, and lends it
// to each chat scenario in turn: the port the relay is told about is never
// free for another process to take, as a port picked ahead and listened on
// again by each scenario was (#186). Connections wait for the next
// scenario's stand-in when none is accepting.
type StandInListener struct {
	ln    net.Listener
	conns chan net.Conn
	done  chan struct{}
	mu    sync.Mutex
	out   bool // a lent listener is open
}

// ListenStandIn starts a StandInListener; the test's end closes it.
func ListenStandIn(t testing.TB) *StandInListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &StandInListener{ln: ln, conns: make(chan net.Conn), done: make(chan struct{})}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case s.conns <- c:
			case <-s.done:
				_ = c.Close()
				return
			}
		}
	}()
	t.Cleanup(func() {
		close(s.done)
		_ = ln.Close()
	})
	return s
}

// Port is the listener's port, for the relay's RELAY_CORE_PORTS.
func (s *StandInListener) Port() int { return s.ln.Addr().(*net.TCPAddr).Port }

// Lend returns a listener that takes the connections until it is closed,
// which leaves the port listening for the next. One is lent at a time: two
// open at once would take each other's connections.
func (s *StandInListener) Lend() (net.Listener, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.out {
		return nil, errors.New("simtest: the stand-in's listener is lent already")
	}
	s.out = true
	return &lent{s: s, closed: make(chan struct{})}, nil
}

type lent struct {
	s      *StandInListener
	closed chan struct{}
	once   sync.Once
}

func (l *lent) Accept() (net.Conn, error) {
	select {
	case c := <-l.s.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	case <-l.s.done:
		return nil, net.ErrClosed
	}
}

func (l *lent) Close() error {
	l.once.Do(func() {
		close(l.closed)
		l.s.mu.Lock()
		l.s.out = false
		l.s.mu.Unlock()
	})
	return nil
}

func (l *lent) Addr() net.Addr { return l.s.ln.Addr() }
