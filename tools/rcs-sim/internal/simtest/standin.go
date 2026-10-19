package simtest

import (
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
)

// StandInPort returns a loopback port for the rcs-as stand-in, which a
// chat scenario listens on and the relay is told about (RELAY_CORE_PORTS).
//
// FreePort's ports come from the kernel's ephemeral range, so they cannot
// be held for the stand-in. A port the kernel hands out for "127.0.0.1:0"
// is also one it hands out as the local port of an outgoing connection, and
// the test process makes many. It is also one the relay's own FreePort picks
// can return. Either way the stand-in's listen failed with "address already
// in use", about once in 700 runs (#133). Each chat scenario listens again
// on the same port, so holding one listener open would not be enough.
//
// StandInPort picks below the ephemeral range, which neither of those ever
// uses. Only another StandInPort pick in the same moment can meet it.
func StandInPort(t testing.TB) int {
	t.Helper()
	low, _ := ephemeralPorts()
	for range 100 {
		port := minStandInPort + rand.IntN(low-minStandInPort)
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			continue
		}
		_ = ln.Close()
		return port
	}
	t.Fatal("no free port below the ephemeral range")
	return 0
}

// minStandInPort keeps StandInPort clear of the registered ports most
// services default to.
const minStandInPort = 10000

// ephemeralPorts returns the kernel's range of local ports for outgoing
// connections (net.ipv4.ip_local_port_range), or Linux's default when it
// cannot be read.
func ephemeralPorts() (low, high int) {
	low, high = 32768, 60999
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return low, high
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return low, high
	}
	l, err1 := strconv.Atoi(f[0])
	h, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil || l <= minStandInPort+100 || h < l {
		return low, high
	}
	return l, h
}
