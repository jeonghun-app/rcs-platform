package simtest

import (
	"net"
	"testing"
)

// A stand-in port is never one the kernel can give an outgoing connection
// or a FreePort pick, which took it about once in 700 runs (#133).
func TestStandInPortsAreBelowTheEphemeralRange(t *testing.T) {
	low, _ := ephemeralPorts()
	for range 200 {
		if p := StandInPort(t); p >= low || p < minStandInPort {
			t.Fatalf("StandInPort = %d, want %d to %d", p, minStandInPort, low-1)
		}
	}
}

// What took the port: an outgoing connection's local port blocks a listener
// on it. Every such port is in the ephemeral range, so a stand-in port is
// never one.
func TestAnOutgoingConnectionsPortIsInTheEphemeralRange(t *testing.T) {
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
	low, high := ephemeralPorts()
	for range 50 {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		p := c.LocalAddr().(*net.TCPAddr).Port
		if _, err := net.Listen("tcp", c.LocalAddr().String()); err == nil {
			t.Fatalf("a listener could take port %d of an open connection", p)
		}
		_ = c.Close()
		if p < low || p > high {
			t.Fatalf("an outgoing connection got port %d, outside %d to %d", p, low, high)
		}
	}
}
