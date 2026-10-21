package transport

import (
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// What sets writeAll's throughput floor, as its documentation gives it (#329):
// the chunk size, a fresh WriteTimeout for every chunk, and the send buffer.
// A change to any of them changes the floor; measure it again on loopback and
// update the documentation of writeAll, socketSendBuffer and
// Config.WriteTimeout.
func TestTheWriteFloorIsSetByTheChunkTheDeadlineAndTheSendBuffer(t *testing.T) {
	if writeChunk != 32<<10 || socketSendBuffer != 128<<10 || DefaultWriteTimeout != 10*time.Second {
		t.Fatalf("writeChunk %d, socketSendBuffer %d and DefaultWriteTimeout %v, but the floor in writeAll's documentation was measured with 32 KiB, 128 KiB and 10 s: measure it again and update the documentation", writeChunk, socketSendBuffer, DefaultWriteTimeout)
	}
	const timeout = 7 * time.Second
	tr, _ := newTransport(t, Config{WriteTimeout: timeout})
	conn := &writeRecorder{}
	f := &flow{conn: conn, q: newSendQueue(1<<20, &queueBudget{max: 1 << 30})}
	msg := make([]byte, 100<<10)
	before := time.Now()
	if err := tr.writeAll(f, msg); err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	want := []int{32 << 10, 32 << 10, 32 << 10, 4 << 10}
	if len(conn.ops) != 2*len(want) {
		t.Fatalf("writeAll did %+v, want a deadline before each of %d writes", conn.ops, len(want))
	}
	for i, n := range want {
		d, w := conn.ops[2*i], conn.ops[2*i+1]
		if d.deadline.IsZero() || d.deadline.Before(before.Add(timeout)) || d.deadline.After(after.Add(timeout)) {
			t.Errorf("chunk %d: deadline %+v, want WriteTimeout from when it was written", i, d)
		}
		if w.n != n {
			t.Errorf("chunk %d: wrote %d bytes, want %d", i, w.n, n)
		}
	}
}

// A chunk write that times out after the kernel took part of it ends the
// message there, and the connection with it, rather than writing on: going
// on after partial progress is the rule writeAll's documentation says was not
// taken (code review of #370).
func TestAChunkThatTimesOutPartWayEndsTheWrite(t *testing.T) {
	tr, _ := newTransport(t, Config{WriteTimeout: time.Second})
	conn := &partialWrite{}
	f := &flow{conn: conn, q: newSendQueue(1<<20, &queueBudget{max: 1 << 30})}
	if err := tr.writeAll(f, make([]byte, 100<<10)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("writeAll returned %v after a chunk timed out part way, want the timeout", err)
	}
	if conn.writes != 2 {
		t.Fatalf("%d writes, want 2: writing went on after the timeout", conn.writes)
	}
}

// partialWrite takes the first write whole and 100 bytes of the second,
// which then times out.
type partialWrite struct {
	writeRecorder
	writes int
}

func (c *partialWrite) Write(b []byte) (int, error) {
	c.writes++
	if c.writes == 2 {
		_, _ = c.writeRecorder.Write(b[:100])
		return 100, os.ErrDeadlineExceeded
	}
	return c.writeRecorder.Write(b)
}

// writeRecorder records the write deadlines and writes it is given, in
// order, and takes every write at once.
type writeRecorder struct {
	net.Conn
	mu  sync.Mutex
	ops []writeOp
}

type writeOp struct {
	deadline time.Time // set for a SetWriteDeadline
	n        int       // set for a Write
}

func (c *writeRecorder) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ops = append(c.ops, writeOp{deadline: t})
	return nil
}

func (c *writeRecorder) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ops = append(c.ops, writeOp{n: len(b)})
	return len(b), nil
}

// tcpPair returns the dialing end of a loopback TCP connection; both ends
// close with the test.
func tcpPair(t *testing.T) *net.TCPConn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	s, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return c.(*net.TCPConn)
}
