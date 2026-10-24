package websocket

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"unicode/utf8"
)

// FuzzRead feeds Read whatever a client may send. It never panics; every
// message it returns is within the bound, and text is UTF-8; whatever it
// writes back is server frames only: unmasked, final, pongs and Closes,
// with nothing after a Close.
func FuzzRead(f *testing.F) {
	f.Add(clientFrame(true, OpText, []byte("hello"), testKey))
	f.Add(append(clientFrame(false, OpText, []byte("he"), testKey), clientFrame(true, opContinuation, []byte("llo"), testKey)...))
	f.Add(clientFrame(true, opPing, []byte("p"), testKey))
	f.Add(clientFrame(true, opClose, closeFrame(StatusNormal, "bye"), testKey))
	f.Add(append([]byte{0x81, 0x80 | 126, 0, 200}, testKey[:]...))
	f.Add(append([]byte{0x82, 0x80 | 127, 0, 0, 0, 0, 0, 1, 0, 0}, testKey[:]...))
	f.Add([]byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'})
	f.Fuzz(func(t *testing.T, in []byte) {
		const limit = 256
		c, out := testConn(in, Options{MaxMessage: limit})
		for i := 0; i <= len(in); i++ {
			op, p, err := c.Read()
			if err != nil {
				break
			}
			if len(p) > limit {
				t.Fatalf("a %d-byte message passed a %d-byte bound", len(p), limit)
			}
			if op == OpText && !utf8.Valid(p) {
				t.Fatal("a text message that is not UTF-8")
			}
			if op != OpText && op != OpBinary {
				t.Fatalf("Read returned opcode %d", op)
			}
		}
		checkServerFrames(t, out.Bytes())
	})
}

// checkServerFrames walks what the server wrote by RFC 6455 §5.2 directly,
// not through readHeader.
func checkServerFrames(t *testing.T, b []byte) {
	t.Helper()
	closed := false
	for len(b) > 0 {
		if closed {
			t.Fatal("a frame after the Close")
		}
		if len(b) < 2 {
			t.Fatalf("a truncated server frame: %x", b)
		}
		if b[0]&0x80 == 0 || b[0]&0x70 != 0 || b[1]&0x80 != 0 {
			t.Fatalf("server frame header %x", b[:2])
		}
		op, n := b[0]&0x0f, int(b[1]&0x7f)
		if op != opPong && op != opClose {
			t.Fatalf("the server answered a client with opcode %d", op)
		}
		if n > maxControlPayload {
			t.Fatalf("a control frame of %d bytes", n)
		}
		if len(b) < 2+n {
			t.Fatalf("a truncated server frame: %x", b)
		}
		if op == opClose {
			closed = true
			if n == 1 {
				t.Fatal("a Close of one byte")
			}
			if n >= 2 && !sendable(int(binary.BigEndian.Uint16(b[2:4]))) {
				t.Fatalf("a Close with status %d", binary.BigEndian.Uint16(b[2:4]))
			}
		}
		b = b[2+n:]
	}
}

// FuzzMessageRoundTrip writes a message as a client does, in fragments
// cut where the input says, with control frames between them, and reads it
// back: the payload, the opcode and the pongs are what was sent.
func FuzzMessageRoundTrip(f *testing.F) {
	f.Add([]byte("hello"), false, uint32(0x01020304), []byte{2, 1})
	f.Add([]byte("한글"), false, uint32(0), []byte{1, 1, 1, 1, 1})
	f.Add(bytes.Repeat([]byte{0}, 300), true, uint32(0xffffffff), []byte{200})
	f.Add([]byte{}, true, uint32(7), []byte{})
	f.Fuzz(func(t *testing.T, payload []byte, binaryOp bool, mask uint32, cuts []byte) {
		if len(payload) > 70000 {
			return
		}
		op := OpBinary
		if !binaryOp {
			if !utf8.Valid(payload) {
				return
			}
			op = OpText
		}
		var key [4]byte
		binary.BigEndian.PutUint32(key[:], mask)
		var in []byte
		rest, first, pings := payload, true, 0
		for _, c := range cuts {
			if len(rest) == 0 {
				break
			}
			n := min(int(c), len(rest))
			fop := opContinuation
			if first {
				fop = op
			}
			in = append(in, clientFrame(false, fop, rest[:n], key)...)
			in = append(in, clientFrame(true, opPing, []byte{c}, key)...)
			rest, first, pings = rest[n:], false, pings+1
		}
		fop := opContinuation
		if first {
			fop = op
		}
		in = append(in, clientFrame(true, fop, rest, key)...)
		c, out := testConn(in, Options{MaxMessage: 70000})
		gotOp, got, err := c.Read()
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if gotOp != op || !bytes.Equal(got, payload) {
			t.Fatalf("read back %d %x, want %d %x", gotOp, got, op, payload)
		}
		if _, _, err := c.Read(); err != io.EOF {
			t.Fatalf("after the message: %v, want io.EOF", err)
		}
		for i := range pings {
			p := out.Next(3)
			if len(p) != 3 || p[0] != 0x80|opPong || p[1] != 1 || p[2] != cuts[i] {
				t.Fatalf("pong %d is %x", i, p)
			}
		}
		if out.Len() != 0 {
			t.Fatalf("%d more bytes written", out.Len())
		}
	})
}
