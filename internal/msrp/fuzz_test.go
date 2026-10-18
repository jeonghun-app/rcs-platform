package msrp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"
	"testing/iotest"
)

var fuzzSeeds = []string{
	wire("MSRP a7k2p9q1 SEND", "To-Path: "+bobURI, "From-Path: "+aliceURI, "Message-ID: m4ss4ge01",
		"Byte-Range: 1-14/14", "Content-Type: text/plain", "", "Hello from us!", "-------a7k2p9q1$"),
	wire("MSRP b0dy1ess SEND", "To-Path: "+bobURI, "From-Path: "+aliceURI, "Message-ID: k33pal1ve", "Byte-Range: 1-0/0", "-------b0dy1ess$"),
	wire("MSRP tr4ns 200 OK", "To-Path: "+aliceURI, "From-Path: "+bobURI, "-------tr4ns$"),
	wire("MSRP r3p0rt REPORT", "To-Path: "+aliceURI, "From-Path: "+bobURI, "Message-ID: msg1", "Byte-Range: 1-3/3",
		"Status: 000 413 Message Too Large", "-------r3p0rt$"),
	wire("MSRP n1ck NICKNAME", "To-Path: "+bobURI, "From-Path: "+aliceURI, `Use-Nickname: "Alice"`, "-------n1ck$"),
	wire("MSRP tidtid SEND", "To-Path: "+bobURI+" "+aliceURI, "From-Path: "+aliceURI, "Message-ID: msg1",
		"Byte-Range: 1-*/*", "Content-ID: <x@y>", "Content-Type: message/cpim", "", "a\r\n-------tidtid*\r\n\r", "-------tidtid+"),
	wire("MSRP bad1 SEND", "From-Path: "+aliceURI, "To-Path: "+bobURI, "-------bad1$"),
	"MSRP abcd SEND\n",
	"",
}

// FuzzReadMessage checks that the reader never panics, that a message it
// accepts survives Marshal and a second read unchanged, and that the
// result does not depend on how the input is split into reads.
func FuzzReadMessage(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		whole := transcript(t, bytes.NewReader(data))
		split := transcript(t, iotest.OneByteReader(bytes.NewReader(data)))
		if whole != split {
			t.Fatalf("reads differ by chunking:\n%s\n---\n%s", whole, split)
		}
	})
}

// transcript reads up to eight messages and describes what came out.
func transcript(t *testing.T, src io.Reader) string {
	t.Helper()
	var out bytes.Buffer
	r := NewReader(src, 2048)
	for range 8 {
		m, err := r.ReadMessage(4096)
		var me *MessageError
		switch {
		case errors.As(err, &me):
			if me.Message == nil || !validIdent(me.Message.TransactionID) {
				t.Fatalf("MessageError without a transaction id: %v", err)
			}
			fmt.Fprintf(&out, "refused %s %d\n", me.Message.TransactionID, me.Code)
			continue
		case err != nil:
			fmt.Fprintf(&out, "end %v\n", errors.Is(err, ErrFraming))
			return out.String()
		}
		b, err := m.Marshal()
		if err != nil {
			// The reader accepts an end-line lookalike inside a body that
			// a sender must never produce (§7.1); nothing else may fail.
			if !bodyHasBoundary(m.Body, m.TransactionID) {
				t.Fatalf("accepted message does not marshal: %v", err)
			}
			fmt.Fprintf(&out, "lookalike %s\n", m.TransactionID)
			continue
		}
		again, err := NewReader(bytes.NewReader(b), 0).ReadMessage(1 << 20)
		if err != nil {
			t.Fatalf("marshalled message does not parse: %v\n%q", err, b)
		}
		b2, err := again.Marshal()
		if err != nil || !bytes.Equal(b, b2) {
			t.Fatalf("round trip changed the message:\n%q\n%q", b, b2)
		}
		fmt.Fprintf(&out, "message %q\n", b)
	}
	return out.String()
}

// FuzzParseURI checks that every URI ParseURI accepts formats to a string
// that parses to an equal URI.
func FuzzParseURI(f *testing.F) {
	for _, s := range []string{
		aliceURI, "msrps://u@[2001:db8::1]:2856/a+b=c/d;tcp;x=y;z", "msrp://192.0.2.1:1;TCP",
		"MSRP://R%65lay.example.net:2855/s;tcp", "msrp://relay.example.net;tcp", "msrp://[::ffff:192.0.2.1]:9/s;tcp",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, err := ParseURI(s)
		if err != nil {
			return
		}
		formatted := u.String()
		v, err := ParseURI(formatted)
		if err != nil {
			t.Fatalf("%q formats as %q, which does not parse: %v", s, formatted, err)
		}
		if !u.Equal(v) || !v.Equal(u) || v.String() != formatted || !u.valid() {
			t.Fatalf("%q and %q differ", s, formatted)
		}
	})
}

// FuzzReassembler feeds arbitrary chunk sequences and checks that the
// limits hold, that a delivered message is exactly as long as its range
// says, and that nothing panics.
func FuzzReassembler(f *testing.F) {
	f.Add([]byte{1, 4, 0x80 | 8, 5, 4, 0x90 | 8, 9, 4, 2})
	f.Add([]byte{9, 2, 2, 1, 8, 0, 200, 3, 1, 1, 0, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		asm := Reassembler{MaxSize: 64, MaxPending: 3}
		flags := []byte{FlagMore, FlagEnd, FlagAbort}
		for i := 0; i+3 <= len(data); i += 3 {
			br := ByteRange{Start: int64(data[i]%80) + 1, End: Unknown, Total: Unknown}
			if data[i+2]&0x80 != 0 {
				br.Total = int64(data[i+2] & 0x7f)
			}
			if !br.valid() {
				continue
			}
			m := &Message{
				Method:       MethodSend,
				MessageID:    fmt.Sprintf("msg%d", data[i+2]%4),
				ByteRange:    &br,
				ContentType:  "text/plain",
				Body:         bytes.Repeat([]byte{data[i]}, int(data[i+1]%24)),
				Continuation: flags[int(data[i+2]>>4)%3],
			}
			whole, err := asm.Add(m)
			if err != nil {
				var se *StatusError
				if !errors.As(err, &se) || (se.Code != StatusBadRequest && se.Code != StatusMessageTooLarge) {
					t.Fatalf("unexpected error %v", err)
				}
			}
			if whole != nil {
				n := int64(len(whole.Body))
				if n > asm.MaxSize || *whole.ByteRange != (ByteRange{Start: 1, End: n, Total: n}) {
					t.Fatalf("delivered %d octets as %v", n, whole.ByteRange)
				}
			}
			if asm.Pending() > asm.MaxPending {
				t.Fatalf("%d incomplete messages held", asm.Pending())
			}
		}
	})
}
