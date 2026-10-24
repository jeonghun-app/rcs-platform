package websocket

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// clientFrame is a client's frame written out by hand, as RFC 6455 §5.2
// lays it out, independently of the package's own encoder.
func clientFrame(fin bool, opcode byte, payload []byte, key [4]byte) []byte {
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	out := []byte{b0}
	switch n := len(payload); {
	case n < 126:
		out = append(out, 0x80|byte(n))
	case n < 1<<16:
		out = append(out, 0x80|126, byte(n>>8), byte(n))
	default:
		out = append(out, 0x80|127)
		for i := 7; i >= 0; i-- {
			out = append(out, byte(uint64(n)>>(8*i)))
		}
	}
	out = append(out, key[:]...)
	for i, c := range payload {
		out = append(out, c^key[i%4])
	}
	return out
}

var testKey = [4]byte{0x37, 0xfa, 0x21, 0x3d}

// readServer reads one server frame: unmasked, final.
func readServer(t *testing.T, r io.Reader) (byte, []byte) {
	t.Helper()
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		t.Fatalf("reading a server frame: %v", err)
	}
	if h[0]&0x80 == 0 || h[0]&0x70 != 0 || h[1]&0x80 != 0 {
		t.Fatalf("server frame header %x: want FIN, no RSV, no mask", h)
	}
	n := int(h[1] & 0x7f)
	switch n {
	case 126:
		var l [2]byte
		io.ReadFull(r, l[:])
		n = int(binary.BigEndian.Uint16(l[:]))
	case 127:
		var l [8]byte
		io.ReadFull(r, l[:])
		n = int(binary.BigEndian.Uint64(l[:]))
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		t.Fatalf("reading a server payload: %v", err)
	}
	return h[0] & 0x0f, p
}

// testConn is a Conn reading in and writing to out.
func testConn(in []byte, o Options) (*Conn, *bytes.Buffer) {
	var out bytes.Buffer
	return newConn(nil, bytes.NewReader(in), &out, o), &out
}

func closeFrame(code int, reason string) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(code)), reason...)
}

func TestAMaskedTextMessageIsRead(t *testing.T) {
	c, _ := testConn(clientFrame(true, OpText, []byte("hello"), testKey), Options{})
	op, p, err := c.Read()
	if err != nil || op != OpText || string(p) != "hello" {
		t.Fatalf("Read = %d %q %v", op, p, err)
	}
}

func TestAFragmentedMessageWithAPingBetweenItsFragmentsIsReassembled(t *testing.T) {
	// §5.4: control frames may come in the middle of a fragmented
	// message, and a fragment may end inside a UTF-8 character.
	text := []byte("한글 text")
	var in []byte
	in = append(in, clientFrame(false, OpText, text[:2], testKey)...)
	in = append(in, clientFrame(true, opPing, []byte("p"), testKey)...)
	in = append(in, clientFrame(false, opContinuation, text[2:5], testKey)...)
	in = append(in, clientFrame(true, opContinuation, text[5:], testKey)...)
	c, out := testConn(in, Options{})
	op, p, err := c.Read()
	if err != nil || op != OpText || !bytes.Equal(p, text) {
		t.Fatalf("Read = %d %q %v", op, p, err)
	}
	if op, p := readServer(t, out); op != opPong || string(p) != "p" {
		t.Fatalf("the ping was answered with %d %q, want a pong with its payload", op, p)
	}
}

func TestPongsAreCounted(t *testing.T) {
	in := append(clientFrame(true, opPong, nil, testKey), clientFrame(true, OpBinary, []byte{1}, testKey)...)
	c, _ := testConn(in, Options{})
	if _, _, err := c.Read(); err != nil {
		t.Fatal(err)
	}
	if c.Pongs() != 1 {
		t.Fatalf("Pongs = %d, want 1", c.Pongs())
	}
}

func TestTheClientsCloseIsEchoedAndReported(t *testing.T) {
	c, out := testConn(clientFrame(true, opClose, closeFrame(StatusGoingAway, "bye"), testKey), Options{})
	_, _, err := c.Read()
	if code, ok := CloseStatus(err); !ok || code != StatusGoingAway {
		t.Fatalf("Read = %v, want the client's 1001", err)
	}
	op, p := readServer(t, out)
	if op != opClose || binary.BigEndian.Uint16(p) != StatusGoingAway {
		t.Fatalf("answered with %d %x, want a Close with 1001", op, p)
	}
	if err := c.WriteText([]byte("late")); !errors.Is(err, ErrClosed) {
		t.Fatalf("a write after the Close = %v, want ErrClosed", err)
	}
	if out.Len() != 0 {
		t.Fatalf("%d bytes were written after the Close", out.Len())
	}
}

func TestAnEmptyCloseIsEchoedEmpty(t *testing.T) {
	c, out := testConn(clientFrame(true, opClose, nil, testKey), Options{})
	_, _, err := c.Read()
	if code, ok := CloseStatus(err); !ok || code != 1005 {
		t.Fatalf("Read = %v, want 1005 (no status)", err)
	}
	if op, p := readServer(t, out); op != opClose || len(p) != 0 {
		t.Fatalf("answered with %d %x, want an empty Close", op, p)
	}
}

// Every frame RFC 6455 forbids a client to send fails the connection
// with the status §7.4.1 gives it, in a Close sent before Read returns.
func TestFramesTheClientMayNotSendFailTheConnection(t *testing.T) {
	long := bytes.Repeat([]byte("a"), DefaultMaxMessage+1)
	for _, tc := range []struct {
		name string
		in   []byte
		code int
	}{
		{"unmasked", []byte{0x81, 0x01, 'a'}, StatusProtocolError},
		{"reserved bit", func() []byte { f := clientFrame(true, OpText, []byte("a"), testKey); f[0] |= 0x40; return f }(), StatusProtocolError},
		{"reserved opcode", clientFrame(true, 0x3, nil, testKey), StatusProtocolError},
		{"reserved control opcode", clientFrame(true, 0xB, nil, testKey), StatusProtocolError},
		{"fragmented ping", clientFrame(false, opPing, nil, testKey), StatusProtocolError},
		{"ping over 125 bytes", clientFrame(true, opPing, bytes.Repeat([]byte("a"), 126), testKey), StatusProtocolError},
		{"16-bit length below 126", append([]byte{0x81, 0x80 | 126, 0, 5}, testKey[:]...), StatusProtocolError},
		{"64-bit length below 65536", append([]byte{0x81, 0x80 | 127, 0, 0, 0, 0, 0, 0, 0, 5}, testKey[:]...), StatusProtocolError},
		{"64-bit length with its top bit set", append([]byte{0x81, 0x80 | 127, 0x80, 0, 0, 0, 0, 0, 0, 0}, testKey[:]...), StatusProtocolError},
		{"continuation first", clientFrame(true, opContinuation, []byte("a"), testKey), StatusProtocolError},
		{"new message inside a fragmented one", append(clientFrame(false, OpText, []byte("a"), testKey), clientFrame(true, OpText, []byte("b"), testKey)...), StatusProtocolError},
		{"text that is not UTF-8", clientFrame(true, OpText, []byte{0xff, 0xfe}, testKey), StatusInvalidPayload},
		{"text whose last fragment leaves a character unfinished", append(clientFrame(false, OpText, []byte("a"), testKey), clientFrame(true, opContinuation, []byte{0xe2, 0x82}, testKey)...), StatusInvalidPayload},
		{"message over the bound", clientFrame(true, OpBinary, long, testKey), StatusTooBig},
		{"fragments over the bound together", append(clientFrame(false, OpBinary, long[:10], testKey), clientFrame(true, opContinuation, long[10:], testKey)...), StatusTooBig},
		{"close of one byte", clientFrame(true, opClose, []byte{3}, testKey), StatusProtocolError},
		{"close with 1005", clientFrame(true, opClose, closeFrame(1005, ""), testKey), StatusProtocolError},
		{"close with 1006", clientFrame(true, opClose, closeFrame(1006, ""), testKey), StatusProtocolError},
		{"close with 999", clientFrame(true, opClose, closeFrame(999, ""), testKey), StatusProtocolError},
		{"close with 2999", clientFrame(true, opClose, closeFrame(2999, ""), testKey), StatusProtocolError},
		{"close with 5000", clientFrame(true, opClose, closeFrame(5000, ""), testKey), StatusProtocolError},
		{"close reason that is not UTF-8", clientFrame(true, opClose, closeFrame(StatusNormal, "\xff"), testKey), StatusInvalidPayload},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, out := testConn(tc.in, Options{})
			_, _, err := c.Read()
			if code, ok := CloseStatus(err); !ok || code != tc.code {
				t.Fatalf("Read = %v, want the connection failed with %d", err, tc.code)
			}
			op, p := readServer(t, out)
			if op != opClose || len(p) < 2 || int(binary.BigEndian.Uint16(p)) != tc.code {
				t.Fatalf("sent %d %x, want a Close with %d", op, p, tc.code)
			}
		})
	}
}

func TestStatusesAClientMaySendAreAccepted(t *testing.T) {
	for _, code := range []int{1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 4999} {
		c, _ := testConn(clientFrame(true, opClose, closeFrame(code, "r"), testKey), Options{})
		if _, _, err := c.Read(); func() bool { got, ok := CloseStatus(err); return !ok || got != code }() {
			t.Errorf("a Close with %d: Read = %v", code, err)
		}
	}
}

func TestAStreamThatEndsInsideAFrameIsAnUnexpectedEOF(t *testing.T) {
	f := clientFrame(true, OpText, []byte("hello"), testKey)
	for cut := 1; cut < len(f); cut++ {
		c, _ := testConn(f[:cut], Options{})
		if _, _, err := c.Read(); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("cut at %d: Read = %v, want io.ErrUnexpectedEOF", cut, err)
		}
	}
	c, _ := testConn(nil, Options{})
	if _, _, err := c.Read(); err != io.EOF {
		t.Fatalf("an empty stream: Read = %v, want io.EOF", err)
	}
}

func TestServerFramesUseTheShortestLength(t *testing.T) {
	for _, n := range []int{0, 125, 126, 65535, 65536} {
		c, out := testConn(nil, Options{})
		if err := c.WriteText(bytes.Repeat([]byte("x"), n)); err != nil {
			t.Fatal(err)
		}
		want := 2
		switch {
		case n > 65535:
			want = 10
		case n > 125:
			want = 4
		}
		if got := out.Len() - n; got != want {
			t.Errorf("a %d-byte message has a %d-byte header, want %d", n, got, want)
		}
		if op, p := readServer(t, out); op != OpText || len(p) != n {
			t.Errorf("a %d-byte message reads back as %d, %d bytes", n, op, len(p))
		}
	}
}

func TestACloseReasonIsCutToFitTheFrameAtACharacter(t *testing.T) {
	c, out := testConn(nil, Options{})
	if err := c.Close(StatusPolicy, strings.Repeat("가", 60)); err != nil {
		t.Fatal(err)
	}
	op, p := readServer(t, out)
	if op != opClose || len(p) > maxControlPayload || binary.BigEndian.Uint16(p) != StatusPolicy {
		t.Fatalf("Close sent %d with %d bytes", op, len(p))
	}
	if !strings.HasPrefix(strings.Repeat("가", 60), string(p[2:])) || len(p[2:])%3 != 0 {
		t.Fatalf("the reason was cut inside a character: %x", p[2:])
	}
	// An ASCII reason keeps all the room the frame has: 123 bytes.
	c, out = testConn(nil, Options{})
	_ = c.Close(StatusPolicy, strings.Repeat("r", 200))
	if _, p := readServer(t, out); len(p) != maxControlPayload {
		t.Fatalf("a Close of %d bytes, want %d", len(p), maxControlPayload)
	}
}

func TestPingRefusesAPayloadOver125Bytes(t *testing.T) {
	c, out := testConn(nil, Options{})
	if err := c.Ping(make([]byte, 126)); err == nil {
		t.Fatal("Ping took 126 bytes")
	}
	if err := c.Ping([]byte("1")); err != nil {
		t.Fatal(err)
	}
	if op, p := readServer(t, out); op != opPing || string(p) != "1" {
		t.Fatalf("sent %d %q", op, p)
	}
}

func TestAcceptKeyIsTheRFCsExample(t *testing.T) {
	// §1.3's worked example.
	if got := AcceptKey("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("AcceptKey = %q", got)
	}
}

func TestHasTokenReadsHeaderLists(t *testing.T) {
	for _, tc := range []struct {
		values []string
		want   bool
	}{
		{[]string{"Upgrade"}, true},
		{[]string{"keep-alive, Upgrade"}, true},
		{[]string{"keep-alive", " upgrade\t"}, true},
		{[]string{"upgrades"}, false},
		{[]string{"keep-alive"}, false},
		{nil, false},
	} {
		if got := HasToken(tc.values, "upgrade"); got != tc.want {
			t.Errorf("HasToken(%q) = %v", tc.values, got)
		}
	}
}

// upgradeServer runs Upgrade behind an httptest server; each accepted
// connection's messages are echoed back as text until Read fails.
func upgradeServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := Upgrade(w, r, Options{})
		var he *HandshakeError
		if errors.As(err, &he) {
			http.Error(w, he.Reason, he.Status)
			return
		}
		if err != nil {
			return
		}
		defer c.Shutdown()
		for {
			_, p, err := c.Read()
			if err != nil {
				return
			}
			if err := c.WriteText(p); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func handshake(t *testing.T, srv *httptest.Server, header http.Header) (*http.Response, net.Conn, *bufio.Reader) {
	t.Helper()
	nc, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	_ = nc.SetDeadline(time.Now().Add(10 * time.Second))
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.Header = header
	if err := req.Write(nc); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(nc)
	res, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	return res, nc, br
}

func goodHeader() http.Header {
	return http.Header{
		"Upgrade":               {"websocket"},
		"Connection":            {"keep-alive, Upgrade"},
		"Sec-Websocket-Version": {"13"},
		"Sec-Websocket-Key":     {"dGhlIHNhbXBsZSBub25jZQ=="},
	}
}

func TestTheOpeningHandshakeIsAnsweredWith101AndTheAcceptKey(t *testing.T) {
	srv := upgradeServer(t)
	res, nc, br := handshake(t, srv, goodHeader())
	if res.StatusCode != http.StatusSwitchingProtocols ||
		res.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" ||
		!HasToken(res.Header.Values("Upgrade"), "websocket") || !HasToken(res.Header.Values("Connection"), "upgrade") {
		t.Fatalf("answered %d %v", res.StatusCode, res.Header)
	}
	// No extension and no subprotocol is ever accepted.
	if res.Header.Get("Sec-WebSocket-Extensions") != "" || res.Header.Get("Sec-WebSocket-Protocol") != "" {
		t.Fatalf("answered with %v", res.Header)
	}
	if _, err := nc.Write(clientFrame(true, OpText, []byte("echo"), testKey)); err != nil {
		t.Fatal(err)
	}
	if op, p := readServer(t, br); op != OpText || string(p) != "echo" {
		t.Fatalf("got %d %q", op, p)
	}
}

func TestAFrameSentWithTheHandshakeIsNotLost(t *testing.T) {
	// A client may write its first frame right behind the request; the
	// server's buffered reader already holds it when the connection is
	// taken over.
	srv := upgradeServer(t)
	nc, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	_ = nc.SetDeadline(time.Now().Add(10 * time.Second))
	var b bytes.Buffer
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.Header = goodHeader()
	_ = req.Write(&b)
	b.Write(clientFrame(true, OpText, []byte("early"), testKey))
	if _, err := nc.Write(b.Bytes()); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(nc)
	if res, err := http.ReadResponse(br, req); err != nil || res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("handshake: %v", err)
	}
	if op, p := readServer(t, br); op != OpText || string(p) != "early" {
		t.Fatalf("got %d %q", op, p)
	}
}

func TestHandshakesThatAreNotVersion13WebSocketsAreRefused(t *testing.T) {
	srv := upgradeServer(t)
	for _, tc := range []struct {
		name   string
		change func(http.Header)
		status int
	}{
		{"no Upgrade", func(h http.Header) { h.Del("Upgrade") }, http.StatusUpgradeRequired},
		{"Upgrade of another protocol", func(h http.Header) { h.Set("Upgrade", "h2c") }, http.StatusUpgradeRequired},
		{"no upgrade in Connection", func(h http.Header) { h.Set("Connection", "keep-alive") }, http.StatusBadRequest},
		{"version 8", func(h http.Header) { h.Set("Sec-Websocket-Version", "8") }, http.StatusUpgradeRequired},
		{"no key", func(h http.Header) { h.Del("Sec-Websocket-Key") }, http.StatusBadRequest},
		{"two keys", func(h http.Header) { h.Add("Sec-Websocket-Key", "dGhlIHNhbXBsZSBub25jZQ==") }, http.StatusBadRequest},
		{"a key of 15 bytes", func(h http.Header) { h.Set("Sec-Websocket-Key", "AAAAAAAAAAAAAAAAAAAA") }, http.StatusBadRequest},
		{"a key that is not base64", func(h http.Header) { h.Set("Sec-Websocket-Key", "not base64!") }, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := goodHeader()
			tc.change(h)
			res, _, _ := handshake(t, srv, h)
			if res.StatusCode != tc.status {
				t.Fatalf("answered %d, want %d", res.StatusCode, tc.status)
			}
			// §4.4: a version it does not take is answered with the
			// one it does.
			if tc.status == http.StatusUpgradeRequired && res.Header.Get("Sec-WebSocket-Version") != "13" {
				t.Fatalf("426 without Sec-WebSocket-Version: 13: %v", res.Header)
			}
		})
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/", nil)
	req.Header = goodHeader()
	if res, err := http.DefaultClient.Do(req); err != nil || res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("a POST handshake: %v %v", res, err)
	}
}
