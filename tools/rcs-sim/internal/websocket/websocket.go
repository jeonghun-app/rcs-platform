// Package websocket is the server side of the WebSocket protocol (RFC 6455),
// as much of it as rcs-bridge's event stream needs (#658): the opening
// handshake, data messages from the client (whole or fragmented, text or
// binary), ping and pong, and the closing handshake. The bridge only writes
// text messages; what a client writes is read so that its control frames are
// answered and its protocol errors close the connection.
//
// No extension and no subprotocol is ever negotiated, so every frame must
// have its reserved bits clear (§5.2). Client frames must be masked (§5.1),
// server frames never are. A message is bounded by Options.MaxMessage before
// any of it is read into memory.
//
// The runtime's only dependencies are the standard library and the AWS SDK,
// so this is written here rather than taken from a library.
package websocket

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// Close status codes (RFC 6455 §7.4.1).
const (
	StatusNormal         = 1000
	StatusGoingAway      = 1001
	StatusProtocolError  = 1002
	StatusUnsupported    = 1003
	StatusInvalidPayload = 1007
	StatusPolicy         = 1008
	StatusTooBig         = 1009
	StatusInternalError  = 1011
)

// acceptGUID is the GUID the accept value is computed with (§1.3).
const acceptGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Defaults.
const (
	// DefaultMaxMessage bounds what a client may send in one message. The
	// event stream expects nothing from it, so a small bound costs nothing.
	DefaultMaxMessage = 4 << 10
	// DefaultWriteTimeout bounds one frame write, so that a client that
	// stops reading cannot hold its writer for ever.
	DefaultWriteTimeout = 10 * time.Second
	// closeWait is how long the connection waits for the client's Close
	// once it has sent its own (§7.1.1: the server closes the TCP
	// connection first, once the handshake is done).
	closeWait = 5 * time.Second
)

// Options configures a connection.
type Options struct {
	// MaxMessage is the largest message a client may send; zero is
	// DefaultMaxMessage. A larger one fails the connection with 1009.
	MaxMessage int
	// WriteTimeout bounds each write; zero is DefaultWriteTimeout.
	WriteTimeout time.Duration
}

// HandshakeError is an opening handshake Upgrade refused. Status is what
// it answered.
type HandshakeError struct {
	Status int
	Reason string
}

func (e *HandshakeError) Error() string {
	return fmt.Sprintf("websocket: handshake refused (%d): %s", e.Status, e.Reason)
}

// closeError is a close of the connection: the status the client sent, or
// the one this end failed the connection with (local).
type closeError struct {
	code   int
	reason string
	local  bool
}

func (e *closeError) Error() string {
	if e.local {
		return fmt.Sprintf("websocket: connection failed with %d: %s", e.code, e.reason)
	}
	return fmt.Sprintf("websocket: closed by the client with %d", e.code)
}

func protocolError(reason string) error {
	return &closeError{code: StatusProtocolError, reason: reason, local: true}
}

// CloseStatus returns the status of a close Read reported, and whether err
// is one: the client's, or the one the connection was failed with.
func CloseStatus(err error) (int, bool) {
	var ce *closeError
	if errors.As(err, &ce) {
		return ce.code, true
	}
	return 0, false
}

// ErrClosed is returned by writes once the connection has sent its Close.
var ErrClosed = errors.New("websocket: closed")

// Conn is a server's WebSocket connection. Read must be called from one
// goroutine at a time; the other methods are safe for concurrent use, also
// with Read.
type Conn struct {
	nc      net.Conn
	r       *bufio.Reader
	max     int
	timeout time.Duration
	pongs   atomic.Int64

	wmu       sync.Mutex
	w         io.Writer
	closeSent bool
	buf       []byte
}

// Upgrade answers a client's opening handshake (RFC 6455 §4.2) with 101
// and returns the connection. A request that is not a version 13
// handshake gets a *HandshakeError, and nothing is written but, for a 426,
// the header fields that name the version and protocol (§4.4): the caller
// answers with its Status, in its own format. Neither an extension nor a
// subprotocol is accepted. Origin is not checked: the bridge's clients are
// applications, not pages, and every request needs the bridge's token.
func Upgrade(w http.ResponseWriter, r *http.Request, o Options) (*Conn, error) {
	key, err := checkHandshake(r)
	if err != nil {
		var he *HandshakeError
		if errors.As(err, &he) && he.Status == http.StatusUpgradeRequired {
			w.Header().Set("Sec-WebSocket-Version", "13")
			w.Header().Set("Upgrade", "websocket")
		}
		return nil, err
	}
	// ResponseController follows Unwrap, so a ResponseWriter that wraps
	// the server's, to record its status say, still hands it over.
	nc, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "the connection cannot be taken over", http.StatusInternalServerError)
		return nil, err
	}
	// The server's read and write timeouts, if any, were set for one HTTP
	// exchange; the connection now lives as long as the stream.
	_ = nc.SetDeadline(time.Time{})
	c := newConn(nc, brw.Reader, nc, o)
	if _, err := io.WriteString(brw.Writer, "HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+AcceptKey(key)+"\r\n\r\n"); err != nil {
		nc.Close()
		return nil, err
	}
	_ = nc.SetWriteDeadline(time.Now().Add(c.timeout))
	if err := brw.Writer.Flush(); err != nil {
		nc.Close()
		return nil, err
	}
	return c, nil
}

// checkHandshake returns the client's Sec-WebSocket-Key once the request
// is a version 13 opening handshake (§4.2.1).
func checkHandshake(r *http.Request) (string, error) {
	switch {
	case r.Method != http.MethodGet:
		return "", &HandshakeError{Status: http.StatusMethodNotAllowed, Reason: "the opening handshake is a GET"}
	case !r.ProtoAtLeast(1, 1):
		return "", &HandshakeError{Status: http.StatusBadRequest, Reason: "the opening handshake needs HTTP/1.1"}
	case !HasToken(r.Header.Values("Upgrade"), "websocket"):
		return "", &HandshakeError{Status: http.StatusUpgradeRequired, Reason: "this resource is a WebSocket: Upgrade: websocket"}
	case !HasToken(r.Header.Values("Connection"), "upgrade"):
		return "", &HandshakeError{Status: http.StatusBadRequest, Reason: "Connection must include upgrade"}
	case r.Header.Get("Sec-WebSocket-Version") != "13":
		// §4.4: answer with the versions this server takes.
		return "", &HandshakeError{Status: http.StatusUpgradeRequired, Reason: "Sec-WebSocket-Version must be 13"}
	}
	keys := r.Header.Values("Sec-WebSocket-Key")
	if len(keys) != 1 {
		return "", &HandshakeError{Status: http.StatusBadRequest, Reason: "exactly one Sec-WebSocket-Key is needed"}
	}
	key := strings.TrimSpace(keys[0])
	// §4.1: the key is 16 random bytes, base64-encoded.
	if b, err := base64.StdEncoding.DecodeString(key); err != nil || len(b) != 16 {
		return "", &HandshakeError{Status: http.StatusBadRequest, Reason: "Sec-WebSocket-Key is not 16 bytes in base64"}
	}
	return key, nil
}

// AcceptKey is the Sec-WebSocket-Accept value for a client's key (§4.2.2).
func AcceptKey(key string) string {
	h := sha1.Sum([]byte(key + acceptGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// HasToken reports whether the comma-separated header values hold token,
// compared without case (RFC 9110 §5.6.1, §7.6.1: Connection and Upgrade
// are lists).
func HasToken(values []string, token string) bool {
	for _, v := range values {
		for t := range strings.SplitSeq(v, ",") {
			if strings.EqualFold(strings.Trim(t, " \t"), token) {
				return true
			}
		}
	}
	return false
}

func newConn(nc net.Conn, r io.Reader, w io.Writer, o Options) *Conn {
	if o.MaxMessage <= 0 {
		o.MaxMessage = DefaultMaxMessage
	}
	if o.WriteTimeout <= 0 {
		o.WriteTimeout = DefaultWriteTimeout
	}
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	return &Conn{nc: nc, r: br, w: w, max: o.MaxMessage, timeout: o.WriteTimeout}
}

// Read returns the next data message, its opcode (OpText or OpBinary) and
// payload. It answers each ping with a pong and counts each pong (Pongs).
// When the client closes, Read answers with a Close of the same status
// (§5.5.1) and returns an error for which CloseStatus reports it; when the
// client breaks the protocol, Read fails the connection with a Close of
// the matching status (§7.1.7) and returns such an error too. Any other
// error is the connection's. After an error the caller closes the
// connection.
func (c *Conn) Read() (byte, []byte, error) {
	var (
		msg     []byte
		op      byte
		started bool
	)
	for {
		h, err := readHeader(c.r)
		if err != nil {
			return 0, nil, c.fail(err)
		}
		// Bounded before anything is read: the length is the client's.
		if !isControl(h.opcode) && h.length > uint64(c.max-len(msg)) {
			return 0, nil, c.fail(&closeError{code: StatusTooBig, reason: "message too big", local: true})
		}
		payload := make([]byte, h.length)
		if _, err := io.ReadFull(c.r, payload); err != nil {
			return 0, nil, c.fail(unexpected(err))
		}
		unmask(payload, h.mask)
		switch h.opcode {
		case opPing:
			if err := c.write(opPong, payload); err != nil && !errors.Is(err, ErrClosed) {
				return 0, nil, err
			}
			continue
		case opPong:
			c.pongs.Add(1)
			continue
		case opClose:
			return 0, nil, c.closed(payload)
		case opContinuation:
			if !started {
				return 0, nil, c.fail(protocolError("continuation without a message"))
			}
		default:
			// §5.4: a new data frame while a message is in progress is
			// an error; control frames may come between its fragments.
			if started {
				return 0, nil, c.fail(protocolError("data frame inside a fragmented message"))
			}
			started, op = true, h.opcode
		}
		msg = append(msg, payload...)
		if !h.fin {
			continue
		}
		// §8.1: a text message is UTF-8 as a whole; a fragment may end
		// inside a character.
		if op == OpText && !utf8.Valid(msg) {
			return 0, nil, c.fail(&closeError{code: StatusInvalidPayload, reason: "text is not UTF-8", local: true})
		}
		return op, msg, nil
	}
}

// fail sends the Close of a protocol error, if err is one, and returns
// err.
func (c *Conn) fail(err error) error {
	var ce *closeError
	if errors.As(err, &ce) && ce.local {
		_ = c.sendClose(ce.code, ce.reason)
	}
	return err
}

// closed answers the client's Close and returns its status (§5.5.1,
// §7.4). A status that may not be sent, or a reason that is not UTF-8,
// fails the connection instead.
func (c *Conn) closed(payload []byte) error {
	switch {
	case len(payload) == 0:
		// No status: 1005 to this end (§7.1.5), and the Close echoed
		// without one.
		_ = c.sendClosePayload(nil)
		return &closeError{code: 1005}
	case len(payload) == 1:
		return c.fail(protocolError("close payload of one byte"))
	}
	code := int(binary.BigEndian.Uint16(payload))
	if !sendable(code) {
		return c.fail(protocolError("close status that may not be sent"))
	}
	if !utf8.Valid(payload[2:]) {
		return c.fail(&closeError{code: StatusInvalidPayload, reason: "close reason is not UTF-8", local: true})
	}
	_ = c.sendClose(code, "")
	return &closeError{code: code, reason: string(payload[2:])}
}

// sendable reports whether code may be sent in a Close (§7.4.1, §7.4.2,
// and the IANA registry's 1012-1014).
func sendable(code int) bool {
	switch {
	case code >= 1000 && code <= 1003, code >= 1007 && code <= 1014:
		return true
	case code >= 3000 && code <= 4999:
		return true
	}
	return false
}

// WriteText sends p as one text message. p must be UTF-8.
func (c *Conn) WriteText(p []byte) error { return c.write(OpText, p) }

// Ping sends a ping with payload p, at most 125 bytes.
func (c *Conn) Ping(p []byte) error {
	if len(p) > maxControlPayload {
		return errors.New("websocket: ping payload over 125 bytes")
	}
	return c.write(opPing, p)
}

// Pongs is how many pongs the client has sent.
func (c *Conn) Pongs() int64 { return c.pongs.Load() }

// Close starts the closing handshake with code and reason, then waits a
// while for the client's Close from Read, which the caller keeps calling
// until it fails. The caller closes the connection with Shutdown once
// Read has returned.
func (c *Conn) Close(code int, reason string) error {
	err := c.sendClose(code, reason)
	if c.nc != nil {
		_ = c.nc.SetReadDeadline(time.Now().Add(closeWait))
	}
	return err
}

// Shutdown closes the underlying connection at once.
func (c *Conn) Shutdown() error {
	if c.nc == nil {
		return nil
	}
	return c.nc.Close()
}

func (c *Conn) sendClose(code int, reason string) error {
	// A reason is cut to fit the control frame, at a character boundary.
	for len(reason) > maxControlPayload-2 {
		_, n := utf8.DecodeLastRuneInString(reason)
		reason = reason[:len(reason)-n]
	}
	p := binary.BigEndian.AppendUint16(nil, uint16(code))
	return c.sendClosePayload(append(p, reason...))
}

// sendClosePayload sends a Close once; nothing is sent after it (§5.5.1).
func (c *Conn) sendClosePayload(p []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closeSent {
		return ErrClosed
	}
	err := c.writeLocked(opClose, p)
	c.closeSent = true
	return err
}

func (c *Conn) write(op byte, p []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closeSent {
		return ErrClosed
	}
	return c.writeLocked(op, p)
}

func (c *Conn) writeLocked(op byte, p []byte) error {
	c.buf = appendFrame(c.buf[:0], op, p)
	if c.nc != nil {
		_ = c.nc.SetWriteDeadline(time.Now().Add(c.timeout))
	}
	_, err := c.w.Write(c.buf)
	if cap(c.buf) > 64<<10 {
		c.buf = nil
	}
	return err
}
