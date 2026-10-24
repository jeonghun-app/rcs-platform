// Package wstest is a WebSocket client for tests of the bridge's event
// stream (RFC 6455 client side, text frames, ping and pong, close). It is
// written apart from package websocket, from the RFC, so that the server's
// tests do not check the server against itself.
package wstest

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// Client is one connection's client end.
type Client struct {
	nc net.Conn
	r  *bufio.Reader
	// NoPong, set before Next is called, leaves pings unanswered, as a
	// client that has gone away would.
	NoPong bool
	pings  atomic.Int64
	pongs  atomic.Int64
	wmu    sync.Mutex
}

// Pings is how many pings Next has read.
func (c *Client) Pings() int64 { return c.pings.Load() }

// Pongs is how many pongs Next has read.
func (c *Client) Pongs() int64 { return c.pongs.Load() }

// Ping sends a ping; Next counts its pong.
func (c *Client) Ping() error { return c.write(0x9, []byte("wstest")) }

// CloseError is the server's Close.
type CloseError struct {
	Code   int
	Reason string
}

func (e *CloseError) Error() string {
	return fmt.Sprintf("wstest: closed with %d: %s", e.Code, e.Reason)
}

// Dial opens a WebSocket to rawURL (http:// or ws://) with header added to
// the handshake. A handshake the server refuses returns its response and
// an error.
func Dial(rawURL string, header http.Header) (*Client, *http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, err
	}
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "http":
	default:
		return nil, nil, errors.New("wstest: only http and ws URLs")
	}
	nc, err := net.DialTimeout("tcp", u.Host, 10*time.Second)
	if err != nil {
		return nil, nil, err
	}
	var key [16]byte
	_, _ = rand.Read(key[:])
	k := base64.StdEncoding.EncodeToString(key[:])
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		nc.Close()
		return nil, nil, err
	}
	for name, vs := range header {
		req.Header[name] = vs
	}
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", k)
	_ = nc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := req.Write(nc); err != nil {
		nc.Close()
		return nil, nil, err
	}
	br := bufio.NewReader(nc)
	res, err := http.ReadResponse(br, req)
	if err != nil {
		nc.Close()
		return nil, nil, err
	}
	sum := sha1.Sum([]byte(k + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if res.StatusCode != http.StatusSwitchingProtocols || res.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) {
		nc.Close()
		return nil, res, fmt.Errorf("wstest: handshake answered %d", res.StatusCode)
	}
	_ = nc.SetDeadline(time.Time{})
	return &Client{nc: nc, r: br}, res, nil
}

// Next returns the next text message within timeout, answering pings
// (unless NoPong) on the way. The server's Close is a *CloseError, after
// which Next has answered it.
func (c *Client) Next(timeout time.Duration) ([]byte, error) {
	_ = c.nc.SetReadDeadline(time.Now().Add(timeout))
	for {
		op, p, err := c.frame()
		if err != nil {
			return nil, err
		}
		switch op {
		case 0x1:
			return p, nil
		case 0x9:
			c.pings.Add(1)
			if !c.NoPong {
				if err := c.write(0xA, p); err != nil {
					return nil, err
				}
			}
		case 0xA:
			c.pongs.Add(1)
		case 0x8:
			ce := &CloseError{Code: 1005}
			if len(p) >= 2 {
				ce.Code, ce.Reason = int(binary.BigEndian.Uint16(p)), string(p[2:])
			}
			_ = c.write(0x8, p[:min(len(p), 2)])
			return nil, ce
		default:
			return nil, fmt.Errorf("wstest: unexpected opcode %d", op)
		}
	}
}

// frame reads one server frame, which must be final and unmasked.
func (c *Client) frame() (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(c.r, h[:]); err != nil {
		return 0, nil, err
	}
	if h[0]&0x80 == 0 || h[0]&0x70 != 0 || h[1]&0x80 != 0 {
		return 0, nil, fmt.Errorf("wstest: server frame header %x", h)
	}
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var l [2]byte
		if _, err := io.ReadFull(c.r, l[:]); err != nil {
			return 0, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(l[:]))
	case 127:
		var l [8]byte
		if _, err := io.ReadFull(c.r, l[:]); err != nil {
			return 0, nil, err
		}
		n = binary.BigEndian.Uint64(l[:])
	}
	if n > 1<<20 {
		return 0, nil, errors.New("wstest: a frame over 1 MiB")
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(c.r, p); err != nil {
		return 0, nil, err
	}
	return h[0] & 0x0f, p, nil
}

// write sends one final, masked frame (RFC 6455 §5.3).
func (c *Client) write(op byte, p []byte) error {
	var key [4]byte
	_, _ = rand.Read(key[:])
	b := []byte{0x80 | op}
	switch n := len(p); {
	case n < 126:
		b = append(b, 0x80|byte(n))
	case n < 1<<16:
		b = append(b, 0x80|126)
		b = binary.BigEndian.AppendUint16(b, uint16(n))
	default:
		b = append(b, 0x80|127)
		b = binary.BigEndian.AppendUint64(b, uint64(n))
	}
	b = append(b, key[:]...)
	for i, x := range p {
		b = append(b, x^key[i%4])
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.nc.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := c.nc.Write(b)
	return err
}

// Drop closes the connection without a Close, as a client that vanishes.
func (c *Client) Drop() error { return c.nc.Close() }

// Close sends a Close with code and closes the connection.
func (c *Client) Close(code int) error {
	_ = c.write(0x8, binary.BigEndian.AppendUint16(nil, uint16(code)))
	return c.nc.Close()
}
