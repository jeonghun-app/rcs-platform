package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

const streamBufferSize = 4096

var crlf = []byte("\r\n")

// deadlineReader moves the read deadline of a stream connection between two
// regimes. Between messages the connection may stay quiet for the idle timeout,
// and every keep-alive starts that period again. Once a byte other than CR or LF
// arrives a message has started, and the rest of it must arrive within the read
// timeout counted from that byte, however it is split across reads: a peer that
// trickles a header one byte at a time is cut off after ReadTimeout, not kept for
// ReadTimeout per byte.
type deadlineReader struct {
	conn       net.Conn
	idle, read time.Duration
	inMessage  bool
	armed      bool
}

func (d *deadlineReader) Read(p []byte) (int, error) {
	if !d.armed {
		timeout := d.idle
		if d.inMessage {
			timeout = d.read
		}
		if err := d.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return 0, err
		}
		d.armed = true
	}
	n, err := d.conn.Read(p)
	if !d.inMessage && hasNonCRLF(p[:n]) {
		d.startMessage()
	}
	return n, err
}

func (d *deadlineReader) startMessage() {
	d.inMessage, d.armed = true, false
}

// betweenMessages restarts the idle period, unless the bytes already buffered
// have begun the next message.
func (d *deadlineReader) betweenMessages(br *bufio.Reader) {
	d.inMessage, d.armed = false, false
	if b, _ := br.Peek(br.Buffered()); hasNonCRLF(b) {
		d.startMessage()
	}
}

func hasNonCRLF(b []byte) bool {
	for _, c := range b {
		if c != '\r' && c != '\n' {
			return true
		}
	}
	return false
}

// serveStream reads messages from a stream flow until the connection fails, then
// closes it. Any error leaves the stream position unknown, so the connection is
// closed rather than resynchronised (RFC 3261 §18.3).
func (t *Transport) serveStream(f *flow) {
	defer t.closeFlow(f)
	d := &deadlineReader{conn: f.conn, idle: t.cfg.IdleTimeout, read: t.cfg.ReadTimeout}
	br := bufio.NewReaderSize(d, streamBufferSize)
	r := sip.NewReader(br, t.cfg.Limits)
	r.OnKeepAlive = func() {
		// RFC 5626 §5.4: answer a double-CRLF ping with a single CRLF pong at once.
		// The write is bounded by WriteTimeout; a peer that pings but does not
		// read loses its connection, as it would for any other write.
		t.stats.keepAlives.Add(1)
		t.write(f, crlf)
		d.betweenMessages(br)
	}
	for {
		msg, err := r.ReadMessage()
		if err != nil {
			t.countReadError(err, d.inMessage)
			return
		}
		d.betweenMessages(br)
		t.deliver(f, msg)
	}
}

func (t *Transport) countReadError(err error, inMessage bool) {
	var ne net.Error
	var pe *sip.ParseError
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
	case errors.As(err, &ne) && ne.Timeout():
		if inMessage {
			t.stats.readTimeouts.Add(1)
		} else {
			t.stats.idleTimeouts.Add(1)
		}
	case errors.As(err, &pe), errors.Is(err, io.ErrUnexpectedEOF):
		// A message cut short by the peer closing is as unframeable as a
		// malformed one.
		t.stats.framingErrors.Add(1)
	}
}

// write sends b on a stream or UDP flow. A stream connection is closed on any
// write error, since the peer may have received part of a message and cannot
// find the start of the next.
func (t *Transport) write(f *flow, b []byte) error {
	if f.conn == nil {
		return t.sendDatagram(f.lis, f.remote, b)
	}
	f.wmu.Lock()
	defer f.wmu.Unlock()
	if f.closed.Load() {
		return ErrNoFlow
	}
	err := f.conn.SetWriteDeadline(time.Now().Add(t.cfg.WriteTimeout))
	if err == nil {
		_, err = f.conn.Write(b)
	}
	if err != nil {
		t.stats.writeErrors.Add(1)
		t.closeFlow(f)
		return fmt.Errorf("transport: writing to %s connection: %w", f.network, err)
	}
	return nil
}

// streamTo returns an open connection to a peer, reusing one when there is one
// (RFC 3261 §18.1.1) and otherwise dialing. Concurrent callers for the same peer
// share one dial, so a burst of requests to a core node opens one connection.
func (t *Transport) streamTo(network Network, addr netip.AddrPort, serverName string) (*flow, error) {
	k := reuseKey{network: network, remote: addr}
	if network == TLS {
		k.serverName = serverName
	}
	if f := t.flows.peer(k); f != nil {
		return f, nil
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, ErrClosed
	}
	if d := t.dialing[k]; d != nil {
		t.mu.Unlock()
		<-d.done
		return d.f, d.err
	}
	// A dial that finished since the check above has entered its flow before
	// leaving t.dialing, so looking again under the lock closes the window.
	if f := t.flows.peer(k); f != nil {
		t.mu.Unlock()
		return f, nil
	}
	d := &dialCall{done: make(chan struct{})}
	t.dialing[k] = d
	t.mu.Unlock()

	d.f, d.err = t.dial(k)

	t.mu.Lock()
	delete(t.dialing, k)
	t.mu.Unlock()
	close(d.done)
	return d.f, d.err
}

func (t *Transport) dial(k reuseKey) (*flow, error) {
	ctx, cancel := context.WithTimeout(context.Background(), t.cfg.DialTimeout)
	defer cancel()
	c, err := t.cfg.Dialer.DialContext(ctx, "tcp", k.remote.String())
	if err != nil {
		t.stats.dialErrors.Add(1)
		return nil, fmt.Errorf("transport: connecting over %s: %w", k.network, err)
	}
	if k.network == TLS {
		cfg := &tls.Config{}
		if t.cfg.TLSClient != nil {
			cfg = t.cfg.TLSClient.Clone()
		}
		if k.serverName != "" {
			cfg.ServerName = k.serverName
		}
		tc := tls.Client(c, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			c.Close()
			t.stats.dialErrors.Add(1)
			return nil, fmt.Errorf("transport: TLS handshake: %w", err)
		}
		c = tc
	}
	f := t.flows.newFlow(k.network, nil, k.remote)
	f.serverName = k.serverName
	f.conn = c
	t.mu.Lock()
	closed := t.closed
	if !closed {
		t.wg.Add(1)
	}
	t.mu.Unlock()
	if closed || !t.flows.addStream(f) {
		if !closed {
			t.wg.Done()
		}
		c.Close()
		return nil, ErrClosed
	}
	t.stats.dialed.Add(1)
	go func() {
		defer t.wg.Done()
		t.serveStream(f)
	}()
	return f, nil
}
