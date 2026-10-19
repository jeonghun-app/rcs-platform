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
	"sync"
	"sync/atomic"
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
//
// An accepted connection starts in a third regime: until its first message is
// complete, the read timeout runs from the start and keep-alives do not restart
// it, so a connection that never sends a message gives back its MaxConnections
// slot after ReadTimeout rather than IdleTimeout.
//
// The idle timeout is the flow's, which Transport.SetFlowIdleTimeout may change
// while an idle period runs; mu guards the state it reads against the reading
// goroutine.
type deadlineReader struct {
	conn net.Conn
	read time.Duration
	idle *atomic.Int64 // the flow's idle timeout, in nanoseconds

	mu        sync.Mutex
	inMessage bool
	// beforeFirst is true until the first message of an accepted connection is
	// complete.
	beforeFirst bool
	armed       bool
	// idleSince is when the current idle period began, once it is armed.
	idleSince time.Time
}

func newDeadlineReader(conn net.Conn, idle *atomic.Int64, read time.Duration, beforeFirst bool) *deadlineReader {
	return &deadlineReader{conn: conn, idle: idle, read: read, beforeFirst: beforeFirst}
}

// strict reports whether the read timeout, not the idle timeout, applies now.
func (d *deadlineReader) strict() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.strictLocked()
}

func (d *deadlineReader) strictLocked() bool { return d.inMessage || d.beforeFirst }

func (d *deadlineReader) Read(p []byte) (int, error) {
	if err := d.arm(); err != nil {
		return 0, err
	}
	n, err := d.conn.Read(p)
	if hasNonCRLF(p[:n]) {
		d.mu.Lock()
		if !d.inMessage {
			d.startMessageLocked()
		}
		d.mu.Unlock()
	}
	return n, err
}

// arm sets the deadline at the start of a regime.
func (d *deadlineReader) arm() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.armed {
		return nil
	}
	now := time.Now()
	timeout := d.read
	if !d.strictLocked() {
		timeout = time.Duration(d.idle.Load())
		d.idleSince = now
	}
	d.armed = true
	return d.conn.SetReadDeadline(now.Add(timeout))
}

// retime applies a changed idle timeout to the idle period now running, counted
// from its start, so a shorter one can end it at once.
func (d *deadlineReader) retime() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.armed && !d.strictLocked() {
		d.conn.SetReadDeadline(d.idleSince.Add(time.Duration(d.idle.Load())))
	}
}

func (d *deadlineReader) startMessageLocked() {
	// Before the first message the deadline already runs from the start.
	if !d.beforeFirst {
		d.armed = false
	}
	d.inMessage = true
}

// keepAlive restarts the idle period after a ping, except before the first
// message.
func (d *deadlineReader) keepAlive(br *bufio.Reader) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.beforeFirst {
		d.betweenMessagesLocked(br)
	}
}

// messageDone ends the first-message regime and restarts the idle period, unless
// the bytes already buffered have begun the next message.
func (d *deadlineReader) messageDone(br *bufio.Reader) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.beforeFirst = false
	d.betweenMessagesLocked(br)
}

func (d *deadlineReader) betweenMessagesLocked(br *bufio.Reader) {
	d.inMessage, d.armed = false, false
	if b, _ := br.Peek(br.Buffered()); hasNonCRLF(b) {
		d.startMessageLocked()
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
func (t *Transport) serveStream(f *flow, accepted bool) {
	defer t.closeFlow(f)
	d := newDeadlineReader(f.conn, &f.idle, t.cfg.ReadTimeout, accepted)
	f.dr.Store(d)
	br := bufio.NewReaderSize(d, streamBufferSize)
	r := sip.NewReader(br, t.cfg.Limits)
	r.OnKeepAlive = func() {
		// RFC 5626 §5.4: answer a double-CRLF ping with a single CRLF pong at once.
		// It is queued without waiting, like everything sent from this
		// goroutine; a peer that pings but does not read loses its connection
		// once its queue is full.
		t.stats.keepAlives.Add(1)
		t.write(f, crlf, false)
		d.keepAlive(br)
	}
	for {
		msg, err := r.ReadMessage()
		if err != nil {
			t.countReadError(err, d.strict())
			return
		}
		d.messageDone(br)
		t.deliver(f, msg)
	}
}

func (t *Transport) countReadError(err error, strict bool) {
	var ne net.Error
	var pe *sip.ParseError
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
	case errors.As(err, &ne) && ne.Timeout():
		if strict {
			t.stats.readTimeouts.Add(1)
		} else {
			t.stats.idleTimeouts.Add(1)
		}
	case errors.As(err, &pe):
		t.stats.framingErrors.Add(1)
	case errors.Is(err, io.ErrUnexpectedEOF):
		// Kept apart from framing errors: a phone losing its radio in the
		// middle of a message is common, malformed bytes are not.
		t.stats.truncatedMessages.Add(1)
	}
}

// write sends b on a UDP flow, or queues it for a stream flow's writer (see
// sendQueue), waiting for room when wait is set. A send that finds no room in
// time fails alone; a NoWait send past the reserve closes the connection. An
// error writing a queued message later closes the connection too, and is seen by
// the sender only as the flow going away.
func (t *Transport) write(f *flow, b []byte, wait bool) error {
	if f.conn == nil {
		return t.sendDatagram(f.lis, f.remote, b)
	}
	r := f.q.push(b, wait, t.cfg.WriteTimeout)
	if r == overBudget {
		// Every queue together is at Config.MaxQueuedBytes. The peer holding the
		// most is the one not reading; closing it frees the most memory, and is
		// fair to a connection that only wants room for one more message.
		t.stats.budgetSheds.Add(1)
		t.shedLargestQueue()
		r = f.q.push(b, false, 0)
	}
	switch r {
	case pushed:
		return nil
	case queueGone:
		return ErrNoFlow
	case waitTimedOut:
		t.stats.queueWaitTimeouts.Add(1)
		return ErrQueueFull
	}
	t.stats.queueOverflows.Add(1)
	t.closeFlow(f)
	return ErrQueueFull
}

// shedLargestQueue closes the stream flow with the most queued output. It looks
// at every stream flow, which is fine for the rare moment the budget runs out.
func (t *Transport) shedLargestQueue() {
	var victim *flow
	most := 0
	for _, f := range t.flows.streams() {
		if n := f.q.size(); n > most {
			victim, most = f, n
		}
	}
	if victim != nil {
		t.closeFlow(victim)
	}
}

// startWriter gives a stream flow its send queue and writer goroutine. It is
// called before the flow can be found, with the transport's WaitGroup already
// held by the caller's goroutine.
func (t *Transport) startWriter(f *flow) {
	limit := t.cfg.SendQueueBytes
	if f.lis != nil {
		limit = f.lis.sendQueue
	}
	f.q = newSendQueue(limit, &t.budget)
	t.wg.Add(1)
	go t.writeLoop(f)
}

// streamTo returns an open connection to a peer, reusing one when there is one
// (RFC 3261 §18.1.1) and otherwise dialing. Concurrent callers for the same peer
// share one dial, so a burst of requests to a core node opens one connection.
func (t *Transport) streamTo(network Network, addr netip.AddrPort, serverName string) (*flow, error) {
	k := reuseKey{network: network, remote: addr}
	if network == TLS {
		if serverName == "" && (t.cfg.TLSClient == nil || t.cfg.TLSClient.ServerName == "") {
			// Go would refuse the handshake anyway; failing here costs no dial.
			return nil, fmt.Errorf("%w: TLS needs a server name to verify", ErrUnroutable)
		}
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
	// Dials in progress count too, so a burst cannot overshoot the limit.
	if t.flows.stats().outbound+len(t.dialing) >= t.cfg.MaxDialedConnections {
		t.mu.Unlock()
		t.stats.dialLimited.Add(1)
		return nil, ErrTooManyConnections
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
	capSendBuffer(c)
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
	f.idle.Store(int64(t.cfg.IdleTimeout))
	f.conn = c
	t.mu.Lock()
	closed := t.closed
	if !closed {
		t.wg.Add(1)
		t.startWriter(f)
	}
	t.mu.Unlock()
	if closed || !t.flows.addStream(f) {
		if !closed {
			f.q.close()
			t.wg.Done()
		}
		c.Close()
		t.flowClosed(f)
		return nil, ErrClosed
	}
	t.stats.dialed.Add(1)
	go func() {
		defer t.wg.Done()
		t.serveStream(f, false)
	}()
	return f, nil
}
