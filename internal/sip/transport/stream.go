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
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

const streamBufferSize = 4096

var (
	crlf = []byte("\r\n")
	ping = []byte("\r\n\r\n")
)

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
	r.OnCRLF = func() {
		if !f.pinging.Load() {
			return
		}
		d.keepAlive(br)
		if t.cfg.OnPong != nil {
			t.panics.Run("OnPong", func() { t.cfg.OnPong(f.id) })
		}
	}
	r.OnKeepAlive = func() {
		if f.pinging.Load() {
			// Two pongs read back to back; answering them would make the
			// peer count our CRLF towards its next ping.
			return
		}
		// RFC 5626 §5.4: answer a double-CRLF ping with a single CRLF pong at once.
		// It is queued without waiting, like everything sent from this
		// goroutine; a peer that pings but does not read loses its connection
		// once its queue is full.
		t.stats.keepAlives.Add(1)
		t.write(f, crlf, false, nil)
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
//
// counted, if set, runs once the message is in the queue's count, waiting or
// queued, or will never be: a send under way stops counting for Flush there
// (#375).
func (t *Transport) write(f *flow, b []byte, wait bool, counted func()) error {
	if counted == nil {
		counted = func() {}
	}
	if f.conn == nil {
		defer counted()
		return t.sendDatagram(f.lis, f.remote, b)
	}
	// One deadline covers the whole send, the retry after shedding included,
	// so a waiting sender blocks for at most WriteTimeout.
	deadline := time.Now().Add(t.cfg.WriteTimeout)
	var r pushResult
	if wait {
		f.q.beginWait(len(b))
		counted()
		r = f.q.push(b, true, deadline)
	} else {
		r = f.q.push(b, false, deadline)
		counted()
	}
	if r == overBudget {
		// Every queue together is at Config.MaxQueuedBytes. Make room by closing
		// connections whose peers have stopped reading, if there are any, and
		// try once more; otherwise only this send fails. f's own connection is
		// never closed for the budget: it may be perfectly healthy.
		// Try again after the scan whatever it did: this send may have waited
		// for another sender's scan, which made room, and other sends or
		// writers may have freed some meanwhile.
		if testHookBeforeShed != nil {
			testHookBeforeShed()
		}
		t.stats.budgetSheds.Add(uint64(t.shedStalledQueues(f, len(b))))
		if wait {
			f.q.beginWait(len(b))
		}
		r = f.q.push(b, wait, deadline)
		if r == overBudget {
			t.stats.budgetRefusals.Add(1)
			return errBudgetFull
		}
	}
	switch r {
	case pushed:
		return nil
	case queueGone:
		return ErrNoFlow
	case waitTimedOut:
		t.stats.queueWaitTimeouts.Add(1)
		return errNoRoom
	}
	// A NoWait message did not fit even in the reserve: the reading goroutine
	// cannot wait, and the peer is not taking what we send.
	t.stats.queueOverflows.Add(1)
	t.closeFlow(f)
	return errQueueOverflow
}

// The two reasons a send fails with the connection left open. Both are
// ErrQueueFull to callers; SendResponse tells them apart, because only the
// first says anything about the peer the response is for.
var (
	// errNoRoom: this connection's own queue had no room within WriteTimeout.
	errNoRoom = fmt.Errorf("%w: no room in the connection's queue within WriteTimeout", ErrQueueFull)
	// errBudgetFull: every queue together was at MaxQueuedBytes and no stalled
	// connection could be closed to make room.
	errBudgetFull = fmt.Errorf("%w: transport-wide budget full", ErrQueueFull)
)

// errQueueOverflow reports that the transport closed a connection whose send
// queue overflowed, so callers that test for ErrNoFlow (and answer 430) see it.
var errQueueOverflow = fmt.Errorf("%w: send queue overflowed; connection closed", ErrNoFlow)

// shedGrace is how recently a writer must have made progress for its connection
// to be safe from shedding: its peer is reading.
func (t *Transport) shedGrace() time.Duration { return min(time.Second, t.cfg.WriteTimeout/2) }

// shedRank orders shedding candidates: a client-facing connection before a core
// one, then the queue fullest relative to its own limit, then the one stalled
// longest. Raw bytes would always pick a core connection, whose limit is 64
// times a client's, although its peer is the one most likely to be reading.
type shedRank struct {
	client  bool
	share   float64
	stalled time.Duration
}

func (a shedRank) before(b shedRank) bool {
	if a.client != b.client {
		return a.client
	}
	if a.share != b.share {
		return a.share > b.share
	}
	return a.stalled > b.stalled
}

// shedScanInterval bounds how often shedStalledQueues looks at every flow. A
// scan of a few thousand flows takes some hundreds of microseconds under the
// flow table's lock, and a full budget refuses sends in bursts; one scan per
// interval keeps that to a fraction of a percent of one core, and a stalled
// peer that one scan missed is still stalled at the next.
const shedScanInterval = 100 * time.Millisecond

// testHookBeforeShed, when a test sets it, runs between a push the budget
// refused and the shedding scan, where other goroutines may free room.
var testHookBeforeShed func()

// shedHeadroom is the share of MaxQueuedBytes a scan frees beyond the shortfall
// of the send that triggered it, by closing stalled client-facing connections.
// Freeing only the shortfall would leave the budget full again for the next
// send, and scans run at most once per shedScanInterval, so a burst after a
// mass stall would be refused for many intervals while stalled clients
// remained to be shed. The amount is fixed, not a level to reach: however much
// healthy queues hold, one scan frees at most the shortfall plus this share,
// and fewer if there are fewer stalled clients. Core connections are never
// closed for headroom: losing one fails every transaction on it, so one is
// shed only while the send itself does not fit.
const shedHeadroom = 0.10

// shedCandidate is a connection a scan may close, with what closing it frees.
type shedCandidate struct {
	f      *flow
	rank   shedRank
	queued int
}

// sortCandidates puts the candidates in the order a scan closes them. The flow
// table is a map, so they arrive in no particular order.
func sortCandidates(cands []shedCandidate) {
	slices.SortFunc(cands, func(a, b shedCandidate) int {
		switch {
		case a.rank.before(b.rank):
			return -1
		case b.rank.before(a.rank):
			return 1
		}
		return 0
	})
}

// shedStalledQueues closes stalled connections other than except, in shedRank
// order: client-facing ones until they have freed the shortfall of need more
// bytes plus shedHeadroom of the budget, core ones only while the shortfall
// remains. It returns how many it closed.
//
// Scans are serialized: a sender that finds the budget full while another
// sender scans waits for that scan and then retries in the room it made,
// rather than being turned away by the rate limit.
//
// A connection with nothing queued, already closing, or whose writer made
// progress within shedGrace, is never a candidate; the others are closed in
// shedRank order. It scans every stream flow, at most once per
// shedScanInterval.
func (t *Transport) shedStalledQueues(except *flow, need int) (closed int) {
	t.shedMu.Lock()
	defer t.shedMu.Unlock()
	now := time.Now()
	if now.UnixNano()-t.lastShedScan.Load() < int64(shedScanInterval) {
		return 0
	}
	t.lastShedScan.Store(now.UnixNano())
	grace := t.shedGrace()
	var cands []shedCandidate
	for _, f := range t.flows.streams() {
		if f == except || f.closed.Load() {
			continue
		}
		queued, idle := f.q.stall(now)
		if queued == 0 || idle < grace {
			continue
		}
		cands = append(cands, shedCandidate{f, shedRank{client: f.lis != nil && f.lis.clientFacing,
			share: float64(queued) / float64(f.q.limit), stalled: idle}, queued})
	}
	sortCandidates(cands)
	overBudget := t.budget.used.Load() + int64(need) - t.budget.max
	clientGoal := overBudget + int64(float64(t.budget.max)*shedHeadroom)
	for _, c := range cands {
		// Clients sort first. A client is worth closing while the client goal
		// is unmet, a core connection while the send does not fit at all; the
		// goal is never below the shortfall, so once a candidate is not worth
		// closing none after it is either.
		if (c.rank.client && clientGoal <= 0) || (!c.rank.client && overBudget <= 0) {
			break
		}
		// A candidate may have started closing since it was looked at; then it
		// frees nothing here and is not counted.
		if t.closeFlow(c.f) {
			closed++
			clientGoal -= int64(c.queued)
			overBudget -= int64(c.queued)
		}
	}
	return closed
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
	ctx, cancel := context.WithTimeout(t.dials, t.cfg.DialTimeout)
	defer cancel()
	c, err := t.cfg.Dialer.DialContext(ctx, "tcp", k.remote.String())
	if err != nil {
		if t.dials.Err() != nil {
			// Close cut it: no dial error.
			return nil, ErrClosed
		}
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
			if t.dials.Err() != nil {
				return nil, ErrClosed
			}
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
