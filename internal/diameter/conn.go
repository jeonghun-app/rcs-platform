package diameter

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// watchdogState is the RFC 3539 §3.4.1 state of an open connection. INITIAL
// and DOWN have no connection, so they are represented by the peer having
// none.
type watchdogState uint8

const (
	watchdogOkay watchdogState = iota
	watchdogSuspect
	watchdogReopen
)

var (
	errWatchdogExpired = errors.New("diameter: watchdog expired with no answer from the peer")
	errDuplicatePeer   = errors.New("diameter: peer identity already has an open connection")
	errPeerDisconnect  = errors.New("diameter: peer sent DPR and did not close the connection")
	errNotDraining     = errors.New("diameter: peer does not read the answers to its requests")
)

type result struct {
	m   *Message
	err error
}

type pendingRequest struct {
	code  uint32
	ch    chan result // buffered: the single completion never blocks
	timer Timer
}

// conn is one transport connection to a peer, from the capabilities exchange
// until it closes. Three goroutines serve an open connection: the read loop
// (which also dispatches requests), the writer, and the watchdog.
//
// The read loop and the watchdog never wait for the writer. If they did, two
// nodes sending each other requests could each fill its write queue while
// its read loop waited for room, and neither would read again: a deadlock
// between two healthy peers. Their messages (base protocol answers,
// node-built error answers, DWRs) therefore go to a separate control queue
// that is bounded by bytes, served first, and never blocks; when it is full
// the peer is not reading what it asked for, and the connection is closed
// (a DWR is dropped instead, which the watchdog counts as unanswered).
// Handlers wait for room in the answer queue, which is written next, so an
// admitted request's answer does not wait behind the node's own requests
// (#117), up to maxAnswersInARow at a time; Send waits for room in the main
// queue, no longer than its timeout.
type conn struct {
	node *Node
	nc   net.Conn
	br   *bufio.Reader

	// Set during the capabilities exchange, read-only afterwards.
	peer *Peer
	caps capabilities
	apps []uint32

	writes       chan queued   // requests, and the DPA, behind them
	answers      chan []byte   // handlers' answers, written before writes
	controlReady chan struct{} // wakes the writer when control gains an entry
	wdFire       chan struct{}
	done         chan struct{}
	ctx          context.Context // handlers' context; ends at close
	cancel       context.CancelFunc
	once         sync.Once

	mu          sync.Mutex
	closed      bool
	running     bool
	pending     map[uint32]*pendingRequest
	hopByHop    uint32
	state       watchdogState
	dwrPending  bool
	numDWA      int
	wdDeadline  time.Time
	wdTimer     Timer
	closing     bool // disconnecting: no new requests either way
	remoteCause int32
	gotDPR      bool
	// active counts running handlers; drained is closed when it reaches
	// zero while a disconnect waits for it.
	active  int
	drained chan struct{}

	controlMu    sync.Mutex
	control      [][]byte
	controlBytes int

	// wroteLast, the writer's alone, is set once it has taken a DPR or DPA
	// from the main queue.
	wroteLast bool
}

func newConn(n *Node, nc net.Conn) *conn {
	c := &conn{
		node:         n,
		nc:           nc,
		br:           bufio.NewReader(nc),
		writes:       make(chan queued, n.cfg.MaxInFlight),
		answers:      make(chan []byte, n.cfg.MaxInFlight),
		controlReady: make(chan struct{}, 1),
		wdFire:       make(chan struct{}, 1),
		done:         make(chan struct{}),
		pending:      make(map[uint32]*pendingRequest),
		hopByHop:     uint32(n.cfg.Random()),
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	return c
}

func (c *conn) remote() string { return c.nc.RemoteAddr().String() }

func (c *conn) nextHopByHop() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	h := c.hopByHop
	c.hopByHop++
	return h
}

func addrOf(a net.Addr) netip.Addr {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.AddrPort().Addr().Unmap()
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// accept runs the responder side of a new inbound connection to its end.
func (n *Node) accept(nc net.Conn, src netip.Addr) {
	c := newConn(n, nc)
	if !n.register(c) {
		n.exchangeDone(src)
		_ = nc.Close()
		return
	}
	err := c.answerCapabilities()
	n.exchangeDone(src)
	if err != nil {
		c.close(err)
		return
	}
	c.run()
}

// answerCapabilities reads the CER and answers it (RFC 6733 §5.3). Anything
// other than a CER first is a reason to close; a CER that fails a check is
// answered with the reason, and the connection is closed by the caller.
func (c *conn) answerCapabilities() error {
	n := c.node
	// The timer also bounds writing the CEA, so a peer that connects and
	// never reads cannot hold the goroutine.
	t := n.cfg.Clock.AfterFunc(n.cfg.CapabilitiesTimeout, func() { _ = c.nc.Close() })
	defer t.Stop()

	m, err := ReadMessage(c.br, n.cfg.Dictionary, n.cfg.Limits)
	var derr *Error
	if errors.As(err, &derr) && isCER(m) {
		return c.rejectCER(m, derr)
	}
	if err != nil {
		return err
	}
	if !isCER(m) {
		return fmt.Errorf("diameter: expected CER, got command %d", m.Code)
	}
	caps, derr := parseCapabilities(m, n.cfg.Dictionary)
	if derr != nil {
		return c.rejectCER(m, derr)
	}
	if !n.accepts(caps, addrOf(c.nc.RemoteAddr())) {
		n.log.Warn("diameter peer rejected: no accept rule matches",
			"peer_host", caps.host, "peer_realm", caps.realm, "remote", c.remote())
		return c.rejectCER(m, &Error{ResultCode: ResultUnknownPeer})
	}
	if !securityAcceptable(caps.inbandSecurity) {
		return c.rejectCER(m, &Error{ResultCode: ResultNoCommonSecurity})
	}
	apps := commonApplications(n.cfg.Applications, caps.authApps)
	if len(apps) == 0 {
		return c.rejectCER(m, &Error{ResultCode: ResultNoCommonApplication})
	}
	c.setPeer(&Peer{}, caps, apps)
	if !n.open(c, c.peer) {
		// No election (§5.6.4): this node never initiates to a peer that
		// may initiate to it, so a second connection from one identity is a
		// stale or misconfigured one. The existing connection's watchdog
		// removes it if it is dead, and the peer retries.
		c.setPeer(nil, caps, apps)
		return c.rejectCER(m, &Error{ResultCode: ResultUnableToComply, Message: "peer already connected"})
	}
	cea := n.NewAnswer(m, ResultSuccess, n.capabilityAVPs(addrOf(c.nc.LocalAddr()))...)
	return c.writeNow(cea)
}

func isCER(m *Message) bool {
	return m != nil && m.IsRequest() && m.Code == CodeCapabilitiesExchange && m.ApplicationID == AppCommon
}

// rejectCER answers a CER with a failure and returns the reason the
// connection closes.
func (c *conn) rejectCER(m *Message, e *Error) error {
	n := c.node
	var extra []*AVP
	if e.Message != "" {
		extra = append(extra, NewAVP(AVPErrorMessage, 0, 0, []byte(e.Message)))
	}
	if e.FailedAVP != nil {
		extra = append(extra, NewGrouped(AVPFailedAVP, FlagMandatory, 0, e.FailedAVP))
	}
	cea := n.NewAnswer(m, e.ResultCode, append(n.capabilityAVPs(addrOf(c.nc.LocalAddr())), extra...)...)
	if err := c.writeNow(cea); err != nil {
		return err
	}
	return fmt.Errorf("diameter: capabilities exchange refused: %w", e)
}

// writeNow writes before the writer goroutine runs.
func (c *conn) writeNow(m *Message) error {
	b, err := m.Encode()
	if err != nil {
		return err
	}
	_, err = c.nc.Write(b)
	return err
}

func (n *Node) accepts(caps capabilities, src netip.Addr) bool {
	return slices.ContainsFunc(n.cfg.Accept, func(r PeerRule) bool {
		return r.matches(caps.host, caps.realm, src)
	})
}

// initiate dials a configured peer and runs the initiator side of the
// capabilities exchange. On success the connection is open and served in the
// background.
func (n *Node) initiate(p *Peer, failedHost string) (*conn, error) {
	dctx, cancel := context.WithCancel(n.ctx)
	t := n.cfg.Clock.AfterFunc(n.cfg.CapabilitiesTimeout, cancel)
	nc, err := n.cfg.Dial(dctx, "tcp", p.cfg.Address)
	t.Stop()
	cancel()
	if err != nil {
		return nil, err
	}
	c := newConn(n, nc)
	if !n.register(c) {
		_ = nc.Close()
		return nil, ErrNodeClosed
	}
	if err := c.requestCapabilities(p); err != nil {
		c.close(err)
		return nil, err
	}
	if failedHost != "" && strings.EqualFold(failedHost, c.caps.host) {
		// Back to the node that just failed: the connection must earn its
		// way back with three watchdog exchanges before it carries traffic
		// (RFC 3539 §3.4.1).
		c.mu.Lock()
		c.state, c.dwrPending = watchdogReopen, true
		c.mu.Unlock()
	}
	if !n.open(c, p) {
		c.close(errDuplicatePeer)
		return nil, errDuplicatePeer
	}
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		c.run()
	}()
	return c, nil
}

// requestCapabilities sends the CER and checks the CEA (RFC 6733 §5.3).
func (c *conn) requestCapabilities(p *Peer) error {
	n := c.node
	t := n.cfg.Clock.AfterFunc(n.cfg.CapabilitiesTimeout, func() { _ = c.nc.Close() })
	defer t.Stop()

	cer := &Message{
		Flags:         FlagRequest,
		Code:          CodeCapabilitiesExchange,
		ApplicationID: AppCommon,
		HopByHop:      c.nextHopByHop(),
		EndToEnd:      n.nextEndToEnd(),
	}
	cer.Add(n.originAVPs()...)
	cer.Add(n.capabilityAVPs(addrOf(c.nc.LocalAddr()))...)
	if err := c.writeNow(cer); err != nil {
		return err
	}
	m, err := ReadMessage(c.br, n.cfg.Dictionary, n.cfg.Limits)
	if err != nil {
		return err
	}
	if m.IsRequest() || m.Code != CodeCapabilitiesExchange || m.HopByHop != cer.HopByHop {
		return fmt.Errorf("diameter: expected CEA, got command %d", m.Code)
	}
	if rc, ok := m.ResultCode(); !ok || rc != ResultSuccess {
		return fmt.Errorf("diameter: capabilities exchange refused by peer: %w", &Error{ResultCode: rc})
	}
	caps, derr := parseCapabilities(m, n.cfg.Dictionary)
	if derr != nil {
		return derr
	}
	if p.cfg.Host != "" && !strings.EqualFold(p.cfg.Host, caps.host) {
		return fmt.Errorf("diameter: peer at %s is %s, configured as %s", p.cfg.Address, caps.host, p.cfg.Host)
	}
	if p.cfg.Realm != "" && !strings.EqualFold(p.cfg.Realm, caps.realm) {
		return fmt.Errorf("diameter: peer at %s is in realm %s, configured as %s", p.cfg.Address, caps.realm, p.cfg.Realm)
	}
	if !securityAcceptable(caps.inbandSecurity) {
		return errors.New("diameter: peer requires in-band security")
	}
	apps := commonApplications(n.cfg.Applications, caps.authApps)
	if len(apps) == 0 {
		return errors.New("diameter: peer has no application in common")
	}
	c.setPeer(p, caps, apps)
	return nil
}

// setPeer records the outcome of the capabilities exchange. It takes the lock
// because Shutdown may close the connection concurrently; once the connection
// is open the fields no longer change and are read without it.
func (c *conn) setPeer(p *Peer, caps capabilities, apps []uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.peer, c.caps, c.apps = p, caps, apps
}

// run serves an open connection until it closes.
func (c *conn) run() {
	n := c.node
	if h := testHookRun.Load(); h != nil {
		(*h)(c)
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.running = true
	reopen := c.state == watchdogReopen
	c.armWatchdogLocked(n.cfg.Clock.Now())
	c.mu.Unlock()
	n.log.Info("diameter peer open", "peer_host", c.caps.host, "peer_realm", c.caps.realm,
		"remote", c.remote(), "applications", c.apps, "reopen", reopen)

	n.wg.Add(2)
	go func() {
		defer n.wg.Done()
		c.writeLoop()
	}()
	go func() {
		defer n.wg.Done()
		c.watchdogLoop()
	}()
	if reopen {
		c.sendDWR()
	}
	c.readLoop()
}

// close ends the connection once: it fails every pending request, cancels
// handlers and removes the connection from the node.
func (c *conn) close(reason error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		pending := c.pending
		c.pending = nil
		if c.wdTimer != nil {
			c.wdTimer.Stop()
		}
		running := c.running
		peer, host := c.peer, c.caps.host
		c.mu.Unlock()

		// The tables go first: whoever waits on done (the reconnect loop)
		// must not find this connection still registered under the peer's
		// identity and refuse its successor as a duplicate.
		c.node.forget(c, peer, host)
		close(c.done)
		c.cancel()
		_ = c.nc.Close()
		for _, p := range pending {
			if p.timer != nil {
				p.timer.Stop()
			}
			p.ch <- result{err: ErrConnectionClosed}
		}
		if running {
			c.node.log.Info("diameter peer closed", "peer_host", host, "remote", c.remote(), "reason", reason)
		} else {
			c.node.log.Info("diameter connection closed before capabilities exchange completed",
				"remote", c.remote(), "reason", reason)
		}
	})
}

// available reports whether c can take a request: it runs, so that a
// Shutdown says goodbye to it with a DPR, and is neither closing nor out
// of the watchdog's OKAY state. A connection the exchange has just opened
// is not yet available: a stop that came before run would close it with
// no DPR, though its peer had been reported available (#587).
func (c *conn) available() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running && !c.closed && !c.closing && c.state == watchdogOkay
}

func (c *conn) remoteDisconnectCause() (int32, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remoteCause, c.gotDPR
}

// controlQueueBytes bounds the control queue. Four maximum-size messages
// leave room for thousands of ordinary answers while capping what a peer that
// sends requests but never reads the answers can make the node hold.
func (c *conn) controlQueueBytes() int { return 4 * c.node.cfg.Limits.MaxMessageSize }

// enqueueControl queues b for the writer ahead of the main queue without ever
// blocking. It reports false when the control queue is full.
func (c *conn) enqueueControl(b []byte) bool {
	c.controlMu.Lock()
	if c.controlBytes+len(b) > c.controlQueueBytes() {
		c.controlMu.Unlock()
		return false
	}
	c.control = append(c.control, b)
	c.controlBytes += len(b)
	c.controlMu.Unlock()
	select {
	case c.controlReady <- struct{}{}:
	default:
	}
	return true
}

func (c *conn) popControl() ([]byte, bool) {
	c.controlMu.Lock()
	defer c.controlMu.Unlock()
	if len(c.control) == 0 {
		return nil, false
	}
	b := c.control[0]
	c.control[0] = nil
	c.control = c.control[1:]
	c.controlBytes -= len(b)
	return b, true
}

// queued is a message in the main queue. last marks the DPR and the DPA,
// which end what the peer is sent; hbh is a request's Hop-by-Hop
// Identifier, so that the writer can end one it drops.
type queued struct {
	b    []byte
	last bool
	hbh  uint32
}

// errDroppedAtDisconnect ends a request the writer dropped behind a DPR or
// DPA. It is ErrPeerUnavailable, as for a request refused before the send,
// since none of it reached the peer: a caller may retry it elsewhere at once
// (cxclient.NeverSent). It already has its End-to-End Identifier, so a retry
// keeps it and carries the T flag, which is harmless for a request the first
// peer never saw.
var errDroppedAtDisconnect = fmt.Errorf("%w: the connection was disconnecting", ErrPeerUnavailable)

// maxAnswersInARow bounds how many handlers' answers the writer sends before
// it serves the main queue again, so that a peer keeping requests
// outstanding faster than it reads the answers cannot hold up the node's
// own requests (an HSS's RTR or PPR) indefinitely (review of #148): at
// most that many answers go ahead of each queued message. A connection
// with a smaller MaxInFlight uses that bound instead.
const maxAnswersInARow = 16

// Test hooks. They are atomic, and get the connection, because a writer or
// sender of an earlier test's node may still run while the next test sets
// them (QA of #367).
var (
	// testHookTookLast runs once the writer has taken a DPR or DPA from the
	// main queue, before it writes the answers queued ahead of it.
	testHookTookLast atomic.Pointer[func(*conn)]
	// testHookDropped runs when the writer drops a request that reached the
	// main queue behind a DPR or DPA.
	testHookDropped atomic.Pointer[func(*conn)]
	// testHookQueuing runs in a request's sender after its closing check,
	// before it waits for room in the main queue.
	testHookQueuing atomic.Pointer[func(*conn, *Message)]
	// testHookRun runs as an open connection starts to run, before it
	// takes the connection's lock.
	testHookRun atomic.Pointer[func(*conn)]
)

// writeLoop writes the control queue first, then handlers' answers, then
// the main queue, but serves the main queue after at most
// maxAnswersInARow (or MaxInFlight) answers in a row.
func (c *conn) writeLoop() {
	limit := min(maxAnswersInARow, cap(c.answers))
	inARow := 0 // answers written since the main queue was last served
	for {
		if b, ok := c.popControl(); ok {
			// The control queue's one request is the watchdog's DWR, which
			// the Closing state does not send either (#376): one queued
			// before the DPR or DPA went out is dropped. Its answer was not
			// awaited.
			if c.wroteLast && len(b) > 4 && CommandFlags(b[4])&FlagRequest != 0 {
				continue
			}
			if !c.write(b) {
				return
			}
			continue
		}
		if inARow >= limit {
			inARow = 0
			select {
			case q := <-c.writes:
				if !c.writeQueued(q) {
					return
				}
				continue
			default:
			}
		}
		select {
		case b := <-c.answers:
			if !c.write(b) {
				return
			}
			inARow++
			continue
		default:
		}
		select {
		case <-c.controlReady:
		case b := <-c.answers:
			if !c.write(b) {
				return
			}
			inARow++
		case q := <-c.writes:
			inARow = 0
			if !c.writeQueued(q) {
				return
			}
		case <-c.done:
			return
		}
	}
}

// writeQueued writes a message from the main queue. A DPR or DPA goes after
// the answers already queued: a select that found both queues ready picks
// one at random, and an answer queued before a DPR or DPA must reach the
// peer before it (drain). Those are all in the queue by now, so only that
// many are written first, however many more arrive.
//
// Nothing but another DPR or DPA from the main queue follows one: a
// connection in the Closing state sends no messages (RFC 6733 §5.6), and the
// DPA is the last the peer gets (§5.4). A DPR or DPA still goes, for a DPR
// that crossed ours. A sender that found the connection open can still be
// waiting for room in the queue when the DPR or DPA goes in, and get its
// request in behind it (#324); that request is dropped and ends at once with
// errDroppedAtDisconnect.
func (c *conn) writeQueued(q queued) bool {
	if c.wroteLast && !q.last {
		c.complete(q.hbh, 0, result{err: errDroppedAtDisconnect})
		if h := testHookDropped.Load(); h != nil {
			(*h)(c)
		}
		return true
	}
	if q.last {
		c.wroteLast = true
		if h := testHookTookLast.Load(); h != nil {
			(*h)(c)
		}
		for range len(c.answers) {
			if !c.write(<-c.answers) {
				return false
			}
		}
	}
	return c.write(q.b)
}

// write sends b, failing the connection when the peer does not take it within
// WriteTimeout. The deadline is on the wall clock because it bounds a socket
// operation, not a protocol timer; the watchdog already detects a silent
// peer, and the deadline additionally frees a writer stuck on one that has
// stopped reading.
func (c *conn) write(b []byte) bool {
	_ = c.nc.SetWriteDeadline(time.Now().Add(c.node.cfg.WriteTimeout))
	if _, err := c.nc.Write(b); err != nil {
		c.close(fmt.Errorf("diameter: write failed: %w", err))
		return false
	}
	return true
}

// encodeAnswer encodes an answer. An answer that cannot be encoded (a handler
// built one larger than the protocol allows) is replaced by
// DIAMETER_UNABLE_TO_COMPLY so the peer is not left waiting.
func (c *conn) encodeAnswer(req, ans *Message) ([]byte, bool) {
	b, err := ans.Encode()
	if err == nil {
		return b, true
	}
	c.node.log.Error("diameter answer cannot be encoded", "command", req.Code,
		"application", req.ApplicationID, "error", err)
	b, err = c.node.errorAnswer(req, &Error{ResultCode: ResultUnableToComply}).Encode()
	return b, err == nil
}

// answerNow sends an answer from the read loop through the control queue. A
// peer that keeps sending requests without reading the answers fills it, and
// is disconnected rather than allowed to stop the read loop.
func (c *conn) answerNow(req, ans *Message) {
	b, ok := c.encodeAnswer(req, ans)
	if !ok {
		return
	}
	if !c.enqueueControl(b) {
		c.node.log.Warn("diameter peer not reading answers: closing", "peer_host", c.caps.host,
			"limit_bytes", c.controlQueueBytes())
		c.close(errNotDraining)
	}
}

// answerQueued sends a handler's answer through the answer queue, waiting
// for room; handlers run on their own goroutines, so waiting stops no one
// else. At most MaxInFlight handlers run, so the queue holds every running
// handler's answer unless the writer is behind on answers already.
func (c *conn) answerQueued(req, ans *Message) {
	b, ok := c.encodeAnswer(req, ans)
	if !ok {
		return
	}
	select {
	case c.answers <- b:
	case <-c.done:
	}
}

// answerLast sends an answer through the main queue, behind the requests
// already queued and every handler answer queued before it: the DPA, which
// ends what the peer is sent (RFC 6733 §5.4).
func (c *conn) answerLast(req, ans *Message) {
	b, ok := c.encodeAnswer(req, ans)
	if !ok {
		return
	}
	select {
	case c.writes <- queued{b: b, last: true}:
	case <-c.done:
	}
}

// roundTrip sends a request and waits for the matching answer. Base protocol
// requests (internal) are sent even when the peer is not available.
func (c *conn) roundTrip(ctx context.Context, req *Message, internal bool) (*Message, error) {
	n := c.node
	p := &pendingRequest{code: req.Code, ch: make(chan result, 1)}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrConnectionClosed
	}
	if !internal && (c.closing || c.state != watchdogOkay) {
		c.mu.Unlock()
		return nil, ErrPeerUnavailable
	}
	req.Flags = (req.Flags | FlagRequest) &^ FlagError
	req.HopByHop = c.hopByHop
	c.hopByHop++
	if req.EndToEnd == 0 {
		req.EndToEnd = n.nextEndToEnd()
	}
	hbh := req.HopByHop
	c.pending[hbh] = p
	p.timer = n.cfg.Clock.AfterFunc(n.cfg.RequestTimeout, func() { c.complete(hbh, 0, result{err: ErrTimeout}) })
	c.mu.Unlock()

	if h := testHookQueuing.Load(); h != nil {
		(*h)(c, req)
	}
	// Waiting for room in the queue ends with the request: its timer or the
	// connection closing completes it, and so does the caller's context.
	b, err := req.Encode()
	if err == nil {
		select {
		case c.writes <- queued{b: b, last: req.Code == CodeDisconnectPeer, hbh: hbh}:
		case r := <-p.ch:
			return r.m, r.err
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	if err != nil {
		c.complete(hbh, 0, result{err: err})
	}
	select {
	case r := <-p.ch:
		return r.m, r.err
	case <-ctx.Done():
		c.complete(hbh, 0, result{err: ctx.Err()})
		r := <-p.ch
		return r.m, r.err
	}
}

// complete delivers the outcome of a pending request once. A non-zero code
// must match the request's command code: an answer to a different command
// under the same identifier is not this request's answer.
func (c *conn) complete(hbh, code uint32, r result) bool {
	c.mu.Lock()
	p, ok := c.pending[hbh]
	if !ok || (code != 0 && p.code != code) {
		c.mu.Unlock()
		return false
	}
	delete(c.pending, hbh)
	c.mu.Unlock()
	if p.timer != nil {
		p.timer.Stop()
	}
	p.ch <- r
	return true
}

func (c *conn) readLoop() {
	n := c.node
	for {
		m, err := ReadMessage(c.br, n.cfg.Dictionary, n.cfg.Limits)
		var derr *Error
		if err != nil && !errors.As(err, &derr) {
			c.close(err)
			return
		}
		process := c.received(m)
		switch {
		case derr != nil && m.IsRequest():
			n.log.Warn("diameter request rejected", "peer_host", c.caps.host, "command", m.Code,
				"application", m.ApplicationID, "result_code", derr.ResultCode)
			c.answerNow(m, n.errorAnswer(m, derr))
		case derr != nil:
			c.complete(m.HopByHop, m.Code, result{err: derr})
		case m.IsRequest():
			c.handleRequest(m, process)
		case process:
			c.handleAnswer(m)
		}
	}
}

// received applies the RFC 3539 §3.4.1 events for a received message and
// reports whether it may be processed: in REOPEN, application messages are
// thrown away, while base protocol messages (a DPA to this node's DPR, for
// one) are still handled, since the throwaway rule is about application
// traffic. Receipt resets the timer (SetWatchdog) in OKAY and SUSPECT only;
// in REOPEN the timer keeps the DWR cadence.
func (c *conn) received(m *Message) bool {
	isDWA := !m.IsRequest() && m.ApplicationID == AppCommon && m.Code == CodeDeviceWatchdog
	c.mu.Lock()
	defer c.mu.Unlock()
	switch c.state {
	case watchdogOkay:
		c.wdDeadline = c.node.cfg.Clock.Now().Add(c.node.watchdogInterval())
		if isDWA {
			c.dwrPending = false
		}
	case watchdogSuspect:
		c.wdDeadline = c.node.cfg.Clock.Now().Add(c.node.watchdogInterval())
		c.dwrPending = c.dwrPending && !isDWA
		c.state = watchdogOkay
		c.node.log.Info("diameter peer recovered", "peer_host", c.caps.host)
	case watchdogReopen:
		if !isDWA {
			return m.ApplicationID == AppCommon
		}
		c.dwrPending = false
		c.numDWA++
		if c.numDWA >= reopenWatchdogsBeforeOpen {
			c.state = watchdogOkay
			c.node.log.Info("diameter peer reopened", "peer_host", c.caps.host)
		}
	}
	return true
}

func (c *conn) handleAnswer(m *Message) {
	if m.ApplicationID == AppCommon && m.Code == CodeDeviceWatchdog {
		return // accounted for by received
	}
	if !c.complete(m.HopByHop, m.Code, result{m: m}) {
		c.node.log.Debug("diameter answer matches no pending request", "peer_host", c.caps.host,
			"command", m.Code, "application", m.ApplicationID)
	}
}

func (c *conn) handleRequest(m *Message, process bool) {
	n := c.node
	if m.ApplicationID == AppCommon {
		switch m.Code {
		case CodeDeviceWatchdog:
			c.answerNow(m, n.NewAnswer(m, ResultSuccess, NewAVP(AVPOriginStateID, FlagMandatory, 0, Unsigned32(n.cfg.OriginStateID))))
		case CodeDisconnectPeer:
			c.disconnected(m)
		case CodeCapabilitiesExchange:
			// Capabilities are exchanged once per connection; changing them
			// later is a separate extension (RFC 6737).
			c.answerNow(m, n.errorAnswer(m, &Error{ResultCode: ResultUnableToComply, Message: "capabilities already exchanged"}))
		default:
			c.answerNow(m, n.errorAnswer(m, &Error{ResultCode: ResultCommandUnsupported}))
		}
		return
	}
	if !process {
		// RFC 3539 discards application messages while reopening; answering
		// instead lets the sender fail over at once rather than at its
		// timeout.
		c.answerNow(m, n.errorAnswer(m, &Error{ResultCode: ResultUnableToDeliver}))
		return
	}
	if !slices.Contains(c.apps, m.ApplicationID) {
		c.answerNow(m, n.errorAnswer(m, &Error{ResultCode: ResultApplicationUnsupported}))
		return
	}
	h, rc := n.handler(m.ApplicationID, m.Code)
	if h == nil {
		c.answerNow(m, n.errorAnswer(m, &Error{ResultCode: rc}))
		return
	}
	if rc := c.startHandler(); rc != 0 {
		c.answerNow(m, n.errorAnswer(m, &Error{ResultCode: rc}))
		return
	}
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer c.finishHandler()
		c.serve(h, m)
	}()
}

// startHandler admits a request to a handler, or returns the result code to
// refuse it with. Checking closing and counting under one lock means a
// disconnect that has seen zero handlers cannot be overtaken by a new one.
func (c *conn) startHandler() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.closing:
		// A connection being disconnected takes no new work (§5.4).
		return ResultUnableToDeliver
	case c.active >= c.node.cfg.MaxInFlight:
		return ResultTooBusy
	}
	c.active++
	return 0
}

// finishHandler runs after the handler's answer is queued, so a drained
// connection has every answer ahead of what is sent next.
func (c *conn) finishHandler() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active--
	if c.active == 0 && c.drained != nil {
		close(c.drained)
		c.drained = nil
	}
}

// drain stops new requests and waits until every running handler has queued
// its answer, stop is closed, or the connection closes. Whatever is queued
// next (DPR or DPA) then follows those answers on the wire.
func (c *conn) drain(stop <-chan struct{}) {
	c.mu.Lock()
	c.closing = true
	if c.active == 0 {
		c.mu.Unlock()
		return
	}
	if c.drained == nil {
		c.drained = make(chan struct{})
	}
	drained := c.drained
	c.mu.Unlock()
	select {
	case <-drained:
	case <-stop:
	case <-c.done:
	}
}

// serve runs a handler and sends its answer. A panicking handler is answered
// with DIAMETER_UNABLE_TO_COMPLY instead of taking the whole node down with
// every other peer's requests.
func (c *conn) serve(h Handler, req *Message) {
	n := c.node
	defer func() {
		if v := recover(); v != nil {
			n.log.Error("diameter handler panicked", "command", req.Code, "application", req.ApplicationID,
				"panic", fmt.Sprint(v))
			c.answerQueued(req, n.errorAnswer(req, &Error{ResultCode: ResultUnableToComply}))
		}
	}()
	ans, err := h.ServeDiameter(c.ctx, c.peer, req)
	var derr *Error
	switch {
	case errors.As(err, &derr):
		ans = n.errorAnswer(req, derr)
	case err != nil:
		n.log.Error("diameter handler failed", "command", req.Code, "application", req.ApplicationID, "error", err)
		ans = n.errorAnswer(req, &Error{ResultCode: ResultUnableToComply})
	case ans == nil:
		n.log.Error("diameter handler returned no answer", "command", req.Code, "application", req.ApplicationID)
		ans = n.errorAnswer(req, &Error{ResultCode: ResultUnableToComply})
	}
	// The answer travels back on the request's identifiers whatever the
	// handler set; the P bit mirrors the request (§6.2).
	ans.Flags = ans.Flags&^(FlagRequest|FlagProxiable|FlagRetransmit) | req.Flags&FlagProxiable
	ans.Code, ans.ApplicationID = req.Code, req.ApplicationID
	ans.HopByHop, ans.EndToEnd = req.HopByHop, req.EndToEnd
	c.answerQueued(req, ans)
}

// disconnected answers a DPR (RFC 6733 §5.4). Requests already being handled
// are answered first, at most for RequestTimeout (the sender would not wait
// longer), so the DPA is the last message the sender gets. The sender closes
// the connection on receiving the DPA; if it does not, this node closes it
// after a grace period.
func (c *conn) disconnected(dpr *Message) {
	n := c.node
	cause := DisconnectRebooting
	if a := dpr.Find(AVPDisconnectCause, 0); a != nil {
		cause, _ = a.Enumerated()
	}
	c.mu.Lock()
	c.closing = true
	c.gotDPR = true
	c.remoteCause = cause
	c.mu.Unlock()
	n.log.Info("diameter peer disconnecting", "peer_host", c.caps.host, "disconnect_cause", cause)
	// The read loop keeps reading (DWRs, late answers) while this waits.
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		stop := make(chan struct{})
		t := n.cfg.Clock.AfterFunc(n.cfg.RequestTimeout, func() { close(stop) })
		c.drain(stop)
		t.Stop()
		c.answerLast(dpr, n.NewAnswer(dpr, ResultSuccess))
		n.cfg.Clock.AfterFunc(disconnectWaitForPeerToDrop, func() { c.close(errPeerDisconnect) })
	}()
}

// disconnect stops taking requests, lets the handlers already running queue
// their answers (until ctx ends), then sends DPR with the cause and closes the
// connection once the DPA arrives, the request times out, or ctx ends
// (RFC 6733 §5.4). Answers are queued before the DPR, so the peer receives
// them before it sees the connection go.
func (c *conn) disconnect(ctx context.Context, cause int32) {
	c.mu.Lock()
	ready := c.running && !c.closing && !c.closed
	c.mu.Unlock()
	if ready {
		c.drain(ctx.Done())
	}
	// Once ctx has ended the caller wants the connections closed now, so no
	// DPR is started.
	if ready && ctx.Err() == nil {
		dpr := &Message{Flags: FlagRequest, Code: CodeDisconnectPeer, ApplicationID: AppCommon}
		dpr.Add(c.node.originAVPs()...)
		dpr.Add(NewAVP(AVPDisconnectCause, FlagMandatory, 0, Enumerated(cause)))
		_, _ = c.roundTrip(ctx, dpr, true)
	}
	c.close(ErrNodeClosed)
}

// armWatchdogLocked is SetWatchdog() of RFC 3539: Tw from now, jittered.
func (c *conn) armWatchdogLocked(now time.Time) {
	tw := c.node.watchdogInterval()
	c.wdDeadline = now.Add(tw)
	c.wdTimer = c.node.cfg.Clock.AfterFunc(tw, c.fireWatchdog)
}

// fireWatchdog runs on the clock's goroutine and must not block; the
// watchdog loop does the work.
func (c *conn) fireWatchdog() {
	select {
	case c.wdFire <- struct{}{}:
	default:
	}
}

func (c *conn) watchdogLoop() {
	for {
		select {
		case <-c.wdFire:
			c.watchdogExpired()
		case <-c.done:
			return
		}
	}
}

// watchdogExpired applies the timer-expiry events of RFC 3539 §3.4.1. Every
// received message moves the deadline forward without touching the timer, so
// an early expiry just re-arms for the remainder.
func (c *conn) watchdogExpired() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	now := c.node.cfg.Clock.Now()
	if now.Before(c.wdDeadline) {
		c.wdTimer = c.node.cfg.Clock.AfterFunc(c.wdDeadline.Sub(now), c.fireWatchdog)
		c.mu.Unlock()
		return
	}
	if c.closing {
		// Disconnecting, from the start of the disconnect (the drain before
		// our DPR, or the peer's DPR) on: no DWR goes, so none can follow the
		// DPR or DPA (RFC 6733 §5.6, Closing; #376), and the DPR's timeout or
		// the peer closing ends the connection, not the watchdog.
		c.armWatchdogLocked(now)
		c.mu.Unlock()
		return
	}
	send, drop := false, false
	switch c.state {
	case watchdogOkay:
		if c.dwrPending {
			// Failover: no new requests until the peer answers again.
			c.state = watchdogSuspect
			c.node.log.Warn("diameter peer suspect: watchdog unanswered", "peer_host", c.caps.host)
		} else {
			send, c.dwrPending = true, true
		}
	case watchdogSuspect:
		drop = true
	case watchdogReopen:
		switch {
		case !c.dwrPending:
			send, c.dwrPending = true, true
		case c.numDWA >= 0:
			c.numDWA = -1
		default:
			drop = true
		}
	}
	c.armWatchdogLocked(now)
	c.mu.Unlock()
	if drop {
		c.close(errWatchdogExpired)
		return
	}
	if send {
		c.sendDWR()
	}
}

// sendDWR sends a watchdog request. Its answer is not awaited: the watchdog
// timer, not a request timeout, decides what a missing DWA means. A DWR that
// does not fit the control queue is dropped, which that timer then treats as
// unanswered.
func (c *conn) sendDWR() {
	n := c.node
	dwr := &Message{
		Flags:         FlagRequest,
		Code:          CodeDeviceWatchdog,
		ApplicationID: AppCommon,
		HopByHop:      c.nextHopByHop(),
		EndToEnd:      n.nextEndToEnd(),
	}
	dwr.Add(n.originAVPs()...)
	dwr.Add(NewAVP(AVPOriginStateID, FlagMandatory, 0, Unsigned32(n.cfg.OriginStateID)))
	b, err := dwr.Encode()
	if err != nil {
		return
	}
	if !c.enqueueControl(b) {
		n.log.Warn("diameter watchdog request dropped: write queue full", "peer_host", c.caps.host)
	}
}
