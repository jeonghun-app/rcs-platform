package transport

import (
	"container/list"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// FlowID names a flow: one TCP or TLS connection, or one UDP source address on one
// listener, in the sense of RFC 5626. It is opaque, unguessable and made only of
// URL-safe base64 characters, which are valid in the user part and parameters of a
// SIP URI, so a service can use it as the flow token of RFC 5626 §5.2 as it is.
//
// A FlowID is a capability to send to a subscriber's connection: it must not be
// logged.
type FlowID string

// WellFormed reports whether id has the form every FlowID has, URL-safe
// base64 of flowTokenBytes: what a service that did not make it, such as
// scscf checking the next hop of a request, can tell of a flow token. It
// says nothing of whether the flow is live.
func (id FlowID) WellFormed() bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(string(id))
	return err == nil && len(b) == flowTokenBytes
}

// flowTokenBytes is how much of the HMAC-SHA256 output a FlowID keeps. 128 bits
// is the truncation RFC 2104 §5 allows for SHA-256 and leaves no chance of
// guessing a live flow.
const flowTokenBytes = 16

// flowKeyLabel separates flow tokens from anything else that might one day be
// computed with the same key.
const flowKeyLabel = "rcs-platform sip flow v1"

// FlowInfo describes a flow.
type FlowInfo struct {
	Network Network
	// Addr is the peer: the client address from the PROXY header when the
	// listener requires one, otherwise the socket peer.
	Addr netip.AddrPort
	// Listener is the name of the listener the flow arrived on, empty for a
	// connection this transport opened.
	Listener string
}

// flow is one entry of the flow table.
type flow struct {
	id      FlowID
	network Network
	remote  netip.AddrPort
	lis     *listener // nil for an outbound connection
	// serverName is the TLS name an outbound connection was verified against;
	// it is part of the reuse key so a connection verified for one name is never
	// reused for another.
	serverName string

	conn net.Conn // nil for UDP
	// q feeds the writer goroutine of a stream flow.
	q      *sendQueue
	closed atomic.Bool
	// idle is a stream flow's idle timeout in nanoseconds, and dr the reader
	// that applies it, once the flow is being served.
	idle atomic.Int64
	dr   atomic.Pointer[deadlineReader]
	// pinging is set by the first Transport.Ping: the flow is then the
	// client end of the RFC 5626 keep-alive, and the CRLFs it reads are
	// pongs.
	pinging atomic.Bool

	// UDP only, guarded by flowTable.mu: when the flow last received a
	// datagram, and its places in the table's recency lists.
	lastSeen time.Time
	inAll    *list.Element
	inIP     *list.Element
}

func (f *flow) info() FlowInfo {
	fi := FlowInfo{Network: f.network, Addr: f.remote}
	if f.lis != nil {
		fi.Listener = f.lis.name
	}
	return fi
}

func (f *flow) source() Source {
	fi := f.info()
	return Source{Flow: f.id, Network: fi.Network, Addr: fi.Addr, Listener: fi.Listener,
		ClientFacing: f.lis != nil && f.lis.clientFacing}
}

// reuseKey identifies the flows a request "to this address" may use.
type reuseKey struct {
	network    Network
	remote     netip.AddrPort
	serverName string
	listener   string // UDP only: a UDP flow belongs to one socket
}

func (f *flow) reuseKey() reuseKey {
	k := reuseKey{network: f.network, remote: f.remote, serverName: f.serverName}
	if f.network == UDP {
		k.listener = f.lis.name
	}
	return k
}

// reusable reports whether requests "to this address" may use the flow. Two
// kinds of accepted connection are not. A TLS one: its peer was never verified as
// a server, so a request meant for a server at that address must open its own
// connection (RFC 5923 §9.2 refuses reuse of a connection whose client presented
// no certificate for the same reason). And one whose address came from a PROXY
// header: whoever reaches the port can write any address there, including a core
// node's, and would then receive the requests meant for it.
func (f *flow) reusable() bool {
	if f.lis == nil {
		return true
	}
	return f.network != TLS && !f.lis.proxy
}

// flowTable maps FlowIDs to flows and peers to reusable flows. Its methods are
// safe for concurrent use. No method holds the lock for longer than a few map
// and list operations: there is no scan of the table.
//
// UDP flows are kept in two recency lists, one for the table and one per source
// IP, most recent first. A datagram moves its flow to the front, an expired flow
// is dropped from the back, and when a limit is reached the oldest flow of that
// IP, or of the table, makes room. So a full table never refuses a new client,
// and one host with many source ports only ever displaces its own flows.
type flowTable struct {
	key         [sha256.Size]byte
	now         func() time.Time
	udpTimeout  time.Duration
	maxUDP      int
	maxUDPPerIP int
	// onClosed is told about every flow that leaves the table, after the lock
	// is released.
	onClosed func(*flow)
	counter  atomic.Uint64

	mu       sync.Mutex
	byID     map[FlowID]*flow
	byPeer   map[reuseKey]*flow
	udpAll   list.List
	udpByIP  map[netip.Addr]*list.List
	inbound  int
	outbound int
	evicted  uint64
	closed   bool
	// gone collects the flows removed under the lock, for onClosed.
	gone []*flow
}

type tableConfig struct {
	udpTimeout          time.Duration
	maxUDP, maxUDPPerIP int
	onClosed            func(*flow)
}

func newFlowTable(key [sha256.Size]byte, now func() time.Time, c tableConfig) *flowTable {
	t := &flowTable{
		key:         key,
		now:         now,
		udpTimeout:  c.udpTimeout,
		maxUDP:      c.maxUDP,
		maxUDPPerIP: c.maxUDPPerIP,
		onClosed:    c.onClosed,
		byID:        make(map[FlowID]*flow),
		byPeer:      make(map[reuseKey]*flow),
		udpByIP:     make(map[netip.Addr]*list.List),
	}
	if t.onClosed == nil {
		t.onClosed = func(*flow) {}
	}
	return t
}

// unlock releases the lock and reports the flows removed while it was held.
func (t *flowTable) unlock() {
	gone := t.gone
	t.gone = nil
	t.mu.Unlock()
	for _, f := range gone {
		t.onClosed(f)
	}
}

// token computes the FlowID of a flow from its identity (ADR 0005). The counter
// makes every flow distinct even when a client reconnects from the same address
// and port, and the per-start key makes the tokens of an earlier process, which
// may have had this task's IP address, meaningless here.
func (t *flowTable) token(network Network, listener string, remote netip.AddrPort, n uint64) FlowID {
	m := hmac.New(sha256.New, t.key[:])
	var b [8]byte
	m.Write([]byte(flowKeyLabel))
	writeField := func(s string) {
		binary.BigEndian.PutUint16(b[:2], uint16(len(s)))
		m.Write(b[:2])
		m.Write([]byte(s))
	}
	writeField(string(network))
	writeField(listener)
	a := remote.Addr().As16()
	m.Write(a[:])
	binary.BigEndian.PutUint16(b[:2], remote.Port())
	m.Write(b[:2])
	binary.BigEndian.PutUint64(b[:], n)
	m.Write(b[:])
	return FlowID(base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:flowTokenBytes]))
}

func (t *flowTable) newFlow(network Network, lis *listener, remote netip.AddrPort) *flow {
	name := ""
	if lis != nil {
		name = lis.name
	}
	return &flow{
		id:      t.token(network, name, remote, t.counter.Add(1)),
		network: network,
		remote:  remote,
		lis:     lis,
	}
}

// addStream enters a connected stream flow. It fails when the table is closed.
func (t *flowTable) addStream(f *flow) bool {
	t.mu.Lock()
	defer t.unlock()
	if t.closed {
		return false
	}
	t.byID[f.id] = f
	if f.reusable() {
		if _, ok := t.byPeer[f.reuseKey()]; !ok {
			t.byPeer[f.reuseKey()] = f
		}
	}
	if f.lis != nil {
		t.inbound++
	} else {
		t.outbound++
	}
	return true
}

// udpFlow returns the live flow of a UDP source on a listener and marks it as just
// seen, or nil if there is none.
func (t *flowTable) udpFlow(lis *listener, remote netip.AddrPort) *flow {
	now := t.now()
	t.mu.Lock()
	defer t.unlock()
	f := t.byPeer[reuseKey{network: UDP, remote: remote, listener: lis.name}]
	if f == nil {
		return nil
	}
	if t.expired(f, now) {
		t.removeLocked(f)
		return nil
	}
	f.lastSeen = now
	t.udpAll.MoveToFront(f.inAll)
	t.udpByIP[remote.Addr()].MoveToFront(f.inIP)
	return f
}

// addUDP enters a new UDP flow, displacing the oldest flow of its source IP or of
// the table when either is at its limit. It returns false when the table is
// closed. A flow for the same source that appeared meanwhile is returned instead.
func (t *flowTable) addUDP(f *flow) (*flow, bool) {
	now := t.now()
	t.mu.Lock()
	defer t.unlock()
	if t.closed {
		return nil, false
	}
	if g := t.byPeer[f.reuseKey()]; g != nil && !t.expired(g, now) {
		return g, true
	}
	for b := t.udpAll.Back(); b != nil && t.expired(b.Value.(*flow), now); b = t.udpAll.Back() {
		t.removeLocked(b.Value.(*flow))
	}
	if g := t.byPeer[f.reuseKey()]; g != nil {
		t.removeLocked(g)
	}
	ip := f.remote.Addr()
	switch perIP := t.udpByIP[ip]; {
	case perIP != nil && perIP.Len() >= t.maxUDPPerIP:
		t.removeLocked(perIP.Back().Value.(*flow))
		t.evicted++
	case t.udpAll.Len() >= t.maxUDP:
		t.removeLocked(t.udpAll.Back().Value.(*flow))
		t.evicted++
	}
	f.lastSeen = now
	t.byID[f.id] = f
	t.byPeer[f.reuseKey()] = f
	f.inAll = t.udpAll.PushFront(f)
	perIP := t.udpByIP[ip]
	if perIP == nil {
		perIP = list.New()
		t.udpByIP[ip] = perIP
	}
	f.inIP = perIP.PushFront(f)
	return f, true
}

func (t *flowTable) expired(f *flow, now time.Time) bool {
	return f.network == UDP && now.Sub(f.lastSeen) > t.udpTimeout
}

// lookup resolves a FlowID. Unknown, forged and stale IDs, closing connections
// and expired UDP flows all give nil.
func (t *flowTable) lookup(id FlowID) *flow {
	t.mu.Lock()
	defer t.unlock()
	f := t.byID[id]
	if f == nil {
		return nil
	}
	if f.closed.Load() || t.expired(f, t.now()) {
		t.removeLocked(f)
		return nil
	}
	return f
}

// peer returns an open flow requests to k may reuse.
func (t *flowTable) peer(k reuseKey) *flow {
	t.mu.Lock()
	defer t.unlock()
	f := t.byPeer[k]
	if f == nil || f.closed.Load() {
		return nil
	}
	return f
}

// remove takes a flow out of the table; it is safe to call more than once.
func (t *flowTable) remove(f *flow) {
	t.mu.Lock()
	defer t.unlock()
	t.removeLocked(f)
}

func (t *flowTable) removeLocked(f *flow) {
	if t.byID[f.id] != f {
		return
	}
	delete(t.byID, f.id)
	if k := f.reuseKey(); t.byPeer[k] == f {
		delete(t.byPeer, k)
	}
	switch {
	case f.network == UDP:
		t.udpAll.Remove(f.inAll)
		ip := f.remote.Addr()
		if perIP := t.udpByIP[ip]; perIP != nil {
			perIP.Remove(f.inIP)
			if perIP.Len() == 0 {
				delete(t.udpByIP, ip)
			}
		}
	case f.lis != nil:
		t.inbound--
	default:
		t.outbound--
	}
	t.gone = append(t.gone, f)
}

// close marks the table closed, removes its UDP flows and returns the stream
// flows still open, which the caller closes.
func (t *flowTable) close() []*flow {
	t.mu.Lock()
	defer t.unlock()
	t.closed = true
	var streams []*flow
	for _, f := range t.byID {
		if f.conn != nil {
			streams = append(streams, f)
		} else {
			t.removeLocked(f)
		}
	}
	return streams
}

// streams returns the stream flows in the table.
func (t *flowTable) streams() []*flow {
	t.mu.Lock()
	defer t.unlock()
	out := make([]*flow, 0, t.inbound+t.outbound)
	for _, f := range t.byID {
		if f.conn != nil && f.q != nil {
			out = append(out, f)
		}
	}
	return out
}

type tableStats struct {
	inbound, outbound, udp int
	evicted                uint64
}

func (t *flowTable) stats() tableStats {
	t.mu.Lock()
	defer t.unlock()
	return tableStats{inbound: t.inbound, outbound: t.outbound, udp: t.udpAll.Len(), evicted: t.evicted}
}
