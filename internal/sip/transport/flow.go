package transport

import (
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
// listener, in the sense of RFC 5626. It is opaque, unguessable and made only of URL-safe
// base64 characters, which are valid in the user part and parameters of a SIP URI,
// so a service can use it as the flow token of RFC 5626 §5.2 as it is.
//
// A FlowID is a capability to send to a subscriber's connection: it must not be
// logged.
type FlowID string

// flowTokenBytes is how much of the HMAC-SHA256 output a FlowID keeps. 128 bits
// is the truncation RFC 2104 §5 allows for SHA-256 and leaves no chance of
// guessing a live flow.
const flowTokenBytes = 16

// flowKeyLabel separates flow tokens from anything else that might one day be
// computed with the same key.
const flowKeyLabel = "rcs-platform sip flow v1"

// FlowInfo describes a live flow.
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
	// wmu serializes writes so two messages never interleave on a stream.
	wmu sync.Mutex
	// lastSeen is when a UDP flow last received a datagram, in Unix nanoseconds.
	lastSeen atomic.Int64
	closed   atomic.Bool
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
	return Source{Flow: f.id, Network: fi.Network, Addr: fi.Addr, Listener: fi.Listener}
}

// reuseKey identifies the flows a request "to this address" may use.
type reuseKey struct {
	network    Network
	remote     netip.AddrPort
	serverName string
	listener   string // UDP only: a UDP flow belongs to one socket
}

// flowTable maps FlowIDs to flows and peers to reusable flows. Its methods are
// safe for concurrent use.
type flowTable struct {
	key [sha256.Size]byte
	now func() time.Time
	// udpIdle is how long a UDP flow lives without a datagram.
	udpIdle    time.Duration
	maxUDP     int
	counter    atomic.Uint64
	mu         sync.Mutex
	byID       map[FlowID]*flow
	byPeer     map[reuseKey]*flow
	udpFlows   int
	closed     bool
	streamOpen int
}

func newFlowTable(key [sha256.Size]byte, now func() time.Time, udpIdle time.Duration, maxUDP int) *flowTable {
	return &flowTable{
		key:     key,
		now:     now,
		udpIdle: udpIdle,
		maxUDP:  maxUDP,
		byID:    make(map[FlowID]*flow),
		byPeer:  make(map[reuseKey]*flow),
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

func (f *flow) reuseKey() reuseKey {
	k := reuseKey{network: f.network, remote: f.remote, serverName: f.serverName}
	if f.network == UDP {
		k.listener = f.lis.name
	}
	return k
}

// reusable reports whether requests "to this address" may use the flow. An
// accepted TLS connection is not: its peer was never verified as a server, so a
// request meant for a server at that address must open its own connection
// (RFC 5923 §9.2 refuses reuse of a connection whose client presented no
// certificate for the same reason).
func (f *flow) reusable() bool {
	return !(f.network == TLS && f.lis != nil)
}

// addStream enters a connected stream flow. It fails when the table is closed.
func (t *flowTable) addStream(f *flow) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	t.byID[f.id] = f
	if f.reusable() {
		if _, ok := t.byPeer[f.reuseKey()]; !ok {
			t.byPeer[f.reuseKey()] = f
		}
	}
	t.streamOpen++
	return true
}

// udp returns the flow of a UDP source on a listener, creating it if needed, and
// marks it as just seen. It returns nil when the table is full or closed.
func (t *flowTable) udp(lis *listener, remote netip.AddrPort) (f *flow, created bool) {
	now := t.now()
	k := reuseKey{network: UDP, remote: remote, listener: lis.name}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, false
	}
	if f = t.byPeer[k]; f != nil && !t.expired(f, now) {
		f.lastSeen.Store(now.UnixNano())
		return f, false
	}
	if f != nil {
		t.removeLocked(f)
	}
	if t.udpFlows >= t.maxUDP {
		// Expired flows are only swept when the table is full, which keeps the
		// common path free of a timer per flow.
		t.sweepLocked(now)
		if t.udpFlows >= t.maxUDP {
			return nil, false
		}
	}
	f = t.newFlow(UDP, lis, remote)
	f.lastSeen.Store(now.UnixNano())
	t.byID[f.id] = f
	t.byPeer[k] = f
	t.udpFlows++
	return f, true
}

func (t *flowTable) expired(f *flow, now time.Time) bool {
	return f.network == UDP && now.Sub(time.Unix(0, f.lastSeen.Load())) > t.udpIdle
}

// lookup resolves a FlowID. Unknown, forged and stale IDs, closed connections and
// expired UDP flows all give nil.
func (t *flowTable) lookup(id FlowID) *flow {
	t.mu.Lock()
	defer t.mu.Unlock()
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

// peer returns an open flow requests to (network, remote, serverName) may reuse.
func (t *flowTable) peer(k reuseKey) *flow {
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.byPeer[k]
	if f == nil || f.closed.Load() {
		return nil
	}
	return f
}

// remove takes a flow out of the table; it is safe to call more than once.
func (t *flowTable) remove(f *flow) {
	t.mu.Lock()
	defer t.mu.Unlock()
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
	if f.network == UDP {
		t.udpFlows--
	} else {
		t.streamOpen--
	}
}

func (t *flowTable) sweepLocked(now time.Time) {
	for _, f := range t.byID {
		if t.expired(f, now) {
			t.removeLocked(f)
		}
	}
}

// close marks the table closed and returns the stream flows still open.
func (t *flowTable) close() []*flow {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	var out []*flow
	for _, f := range t.byID {
		if f.conn != nil {
			out = append(out, f)
		}
	}
	return out
}

func (t *flowTable) openStreams() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.streamOpen
}
