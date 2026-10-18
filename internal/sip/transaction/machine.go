package transaction

import (
	"sync"
	"time"
)

// State is the state of a transaction (RFC 3261 §17, RFC 6026 §7.1 and §7.2).
type State int

// The states of the four state machines. Calling exists only for client INVITE
// and Trying only for non-INVITE transactions; Accepted is RFC 6026's and exists
// only for INVITE transactions; Confirmed exists only for server INVITE.
const (
	Calling State = iota + 1
	Trying
	Proceeding
	Accepted
	Completed
	Confirmed
	Terminated
)

func (s State) String() string {
	switch s {
	case Calling:
		return "Calling"
	case Trying:
		return "Trying"
	case Proceeding:
		return "Proceeding"
	case Accepted:
		return "Accepted"
	case Completed:
		return "Completed"
	case Confirmed:
		return "Confirmed"
	case Terminated:
		return "Terminated"
	}
	return "State(?)"
}

// timerID names a timer slot. Each machine needs at most one timer of each
// kind at a time, so the RFC timers share four slots:
//
//	retransmit  A (client INVITE), E (client non-INVITE), G (server INVITE)
//	timeout     B, F, H
//	linger      D, K, I, J, L, M: how long a finished transaction absorbs
//	            retransmissions
//	trying      the 200 ms 100 Trying delay (§17.2.1)
type timerID int

const (
	timerRetransmit timerID = iota
	timerTimeout
	timerLinger
	timerTrying
	timerSlots
)

type armedTimer struct {
	timer Timer
	seq   uint64
}

// machine is what the four state machines share: a lock, a state, and timers
// whose stale firings are ignored.
type machine struct {
	l      *Layer
	key    string
	server bool
	// onTimer handles a timer that fired; it runs with mu held.
	onTimer func(timerID) func()

	mu       sync.Mutex
	state    State
	reliable bool
	timers   [timerSlots]armedTimer
	seq      uint64
	// interval is the current retransmission interval of A, E or G.
	interval time.Duration
}

// arm (re)starts a timer. A timer that was already running is stopped, and if it
// fires anyway its sequence number no longer matches and the firing is ignored.
// mu must be held.
func (m *machine) arm(id timerID, d time.Duration) {
	m.stop(id)
	m.seq++
	seq := m.seq
	m.timers[id] = armedTimer{seq: seq, timer: m.l.clock.AfterFunc(d, func() { m.fire(id, seq) })}
}

// stop cancels a timer. mu must be held.
func (m *machine) stop(id timerID) {
	if t := m.timers[id].timer; t != nil {
		t.Stop()
	}
	m.timers[id] = armedTimer{}
}

func (m *machine) fire(id timerID, seq uint64) {
	m.mu.Lock()
	if m.timers[id].seq != seq || m.state == Terminated {
		m.mu.Unlock()
		return
	}
	m.timers[id] = armedTimer{}
	notify := m.onTimer(id)
	m.mu.Unlock()
	if notify != nil {
		notify()
	}
}

// linger moves to state s and, after d, to Terminated. A reliable transport needs
// no lingering, since there are no retransmissions to absorb, and d is then zero.
// mu must be held.
func (m *machine) linger(s State, d time.Duration) {
	m.stop(timerRetransmit)
	m.stop(timerTimeout)
	m.stop(timerTrying)
	if d <= 0 {
		m.terminate()
		return
	}
	m.state = s
	m.arm(timerLinger, d)
}

// terminate ends the transaction and removes it from the layer. mu must be held.
func (m *machine) terminate() {
	if m.state == Terminated {
		return
	}
	m.state = Terminated
	for id := range m.timers {
		m.stop(timerID(id))
	}
	m.l.remove(m.key, m.server)
}

// unlessReliable returns d for an unreliable transport and zero for a reliable
// one: the Timer D, I, J and K rule.
func (m *machine) unlessReliable(d time.Duration) time.Duration {
	if m.reliable {
		return 0
	}
	return d
}
