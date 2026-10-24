package bridge

import (
	"encoding/json"
	"sync"
)

// The events of GET /v1/events (docs/rcs-bridge.md), one JSON text frame
// each.
type (
	messageEvent struct {
		Type     string `json:"type"`
		Endpoint string `json:"endpoint"`
		From     string `json:"from"`
		// FromEndpoint is set when the sender is one of the bridge's
		// endpoints.
		FromEndpoint string `json:"from_endpoint,omitempty"`
		MessageID    string `json:"message_id"`
		ContentType  string `json:"content_type"`
		Body         string `json:"body"`
		At           string `json:"at"`
	}
	imdnEvent struct {
		Type         string `json:"type"`
		Endpoint     string `json:"endpoint"`
		FromEndpoint string `json:"from_endpoint,omitempty"`
		MessageID    string `json:"message_id"`
		Status       string `json:"status"`
	}
	registrationEvent struct {
		Type     string `json:"type"`
		Endpoint string `json:"endpoint"`
		State    string `json:"state"`
		Reason   string `json:"reason,omitempty"`
	}
)

// Bounds of the fan-out.
const (
	// maxSubscribers bounds the event streams open at once.
	maxSubscribers = 16
	// subscriberQueue is how many events a stream may fall behind by
	// before it is closed; the application reconnects.
	subscriberQueue = 1024
)

// hub fans each event out to every open stream. A stream that falls
// behind is dropped rather than waited for, so one slow reader never holds
// up the endpoints or the other streams.
type hub struct {
	mu     sync.Mutex
	subs   map[*subscriber]struct{}
	closed bool
}

// subscriber is one stream's queue. gone is closed when the hub lets go of
// it: closing says why.
type subscriber struct {
	events  chan []byte
	gone    chan struct{}
	closing closeReason
}

// closeReason is why the hub let go of a stream.
type closeReason int

const (
	closedByStream closeReason = iota
	closedBehind
	closedShutdown
)

func newHub() *hub { return &hub{subs: map[*subscriber]struct{}{}} }

// subscribe opens a stream's queue; false when the bridge is closing or
// holds as many streams as it may.
func (h *hub) subscribe() (*subscriber, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || len(h.subs) >= maxSubscribers {
		return nil, false
	}
	s := &subscriber{events: make(chan []byte, subscriberQueue), gone: make(chan struct{})}
	h.subs[s] = struct{}{}
	return s, true
}

// unsubscribe lets go of s, once.
func (h *hub) unsubscribe(s *subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dropLocked(s, closedByStream)
}

func (h *hub) dropLocked(s *subscriber, why closeReason) {
	if _, ok := h.subs[s]; !ok {
		return
	}
	delete(h.subs, s)
	s.closing = why
	close(s.gone)
}

// publish sends ev to every stream and returns how many took it into
// their queues: zero when none is open. Events reach each stream in the
// order they were published.
func (h *hub) publish(ev any) int {
	b, err := json.Marshal(ev)
	if err != nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for s := range h.subs {
		select {
		case s.events <- b:
			n++
		default:
			h.dropLocked(s, closedBehind)
		}
	}
	return n
}

// close lets go of every stream and opens no other.
func (h *hub) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for s := range h.subs {
		h.dropLocked(s, closedShutdown)
	}
}
