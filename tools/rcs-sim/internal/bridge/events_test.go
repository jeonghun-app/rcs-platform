package bridge

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/websocket/wstest"
)

func TestEveryStreamGetsEveryEventInOrder(t *testing.T) {
	h := newHarness(t)
	a, b := h.events(), h.events()
	for i := range 5 {
		h.online(fmt.Sprintf("car-%d", i))
	}
	for _, s := range []*stream{a, b} {
		for i := range 5 {
			if ev := s.next(); ev["type"] != "registration" || ev["endpoint"] != fmt.Sprintf("car-%d", i) || ev["state"] != "registered" {
				t.Fatalf("event %d: %v", i, ev)
			}
		}
	}
}

// One stream reads, one does not: once the reader has emptied its queue,
// the next event fills the other's and drops it, and the reader gets it.
// In that order, on the test's goroutine, so that no scheduling can let the
// reader's queue fill too (QA on #661: -cpu 1 failed every time).
func TestAStreamThatFallsBehindIsDroppedWithoutHoldingTheOthers(t *testing.T) {
	hb := newHub()
	slow, _ := hb.subscribe()
	fast, _ := hb.subscribe()
	for i := range subscriberQueue {
		if n := hb.publish(registrationEvent{Type: "registration", Endpoint: fmt.Sprint(i)}); n != 2 {
			t.Fatalf("event %d went to %d streams, want both", i, n)
		}
	}
	for range subscriberQueue {
		<-fast.events
	}
	if n := hb.publish(registrationEvent{Type: "registration", Endpoint: "one more"}); n != 1 {
		t.Fatalf("the event past the slow stream's queue went to %d streams, want the reader's only", n)
	}
	select {
	case <-slow.gone:
	default:
		t.Fatal("the stream that read nothing is still subscribed")
	}
	if slow.closing != closedBehind {
		t.Fatalf("dropped for %v", slow.closing)
	}
	select {
	case <-fast.gone:
		t.Fatal("the reading stream was dropped")
	case ev := <-fast.events:
		if !strings.Contains(string(ev), "one more") {
			t.Fatalf("the reader got %s", ev)
		}
	}
}

func TestADroppedStreamIsClosedWith1008(t *testing.T) {
	h := newHarness(t)
	s := h.events()
	h.b.hub.mu.Lock()
	for sub := range h.b.hub.subs {
		h.b.hub.dropLocked(sub, closedBehind)
	}
	h.b.hub.mu.Unlock()
	_, err := s.c.Next(10 * time.Second)
	var ce *wstest.CloseError
	if !errors.As(err, &ce) || ce.Code != 1008 {
		t.Fatalf("the stream ended with %v, want a Close with 1008", err)
	}
}

// pingArmed waits until the stream's ping timer is armed again.
func pingArmed(t *testing.T, h *harness) {
	t.Helper()
	eventually(t, "the ping timer is armed", func() bool {
		h.clock.mu.Lock()
		defer h.clock.mu.Unlock()
		for _, tm := range h.clock.timers {
			if tm.d == pingInterval && !tm.stopped {
				return true
			}
		}
		return false
	})
}

func TestAStreamIsPingedAndClosedWhenAPingGoesUnanswered(t *testing.T) {
	h := newHarness(t)
	s := h.events()
	s.c.NoPong = true
	pingArmed(t, h)
	h.clock.fire(pingInterval)
	pingArmed(t, h)
	// The ping is out before the event published after it.
	h.online("car")
	s.await("registration", "car")
	if s.c.Pings() != 1 {
		t.Fatalf("%d pings read, want 1", s.c.Pings())
	}
	h.clock.fire(pingInterval)
	_, err := s.c.Next(10 * time.Second)
	var ne net.Error
	if err == nil || errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("the stream did not end: %v", err)
	}
	// Its slot is free again.
	eventually(t, "the stream is unsubscribed", func() bool {
		h.b.hub.mu.Lock()
		defer h.b.hub.mu.Unlock()
		return len(h.b.hub.subs) == 0
	})
}

// A client that vanishes without a Close gives its slot back once the
// bridge reads the end of its connection, without waiting for the ping
// timeout (QA on #661).
func TestStreamsThatVanishGiveTheirSlotsBack(t *testing.T) {
	h := newHarness(t)
	var streams []*stream
	for range maxSubscribers {
		streams = append(streams, h.events())
	}
	for _, s := range streams {
		s.c.Drop()
	}
	eventually(t, "the slots are free", func() bool {
		h.b.hub.mu.Lock()
		defer h.b.hub.mu.Unlock()
		return len(h.b.hub.subs) == 0
	})
	h.events()
}

func TestStreamsBeyondTheBoundAreRefused(t *testing.T) {
	h := newHarness(t)
	for range maxSubscribers {
		h.events()
	}
	_, res, err := wstest.Dial(h.srv.URL+"/v1/events", http.Header{"Authorization": {"Bearer " + testToken}})
	if err == nil || res == nil || res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("stream %d: %v %v, want 503", maxSubscribers+1, res, err)
	}
}

func TestARequestThatIsNotAWebSocketIsRefusedOnTheEventsPath(t *testing.T) {
	h := newHarness(t)
	if status, _ := h.call(http.MethodGet, "/v1/events", nil); status != http.StatusUpgradeRequired {
		t.Fatalf("answered %d, want 426", status)
	}
	// And its slot is given back.
	h.b.hub.mu.Lock()
	n := len(h.b.hub.subs)
	h.b.hub.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d streams subscribed", n)
	}
}
