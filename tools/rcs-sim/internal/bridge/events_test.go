package bridge

import (
	"errors"
	"fmt"
	"net"
	"net/http"
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

func TestAStreamThatFallsBehindIsDroppedWithoutHoldingTheOthers(t *testing.T) {
	hb := newHub()
	slow, _ := hb.subscribe()
	fast, _ := hb.subscribe()
	got := make(chan int)
	go func() {
		n := 0
		for {
			select {
			case <-fast.events:
				n++
			case <-fast.gone:
				got <- n
				return
			}
			if n == subscriberQueue+10 {
				got <- n
				return
			}
		}
	}()
	for i := range subscriberQueue + 10 {
		hb.publish(registrationEvent{Type: "registration", Endpoint: fmt.Sprint(i)})
	}
	if n := <-got; n != subscriberQueue+10 {
		t.Fatalf("the reading stream got %d events", n)
	}
	select {
	case <-slow.gone:
	default:
		t.Fatal("the stream that read nothing is still subscribed")
	}
	if slow.closing != closedBehind {
		t.Fatalf("dropped for %v", slow.closing)
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
