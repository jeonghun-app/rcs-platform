package bridge

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/websocket/wstest"
)

func TestRefreshIsTimedAsTS24229Says(t *testing.T) {
	for _, tc := range []struct{ expires, want time.Duration }{
		{600000 * time.Second, 599400 * time.Second},
		{3600 * time.Second, 3000 * time.Second},
		{1201 * time.Second, 601 * time.Second},
		{1200 * time.Second, 600 * time.Second},
		{600 * time.Second, 300 * time.Second},
		{time.Second, time.Second},
		{0, time.Second},
	} {
		if got := refreshIn(tc.expires); got != tc.want {
			t.Errorf("refreshIn(%v) = %v, want %v", tc.expires, got, tc.want)
		}
	}
}

func TestARegistrationIsRefreshedBeforeItExpires(t *testing.T) {
	h := newHarness(t)
	h.online("car")
	if p := h.clock.pending(); !slices.Equal(p, []time.Duration{3000 * time.Second}) {
		t.Fatalf("pending timers %v, want the refresh at 3000 s", p)
	}
	h.clock.fire(3000 * time.Second)
	if _, refreshes := h.net.counts(); refreshes != 1 {
		t.Fatalf("%d refreshes", refreshes)
	}
	// And the next one is scheduled from what the refresh granted.
	if p := h.clock.pending(); !slices.Equal(p, []time.Duration{3000 * time.Second}) {
		t.Fatalf("pending timers %v after the refresh", p)
	}
}

func TestAFailedRegistrationIsReportedAndTriedAgainLater(t *testing.T) {
	h := newHarness(t)
	ev := h.events()
	h.net.failRegister = 2
	status, out := h.call(http.MethodPut, "/v1/endpoints/car", nil)
	if status != http.StatusCreated || out["registered"] != false {
		t.Fatalf("answered %d %v, want 201 unregistered", status, out)
	}
	if got := ev.await("registration", "car"); got["state"] != "failed" || got["reason"] != "sipua: REGISTER answered 403" {
		t.Fatalf("event %v", got)
	}
	// Retries back off: 2 s, then 4 s.
	if n := h.clock.fire(minRetry); n != 1 {
		t.Fatalf("pending %v, want a retry after %v", h.clock.pending(), minRetry)
	}
	if got := ev.await("registration", "car"); got["state"] != "failed" {
		t.Fatalf("event %v", got)
	}
	if n := h.clock.fire(2 * minRetry); n != 1 {
		t.Fatalf("pending %v, want a retry after %v", h.clock.pending(), 2*minRetry)
	}
	if got := ev.await("registration", "car"); got["state"] != "registered" {
		t.Fatalf("event %v", got)
	}
	if !h.net.registered(msisdnPrefix + "000") {
		t.Fatal("not registered")
	}
}

func TestRetriesBackOffToAMinute(t *testing.T) {
	h := newHarness(t)
	h.net.failRegister = 100
	h.call(http.MethodPut, "/v1/endpoints/car", nil)
	var waits []time.Duration
	for range 8 {
		p := h.clock.pending()
		if len(p) != 1 {
			t.Fatalf("pending %v", p)
		}
		waits = append(waits, p[0])
		h.clock.fire(p[0])
	}
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, time.Minute, time.Minute, time.Minute}
	if !slices.Equal(waits, want) {
		t.Fatalf("waits %v, want %v", waits, want)
	}
}

func TestAnEndpointPutOfflineStopsTrying(t *testing.T) {
	h := newHarness(t)
	h.net.failRegister = 100
	h.call(http.MethodPut, "/v1/endpoints/car", nil)
	h.call(http.MethodPut, "/v1/endpoints/car", map[string]bool{"online": false})
	if p := h.clock.pending(); len(p) != 0 {
		t.Fatalf("pending %v after offline", p)
	}
	n, _ := h.net.counts()
	h.clock.fire(minRetry)
	if again, _ := h.net.counts(); again != n {
		t.Fatal("registered again while offline")
	}
}

func TestALostFlowIsReportedAndRegisteredAgain(t *testing.T) {
	h := newHarness(t)
	ev := h.events()
	h.online("car")
	ev.await("registration", "car")
	h.net.drop(msisdnPrefix + "000")
	if got := ev.await("registration", "car"); got["state"] != "failed" || got["reason"] != reasonFlowLost {
		t.Fatalf("event %v", got)
	}
	eventually(t, "a retry is scheduled", func() bool { return slices.Contains(h.clock.pending(), minRetry) })
	h.clock.fire(minRetry)
	if got := ev.await("registration", "car"); got["state"] != "registered" {
		t.Fatalf("event %v", got)
	}
}

func TestAFailedRefreshLosesTheFlowAndRegistersAnew(t *testing.T) {
	h := newHarness(t)
	ev := h.events()
	h.online("car")
	ev.await("registration", "car")
	h.net.mu.Lock()
	h.net.failRefresh = true
	h.net.mu.Unlock()
	h.clock.fire(3000 * time.Second)
	if got := ev.await("registration", "car"); got["state"] != "failed" || got["reason"] != "sipua: REGISTER answered 500" {
		t.Fatalf("event %v", got)
	}
	if h.net.registered(msisdnPrefix + "000") {
		t.Fatal("the failed flow is still registered")
	}
	h.clock.fire(minRetry)
	if got := ev.await("registration", "car"); got["state"] != "registered" {
		t.Fatalf("event %v", got)
	}
}

func TestAPutOnlineWhileARetryIsPendingRegistersAtOnce(t *testing.T) {
	h := newHarness(t)
	h.net.failRegister = 1
	h.call(http.MethodPut, "/v1/endpoints/car", nil)
	if status, out := h.call(http.MethodPut, "/v1/endpoints/car", nil); status != http.StatusOK || out["registered"] != true {
		t.Fatalf("answered %d %v", status, out)
	}
	if p := h.clock.pending(); !slices.Equal(p, []time.Duration{3000 * time.Second}) {
		t.Fatalf("pending %v, want the refresh only", p)
	}
}

func TestCloseUnregistersEveryEndpointAndEndsTheStreams(t *testing.T) {
	h := newHarness(t)
	ev := h.events()
	h.online("car")
	h.online("phone")
	ev.await("registration", "phone")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h.b.Close(ctx)
	for _, n := range []string{"000", "001"} {
		if h.net.registered(msisdnPrefix + n) {
			t.Fatalf("%s is still registered", n)
		}
	}
	// What was published before goes first, then the Close.
	for {
		_, err := ev.c.Next(10 * time.Second)
		if err == nil {
			continue
		}
		var ce *wstest.CloseError
		if !errors.As(err, &ce) || ce.Code != 1001 {
			t.Fatalf("the stream ended with %v, want a Close with 1001", err)
		}
		break
	}
	if status, _ := h.call(http.MethodPut, "/v1/endpoints/car", nil); status != http.StatusServiceUnavailable {
		t.Fatalf("a PUT after Close answered %d", status)
	}
	if p := h.clock.pending(); len(p) != 0 {
		t.Fatalf("pending %v after Close", p)
	}
}
