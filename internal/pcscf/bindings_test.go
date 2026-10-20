package pcscf

import (
	"errors"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// take is l.take without the wait.
func take(l *bindingLimit, flow transport.FlowID, n int) error {
	_, err := l.take(flow, n)
	return err
}

// A flow takes at most its share of bindings and the task at most its
// total; one refused takes nothing, and given back ones are free again.
func TestBindingsAreLimitedPerFlowAndPerTask(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	l := newBindingLimit(2, 3, 100, clock.now)
	if take(l, "FLOW-A", 2) != nil || !errors.Is(take(l, "FLOW-A", 1), errBindingLimit) {
		t.Fatal("the flow's limit")
	}
	if take(l, "FLOW-B", 1) != nil || !errors.Is(take(l, "FLOW-C", 1), errBindingLimit) || l.held() != 3 {
		t.Fatalf("the task's limit: %d held", l.held())
	}
	if !errors.Is(take(l, "FLOW-B", 2), errBindingLimit) || l.held() != 3 {
		t.Fatalf("a refused take took %d", l.held())
	}
	l.give("FLOW-A", 1)
	if take(l, "FLOW-C", 1) != nil || l.held() != 3 {
		t.Fatal("a binding given back is not free")
	}
	// Giving back more than a flow holds frees only what it holds.
	l.give("FLOW-B", 5)
	if l.held() != 2 || take(l, "FLOW-A", 1) != nil {
		t.Fatalf("held %d", l.held())
	}
	if l.most() != 2 {
		t.Errorf("most %d", l.most())
	}
}

// A flow creates at most perMinute bindings at once, and perMinute a
// minute after, whatever it gives back; a refusal says how long until it
// may create what it asked for, and takes nothing. A flow forgotten, or
// whose count has filled again, starts afresh.
func TestBindingsCreatedAreLimitedPerMinute(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	l := newBindingLimit(100, 1000, 6, clock.now) // one every 10 s
	for range 6 {
		if take(l, "FLOW-A", 1) != nil {
			t.Fatal("refused within the minute's share")
		}
		l.give("FLOW-A", 1)
	}
	wait, err := l.take("FLOW-A", 2)
	if !errors.Is(err, errBindingRate) || wait != 20*time.Second || l.held() != 0 {
		t.Fatalf("past the rate: %v, %v, held %d", wait, err, l.held())
	}
	if take(l, "FLOW-B", 1) != nil {
		t.Fatal("another flow is limited too")
	}
	l.give("FLOW-B", 1)
	clock.t = clock.t.Add(19 * time.Second)
	if wait, err := l.take("FLOW-A", 2); !errors.Is(err, errBindingRate) || wait != time.Second {
		t.Fatalf("after 19 s: %v, %v", wait, err)
	}
	clock.t = clock.t.Add(time.Second)
	if take(l, "FLOW-A", 2) != nil {
		t.Fatal("refused once the wait is over")
	}
	if l.most() != 6 {
		t.Errorf("most %d", l.most())
	}
	l.forget("FLOW-A")
	l.give("FLOW-A", 2)
	if take(l, "FLOW-A", 6) != nil {
		t.Fatal("a forgotten flow is still counted")
	}
	l.give("FLOW-A", 6)
	clock.t = clock.t.Add(59 * time.Second)
	l.sweep()
	if len(l.created) != 1 || l.created["FLOW-A"] == nil {
		t.Fatalf("counts kept: %v", l.created)
	}
	clock.t = clock.t.Add(time.Second)
	l.sweep()
	if len(l.created) != 0 {
		t.Errorf("full counts kept: %d", len(l.created))
	}
}
