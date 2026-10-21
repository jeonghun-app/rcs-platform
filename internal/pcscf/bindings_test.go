package pcscf

import (
	"errors"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// take is l.take for flow's own share, without the wait.
func take(l *bindingLimit, flow transport.FlowID, n int) error {
	_, err := l.take(share{flow: flow}, n)
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
	l.give(share{flow: "FLOW-A"}, 1)
	if take(l, "FLOW-C", 1) != nil || l.held() != 3 {
		t.Fatal("a binding given back is not free")
	}
	// Giving back more than a flow holds frees only what it holds.
	l.give(share{flow: "FLOW-B"}, 5)
	if l.held() != 2 || take(l, "FLOW-A", 1) != nil {
		t.Fatalf("held %d", l.held())
	}
	if l.most(false) != 2 {
		t.Errorf("most %d", l.most(false))
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
		l.give(share{flow: "FLOW-A"}, 1)
	}
	wait, err := l.take(share{flow: "FLOW-A"}, 2)
	if !errors.Is(err, errBindingRate) || wait != 20*time.Second || l.held() != 0 {
		t.Fatalf("past the rate: %v, %v, held %d", wait, err, l.held())
	}
	if take(l, "FLOW-B", 1) != nil {
		t.Fatal("another flow is limited too")
	}
	l.give(share{flow: "FLOW-B"}, 1)
	clock.t = clock.t.Add(19 * time.Second)
	if wait, err := l.take(share{flow: "FLOW-A"}, 2); !errors.Is(err, errBindingRate) || wait != time.Second {
		t.Fatalf("after 19 s: %v, %v", wait, err)
	}
	clock.t = clock.t.Add(time.Second)
	if take(l, "FLOW-A", 2) != nil {
		t.Fatal("refused once the wait is over")
	}
	if l.most(false) != 6 {
		t.Errorf("most %d", l.most(false))
	}
	l.forget("FLOW-A")
	l.give(share{flow: "FLOW-A"}, 2)
	if take(l, "FLOW-A", 6) != nil {
		t.Fatal("a forgotten flow is still counted")
	}
	l.give(share{flow: "FLOW-A"}, 6)
	clock.t = clock.t.Add(59 * time.Second)
	l.sweep()
	if len(l.created) != 1 || l.created[share{flow: "FLOW-A"}] == nil {
		t.Fatalf("counts kept: %v", l.created)
	}
	clock.t = clock.t.Add(time.Second)
	l.sweep()
	if len(l.created) != 0 {
		t.Errorf("full counts kept: %d", len(l.created))
	}
}

// rcs-as's offers toward a flow take from a share of their own, with its
// own limits, so a flow full of them can still make its own; the task's
// total is the one of both (#315 code review 2, security review).
func TestCoreOffersHaveAShareOfTheirOwn(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	l := newBindingLimit(2, 5, 100, clock.now).coreOfferShare(1, 3)
	in := share{flow: "FLOW-A", coreOffer: true}
	if _, err := l.take(in, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := l.take(in, 1); !errors.Is(err, errBindingLimit) {
		t.Fatalf("past the core offers' share: %v", err)
	}
	if take(l, "FLOW-A", 2) != nil || l.held() != 3 {
		t.Fatalf("the client's own share: %d held", l.held())
	}
	if l.most(false) != 2 || l.most(true) != 1 {
		t.Errorf("most %d, %d", l.most(false), l.most(true))
	}
	// Each creates at its own rate.
	l.give(in, 1)
	for range 2 {
		if _, err := l.take(in, 1); err != nil {
			t.Fatal(err)
		}
		l.give(in, 1)
	}
	if wait, err := l.take(in, 1); !errors.Is(err, errBindingRate) || wait != 20*time.Second {
		t.Fatalf("past the core offers' rate: %v, %v", wait, err)
	}
	// FLOW-A's own 2 and FLOW-B's 2 leave the task 1 of its 5.
	if take(l, "FLOW-B", 2) != nil || !errors.Is(take(l, "FLOW-C", 2), errBindingLimit) {
		t.Fatal("the task's total")
	}
	if _, err := l.take(share{flow: "FLOW-C", coreOffer: true}, 1); err != nil || l.held() != 5 {
		t.Fatalf("the task's last binding: %v, %d held", err, l.held())
	}
	// The sweep judges each share's count by that share's own rate: the
	// core offers', at 3 a minute, is full again 30 s after one creation
	// (#315 QA round 3).
	sweepy := newBindingLimit(16, 100, 100, clock.now).coreOfferShare(16, 3)
	if _, err := sweepy.take(share{flow: "FLOW-D", coreOffer: true}, 1); err != nil {
		t.Fatal(err)
	}
	sweepy.give(share{flow: "FLOW-D", coreOffer: true}, 1)
	clock.t = clock.t.Add(30 * time.Second)
	sweepy.sweep()
	if len(sweepy.created) != 0 {
		t.Errorf("a full core offers' count kept: %v", sweepy.created)
	}
	// forget drops both shares' counts.
	l.forget("FLOW-A")
	if _, ok := l.created[in]; ok {
		t.Error("the core offers' count kept")
	}
	if _, ok := l.created[share{flow: "FLOW-A"}]; ok {
		t.Error("the client's count kept")
	}
}
