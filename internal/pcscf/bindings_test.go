package pcscf

import (
	"errors"
	"testing"
)

// A flow takes at most its share of bindings and the task at most its
// total; one refused takes nothing, and given back ones are free again.
func TestBindingsAreLimitedPerFlowAndPerTask(t *testing.T) {
	l := newBindingLimit(2, 3)
	if l.take("FLOW-A", 2) != nil || !errors.Is(l.take("FLOW-A", 1), errBindingLimit) {
		t.Fatal("the flow's limit")
	}
	if l.take("FLOW-B", 1) != nil || !errors.Is(l.take("FLOW-C", 1), errBindingLimit) || l.held() != 3 {
		t.Fatalf("the task's limit: %d held", l.held())
	}
	if !errors.Is(l.take("FLOW-B", 2), errBindingLimit) || l.held() != 3 {
		t.Fatalf("a refused take took %d", l.held())
	}
	l.give("FLOW-A", 1)
	if l.take("FLOW-C", 1) != nil || l.held() != 3 {
		t.Fatal("a binding given back is not free")
	}
	// Giving back more than a flow holds frees only what it holds.
	l.give("FLOW-B", 5)
	if l.held() != 2 || l.take("FLOW-A", 1) != nil {
		t.Fatalf("held %d", l.held())
	}
}
