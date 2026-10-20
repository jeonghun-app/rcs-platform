package groupstore_test

import (
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore/storetest"
)

func TestMemoryMeetsTheContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) groupstore.Store { return groupstore.NewMemory() })
}

func TestStatesHaveNamesAndOnlyCurrentOnesAreActive(t *testing.T) {
	for s, want := range map[groupstore.State]string{groupstore.Invited: "invited", groupstore.Joined: "joined",
		groupstore.Left: "left", groupstore.Removed: "removed", 0: "unknown"} {
		if s.String() != want || s.Active() != (s == groupstore.Invited || s == groupstore.Joined) {
			t.Errorf("%d: %s, active %v", s, s, s.Active())
		}
	}
	g := groupstore.Group{Participants: []groupstore.Participant{{Identity: "a"}}}
	if _, ok := g.Participant("a"); !ok {
		t.Error("participant not found")
	}
	if _, ok := g.Participant("b"); ok {
		t.Error("a stranger found")
	}
}
