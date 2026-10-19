package store_test

import (
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store/storetest"
)

func TestMemoryMeetsTheContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Store { return store.NewMemory() })
}

func TestModesHaveNames(t *testing.T) {
	for m, want := range map[store.Mode]string{store.Chat: "chat", store.Standalone: "standalone", 0: "unknown"} {
		if m.String() != want {
			t.Errorf("%d = %q", m, m.String())
		}
	}
}
