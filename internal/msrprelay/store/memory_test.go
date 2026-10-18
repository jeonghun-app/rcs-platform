package store_test

import (
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/store"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/store/storetest"
)

func TestMemoryMeetsTheContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Store { return store.NewMemory() })
}

func TestMemorySharedByEveryCallMeetsTheContract(t *testing.T) {
	// The integration run shares one table between subtests; so does this.
	m := store.NewMemory()
	storetest.Run(t, func(*testing.T) store.Store { return m })
	if m.Len() == 0 {
		t.Fatal("the contract left no binding behind; Len counts nothing")
	}
}
