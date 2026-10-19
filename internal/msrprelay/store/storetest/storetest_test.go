package storetest_test

import (
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/store"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/store/storetest"
)

// The contract itself is exercised through the memory backend, which is
// what makes its own coverage visible in this package.
func TestContractPassesOnTheMemoryBackend(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Store { return store.NewMemory() })
}
