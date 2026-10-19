package storetest

import (
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
)

// The suite itself is checked against the memory backend, whose behaviour
// is the reference.
func TestSuitePassesAgainstTheMemoryStore(t *testing.T) {
	Run(t, func(*testing.T) store.Store { return store.NewMemory() }, Options{})
}
