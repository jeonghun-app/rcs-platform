package store_test

import (
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store/storetest"
)

func TestMemoryStoreBehavesAsTheHSSExpects(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Store { return store.NewMemory() }, storetest.Options{})
}
