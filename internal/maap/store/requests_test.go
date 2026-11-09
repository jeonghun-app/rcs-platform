package store_test

import (
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store/storetest"
)

func TestMemoryRequestsMeetTheContract(t *testing.T) {
	storetest.RunRequests(t, func(*testing.T) store.Requests { return store.NewMemoryRequests() })
}
