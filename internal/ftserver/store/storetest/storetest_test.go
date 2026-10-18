package storetest_test

import (
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store/storetest"
)

// The contract runs here against the memory backends so that a change to
// the contract itself is checked without containers.
func TestContractHoldsForTheMemoryBackends(t *testing.T) {
	storetest.Metadata(t, func(*testing.T) store.Metadata { return store.NewMemory() })
	storetest.Blobs(t, store.NewMemoryBlobs(4), 4)
}

func TestEqualTellsRecordsApart(t *testing.T) {
	a := storetest.Record("id", "owner", "tid")
	b := a.Clone()
	if !storetest.Equal(a, b) {
		t.Fatal("a record differs from its clone")
	}
	b.Thumbnail = &store.Thumbnail{Size: 1}
	if storetest.Equal(a, b) {
		t.Fatal("a thumbnail went unnoticed")
	}
	b = a.Clone()
	b.Parts = []store.Part{{Number: 1}}
	if storetest.Equal(a, b) {
		t.Fatal("a part went unnoticed")
	}
}
