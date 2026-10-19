package hss

import (
	"sync"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/milenage"
)

// Two HSS tasks share the store, as in production, and S-CSCFs send MARs
// for one subscriber to both at once. Every vector must carry its own
// sequence number, and together they must be exactly 1..n: no SQN is handed
// out twice (the card would refuse the second) and none is skipped
// unexpectedly. Run it under the race detector (make race).
func TestConcurrentMARsOnTwoTasksNeverShareASequenceNumber(t *testing.T) {
	e := newEnv(t)
	concurrentMARs(t, e, e.h, e.newHSS(nil))
}

// concurrentMARs runs the check with two HSS tasks over e's store.
func concurrentMARs(t *testing.T, e *env, a, b *HSS) {
	e.provision(impi1, impu1)
	taskA := serveHSS(t, a, "hss-a.rcs.local")
	taskB := serveHSS(t, b, "hss-b.rcs.local")
	clients := []*cscf{
		connectCSCF(t, taskA, "scscf-1.rcs.local"),
		connectCSCF(t, taskB, "scscf-2.rcs.local"),
		connectCSCF(t, taskA, "scscf-3.rcs.local"),
		connectCSCF(t, taskB, "scscf-4.rcs.local"),
	}
	const perClient, vectors = 12, 2
	var mu sync.Mutex
	seen := map[uint64]int{}
	var wg sync.WaitGroup
	for i, c := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var last milenage.SQN
			for range perClient {
				maa := c.mar(impi1, impu1, cx.SchemeDigestAKAv1MD5, vectors, scscfName, nil)
				if maa.Result != resSuccess || len(maa.AuthDataItems) != vectors {
					t.Errorf("client %d: MAA %v with %d items", i, maa.Result, len(maa.AuthDataItems))
					return
				}
				for _, item := range maa.AuthDataItems {
					sqn, err := sqnFrom(item)
					if err != nil {
						t.Error(err)
						return
					}
					// One client's vectors are in increasing order: a later
					// MAA never reuses an earlier one's numbers.
					if sqn.SEQ() <= last.SEQ() {
						t.Errorf("client %d: SEQ %d after %d", i, sqn.SEQ(), last.SEQ())
					}
					last = sqn
					mu.Lock()
					seen[sqn.SEQ()]++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	total := uint64(len(clients) * perClient * vectors)
	for seq := uint64(1); seq <= total; seq++ {
		if seen[seq] != 1 {
			t.Errorf("SEQ %d issued %d times", seq, seen[seq])
		}
	}
	if len(seen) != int(total) {
		t.Errorf("%d distinct SEQs, want %d", len(seen), total)
	}
	if got := milenage.SQN(e.sub(impi1).AKA.SQN).SEQ(); got != total {
		t.Errorf("stored SEQ = %d, want %d", got, total)
	}
}
