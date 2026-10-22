package hss

import (
	"strings"
	"sync"
	"testing"
	"time"

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

// marWait is the Cx timeout of the concurrent MARs: only a hang guard.
const marWait = 30 * time.Second

// concurrentMARs runs the check with two HSS tasks over e's store.
func concurrentMARs(t *testing.T, e *env, a, b *HSS) {
	e.provision(impi1, impu1)
	// A MAR's Cx timeout covers its wait for the subscriber's lock, behind
	// the other clients' MARs on the same task, as well as its own reads
	// and writes, and the retries of a write that lost to the other task,
	// which run until that deadline (#200). On a loaded host DynamoDB Local
	// takes more than DefaultCxTimeout for that, and more than 10 s when
	// make test-integration's other packages share it (#487). The property
	// here is the sequence numbers, so the bound is only the hang guard.
	taskA := serveHSSWith(t, a, "hss-a.rcs.local", marWait)
	taskB := serveHSSWith(t, b, "hss-b.rcs.local", marWait)
	t.Cleanup(func() {
		if t.Failed() {
			// What made a MAR fail: a deadline or a write that kept
			// losing to the other task (errContention) (#487).
			t.Logf("store.conflict %d, cx.mar.error %d", e.metrics.get("store.conflict"), e.metrics.get("cx.mar.error"))
			for _, l := range strings.Split(e.logs.String(), "\n") {
				if strings.Contains(l, "Cx request failed") {
					t.Log(l)
				}
			}
		}
	})
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
