package pcscf

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// The acceptance tests of #234, from QA's review of #221: a request the core
// sends a client whose flow then closes, before any answer, reaches the core
// as 430 at once, not as a 408 after Timer B or no answer after Timer F.

func setupTerm(t *testing.T) (*service, *peer, string, *peer) {
	t.Helper()
	icscf := startCoreNode(t, echo200)
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1")})
	c, path := registered(t, s, icscf)
	return s, c, path, dial(t, s.core, nil)
}

// finalWithin reads the core's responses until the final one and says how
// long it took; it runs on other goroutines than the test's, so it returns
// its error.
func finalWithin(core *peer) (int, time.Duration, error) {
	start := time.Now()
	_ = core.nc.SetDeadline(time.Now().Add(45 * time.Second))
	for {
		m, err := core.r.ReadMessage()
		if err != nil {
			return 0, time.Since(start), err
		}
		if res, ok := m.(*sip.Response); ok && res.StatusCode >= 200 {
			return res.StatusCode, time.Since(start), nil
		}
	}
}

func TestAFlowThatClosesWithAnInviteOutstandingIs430(t *testing.T) {
	_, c, path, core := setupTerm(t)
	core.write(coreRequest("INVITE", "sip:alice@192.0.2.10:40000;transport=tcp", fmt.Sprintf("close-inv-%d", requests.Add(1)), "", 1, "Route: <"+path+">"))
	_ = c.nextRequest()
	_ = c.nc.Close()
	if code, took, err := finalWithin(core); err != nil || code != 430 || took > 5*time.Second {
		t.Errorf("%d (%v) after %v, want 430 at once", code, err, took.Round(time.Millisecond))
	}
}

func TestAFlowThatClosesWithAMessageOutstandingIs430(t *testing.T) {
	_, c, path, core := setupTerm(t)
	core.write(coreRequest("MESSAGE", "sip:alice@192.0.2.10:40000;transport=tcp", fmt.Sprintf("close-msg-%d", requests.Add(1)), "", 1, "Route: <"+path+">"))
	_ = c.nextRequest()
	_ = c.nc.Close()
	if code, took, err := finalWithin(core); err != nil || code != 430 || took > 5*time.Second {
		t.Errorf("%d (%v) after %v, want 430 at once", code, err, took.Round(time.Millisecond))
	}
}

// QA measured 5 of 40 flows getting a 430 when each closed during a
// concurrent send; every one must, at once.
func TestFlowsThatCloseDuringConcurrentSendsAreAll430(t *testing.T) {
	const n = 40
	icscf := startCoreNode(t, echo200)
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1")})
	var wg sync.WaitGroup
	codes := make([]int, n)
	took := make([]time.Duration, n)
	for i := range n {
		c, path := registered(t, s, icscf)
		core := dial(t, s.core, nil)
		wg.Add(1)
		go func() {
			defer wg.Done()
			core.write(coreRequest("MESSAGE", "sip:alice@192.0.2.10:40000;transport=tcp", fmt.Sprintf("close-many-%d", requests.Add(1)), "", 1, "Route: <"+path+">"))
			time.Sleep(time.Duration(i%4) * 300 * time.Microsecond)
			_ = c.nc.Close()
			codes[i], took[i], _ = finalWithin(core)
		}()
	}
	wg.Wait()
	for i, code := range codes {
		if code != 430 || took[i] > 3*time.Second {
			t.Errorf("flow %d: %d after %v, want 430 at once", i, code, took[i].Round(time.Millisecond))
		}
	}
}

// QA of #293: the drain closes the last flows just before the proxy closes,
// and their requests still get the 430.
func TestADrainedFlowsPendingRequestIs430(t *testing.T) {
	for _, flows := range []int{1, 3} {
		t.Run(fmt.Sprint(flows), func(t *testing.T) {
			icscf := startCoreNode(t, echo200)
			cfg := testConfig()
			cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
			cfg.DrainTimeout = 600 * time.Millisecond
			s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1")})
			var cores []*peer
			for range flows {
				c, path := registered(t, s, icscf)
				core := dial(t, s.core, nil)
				core.write(coreRequest("MESSAGE", "sip:alice@192.0.2.10:40000;transport=tcp", fmt.Sprintf("drain-%d", requests.Add(1)), "", 1, "Route: <"+path+">"))
				_ = c.nextRequest()
				cores = append(cores, core)
			}
			codes := make([]int, flows)
			errs := make([]error, flows)
			var wg sync.WaitGroup
			for i, core := range cores {
				wg.Add(1)
				go func() { defer wg.Done(); codes[i], _, errs[i] = finalWithin(core) }()
			}
			s.stop()
			wg.Wait()
			for i := range codes {
				if codes[i] != 430 {
					t.Errorf("flow %d of %d: %d (%v), want 430", i, flows, codes[i], errs[i])
				}
			}
		})
	}
}
