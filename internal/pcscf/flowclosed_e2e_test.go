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
// concurrent send; every one must.
func TestFlowsThatCloseDuringConcurrentSendsAreAll430(t *testing.T) {
	const n = 20
	icscf := startCoreNode(t, echo200)
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1")})
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := range n {
		c, path := registered(t, s, icscf)
		core := dial(t, s.core, nil)
		wg.Add(1)
		go func() {
			defer wg.Done()
			core.write(coreRequest("MESSAGE", "sip:alice@192.0.2.10:40000;transport=tcp", fmt.Sprintf("close-many-%d", requests.Add(1)), "", 1, "Route: <"+path+">"))
			time.Sleep(time.Duration(i%4) * 300 * time.Microsecond)
			_ = c.nc.Close()
			codes[i], _, _ = finalWithin(core)
		}()
	}
	wg.Wait()
	for i, code := range codes {
		if code != 430 {
			t.Errorf("flow %d: %d, want 430", i, code)
		}
	}
}
