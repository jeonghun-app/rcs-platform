package pcscf

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// The acceptance tests of #234, from QA's review of #221: a request the core
// sends a client whose flow then closes, before any answer, reaches the core
// as 430 at once, not as a 408 after Timer B or no answer after Timer F.
//
// The code tells which: only the flow's close ends the branch with 430, and
// without it the INVITE gets 408 and the MESSAGE nothing, so the tests check
// the code and not the time it took, which a loaded host stretches (#412).
// The read deadline, past Timer F, only bounds a hang.

func setupTerm(t *testing.T) (*service, *peer, string, *peer) {
	t.Helper()
	icscf := startCoreNode(t, echo200)
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1")})
	c, path := registered(t, s, icscf)
	return s, c, path, dial(t, s.core, nil)
}

// finalWithin reads the core's responses until the final one; it runs on
// other goroutines than the test's, so it returns its error.
func finalWithin(core *peer) (int, error) {
	_ = core.nc.SetDeadline(time.Now().Add(45 * time.Second))
	for {
		m, err := core.r.ReadMessage()
		if err != nil {
			return 0, err
		}
		if res, ok := m.(*sip.Response); ok && res.StatusCode >= 200 {
			return res.StatusCode, nil
		}
	}
}

func TestAFlowThatClosesWithAnInviteOutstandingIs430(t *testing.T) {
	_, c, path, core := setupTerm(t)
	core.write(withAudioOffer(coreRequest("INVITE", "sip:alice@192.0.2.10:40000;transport=tcp", fmt.Sprintf("close-inv-%d", requests.Add(1)), "", 1, "Route: <"+path+">")))
	_ = c.nextRequest()
	_ = c.nc.Close()
	if code, err := finalWithin(core); err != nil || code != 430 {
		t.Errorf("%d (%v), want 430", code, err)
	}
}

func TestAFlowThatClosesWithAMessageOutstandingIs430(t *testing.T) {
	_, c, path, core := setupTerm(t)
	core.write(coreRequest("MESSAGE", "sip:alice@192.0.2.10:40000;transport=tcp", fmt.Sprintf("close-msg-%d", requests.Add(1)), "", 1, "Route: <"+path+">"))
	_ = c.nextRequest()
	_ = c.nc.Close()
	if code, err := finalWithin(core); err != nil || code != 430 {
		t.Errorf("%d (%v), want 430", code, err)
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
	for i := range n {
		c, path := registered(t, s, icscf)
		core := dial(t, s.core, nil)
		wg.Add(1)
		go func() {
			defer wg.Done()
			core.write(coreRequest("MESSAGE", "sip:alice@192.0.2.10:40000;transport=tcp", fmt.Sprintf("close-many-%d", requests.Add(1)), "", 1, "Route: <"+path+">"))
			time.Sleep(time.Duration(i%4) * 300 * time.Microsecond)
			_ = c.nc.Close()
			codes[i], _ = finalWithin(core)
		}()
	}
	wg.Wait()
	for i, code := range codes {
		if code != 430 {
			t.Errorf("flow %d: %d, want 430", i, code)
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
				go func() { defer wg.Done(); codes[i], errs[i] = finalWithin(core) }()
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

// QA of #293: the wait after the drain is bounded. A REGISTER the core never
// answers holds a request in progress to the end; the stop still returns
// after answersWait, well inside the stop margin.
func TestTheStopWaitForAnswersIsBounded(t *testing.T) {
	icscf := startCoreNode(t, func(*sip.Request) string { return "" })
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	cfg.DrainTimeout = 200 * time.Millisecond
	s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1")})
	c := dial(t, s.client, nil)
	n := strconv.FormatInt(requests.Add(1), 10)
	c.write(strings.ReplaceAll(registerText(outboundContact, "Supported: outbound"), "reg-1", "reg-stop-"+n))
	icscf.receive(t)
	start := time.Now()
	s.stop()
	if took := time.Since(start); took > 4*time.Second {
		t.Errorf("stop took %v with a REGISTER pending at the core, want about answersWait", took)
	}
	if answersWait >= stopMargin {
		t.Errorf("answersWait %v is not inside the %v stop margin", answersWait, stopMargin)
	}
}
