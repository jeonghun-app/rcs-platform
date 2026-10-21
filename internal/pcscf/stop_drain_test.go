package pcscf

import (
	"fmt"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// #281: a request of the core still in progress when pcscf stops gets a
// final response by the end of the drain: 500 with Retry-After, so scscf
// tries elsewhere at once, or 430 when the client's flow closed under it
// (#234). Before, the core got nothing until its own Timer F.
func TestAStopAnswersTheCoreRequestsLeftInProgress(t *testing.T) {
	icscf := startCoreNode(t, echo200)
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	cfg.DrainTimeout = time.Second
	s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1")})
	c, path := registered(t, s, icscf)
	core := dial(t, s.core, nil)
	core.write(coreRequest("MESSAGE", "sip:alice@192.0.2.10:40000;transport=tcp", fmt.Sprintf("stop-%d", requests.Add(1)), "", 1, "Route: <"+path+">"))
	_ = c.nextRequest() // and never answered
	go s.stop()
	start := time.Now()
	_ = core.nc.SetDeadline(time.Now().Add(10 * time.Second))
	for {
		m, err := core.r.ReadMessage()
		if err != nil {
			t.Fatalf("no final response after %v: %v", time.Since(start), err)
		}
		res, ok := m.(*sip.Response)
		if !ok || res.StatusCode < 200 {
			continue
		}
		switch {
		case res.StatusCode == 500 && res.Header.Get("Retry-After") != "":
		case res.StatusCode == 430:
		default:
			t.Fatalf("core got %d (Retry-After %q), want 500 with Retry-After or 430", res.StatusCode, res.Header.Get("Retry-After"))
		}
		if took := time.Since(start); took > 5*time.Second {
			t.Fatalf("answered after %v, want by the 1 s drain", took)
		}
		return
	}
}
