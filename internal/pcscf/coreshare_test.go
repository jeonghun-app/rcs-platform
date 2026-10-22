package pcscf

import (
	"context"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// The proxy's context bytes keep the core its share, as the transaction
// layer's caps do (#489): a request too large for the client-facing 80% of
// them is refused with 503 from a client, and routed from the core.
func TestTheCoreKeepsItsShareOfTheProxysBytes(t *testing.T) {
	// The proxy charges the header twice: about 20 KB here, past 80% of
	// 22000 bytes and within all of them.
	pad := "X-Pad: " + strings.Repeat("x", 10000)
	router := proxy.RouterFunc(func(context.Context, *proxy.Request) proxy.Decision { return proxy.Decision{Status: 403} })
	s := start(t, testConfig(), deps{router: router, contextBytes: 22000})
	if res, err := dial(t, s.client, nil).tryWith(pad); err != nil || res.StatusCode != 503 {
		t.Fatalf("from a client: %v, %v; want 503", res, err)
	}
	if res, err := dial(t, s.core, nil).tryWith(pad); err != nil || res.StatusCode != 403 {
		t.Fatalf("from the core: %v, %v; want it routed (403)", res, err)
	}
}
