package pcscf

import (
	"context"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// The caps and the send-queue budget are read from their settings (#482).
func TestTheCapsAndTheSendQueueAreRead(t *testing.T) {
	c, err := configure(with(devEnv,
		"PCSCF_MAX_SERVER_TRANSACTIONS", "30000", "PCSCF_MAX_SERVER_TRANSACTION_BYTES", "536870912",
		"PCSCF_MAX_QUEUED_BYTES", "134217728", "PCSCF_WRITE_TIMEOUT", "20s"))
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxServerTransactions != 30000 || c.MaxServerTransactionBytes != 512<<20 || c.MaxQueuedBytes != 128<<20 || c.WriteTimeout != 20*time.Second {
		t.Fatalf("read %d, %d, %d, %v", c.MaxServerTransactions, c.MaxServerTransactionBytes, c.MaxQueuedBytes, c.WriteTimeout)
	}
}

// pcscf's proxy takes its bounds as icscf's does: the layer's caps, as many
// contexts as server transactions, and the same bytes.
func TestProxyLimitsFollowTheTransactionCaps(t *testing.T) {
	tcfg, contexts, bytes := proxyLimits(Config{MaxServerTransactions: 30000, MaxServerTransactionBytes: 512 << 20})
	if tcfg.MaxServerTransactions != 30000 || tcfg.MaxServerTransactionBytes != 512<<20 || contexts != 30000 || bytes != 512<<20 {
		t.Fatalf("proxyLimits = %+v, %d, %d", tcfg, contexts, bytes)
	}
}

// The transport gets the send-queue budget and the write timeout.
func TestTheTransportGetsTheSendQueueBudget(t *testing.T) {
	got := make(chan transport.Config, 1)
	cfg := testConfig()
	cfg.MaxQueuedBytes, cfg.WriteTimeout = 64<<20, 20*time.Second
	start(t, cfg, deps{transportConfig: func(c transport.Config) { got <- c }})
	if c := <-got; c.MaxQueuedBytes != 64<<20 || c.WriteTimeout != 20*time.Second {
		t.Fatalf("transport MaxQueuedBytes %d, WriteTimeout %v", c.MaxQueuedBytes, c.WriteTimeout)
	}
}

// The proxy gets the caps for its transaction layer, as many contexts and as
// many bytes, and the transaction clock: run sets each of them (#485 code
// review).
func TestTheProxyGetsTheCapsAndTheClock(t *testing.T) {
	got := make(chan proxy.Config, 1)
	clock := &fakeTransactionClock{}
	cfg := testConfig()
	cfg.MaxServerTransactions, cfg.MaxServerTransactionBytes = 30000, 512<<20
	start(t, cfg, deps{clock: clock, proxyConfig: func(c proxy.Config) { got <- c }})
	c := <-got
	if c.Transaction.MaxServerTransactions != 30000 || c.Transaction.MaxServerTransactionBytes != 512<<20 {
		t.Errorf("transaction layer caps %d, %d", c.Transaction.MaxServerTransactions, c.Transaction.MaxServerTransactionBytes)
	}
	if c.Transaction.Clock != clock {
		t.Error("the transaction layer is not on the clock run was given")
	}
	if c.MaxContexts != 30000 || c.MaxContextBytes != 512<<20 {
		t.Errorf("proxy MaxContexts %d, MaxContextBytes %d", c.MaxContexts, c.MaxContextBytes)
	}
}

// holdingRouter holds every request until released, so that it stays in
// progress.
type holdingRouter struct {
	entered chan struct{}
	release chan struct{}
}

func (r *holdingRouter) Route(ctx context.Context, _ *proxy.Request) proxy.Decision {
	r.entered <- struct{}{}
	select {
	case <-r.release:
	case <-ctx.Done():
	}
	return proxy.Decision{Status: 403}
}

// With PCSCF_MAX_SERVER_TRANSACTIONS at one, a second request while the
// first is in progress is refused with 503: the caps reach the layer.
func TestTheServerTransactionCapReachesTheLayer(t *testing.T) {
	r := &holdingRouter{entered: make(chan struct{}, 4), release: make(chan struct{})}
	cfg := testConfig()
	cfg.MaxServerTransactions = 1
	s := start(t, cfg, deps{router: r})
	first := dial(t, s.client, nil)
	done := make(chan int, 1)
	go func() {
		res, err := first.tryWith()
		if err != nil {
			done <- 0
			return
		}
		done <- res.StatusCode
	}()
	<-r.entered
	if res, err := dial(t, s.client, nil).tryWith(); err != nil || res.StatusCode != 503 {
		t.Fatalf("second request: %v, %v; want 503", res, err)
	}
	close(r.release)
	if code := <-done; code != 403 {
		t.Fatalf("the first request got %d, want the Router's 403", code)
	}
}
