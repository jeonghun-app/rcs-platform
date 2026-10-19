package transaction

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

func TestRequestsBeyondTheCapGet503WithRetryAfterAndNeverReachTheTU(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{MaxServerTransactions: 2, RetryAfter: 1500 * time.Millisecond,
		IDs: sip.IDGenerator{Rand: bytes.NewReader(bytes.Repeat([]byte{0xab}, 64))}})
	first := request(t, "MESSAGE", "z9hG4bKcap1")
	h.receive(first)
	h.receive(request(t, "INVITE", "z9hG4bKcap2"))
	check(t, "TU calls", h.tu.take(), []string{"request MESSAGE", "request INVITE"})
	h.sender.take() // the INVITE's 100 Trying

	h.receive(request(t, "OPTIONS", "z9hG4bKcap3"))
	if got := h.tu.take(); len(got) != 0 {
		t.Fatalf("a request beyond the cap reached the TU: %q", got)
	}
	res, ok := h.sender.last().(*sip.Response)
	if !ok || res.StatusCode != 503 {
		t.Fatalf("sent %v, want 503", h.sender.last())
	}
	if got := res.Header.Get("Retry-After"); got != "2" {
		t.Errorf("Retry-After = %q, want whole seconds rounded up", got)
	}
	if to, _ := res.Header.To(); to.Tag() != strings.Repeat("ab", 8) {
		t.Errorf("To tag = %q, want one from Config.IDs", to.Tag())
	}
	if err := res.Validate(); err != nil {
		t.Errorf("503 does not validate: %v", err)
	}
	// It is sent from the reading goroutine, which must not wait for a queue.
	if m := h.sender.modes(); m[len(m)-1] != "503 nowait" {
		t.Errorf("503 sent as %q", m[len(m)-1])
	}
	s := h.layer.Stats()
	if s.ServerTransactions != 2 || s.ServerTransactionsRejected != 1 {
		t.Fatalf("stats = %+v", s)
	}

	// A retransmission of a live transaction is still matched, not refused.
	h.sender.take()
	h.receive(first)
	if got := h.layer.Stats().ServerTransactionsRejected; got != 1 {
		t.Fatalf("a retransmission was refused: %d rejections", got)
	}
}

func TestCancelAndAckAreNotRefusedAtTheCap(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{MaxServerTransactions: 1})
	inv := request(t, "INVITE", "z9hG4bKc1")
	h.receive(inv)
	h.receive(request(t, "CANCEL", "z9hG4bKc1"))
	h.receive(request(t, "ACK", "z9hG4bKother"))
	check(t, "TU calls", h.tu.take(), []string{"request INVITE", "request CANCEL", "stray ACK"})
	if s := h.layer.Stats(); s.ServerTransactionsRejected != 0 || s.ServerTransactions != 2 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestRoomReturnsWhenAServerTransactionEnds(t *testing.T) {
	h := newHarness(t, transport.TCP, Config{MaxServerTransactions: 1})
	req := request(t, "MESSAGE", "z9hG4bKr1")
	h.receive(req)
	// Over TCP a final response ends a non-INVITE transaction at once (Timer J
	// is zero).
	if err := h.tu.lastTx().Respond(response(t, req, 200)); err != nil {
		t.Fatal(err)
	}
	h.receive(request(t, "MESSAGE", "z9hG4bKr2"))
	check(t, "TU calls", h.tu.take(), []string{"request MESSAGE", "request MESSAGE"})
	if got := h.layer.Stats().ServerTransactionsRejected; got != 0 {
		t.Fatalf("refused %d requests with room available", got)
	}
}

func TestDefaultCapAndRetryAfter(t *testing.T) {
	l := New(&fakeSender{}, &tuRecorder{}, Config{})
	if l.maxServers != DefaultMaxServerTransactions || l.retryAfter != "5" {
		t.Fatalf("defaults = %d, %q", l.maxServers, l.retryAfter)
	}
}

func TestConfigValidationRefusesUnusableValues(t *testing.T) {
	for name, cfg := range map[string]Config{
		"negative cap":         {MaxServerTransactions: -1},
		"cap above the bound":  {MaxServerTransactions: MaxMaxServerTransactions + 1},
		"negative Retry-After": {RetryAfter: -time.Second},
		"negative T1":          {T1: -time.Millisecond},
	} {
		if cfg.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, cfg := range map[string]Config{
		"zero takes defaults": {},
		"smallest cap":        {MaxServerTransactions: 1},
		"largest cap":         {MaxServerTransactions: MaxMaxServerTransactions},
	} {
		if err := cfg.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("New accepted an invalid configuration")
		}
	}()
	New(&fakeSender{}, &tuRecorder{}, Config{MaxServerTransactions: -1})
}

func TestRefusalWithoutRandomnessSendsNothing(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{MaxServerTransactions: 1, IDs: sip.IDGenerator{Rand: bytes.NewReader(nil)}})
	h.receive(request(t, "MESSAGE", "z9hG4bKn1"))
	h.sender.take()
	h.receive(request(t, "MESSAGE", "z9hG4bKn2"))
	if got := h.sender.take(); len(got) != 0 {
		t.Fatalf("sent %q without a To tag to give it", got)
	}
	if got := h.layer.Stats().ServerTransactionsRejected; got != 1 {
		t.Fatalf("rejections = %d", got)
	}
}
