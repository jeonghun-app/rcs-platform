package transaction

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

func TestRequestsBeyondTheCapGet503WithRetryAfterAndNeverReachTheTU(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{MaxServerTransactions: 2, RetryAfter: 1500 * time.Millisecond})
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
	if to, _ := res.Header.To(); len(to.Tag()) != 16 {
		t.Errorf("To tag = %q, want 16 hex digits", to.Tag())
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
	l := mustNew(t, &fakeSender{}, &tuRecorder{}, Config{})
	if l.maxServers != DefaultMaxServerTransactions || l.retryAfter != "5" || l.maxBytes != DefaultMaxServerTransactionBytes ||
		l.clientServers != int64(DefaultMaxServerTransactions*DefaultClientShare) {
		t.Fatalf("defaults = %d, %q, %d, %d", l.maxServers, l.retryAfter, l.maxBytes, l.clientServers)
	}
}

func TestConfigValidationRefusesUnusableValues(t *testing.T) {
	for name, cfg := range map[string]Config{
		"negative cap":             {MaxServerTransactions: -1},
		"cap above the bound":      {MaxServerTransactions: MaxMaxServerTransactions + 1},
		"negative Retry-After":     {RetryAfter: -time.Second},
		"negative T1":              {T1: -time.Millisecond},
		"negative T2":              {T2: -time.Millisecond},
		"negative T4":              {T4: -time.Millisecond},
		"negative byte bound":      {MaxServerTransactionBytes: -1},
		"client share above 1":     {ClientShare: 1.5},
		"negative client share":    {ClientShare: -0.1},
		"Retry-After past an hour": {RetryAfter: MaxRetryAfter + time.Second},
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
	if _, err := New(&fakeSender{}, &tuRecorder{}, Config{MaxServerTransactions: -1}); err == nil {
		t.Error("New accepted an invalid configuration")
	}
}

func TestNewFailsWithoutRandomnessForItsKey(t *testing.T) {
	if _, err := New(&fakeSender{}, &tuRecorder{}, Config{IDs: sip.IDGenerator{Rand: bytes.NewReader(nil)}}); err == nil {
		t.Fatal("New built a layer with no key")
	}
}

// Code review (PR #170), finding 1: RFC 3261 §8.2.7 has a stateless UAS give
// a request the same To tag every time and ignore the ACK for its response.
// QA (second round): an RFC 2543 client, whose branch has no magic cookie and
// whose ACK is matched on the To tag (§17.2.3), gets the same.
func TestRefusedInviteGetsTheSameTagAndItsAckGoesNowhere(t *testing.T) {
	for _, branch := range []string{"z9hG4bKinv", "oldstyle1"} {
		t.Run(branch, func(t *testing.T) {
			h := newHarness(t, transport.UDP, Config{MaxServerTransactions: 1})
			h.receive(request(t, "MESSAGE", "z9hG4bKfill"))
			h.tu.take()
			inv := request(t, "INVITE", branch)
			tags := map[string]bool{}
			var tag string
			for range 2 { // the INVITE and a retransmission of it
				h.receive(inv)
				to, _ := lastResponse(t, h).Header.To()
				tag = to.Tag()
				tags[tag] = true
			}
			if len(tags) != 1 {
				t.Fatalf("a retransmission got another To tag: %v", tags)
			}
			ack := request(t, "ACK", branch)
			ack.Header.Set("To", "<sip:bob@example.com>;tag="+tag)
			h.receive(ack)
			if got := h.tu.take(); len(got) != 0 {
				t.Fatalf("the ACK for the 503 reached the TU: %q", got)
			}
			// An ACK with another tag is not ours, and goes to the TU as before.
			other := request(t, "ACK", branch)
			other.Header.Set("To", "<sip:bob@example.com>;tag=someone-else")
			h.receive(other)
			check(t, "TU calls", h.tu.take(), []string{"stray ACK"})
			if s := h.layer.Stats(); s.RefusalAcksAbsorbed != 1 {
				t.Fatalf("stats = %+v", s)
			}
		})
	}
}

// QA (PR #170): a CANCEL that cancels no live INVITE counts against the cap
// like any request; before, 1000 of them made 1000 transactions at a cap of 2.
func TestUnmatchedCancelsAreRefusedAtTheCap(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{MaxServerTransactions: 2})
	h.receive(request(t, "MESSAGE", "z9hG4bKfill1"))
	h.receive(request(t, "MESSAGE", "z9hG4bKfill2"))
	for i := 0; i < 1000; i++ {
		h.receive(request(t, "CANCEL", fmt.Sprintf("z9hG4bKcancel%d", i)))
	}
	for _, tx := range h.tu.txs {
		if tx.req.Method == "CANCEL" {
			_ = tx.Respond(response(t, tx.req, 481))
		}
	}
	h.clock.advance(31 * time.Second)
	if s := h.layer.Stats(); s.ServerTransactions > 2*2 {
		t.Fatalf("live server transactions = %d with cap 2", s.ServerTransactions)
	}
}

// Code review (PR #170), finding 3: the count alone would let 20000 requests
// with 1 MiB bodies hold 20 GiB, so the bytes are bounded too.
func TestRequestBytesAreBoundedAsWellAsTheirNumber(t *testing.T) {
	h := newHarness(t, transport.TCP, Config{MaxServerTransactionBytes: 64 << 10})
	big := func(branch string) *sip.Request {
		req := request(t, "MESSAGE", branch)
		req.Body = make([]byte, 28<<10)
		return req
	}
	first := big("z9hG4bKbig1")
	h.receive(first)
	h.receive(big("z9hG4bKbig2"))
	h.receive(big("z9hG4bKbig3")) // a third would pass 64 KiB
	check(t, "TU calls", h.tu.take(), []string{"request MESSAGE", "request MESSAGE"})
	if res := lastResponse(t, h); res.StatusCode != 503 {
		t.Fatalf("third request got %d, want 503", res.StatusCode)
	}
	s := h.layer.Stats()
	if s.ServerTransactionBytes < 2*28<<10 || s.ServerTransactionBytes > 64<<10 || s.ServerTransactionsRejected != 1 {
		t.Fatalf("stats = %+v", s)
	}
	// Ending a transaction gives its bytes back (Timer J is zero over TCP).
	if err := h.tu.txs[0].Respond(response(t, first, 200)); err != nil {
		t.Fatal(err)
	}
	h.receive(big("z9hG4bKbig4"))
	check(t, "TU calls", h.tu.take(), []string{"request MESSAGE"})
}

// Code review (PR #170), question 5: clients may use only ClientShare of the
// caps, so a flood of them cannot get the core's requests refused.
func TestClientFloodLeavesRoomForCoreRequests(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{MaxServerTransactions: 10, ClientShare: 0.8})
	from := func(m sip.Message, client bool) {
		h.layer.Receive(transport.Inbound{Message: m, Source: transport.Source{Flow: "f", Network: transport.UDP, ClientFacing: client}})
	}
	for i := range 20 {
		from(request(t, "MESSAGE", fmt.Sprintf("z9hG4bKclient%d", i)), true)
	}
	if s := h.layer.Stats(); s.ServerTransactions != 8 || s.ServerTransactionsRejected != 12 {
		t.Fatalf("after the client flood: %+v", s)
	}
	h.tu.take()
	for i := range 2 {
		from(request(t, "MESSAGE", fmt.Sprintf("z9hG4bKcore%d", i)), false)
	}
	check(t, "TU calls", h.tu.take(), []string{"request MESSAGE", "request MESSAGE"})
}

func lastResponse(t *testing.T, h *harness) *sip.Response {
	t.Helper()
	res, ok := h.sender.last().(*sip.Response)
	if !ok {
		t.Fatalf("last sent = %v, want a response", h.sender.last())
	}
	return res
}
