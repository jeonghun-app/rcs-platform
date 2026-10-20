package transaction

import (
	"errors"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// overFlow starts a client transaction for req sent over the flow id.
func (h *harness) overFlow(branch, method, id string) *ClientTransaction {
	h.t.Helper()
	tx, err := h.layer.Request(request(h.t, method, branch), transport.Destination{Flow: transport.FlowID(id)}, h.handler)
	if err != nil {
		h.t.Fatal(err)
	}
	return tx
}

// #234: a flow that closes ends at once every client transaction sent over
// it that awaits a final response, an INVITE before or after a provisional
// and a non-INVITE alike, with an error a proxy answers 430.
func TestAFlowThatClosesEndsTheTransactionsPendingOnIt(t *testing.T) {
	h := newHarness(t, transport.TCP, Config{})
	calling := h.overFlow("z9hG4bKfc1", "INVITE", "f1")
	proceeding := h.overFlow("z9hG4bKfc2", "INVITE", "f1")
	h.receive(response(t, proceeding.Request(), 180))
	message := h.overFlow("z9hG4bKfc3", "MESSAGE", "f1")
	other := h.overFlow("z9hG4bKfc4", "MESSAGE", "f2")
	h.takeResponses()

	h.layer.FlowClosed("f1")
	check(t, "handlers", h.takeResponses(), []string{
		"error: " + ErrFlowClosed.Error(), "error: " + ErrFlowClosed.Error(), "error: " + ErrFlowClosed.Error(),
	})
	for _, tx := range []*ClientTransaction{calling, proceeding, message} {
		if tx.State() != Terminated {
			t.Errorf("%s: state %s, want Terminated", tx.Request().Method, tx.State())
		}
	}
	if !errors.Is(ErrFlowClosed, transport.ErrNoFlow) {
		t.Error("ErrFlowClosed does not wrap transport.ErrNoFlow, which a proxy answers 430")
	}
	if other.State() != Trying {
		t.Errorf("a transaction on another flow is %s", other.State())
	}
	// Nothing more reaches the handlers, not even Timer B or F.
	h.clock.advance(time.Hour)
	check(t, "after an hour", h.takeResponses(), []string{"error: " + ErrTimeout.Error()})
}

// A transaction that has its final response is not touched, and the index
// of transactions by flow empties as they end.
func TestAFlowThatClosesLeavesAnsweredTransactionsAlone(t *testing.T) {
	h := newHarness(t, transport.TCP, Config{})
	done := h.overFlow("z9hG4bKfc5", "MESSAGE", "f1")
	h.receive(response(t, done.Request(), 200))
	rejected := h.overFlow("z9hG4bKfc6", "INVITE", "f1")
	h.receive(response(t, rejected.Request(), 486))
	h.takeResponses()
	h.layer.FlowClosed("f1")
	if got := h.takeResponses(); len(got) != 0 {
		t.Fatalf("answered transactions were ended again: %q", got)
	}
	h.clock.advance(time.Hour)
	h.layer.mu.Lock()
	left := len(h.layer.byFlow)
	h.layer.mu.Unlock()
	if left != 0 {
		t.Errorf("%d flows still indexed after every transaction ended", left)
	}
}

// A flow that closes while the request is still being sent ends it as well:
// the send either fails, or completes and FlowClosed then finds it pending.
func TestAFlowThatClosesDuringTheSendIsNotMissed(t *testing.T) {
	for range 50 {
		h := newHarness(t, transport.TCP, Config{})
		closed := make(chan struct{})
		h.sender.mu.Lock()
		h.sender.onSend = func() {
			go func() { h.layer.FlowClosed("f1"); close(closed) }()
		}
		h.sender.mu.Unlock()
		tx := h.overFlow("z9hG4bKfc7", "MESSAGE", "f1")
		<-closed
		if tx.State() != Terminated {
			t.Fatalf("state %s after the flow closed during the send", tx.State())
		}
	}
}
