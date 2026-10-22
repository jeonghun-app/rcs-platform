package transaction

import (
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// panicSender panics on every request, as a transport whose dial has a
// bug (#582), and answers nothing.
type panicSender struct{ nullSender }

func (panicSender) SendRequest(*sip.Request, transport.Destination, ...transport.SendOption) (transport.Network, error) {
	panic("sender bug")
}

// A send that panics leaves the layer as it found it (#582): the panic goes
// on to Request's caller, which may contain it (#471), the transaction
// recorded before the send is gone, its flow's entry with it, and Close
// returns at once.
func TestARequestWhoseSendPanicsLeavesNoTransaction(t *testing.T) {
	l := mustNew(t, panicSender{}, handoffTU{200}, Config{})
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("Request did not pass the send's panic on")
			}
		}()
		_, _ = l.Request(request(t, "OPTIONS", "z9hG4bK-panic"), transport.Destination{Flow: "flow-1"},
			func(*sip.Response, error) {})
	}()
	if clients, _ := l.Len(); clients != 0 {
		t.Errorf("%d client transactions left", clients)
	}
	l.mu.Lock()
	flows := len(l.byFlow)
	l.mu.Unlock()
	if flows != 0 {
		t.Errorf("%d flows still hold a transaction", flows)
	}
	closed := make(chan struct{})
	go func() { l.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(30 * time.Second): // a hang guard
		t.Fatal("Close did not return")
	}
}
