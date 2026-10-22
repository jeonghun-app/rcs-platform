package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// A final the transaction refuses, here because the layer answered 500
// itself while the final was in the gap, never reaches SendResponse. Its
// hold must still end, or every later Flush, and so Drain, waits for it
// until its deadline (QA of #493).
func TestAFinalTheTransactionRefusesLeavesNoHoldBehind(t *testing.T) {
	drainSendWait = time.Hour
	t.Cleanup(func() { drainSendWait = DrainSendWait })
	in, release := make(chan struct{}, 1), make(chan struct{})
	var once sync.Once
	letGo := func() { once.Do(func() { close(release) }) }
	hold := func() {
		select {
		case in <- struct{}{}:
		default:
		}
		<-release
	}
	handingFinal.Store(&hold)
	t.Cleanup(func() { handingFinal.Store(nil); letGo() })
	clk := &fakeClock{}
	var px atomic.Pointer[Proxy]
	tr, err := transport.New(transport.Config{}, func(m transport.Inbound) {
		if p := px.Load(); p != nil {
			p.Receive(m)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	addr, err := tr.Listen(transport.ListenerConfig{Network: transport.TCP, Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(tr, Config{
		Self:        []sip.URI{mustURI("sip:" + addr.String() + ";lr")},
		Transaction: transaction.Config{Clock: clk},
		Router:      RouterFunc(func(context.Context, *Request) Decision { return Decision{Status: 200} }),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	t.Cleanup(letGo)
	px.Store(p)
	nc, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	if _, err := io.WriteString(nc, "MESSAGE sip:bob@example.com SIP/2.0\r\n"+
		"Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bK-qa-refused\r\nMax-Forwards: 70\r\n"+
		"To: <sip:bob@example.com>\r\nFrom: <sip:alice@example.com>;tag=a1\r\n"+
		"Call-ID: qa-refused\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-in:
	case <-time.After(30 * time.Second):
		t.Fatal("the 200 never reached the gap")
	}
	clk.advance(3 * time.Minute) // past the layer's safety net: it answers 500
	_ = nc.SetReadDeadline(time.Now().Add(30 * time.Second))
	r := sip.NewReader(bufio.NewReader(nc), sip.Limits{})
	for {
		m, err := r.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		if res, ok := m.(*sip.Response); ok && res.StatusCode >= 200 {
			if res.StatusCode != 500 {
				t.Fatalf("got %d, want the layer's 500", res.StatusCode)
			}
			break
		}
	}
	letGo()
	deadline := time.Now().Add(30 * time.Second)
	for p.Layer().Stats().LateFinalResponses != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("layer stats %+v, want one late final", p.Layer().Stats())
		}
		time.Sleep(time.Millisecond)
	}
	done := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		p.Drain(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second): // the deadline is an hour
		t.Fatal("Drain still waits for the hold of a final the transaction refused")
	}
}
