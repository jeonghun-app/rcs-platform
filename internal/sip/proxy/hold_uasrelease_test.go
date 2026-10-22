package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// A Serve handler's second final is refused (ErrState) and never reaches
// SendResponse: the hold UAS.Respond takes before its answered check must
// still end, or the Drain after waits for it until its deadline (QA of
// #493).
func TestAServedFinalThatIsRefusedLeavesNoHoldBehind(t *testing.T) {
	drainSendWait = time.Hour
	t.Cleanup(func() { drainSendWait = DrainSendWait })
	second := make(chan error, 1)
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
		Self: []sip.URI{mustURI("sip:" + addr.String() + ";lr")},
		Router: RouterFunc(func(context.Context, *Request) Decision {
			return Decision{Serve: func(_ context.Context, u *UAS) {
				res, _ := sip.NewResponse(u.Request().Message, 200, "", "uas1")
				_ = u.Respond(res)
				again, _ := sip.NewResponse(u.Request().Message, 486, "", "uas1")
				second <- u.Respond(again)
			}}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	px.Store(p)
	nc, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	if _, err := io.WriteString(nc, "MESSAGE sip:bob@example.com SIP/2.0\r\n"+
		"Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bK-qa-uas-twice\r\nMax-Forwards: 70\r\n"+
		"To: <sip:bob@example.com>\r\nFrom: <sip:alice@example.com>;tag=a1\r\n"+
		"Call-ID: qa-uas-twice\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-second:
		if !errors.Is(err, transaction.ErrState) {
			t.Fatalf("second final: %v, want ErrState", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the handler never answered twice")
	}
	_ = nc.SetReadDeadline(time.Now().Add(30 * time.Second))
	m, err := sip.NewReader(bufio.NewReader(nc), sip.Limits{}).ReadMessage()
	if res, ok := m.(*sip.Response); err != nil || !ok || res.StatusCode != 200 {
		t.Fatalf("the sender got %v, %v, want the 200", m, err)
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
		t.Fatal("Drain still waits for the hold of a served final that was refused")
	}
}
