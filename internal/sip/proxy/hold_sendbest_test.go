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
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// The proxy's best failure, here the 480 for a target whose flow is gone,
// is held in the gap like any other final (sendBest; QA of #493).
func TestDrainWaitsForTheBestFailureTheTransactionLayerHas(t *testing.T) {
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
			return Decision{Targets: []Target{{URI: mustURI("sip:bob@192.0.2.10"), Destination: &transport.Destination{Flow: "gone"}}}}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	t.Cleanup(letGo) // before p.Close, which waits for the held final
	px.Store(p)
	nc, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	if _, err := io.WriteString(nc, "MESSAGE sip:bob@example.com SIP/2.0\r\n"+
		"Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bK-held-final\r\nMax-Forwards: 70\r\n"+
		"To: <sip:bob@example.com>\r\nFrom: <sip:alice@example.com>;tag=a1\r\n"+
		"Call-ID: held-final\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-in:
	case <-time.After(30 * time.Second):
		t.Fatal("the 200 never reached the gap")
	}
	done := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		p.Drain(ctx)
		_ = tr.Close() // as pcscf and icscf do
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Drain returned while the 200 was still on its way to the transport")
	case <-time.After(drainFlushStall + 500*time.Millisecond):
	}
	letGo()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Drain did not return once the 200 was sent")
	}
	_ = nc.SetReadDeadline(time.Now().Add(30 * time.Second))
	m, err := sip.NewReader(bufio.NewReader(nc), sip.Limits{}).ReadMessage()
	if res, ok := m.(*sip.Response); err != nil || !ok || res.StatusCode != 480 {
		t.Fatalf("the sender got %v, %v, want the 480", m, err)
	}
}
