package msrprelay

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/store"
)

// panicOnceStore panics on its first Get, as a bug in the store's client
// would, on the connection's reading goroutine, where the binder runs.
type panicOnceStore struct {
	store.Store
	gets atomic.Int32
}

func (s *panicOnceStore) Get(ctx context.Context, id string, now time.Time) (store.Binding, error) {
	if s.gets.Add(1) == 1 {
		panic("store")
	}
	return s.Store.Get(ctx, id, now)
}

// A panic on a client connection's reading goroutine ends that connection
// only, and is counted as msrp.callback_panics: the client's next
// connection is bridged (#445).
func TestAPanicOnAClientConnectionEndsOnlyThatConnection(t *testing.T) {
	r := newRigWithStore(t, 1, &panicOnceStore{Store: store.NewMemory()})
	b := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "core_path": []string{r.as.uri("asp4n1c")}})
	r.as.session(t, "asp4n1c", b.coreLocal, newRecorder())
	if _, err := r.dial(0, nil).open(t, b.clientPath, newRecorder()); err == nil {
		t.Fatal("the connection whose bind panicked was served")
	}
	if got := r.metrics.count(msrp.MetricCallbackPanics); got != 1 {
		t.Fatalf("%s = %d, want 1", msrp.MetricCallbackPanics, got)
	}
	// The connection's end says why, and its bind slot is free again
	// (#471 code review).
	eventually(t, "Client.Closed.Panicked", func() bool { return r.metrics.count(mClientPrefix+"Closed.Panicked") == 1 })
	if n := len(r.relays[0].binds); n != 0 {
		t.Fatalf("%d bind slots held after the panic", n)
	}
	if _, err := r.dial(0, nil).open(t, b.clientPath, newRecorder()); err != nil {
		t.Fatalf("the next connection: %v", err)
	}
}

// panicsOnce makes the first connection it accepts panic when asked its
// address, as a bug in reading a client's address would on handle's
// goroutine.
type panicsOnce struct {
	net.Listener
	accepted atomic.Int32
}

func (l *panicsOnce) Accept() (net.Conn, error) {
	nc, err := l.Listener.Accept()
	if err == nil && l.accepted.Add(1) == 1 {
		return addrPanics{nc}, nil
	}
	return nc, err
}

type addrPanics struct{ net.Conn }

func (addrPanics) RemoteAddr() net.Addr { panic("address") }

// A panic on handle's goroutine, before the connection reads a request,
// ends that connection only and is counted; the next connection is
// bridged.
func TestAPanicBeforeAClientConnectionReadsEndsOnlyThatConnection(t *testing.T) {
	r := newRig(t, 1, listenerWrap(func(ln net.Listener) net.Listener { return &panicsOnce{Listener: ln} }))
	b := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "core_path": []string{r.as.uri("asp4n1c2")}})
	r.as.session(t, "asp4n1c2", b.coreLocal, newRecorder())
	if _, err := r.dial(0, nil).open(t, b.clientPath, newRecorder()); err == nil {
		t.Fatal("the connection whose handling panicked was served")
	}
	// handle's deferred calls close the connection while the panic
	// unwinds, before the Guard counts it: the count is waited for.
	eventually(t, "the handle panic's count", func() bool { return r.metrics.count(msrp.MetricCallbackPanics) == 1 })
	if _, err := r.dial(0, nil).open(t, b.clientPath, newRecorder()); err != nil {
		t.Fatalf("the next connection: %v", err)
	}
}

// readPanicsOnce panics in its first Read, as a bug in reading the core's
// input would.
type readPanicsOnce struct {
	net.Conn
	read atomic.Bool
}

func (c *readPanicsOnce) Read(b []byte) (int, error) {
	if c.read.CompareAndSwap(false, true) {
		panic("core")
	}
	return c.Conn.Read(b)
}

// A panic on a connection toward rcs-as is counted as msrp.callback_panics
// too, and its end as Core.Closed.Panicked: newRelay gives the core side
// the guard as well (#471 QA).
func TestAPanicOnACoreConnectionIsCounted(t *testing.T) {
	r := newRig(t, 1, func(o *relayOptions) {
		dial := o.Dial
		o.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			nc, err := dial(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return &readPanicsOnce{Conn: nc}, nil
		}
	})
	b := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "core_path": []string{r.as.uri("asc0re")}})
	r.as.session(t, "asc0re", b.coreLocal, newRecorder())
	_, _ = r.dial(0, nil).open(t, b.clientPath, newRecorder())
	eventually(t, "the core connection's panic", func() bool {
		return r.metrics.count(msrp.MetricCallbackPanics) == 1 && r.metrics.count(mCorePrefix+"Closed.Panicked") == 1
	})
}
