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
	// The connection's end says why.
	eventually(t, "Client.Closed.Panicked", func() bool { return r.metrics.count(mClientPrefix+"Closed.Panicked") == 1 })
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
	if got := r.metrics.count(msrp.MetricCallbackPanics); got != 1 {
		t.Fatalf("%s = %d, want 1", msrp.MetricCallbackPanics, got)
	}
	if _, err := r.dial(0, nil).open(t, b.clientPath, newRecorder()); err != nil {
		t.Fatalf("the next connection: %v", err)
	}
}
