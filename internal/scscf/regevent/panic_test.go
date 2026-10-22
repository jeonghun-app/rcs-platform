package regevent

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/panics"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// panickingSender panics on its next Send once armed, then sends as
// sender does.
type panickingSender struct {
	*sender
	armed atomic.Bool
}

func (p *panickingSender) Send(ctx context.Context, req *sip.Request) (*sip.Response, error) {
	if p.armed.CompareAndSwap(true, false) {
		panic("regevent test panic")
	}
	return p.sender.Send(ctx, req)
}

// TestAPanickingNOTIFYEndsThatNOTIFYOnly (#488): a NOTIFY whose send
// panics is recovered and counted, and its set and hop are released: the
// next change's NOTIFY to the same subscriber goes, and Wait returns.
func TestAPanickingNOTIFYEndsThatNOTIFYOnly(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	s := &panickingSender{sender: e.send}
	guard := panics.New(panics.Config{Metric: "background.panics", Message: "test", Log: slog.New(slog.DiscardHandler)})
	u, err := sip.ParseURI("sip:scscf." + realm)
	if err != nil {
		t.Fatal(err)
	}
	// One task at a time for a set: a NOTIFY that kept its set's place
	// would hold up the next.
	n, err := New(Config{Store: e.store, Sender: s, Contact: u, Now: e.clock.Now, Rand: rand.NewChaCha8([32]byte{1}),
		SetConcurrency: 1, Panics: guard})
	if err != nil {
		t.Fatal(err)
	}
	e.subscribed(n)
	sent := len(e.send.notifies())
	s.armed.Store(true)
	change := func(from *state.Registration, exp time.Duration) *state.Registration {
		after := from.Clone()
		after.Contacts = []state.Contact{binding(1, exp)}
		after = e.saved(after)
		n.Changed(bg, from, after, Registered)
		return after
	}
	next := change(before, 2*time.Hour)
	// The next change comes once the first's NOTIFY has panicked, so that
	// the two are not merged into one.
	deadline := time.Now().Add(10 * time.Second)
	for guard.Panics() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the NOTIFY did not panic")
		}
		time.Sleep(time.Millisecond)
	}
	change(next, 3*time.Hour)
	done := make(chan struct{})
	go func() {
		n.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Wait did not return after the panic")
	}
	if guard.Panics() != 1 {
		t.Errorf("%d panics recovered, want 1", guard.Panics())
	}
	if got := len(e.send.notifies()) - sent; got != 1 {
		t.Errorf("%d NOTIFYs after the panicking one, want the next change's", got)
	}
}

// readPanics is the memory store, whose next Registration read panics once
// armed, as a bug in a store's decoding would.
type readPanics struct {
	*state.Memory
	armed atomic.Bool
}

func (s *readPanics) Registration(ctx context.Context, k state.SetKey) (*state.Registration, error) {
	if s.armed.CompareAndSwap(true, false) {
		panic("regevent test panic")
	}
	return s.Memory.Registration(ctx, k)
}

// TestAPanicPreparingANOTIFYGivesItsWorkerBack (#527 code review): a
// NOTIFY whose preparation on a worker panics, in the store's read of the
// set, is recovered and counted, and gives back its worker, set and hop:
// with one of each, the next change's NOTIFY still goes, and Wait returns.
func TestAPanicPreparingANOTIFYGivesItsWorkerBack(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	st := &readPanics{Memory: e.store}
	guard := panics.New(panics.Config{Metric: "background.panics", Message: "test", Log: slog.New(slog.DiscardHandler)})
	u, err := sip.ParseURI("sip:scscf." + realm)
	if err != nil {
		t.Fatal(err)
	}
	n, err := New(Config{Store: st, Sender: e.send, Contact: u, Now: e.clock.Now, Rand: rand.NewChaCha8([32]byte{1}),
		Workers: 1, SetConcurrency: 1, HopConcurrency: 1, Panics: guard})
	if err != nil {
		t.Fatal(err)
	}
	e.subscribed(n)
	sent := len(e.send.notifies())
	st.armed.Store(true)
	change := func(from *state.Registration, exp time.Duration) *state.Registration {
		after := from.Clone()
		after.Contacts = []state.Contact{binding(1, exp)}
		after = e.saved(after)
		n.Changed(bg, from, after, Registered)
		return after
	}
	next := change(before, 2*time.Hour)
	deadline := time.Now().Add(10 * time.Second)
	for guard.Panics() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the preparation did not panic")
		}
		time.Sleep(time.Millisecond)
	}
	change(next, 3*time.Hour)
	done := make(chan struct{})
	go func() {
		n.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Wait did not return after the panic")
	}
	if got := len(e.send.notifies()) - sent; got != 1 {
		t.Errorf("%d NOTIFYs after the panicking one, want the next change's", got)
	}
}
