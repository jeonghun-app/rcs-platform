package regevent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// onceFailing fails the first NOTIFY with err (or answers code), then 200s.
type onceFailing struct {
	mu     sync.Mutex
	failed bool
	err    error
	code   int
	ok     []*sip.Request
}

func (o *onceFailing) Send(_ context.Context, req *sip.Request) (*sip.Response, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.failed {
		o.failed = true
		if o.err != nil {
			return nil, o.err
		}
		return sip.NewResponse(req, o.code, "", "s")
	}
	o.ok = append(o.ok, req)
	return sip.NewResponse(req, 200, "", "s")
}

// TestAFinalThatFailsOnceIsSentAgain: the set ends; its terminated NOTIFY
// meets a full transport queue, or a 503 from a busy P-CSCF. Over the next
// minutes of sweeps, the subscriber gets a terminated NOTIFY (QA's F1 on
// #256).
func TestAFinalThatFailsOnceIsSentAgain(t *testing.T) {
	for name, o := range map[string]*onceFailing{
		"queue full": {err: transport.ErrQueueFull},
		"503":        {code: 503},
		"500":        {code: 500},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			before := e.registered(binding(1, time.Hour))
			e.subscribed(e.notifier(1))
			n := newNotifierWith(t, e, e.store, o)
			if err := n.Ended(bg, before, Rejected); err != nil {
				t.Fatal(err)
			}
			n.Wait()
			for range 30 {
				e.clock.advance(10 * time.Second)
				_, _ = n.Sweep(bg, 10)
				n.Wait()
			}
			got := 0
			for _, r := range o.ok {
				if ss, _ := r.Header.SubscriptionState(); ss.State == "terminated" {
					got++
				}
			}
			if got != 1 || len(e.subscriptions(impu1)) != 0 {
				t.Errorf("%s: terminated NOTIFYs delivered after the failure %d, subscriptions left %d; want 1 and 0", name, got, len(e.subscriptions(impu1)))
			}
		})
	}
}

// TestAFinalNobodyAnswersIsGivenUpAfterFiveSends: sent again later each
// time, then deleted and counted; one answered with a §4.2.2 code is not
// sent again.
func TestAFinalNobodyAnswersIsGivenUpAfterFiveSends(t *testing.T) {
	for name, c := range map[string]struct {
		s     Sender
		sends int
	}{
		"no answer":  {silent{}, maxFinalSends},
		"481":        {&sender{status: 481}, 1},
		"queue full": {&sender{err: transport.ErrQueueFull}, maxFinalSends},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			before := e.registered(binding(1, time.Hour))
			e.subscribed(e.notifier(1))
			m := &counts{}
			rec := &countingSender{Sender: c.s}
			n := newNotifierWith(t, e, e.store, rec, func(cfg *Config) { cfg.NotifyTimeout, cfg.Metrics = 10*time.Millisecond, m })
			if err := n.Ended(bg, before, Rejected); err != nil {
				t.Fatal(err)
			}
			n.Wait()
			for range 60 {
				e.clock.advance(10 * time.Second)
				_, _ = n.Sweep(bg, 10)
				n.Wait()
			}
			if got := rec.count(); got != c.sends {
				t.Errorf("%d sends, want %d", got, c.sends)
			}
			if len(e.subscriptions(impu1)) != 0 {
				t.Error("the subscription is left")
			}
			abandoned := int64(0)
			if c.sends == maxFinalSends {
				abandoned = 1
			}
			if m.get("regevent.final_abandoned") != abandoned {
				t.Errorf("final_abandoned %d", m.get("regevent.final_abandoned"))
			}
		})
	}
}

// countingSender counts the NOTIFYs passed to Sender.
type countingSender struct {
	Sender
	mu sync.Mutex
	n  int
}

func (c *countingSender) Send(ctx context.Context, req *sip.Request) (*sip.Response, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.Sender.Send(ctx, req)
}

func (c *countingSender) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// TestALapsedSubscriptionsFinalIsSavedBeforeItIsSent: the end is found
// while notifying (the binding moved to another P-CSCF), so nothing saved
// it before; it is saved Terminated, with its reason, before it is numbered,
// and a send without an answer is made again with that reason.
func TestALapsedSubscriptionsFinalIsSavedBeforeItIsSent(t *testing.T) {
	e := newEnv(t)
	s := e.registered(binding(1, time.Hour))
	e.subscribed(e.notifier(1))
	moved := s.Clone()
	moved.Contacts[0].Path = []string{"<sip:orig@pcscf2." + realm + ";lr>"}
	moved = e.saved(moved)
	o := &onceFailing{code: 503}
	n := newNotifierWith(t, e, e.store, o)
	n.Changed(bg, s, moved, Registered)
	n.Wait()
	for range 3 {
		e.clock.advance(10 * time.Second)
		_, _ = n.Sweep(bg, 10)
		n.Wait()
	}
	if len(o.ok) != 1 {
		t.Fatalf("%d NOTIFYs after the failed one", len(o.ok))
	}
	if ss, _ := o.ok[0].Header.SubscriptionState(); ss.State != "terminated" || ss.Reason() != "deactivated" {
		t.Errorf("sent again as %+v, want terminated;reason=deactivated", ss)
	}
	if len(e.subscriptions(impu1)) != 0 {
		t.Error("the subscription is left")
	}
}

// TestAnEndOfASetRegisteredAgainHasNoBody: the set ended, and a device
// registered it again, a new record, before the end's NOTIFY went; the
// NOTIFY says terminated, deactivated, and lists no identity, which the new
// registration owns (#256 code review).
func TestAnEndOfASetRegisteredAgainHasNoBody(t *testing.T) {
	e := newEnv(t)
	old := e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	e.subscribed(n)
	k := len(e.send.notifies())
	if err := e.store.DeleteRegistration(bg, old); err != nil {
		t.Fatal(err)
	}
	e.saved(&state.Registration{Key: set1, Incarnation: 8, Contacts: []state.Contact{binding(2, time.Hour)}, Identities: old.Identities})
	if err := n.Ended(bg, old, Deactivated); err != nil {
		t.Fatal(err)
	}
	n.Wait()
	got := e.send.notifies()[k:]
	if len(got) != 1 {
		t.Fatalf("%d NOTIFYs", len(got))
	}
	if ss, _ := got[0].Header.SubscriptionState(); ss.State != "terminated" || ss.Reason() != "deactivated" || len(got[0].Body) != 0 {
		t.Errorf("the end: %+v with %d bytes of body", ss, len(got[0].Body))
	}
}
