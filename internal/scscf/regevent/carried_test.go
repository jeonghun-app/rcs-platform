package regevent

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// Tests of #492: a change's NOTIFYs carry the record the change saved.

// registrationReads counts the reads of registration records.
type registrationReads struct {
	state.Store
	n atomic.Int64
}

func (s *registrationReads) Registration(ctx context.Context, k state.SetKey) (*state.Registration, error) {
	s.n.Add(1)
	return s.Store.Registration(ctx, k)
}

// TestAChangesNotifiesCarryItsRecordWithoutReadingItAgain: a refresh sends
// each of the set's subscriptions its NOTIFY, with the refreshed expiry,
// and reads the record for none of them: the change has it already.
func TestAChangesNotifiesCarryItsRecordWithoutReadingItAgain(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	e.subscribedMany(2)
	st := &registrationReads{Store: e.store}
	n := newNotifierWith(t, e, st, e.send)
	sent := len(e.send.notifies())
	after := before.Clone()
	after.Contacts[0].Expires = t0.Add(2 * time.Hour)
	after = e.saved(after)
	n.Changed(bg, before, after, Registered)
	n.Wait()
	got := e.send.notifies()[sent:]
	if len(got) != 2 {
		t.Fatalf("%d NOTIFYs for a refresh of a set with 2 subscriptions, want 2", len(got))
	}
	for _, r := range got {
		doc, _, _ := info(t, r)
		reg, _ := doc.ByAOR(sip.URI{Scheme: "sip", User: "+15550100001", Host: realm})
		if len(reg.Contacts) != 1 || reg.Contacts[0].Expires == nil || *reg.Contacts[0].Expires != 7200 {
			t.Errorf("%s: contacts %+v, want the binding refreshed to 7200 s", r.Header.Get("Call-ID"), reg.Contacts)
		}
	}
	if r := st.n.Load(); r != 0 {
		t.Errorf("%d reads of the record for the change's NOTIFYs, want none", r)
	}
}

// TestAMergedNotifyCarriesTheNewerRecordWhicheverCameFirst: two changes'
// NOTIFYs to the same subscriptions merge while they wait, the newer
// change's fan-out queued first. The NOTIFY that goes carries the newer
// record: binding 2 removed by the first change and binding 3 by the second
// are both gone from it.
func TestAMergedNotifyCarriesTheNewerRecordWhicheverCameFirst(t *testing.T) {
	e := newEnv(t)
	s0 := e.registered(binding(1, time.Hour), binding(2, time.Hour), binding(3, time.Hour))
	e.subscribedMany(1)
	g := &recGate{release: make(chan struct{})}
	m := &counts{}
	n := newNotifierWith(t, e, e.store, g, func(c *Config) { c.SetConcurrency, c.Metrics = 1, m })
	// A third change takes the set's one slot, so the two after it wait.
	s1 := s0.Clone()
	s1.Contacts[0].Expires = t0.Add(2 * time.Hour)
	s1 = e.saved(s1)
	n.Changed(bg, s0, s1, Registered)
	settled(t, n, 0)
	s2 := s1.Clone()
	s2.Contacts = []state.Contact{s1.Contacts[0], s1.Contacts[2]}
	s2 = e.saved(s2)
	s3 := s2.Clone()
	s3.Contacts = s3.Contacts[:1]
	s3 = e.saved(s3)
	n.Changed(bg, s2, s3, Expired)
	settled(t, n, 1)
	n.Changed(bg, s1, s2, Registered)
	settled(t, n, 1)
	close(g.release)
	n.Wait()
	if m.get("regevent.notify_merged") != 1 {
		t.Fatalf("%d merged, want 1", m.get("regevent.notify_merged"))
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	last := g.sent[len(g.sent)-1]
	doc, _, _ := info(t, last)
	reg, _ := doc.ByAOR(sip.URI{Scheme: "sip", User: "+15550100001", Host: realm})
	for _, c := range reg.Contacts {
		if c.Active() && c.URI != binding(1, 0).URI {
			t.Errorf("the merged NOTIFY has %s active, want binding 1 alone, as the newer record has it", c.URI)
		}
	}
}
