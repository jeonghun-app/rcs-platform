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
// and reads the record for none of them: the change has it already. The
// subscriptions have numbered a NOTIFY first, as a subscription's first
// change's NOTIFY reads the record (prepare).
func TestAChangesNotifiesCarryItsRecordWithoutReadingItAgain(t *testing.T) {
	e := newEnv(t)
	v0 := e.registered(binding(1, time.Hour))
	e.subscribedMany(2)
	st := &registrationReads{Store: e.store}
	n := newNotifierWith(t, e, st, e.send)
	before := e.touched(v0)
	n.Changed(bg, v0, before, Registered)
	n.Wait()
	if r := st.n.Load(); r != 2 {
		t.Fatalf("%d reads of the record for the first change's 2 NOTIFYs, want 2", r)
	}
	st.n.Store(0)
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
// NOTIFYs to the same subscriptions merge while they wait, in either order
// of their fan-outs. The NOTIFY that goes carries the newer record: binding
// 2 removed by the first change and binding 3 by the second are both gone
// from it.
func TestAMergedNotifyCarriesTheNewerRecordWhicheverCameFirst(t *testing.T) {
	for _, tc := range []struct {
		name       string
		newerFirst bool
	}{
		{"the newer change's fan-out first", true},
		{"the older change's fan-out first", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			s0 := e.registered(binding(1, time.Hour), binding(2, time.Hour), binding(3, time.Hour))
			e.subscribedMany(1)
			g := &recGate{release: make(chan struct{})}
			m := &counts{}
			n := newNotifierWith(t, e, e.store, g, func(c *Config) { c.SetConcurrency, c.Metrics = 1, m })
			// A third change takes the set's one slot, so the two after
			// it wait. Its NOTIFY numbers the subscription's first, so
			// that theirs carry their records (prepare).
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
			changes := []func(){
				func() { n.Changed(bg, s1, s2, Registered) },
				func() { n.Changed(bg, s2, s3, Expired) },
			}
			if tc.newerFirst {
				changes[0], changes[1] = changes[1], changes[0]
			}
			for _, c := range changes {
				c()
				settled(t, n, 1)
			}
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
		})
	}
}

// TestAChangeNumberedAfterTheFirstNotifyTellsNoOlderState (#492 code
// review): the subscription is made at v0, and v1 and v2 each add a binding
// before its first NOTIFY reads v2. The v0 to v1 change's NOTIFY, the first
// NextNotify numbers, still has the three bindings: v1 lacks the third,
// which a P-CSCF would take for its end, though v2's NOTIFY shows it again.
func TestAChangeNumberedAfterTheFirstNotifyTellsNoOlderState(t *testing.T) {
	e := newEnv(t)
	v0 := e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	res, first := n.Subscribe(bg, subscribe(t, impu1, pcscfPath, 600000))
	wantStatus(t, res, 200)
	v1 := v0.Clone()
	v1.Contacts = append(v1.Contacts, binding(2, time.Hour))
	v1 = e.saved(v1)
	v2 := v1.Clone()
	v2.Contacts = append(v2.Contacts, binding(3, time.Hour))
	v2 = e.saved(v2)
	first(bg)
	n.Changed(bg, v0, v1, Registered)
	n.Wait()
	got := e.send.notifies()
	if len(got) != 2 {
		t.Fatalf("%d NOTIFYs, want the first and the change's", len(got))
	}
	for i, r := range got {
		doc, _, _ := info(t, r)
		if a := activeURIs(doc, impu1); doc.Version != uint32(i) || len(a) != 3 {
			t.Errorf("NOTIFY of version %d has %v active, want version %d with the 3 bindings of v2", doc.Version, a, i)
		}
	}
}

// TestAChangesRecordThatWouldEndASubscriptionIsCheckedAsItIsNow (#492 code
// review): binding 1, on the subscribed P-CSCF, goes in v1 and is back in
// v2, and binding 9 on another P-CSCF stays. v2's NOTIFY is numbered first;
// the v0 to v1 change's, run late, does not end the subscription by v1,
// which has no binding on the P-CSCF: v2, the record now, has one.
func TestAChangesRecordThatWouldEndASubscriptionIsCheckedAsItIsNow(t *testing.T) {
	e := newEnv(t)
	other := binding(9, time.Hour)
	other.Path = []string{"<sip:term@pcscf2." + realm + ";lr>"}
	v0 := e.registered(binding(1, time.Hour), other)
	n := e.notifier(1)
	e.subscribed(n)
	v1 := v0.Clone()
	v1.Contacts = []state.Contact{other}
	v1 = e.saved(v1)
	v2 := v1.Clone()
	v2.Contacts = []state.Contact{binding(1, 2*time.Hour), other}
	v2 = e.saved(v2)
	n.Changed(bg, v1, v2, Registered)
	n.Wait()
	n.Changed(bg, v0, v1, Unregistered)
	n.Wait()
	got := e.send.notifies()
	if len(got) != 3 {
		t.Errorf("%d NOTIFYs, want the first and one for each change", len(got))
	}
	for _, r := range got {
		// Read from the header: a NOTIFY that ended the subscription
		// would have no body.
		if ss, err := r.Header.SubscriptionState(); err != nil || ss.State != "active" {
			t.Errorf("a NOTIFY says %s %v, want active: the P-CSCF is on a live binding of the record now", ss.State, ss.Params)
		}
	}
	if subs := e.subscriptions(impu1); len(subs) != 1 || subs[0].Terminated {
		t.Errorf("subscriptions left %+v, want the one, not terminated", subs)
	}
}

// numberedDuringRead is the memory store, whose next Registration read,
// once armed, is followed by another instance's save of a newer record and
// the numbering of its NOTIFY, before the read returns.
type numberedDuringRead struct {
	*state.Memory
	reads atomic.Int64
	armed atomic.Bool
	sub   string
	newer *state.Registration
	err   error
}

func (s *numberedDuringRead) Registration(ctx context.Context, k state.SetKey) (*state.Registration, error) {
	s.reads.Add(1)
	r, err := s.Memory.Registration(ctx, k)
	if s.armed.CompareAndSwap(true, false) {
		saved, serr := s.Memory.SaveRegistration(ctx, s.newer)
		if serr == nil {
			_, _, serr = s.Memory.NextNotify(ctx, s.sub, saved.Version)
		}
		s.err = serr
	}
	return r, err
}

// TestALateChangeReadsTheRecordOnceThoughItIsStaleAgain (#492 QA): a late
// change's NOTIFY, refused its number for the record it carries, reads the
// record and is refused again, as a newer record's NOTIFY was numbered
// meanwhile. It is not sent, and does not read the record again: the newer
// record's NOTIFY tells what this one would.
func TestALateChangeReadsTheRecordOnceThoughItIsStaleAgain(t *testing.T) {
	e := newEnv(t)
	v0 := e.registered(binding(1, time.Hour), binding(2, time.Hour))
	st := &numberedDuringRead{Memory: e.store}
	m := &counts{}
	n := newNotifierWith(t, e, st, e.send, func(c *Config) { c.Metrics = m })
	e.subscribed(n)
	v1 := v0.Clone()
	v1.Contacts = []state.Contact{binding(1, time.Hour)}
	v1 = e.saved(v1)
	v2 := v1.Clone()
	v2.Contacts = []state.Contact{binding(1, 2*time.Hour)}
	v2 = e.saved(v2)
	n.Changed(bg, v1, v2, Registered)
	n.Wait()
	v3 := v2.Clone()
	v3.Contacts = []state.Contact{binding(1, 3*time.Hour)}
	st.sub, st.newer = e.subscriptions(impu1)[0].ID, v3
	st.reads.Store(0)
	st.armed.Store(true)
	sent := len(e.send.notifies())
	n.Changed(bg, v0, v1, Unregistered)
	n.Wait()
	if st.err != nil || st.armed.Load() {
		t.Fatalf("the newer record's NOTIFY was not numbered during the read: %v", st.err)
	}
	if got := len(e.send.notifies()) - sent; got != 0 {
		t.Errorf("%d NOTIFYs of the late change, want none: a newer one has its number", got)
	}
	if r := st.reads.Load(); r != 1 {
		t.Errorf("%d reads of the record for the late change's NOTIFY, want 1", r)
	}
	if got := m.get("regevent.notify_superseded"); got != 1 {
		t.Errorf("%d superseded, want 1", got)
	}
}
