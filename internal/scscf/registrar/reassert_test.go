package registrar

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// countingMetrics records the registrar's counters.
type countingMetrics struct {
	mu sync.Mutex
	n  map[string]int64
}

func (m *countingMetrics) Count(name string, v int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.n == nil {
		m.n = map[string]int64{}
	}
	m.n[name] += v
}

func (m *countingMetrics) get(name string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.n[name]
}

// TestAReassignTheHSSDoesNotTakeMarksTheSetForASweep: A's deregistration is
// overtaken by B's registration, so the S-CSCF tells the HSS again that it
// serves the set; when that SAR fails, the HSS may hold the set as
// deregistered while B is registered here, so the record is marked for a
// sweep to try again after reassertBackoff (#196 code review).
func TestAReassignTheHSSDoesNotTakeMarksTheSetForASweep(t *testing.T) {
	e := newEnv(t)
	a := e.akaUser(impi1, impu1, tel1)
	a.instance = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>"
	wantStatus(t, a.registerWith(e.instance(1), 600), 200)
	b := device(a, 2)
	ch := &crossingHSS{HSS: e.hss, kind: cx.UserDeregistration}
	ch.hook = func() { wantStatus(t, b.registerWith(e.instance(2), 600), 200) }
	e.hss.sarHook = func(r *cx.SAR) (*cx.SAA, error) {
		if r.AssignmentType == cx.Registration && r.UserDataAlreadyAvailable == cx.UserDataAlreadyAvailable {
			// Only the reassign: B's own SAR asked for the User-Data.
			return nil, errUnreachable
		}
		return nil, nil
	}
	m := &countingMetrics{}
	g := e.instance(3, func(c *Config) { c.HSS, c.Metrics = ch, m })
	auth := a.answer(g.Register(bg, a.request(0, ""), upstream), 0)
	wantStatus(t, g.Register(bg, a.request(0, auth), upstream), 200)
	r, err := regOf(e, impu1)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Contacts) != 1 || !r.Reassert.Equal(e.clock.Now().Add(reassertBackoff)) || r.ReassertAttempts != 1 {
		t.Errorf("after the failed reassign: %d contacts, Reassert in %v, %d attempts", len(r.Contacts), r.Reassert.Sub(e.clock.Now()), r.ReassertAttempts)
	}
	if !r.SweepAt().Equal(r.Reassert) {
		t.Errorf("a sweep is due in %v, not at the Reassert", r.SweepAt().Sub(e.clock.Now()))
	}
	if got := m.get("registrar.reassert_failed"); got != 1 {
		t.Errorf("registrar.reassert_failed = %d, want 1", got)
	}
	wantSameBindings(t, e, 1, impu1, tel1)
}

// flakyIdentities fails the first DeleteIdentity, as a throttled request
// does, or with read set the first Identity read once armed.
type flakyIdentities struct {
	state.Store
	read bool
	mu   sync.Mutex
	// armed is when to fail: from the start for a delete, after the
	// deregistration's SAR for a read, which the REGISTER also makes first.
	armed, failed bool
}

func (s *flakyIdentities) fail(read bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if read != s.read || !s.armed || s.failed {
		return false
	}
	s.failed = true
	return true
}

func (s *flakyIdentities) arm() {
	s.mu.Lock()
	s.armed = true
	s.mu.Unlock()
}

func (s *flakyIdentities) Identity(ctx context.Context, impu string, now time.Time) (*state.Identity, error) {
	if s.fail(true) {
		return nil, errors.New("store: throttled")
	}
	return s.Store.Identity(ctx, impu, now)
}

func (s *flakyIdentities) DeleteIdentity(ctx context.Context, i *state.Identity) error {
	if s.fail(false) {
		return errors.New("store: throttled")
	}
	return s.Store.DeleteIdentity(ctx, i)
}

// TestADeregistrationThatCannotDeleteAnIdentityLeavesTheSetToTheSweep: the
// HSS has taken the deregistration, so the client gets its 200, but the
// identity items go before the record: with one left, the record keeps its
// lease for the sweep after it to finish, rather than vanishing with an item
// still naming it (#184 and #196 QA).
func TestADeregistrationThatCannotDeleteAnIdentityLeavesTheSetToTheSweep(t *testing.T) {
	for name, read := range map[string]bool{"delete": false, "read": true} {
		t.Run(name, func(t *testing.T) { testDeregistrationLeftToTheSweep(t, read) })
	}
}

func testDeregistrationLeftToTheSweep(t *testing.T, read bool) {
	e := newEnv(t)
	a := e.akaUser(impi1, impu1, tel1)
	wantStatus(t, a.registerWith(e.instance(1), 600), 200)
	m := &countingMetrics{}
	flaky := &flakyIdentities{Store: e.store, read: read, armed: !read}
	e.hss.sarHook = func(r *cx.SAR) (*cx.SAA, error) {
		if r.AssignmentType == cx.UserDeregistration {
			flaky.arm()
		}
		return nil, nil
	}
	g := e.instance(2, func(c *Config) { c.Store, c.Metrics = flaky, m })
	wantStatus(t, a.registerWith(g, 0), 200)
	r, err := e.store.Registration(bg, state.SetKey{IMPI: impi1, IMPU: impu1})
	if err != nil {
		t.Fatalf("the record went with an identity left: %v", err)
	}
	if len(r.Contacts) != 0 || !r.Deregistering.After(e.clock.Now()) {
		t.Errorf("left with %d contacts, Deregistering %v", len(r.Contacts), r.Deregistering)
	}
	if got := m.get("registrar.deregistration_left_to_sweep"); got != 1 {
		t.Errorf("registrar.deregistration_left_to_sweep = %d, want 1", got)
	}
	if _, sars := e.hss.counts(); sars != 2 {
		t.Errorf("%d SARs, want the registration's and the deregistration's", sars)
	}
	// A registration after that starts afresh, and every identity points at
	// its record.
	e.hss.sarHook = nil
	e.clock.advance(time.Second)
	wantStatus(t, a.registerWith(e.instance(3), 600), 200)
	wantSameBindings(t, e, 1, impu1, tel1)
}

// TestAContactParameterWithATabIsKept: HTAB is allowed in a quoted string
// (RFC 3261 §25.1), so it is written back, not refused as a control
// character (#196 code review).
func TestAContactParameterWithATabIsKept(t *testing.T) {
	for name, value := range map[string]string{"as is": "a\tb", "quoted-pair": "a\\\tb"} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			g := e.instance(1)
			u := e.akaUser(impi1, impu1)
			u.contact = ""
			contact := "Contact: <sip:uea@192.0.2.10:5060;transport=tcp>;expires=600;+x.tag=\"" + value + "\""
			auth := u.answer(g.Register(bg, u.request(-1, "", contact), upstream), 0)
			res := g.Register(bg, u.request(-1, auth, contact), upstream)
			wantStatus(t, res, 200)
			if got := fmt.Sprint(res.Header.Values("Contact")); !strings.Contains(got, "\t") {
				t.Errorf("the 200's Contact lost the tab: %q", got)
			}
		})
	}
}

// TestAnIdentityIsFoundForAsLongAsItsSetIsRegistered: an identity's item has
// a KeepUntil, a safety net for one a deregistration left; re-registrations
// must extend it, as they do the profile, or a registered user would stop
// being found a day after registering.
func TestAnIdentityIsFoundForAsLongAsItsSetIsRegistered(t *testing.T) {
	for _, expires := range []int{3600, 13 * 3600, 600000} {
		t.Run(fmt.Sprint(expires), func(t *testing.T) {
			e := newEnv(t)
			g := e.instance(1)
			u := e.akaUser(impi1, impu1, tel1)
			end := t0.Add(10 * 24 * time.Hour)
			next := e.clock.Now()
			for e.clock.Now().Before(end) {
				if !e.clock.Now().Before(next) {
					wantStatus(t, u.registerWith(g, expires), 200)
					// Refreshed 600 s before the expiry granted (TS 24.229
					// §5.1.1.4.1).
					r, err := regOf(e, impu1)
					if err != nil {
						t.Fatal(err)
					}
					next = r.Contacts[0].Expires.Add(-600 * time.Second)
				}
				for _, impu := range []string{impu1, tel1} {
					if _, err := e.store.Identity(bg, impu, e.clock.Now()); err != nil {
						t.Fatalf("%v after the first registration, %s: %v", e.clock.Now().Sub(t0), impu, err)
					}
				}
				e.clock.advance(time.Hour)
			}
		})
	}
}

// TestRepointingAnIdentityNeverBringsItsKeepUntilCloser: an identity kept
// longer for its set than this registration needs, as after a longer one,
// keeps that when the set changes and it is saved again.
func TestRepointingAnIdentityNeverBringsItsKeepUntilCloser(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1, tel1)
	wantStatus(t, u.registerWith(g, 600), 200)
	long := t0.Add(10 * 24 * time.Hour)
	if err := e.store.KeepIdentity(bg, tel1, long, e.clock.Now()); err != nil {
		t.Fatal(err)
	}
	// The HSS bars tel1, which the next SAA that carries User-Data tells.
	e.hss.mu.Lock()
	e.hss.subs[impi1].barred = map[string]bool{tel1: true}
	e.hss.mu.Unlock()
	if err := e.store.DeleteProfile(bg, state.SetKey{IMPI: impi1, IMPU: impu1}); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, u.registerWith(g, 600), 200)
	id, err := e.store.Identity(bg, tel1, e.clock.Now())
	if err != nil || !id.Barred || !id.KeepUntil.Equal(long) {
		t.Errorf("tel1 after the set changed: %+v, %v; want barred and kept until %v", id, err, long)
	}
}
