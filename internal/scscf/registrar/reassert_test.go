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
	m := &counts{}
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
	m := &counts{}
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

// beforeSAR runs hook once before it forwards the first SAR that match
// takes: what happens elsewhere while that SAR is on its way to the HSS.
type beforeSAR struct {
	HSS
	match func(*cx.SAR) bool
	once  sync.Once
	hook  func()
}

func (b *beforeSAR) SAR(ctx context.Context, r *cx.SAR) (*cx.SAA, error) {
	if b.match(r) {
		b.once.Do(b.hook)
	}
	return b.HSS.SAR(ctx, r)
}

// isReassertion matches a SAR that tells the HSS again that this S-CSCF
// serves a set, which asks for no User-Data, unlike a REGISTER's own.
func isReassertion(r *cx.SAR) bool {
	return r.UserDataAlreadyAvailable == cx.UserDataAlreadyAvailable &&
		(r.AssignmentType == cx.Registration || r.AssignmentType == cx.UnregisteredUser)
}

// wantDeregisteredLast fails unless the set holds no binding here, only
// the undo's tombstone, and the HSS was last told of a deregistration; and
// unless the sweep after the tombstone's lease ends it.
func wantDeregisteredLast(t *testing.T, e *env) {
	t.Helper()
	wantOnlyATombstone(t, e)
	if got := e.hss.sarsOf(); len(got) == 0 || got[len(got)-1] != cx.UserDeregistration {
		t.Errorf("SARs %v, want the HSS told USER_DEREGISTRATION last", got)
	}
	e.clock.advance(state.SweepLease)
	if _, err := e.instance(9).Sweep(bg, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Registration(bg, set1); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("the tombstone outlived the sweep after its lease: %v", err)
	}
	if got := e.hss.sarsOf(); got[len(got)-1] != cx.TimeoutDeregistration && got[len(got)-1] != cx.UserDeregistration {
		t.Errorf("SARs %v after the sweep, want a deregistration last", got)
	}
}

// wantOnlyATombstone fails unless set1 is gone or held by a
// deregistration's lease without bindings.
func wantOnlyATombstone(t *testing.T, e *env) {
	t.Helper()
	r, err := e.store.Registration(bg, set1)
	switch {
	case errors.Is(err, state.ErrNotFound):
	case err != nil:
		t.Fatal(err)
	case len(r.Contacts) != 0 || r.Deregistering.IsZero():
		t.Fatalf("the set is still here: %+v", r)
	}
}

// TestAReassertOvertakenByADeregistrationIsUndone (#241; QA on #210): the
// sweep's SAR REGISTRATION reaches the HSS after the user's deregistration,
// or an RTR's end, has; the HSS is told of the deregistration again.
func TestAReassertOvertakenByADeregistrationIsUndone(t *testing.T) {
	for name, end := range map[string]func(t *testing.T, e *env, u *ue){
		"the user's": func(t *testing.T, e *env, u *ue) { wantStatus(t, u.registerWith(e.instance(2), 0), 200) },
		"an RTR's": func(t *testing.T, e *env, _ *ue) {
			wantResult(t, e.instance(2).HandleRTR(bg, &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.ServerChange}}), resultSuccess)
		},
		// One still under way: its lease holds the record, its SAR has
		// reached the HSS.
		"one under way": func(t *testing.T, e *env, _ *ue) {
			r := must(e.store.Registration(bg, set1))(t)
			r.Contacts, r.Deregistering = nil, e.clock.Now().Add(state.SweepLease)
			must(e.store.SaveRegistration(bg, r))(t)
			must(e.hss.SAR(bg, &cx.SAR{UserName: impi1, PublicIdentities: []string{impu1}, AssignmentType: cx.UserDeregistration}))(t)
		},
		// An unregistered user's under way: live by the user's state, but
		// under a lease (#410 code review).
		"an unregistered user's under way": func(t *testing.T, e *env, _ *ue) {
			r := must(e.store.Registration(bg, set1))(t)
			r.Contacts, r.Deregistering, r.Unregistered = nil, e.clock.Now().Add(state.SweepLease), e.clock.Now().Add(time.Hour)
			must(e.store.SaveRegistration(bg, r))(t)
			must(e.hss.SAR(bg, &cx.SAR{UserName: impi1, PublicIdentities: []string{impu1}, AssignmentType: cx.UserDeregistration}))(t)
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			u := reassertDue(t, e, e.instance(1))
			b := &beforeSAR{HSS: e.hss, match: isReassertion}
			b.hook = func() { end(t, e, u) }
			m := &counts{}
			if _, err := e.instance(3, func(c *Config) { c.HSS, c.Metrics = b, m }).Sweep(bg, 10); err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(name, "under way") {
				// The deregistration under way finishes after.
				must(0, e.store.DeleteRegistration(bg, must(e.store.Registration(bg, set1))(t)))(t)
			}
			wantDeregisteredLast(t, e)
			if m.get("registrar.reassert_undone") != 1 {
				t.Errorf("registrar.reassert_undone = %d", m.get("registrar.reassert_undone"))
			}
		})
	}
}

// TestAReassignOvertakenByADeregistrationIsUndone (#241; code review on
// #210): A's deregistration was overtaken by B's registration, and while
// the SAR that gives the set back to the HSS is on its way, B deregisters
// to the end.
func TestAReassignOvertakenByADeregistrationIsUndone(t *testing.T) {
	e := newEnv(t)
	a := e.akaUser(impi1, impu1, tel1)
	a.instance = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>"
	wantStatus(t, a.registerWith(e.instance(1), 600), 200)
	b := device(a, 2)
	overtaken := &crossingHSS{HSS: e.hss, kind: cx.UserDeregistration}
	overtaken.hook = func() { wantStatus(t, b.registerWith(e.instance(2), 600), 200) }
	reassigned := &beforeSAR{HSS: overtaken, match: isReassertion}
	reassigned.hook = func() { wantStatus(t, b.registerWith(e.instance(4), 0), 200) }
	g := e.instance(3, func(c *Config) { c.HSS = reassigned })
	auth := a.answer(g.Register(bg, a.request(0, ""), upstream), 0)
	wantStatus(t, g.Register(bg, a.request(0, auth), upstream), 200)
	wantDeregisteredLast(t, e)
}

// TestAnUndoOvertakenByARegistrationMarksTheSet (#241): a REGISTER that
// makes the set live again while the undo's SAR is on its way may have its
// SAR reach the HSS first; the record is marked for a sweep to tell the
// HSS again.
func TestAnUndoOvertakenByARegistrationMarksTheSet(t *testing.T) {
	e := newEnv(t)
	u := reassertDue(t, e, e.instance(1))
	b := &beforeSAR{HSS: e.hss, match: isReassertion}
	b.hook = func() { wantStatus(t, u.registerWith(e.instance(2), 0), 200) }
	undo := &beforeSAR{HSS: b, match: func(r *cx.SAR) bool { return r.AssignmentType == cx.UserDeregistration }}
	undo.hook = func() { wantStatus(t, u.registerWith(e.instance(4), 600), 200) }
	// The user's own deregistration goes through e.hss: only the sweep's
	// SARs pass the hooks, the undo first among USER_DEREGISTRATIONs.
	if _, err := e.instance(3, func(c *Config) { c.HSS = undo }).Sweep(bg, 10); err != nil {
		t.Fatal(err)
	}
	r := must(regOf(e, impu1))(t)
	if len(r.Contacts) != 1 || !r.Reassert.Equal(e.clock.Now().Add(reassertBackoff)) {
		t.Errorf("after the undo: %d contacts, Reassert %v", len(r.Contacts), r.Reassert)
	}
}

// TestAnUnregisteredUsersRecordIsReassignedAsUnregistered (#241, #210 code
// review): the record that overtook a deregistration is an unregistered
// user's, as a terminating request leaves one (#14), and the HSS is told
// UNREGISTERED_USER, not REGISTRATION; its identities are kept until its
// state ends.
func TestAnUnregisteredUsersRecordIsReassignedAsUnregistered(t *testing.T) {
	e := newEnv(t)
	a := e.akaUser(impi1, impu1, tel1)
	wantStatus(t, a.registerWith(e.instance(1), 600), 200)
	// Past what A's registration kept the identities for.
	until := e.clock.Now().Add(600*time.Second + state.ProfileGrace + time.Hour)
	ch := &crossingHSS{HSS: e.hss, kind: cx.UserDeregistration}
	ch.hook = func() {
		r := must(e.store.Registration(bg, set1))(t)
		r.Deregistering, r.Unregistered, r.Incarnation = time.Time{}, until, r.Incarnation+1
		must(e.store.SaveRegistration(bg, r))(t)
	}
	g := e.instance(3, func(c *Config) { c.HSS = ch })
	auth := a.answer(g.Register(bg, a.request(0, ""), upstream), 0)
	wantStatus(t, g.Register(bg, a.request(0, auth), upstream), 200)
	got := e.hss.sarsOf()
	if len(got) == 0 || got[len(got)-1] != cx.UnregisteredUser {
		t.Errorf("SARs %v, want UNREGISTERED_USER last", got)
	}
	for _, impu := range []string{impu1, tel1} {
		id := must(e.store.Identity(bg, impu, e.clock.Now()))(t)
		if id.KeepUntil.Before(until) {
			t.Errorf("%s kept until %v, before the state ends at %v", impu, id.KeepUntil, until)
		}
	}
}

// failingSARs fails the SARs of a kind that pass it, as an HSS out of
// reach does: the first times of them, every one when times is 0.
type failingSARs struct {
	HSS
	kind  cx.ServerAssignmentType
	times int
	mu    sync.Mutex
	n     int
}

func (f *failingSARs) SAR(ctx context.Context, r *cx.SAR) (*cx.SAA, error) {
	if r.AssignmentType == f.kind {
		f.mu.Lock()
		fail := f.times == 0 || f.n < f.times
		if fail {
			f.n++
		}
		f.mu.Unlock()
		if fail {
			return nil, errUnreachable
		}
	}
	return f.HSS.SAR(ctx, r)
}

func (f *failingSARs) failed() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n
}

// TestAnUndoTheHSSDoesNotTakeIsCounted (#241, #410 code review): the undo
// is tried undoAttempts times, then counted and logged, not returned, as no
// record is left for anyone to try again from; its tombstone stays for the
// sweep after its lease.
func TestAnUndoTheHSSDoesNotTakeIsCounted(t *testing.T) {
	e := newEnv(t)
	u := reassertDue(t, e, e.instance(1))
	f := &failingSARs{HSS: e.hss, kind: cx.UserDeregistration}
	b := &beforeSAR{HSS: f, match: isReassertion}
	b.hook = func() { wantStatus(t, u.registerWith(e.instance(2), 0), 200) }
	m := &counts{}
	k := len(e.hss.sarsOf())
	if _, err := e.instance(3, func(c *Config) { c.HSS, c.Metrics = b, m }).Sweep(bg, 10); err != nil {
		t.Error(err)
	}
	if m.get("registrar.reassert_undo_failed") != 1 || m.get("registrar.reassert_undone") != 0 || f.failed() != undoAttempts {
		t.Errorf("undo_failed %d, undone %d, %d undo SARs", m.get("registrar.reassert_undo_failed"), m.get("registrar.reassert_undone"), f.failed())
	}
	_ = k
	wantOnlyATombstone(t, e)
}

// TestAnUndoTriesAFailureThatMayPassAgain (#410 code review): one SAR the
// HSS does not take is sent again, and the set ends there.
func TestAnUndoTriesAFailureThatMayPassAgain(t *testing.T) {
	e := newEnv(t)
	u := reassertDue(t, e, e.instance(1))
	f := &failingSARs{HSS: e.hss, kind: cx.UserDeregistration, times: 1}
	b := &beforeSAR{HSS: f, match: isReassertion}
	b.hook = func() { wantStatus(t, u.registerWith(e.instance(2), 0), 200) }
	m := &counts{}
	if _, err := e.instance(3, func(c *Config) { c.HSS, c.Metrics = b, m }).Sweep(bg, 10); err != nil {
		t.Fatal(err)
	}
	wantDeregisteredLast(t, e)
	if m.get("registrar.reassert_undone") != 1 || m.get("registrar.reassert_undo_failed") != 0 {
		t.Errorf("undone %d, undo_failed %d", m.get("registrar.reassert_undone"), m.get("registrar.reassert_undo_failed"))
	}
}

// TestAnUndoTheHSSRefusesForGoodIsNotSentAgain (#410 code review): a user
// the HSS no longer has holds nothing to undo.
func TestAnUndoTheHSSRefusesForGoodIsNotSentAgain(t *testing.T) {
	e := newEnv(t)
	u := reassertDue(t, e, e.instance(1))
	b := &beforeSAR{HSS: &refusingDeregistrations{HSS: e.hss}, match: isReassertion}
	b.hook = func() { wantStatus(t, u.registerWith(e.instance(2), 0), 200) }
	m := &counts{}
	k := len(e.hss.sarsOf())
	if _, err := e.instance(3, func(c *Config) { c.HSS, c.Metrics = b, m }).Sweep(bg, 10); err != nil {
		t.Fatal(err)
	}
	if m.get("registrar.reassert_undo_refused") != 1 || m.get("registrar.reassert_undo_failed") != 0 {
		t.Errorf("undo_refused %d, undo_failed %d", m.get("registrar.reassert_undo_refused"), m.get("registrar.reassert_undo_failed"))
	}
	undos := 0
	for _, sar := range e.hss.sarsOf()[k:] {
		if sar == cx.UserDeregistration {
			undos++
		}
	}
	// The user's own deregistration, and one refused undo.
	if r := refusals(b); undos != 1 || r != 1 {
		t.Errorf("%d USER_DEREGISTRATIONs reached the HSS, %d refused", undos, r)
	}
}

// refusingDeregistrations answers every USER_DEREGISTRATION that passes it
// DIAMETER_ERROR_USER_UNKNOWN, without the HSS seeing it.
type refusingDeregistrations struct {
	HSS
	mu      sync.Mutex
	refused int
}

func (r *refusingDeregistrations) SAR(ctx context.Context, s *cx.SAR) (*cx.SAA, error) {
	if s.AssignmentType == cx.UserDeregistration {
		r.mu.Lock()
		r.refused++
		r.mu.Unlock()
		return &cx.SAA{Answer: cx.Answer{Result: cx.ExperimentalResult(cx.ErrorUserUnknown)}}, nil
	}
	return r.HSS.SAR(ctx, s)
}

func refusals(b *beforeSAR) int {
	r := b.HSS.(*refusingDeregistrations)
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.refused
}

// TestAFailedUndoOfAReassignLeavesNothingToTheSweep (#410 code review): the
// deregistration whose endSet gave the set back finished; an undo the HSS
// did not take is no deregistration left to the sweep.
func TestAFailedUndoOfAReassignLeavesNothingToTheSweep(t *testing.T) {
	e := newEnv(t)
	a := e.akaUser(impi1, impu1, tel1)
	a.instance = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>"
	wantStatus(t, a.registerWith(e.instance(1), 600), 200)
	b := device(a, 2)
	overtaken := &crossingHSS{HSS: e.hss, kind: cx.UserDeregistration}
	overtaken.hook = func() { wantStatus(t, b.registerWith(e.instance(2), 600), 200) }
	reassigned := &beforeSAR{HSS: overtaken, match: isReassertion}
	reassigned.hook = func() { wantStatus(t, b.registerWith(e.instance(4), 0), 200) }
	// Past the hooks, every USER_DEREGISTRATION of instance 3 fails: A's
	// own went first, through the crossing.
	m := &counts{}
	failing := &failingAfterFirst{HSS: reassigned, kind: cx.UserDeregistration}
	g := e.instance(3, func(c *Config) { c.HSS, c.Metrics = failing, m })
	auth := a.answer(g.Register(bg, a.request(0, ""), upstream), 0)
	wantStatus(t, g.Register(bg, a.request(0, auth), upstream), 200)
	if m.get("registrar.reassert_undo_failed") != 1 || m.get("registrar.deregistration_left_to_sweep") != 0 {
		t.Errorf("undo_failed %d, deregistration_left_to_sweep %d", m.get("registrar.reassert_undo_failed"), m.get("registrar.deregistration_left_to_sweep"))
	}
}

// failingAfterFirst forwards the first SAR of kind and fails the others.
type failingAfterFirst struct {
	HSS
	kind cx.ServerAssignmentType
	mu   sync.Mutex
	seen int
}

func (f *failingAfterFirst) SAR(ctx context.Context, r *cx.SAR) (*cx.SAA, error) {
	if r.AssignmentType == f.kind {
		f.mu.Lock()
		f.seen++
		n := f.seen
		f.mu.Unlock()
		if n > 1 {
			return nil, errUnreachable
		}
	}
	return f.HSS.SAR(ctx, r)
}

// holdingHSS forwards a REGISTER's own SAR REGISTRATION at once, but holds
// its answer until release is closed, as an SAA late on the wire.
type holdingHSS struct {
	HSS
	once      sync.Once
	forwarded chan struct{}
	release   chan struct{}
}

func (h *holdingHSS) SAR(ctx context.Context, r *cx.SAR) (*cx.SAA, error) {
	saa, err := h.HSS.SAR(ctx, r)
	if r.AssignmentType == cx.Registration && r.UserDataAlreadyAvailable != cx.UserDataAlreadyAvailable {
		h.once.Do(func() { close(h.forwarded) })
		<-h.release
	}
	return saa, err
}

// TestAnUndoCrossingARegistersLateAnswerMarksTheSet (#410 code review): a
// REGISTER whose SAR reaches the HSS before the undo's, but whose record is
// saved after the undo, takes the set over from the undo's tombstone; the
// record is marked for the sweep to tell the HSS again.
func TestAnUndoCrossingARegistersLateAnswerMarksTheSet(t *testing.T) {
	e := newEnv(t)
	u := reassertDue(t, e, e.instance(1))
	b := &beforeSAR{HSS: e.hss, match: isReassertion}
	b.hook = func() { wantStatus(t, u.registerWith(e.instance(2), 0), 200) }
	h := &holdingHSS{HSS: e.hss, forwarded: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	undo := &beforeSAR{HSS: b, match: func(r *cx.SAR) bool { return r.AssignmentType == cx.UserDeregistration }}
	undo.hook = func() {
		go func() {
			defer close(done)
			wantStatus(t, u.registerWith(e.instance(4, func(c *Config) { c.HSS = h }), 600), 200)
		}()
		recvWithin(t, h.forwarded)
	}
	// The REGISTER's record is saved once its answer comes, after the
	// undo: released when the undo has been sent.
	after := &afterSAR{HSS: undo, match: func(r *cx.SAR) bool { return r.AssignmentType == cx.UserDeregistration }, then: func() { close(h.release); <-done }}
	if _, err := e.instance(3, func(c *Config) { c.HSS = after }).Sweep(bg, 10); err != nil {
		t.Fatal(err)
	}
	sars := e.hss.sarsOf()
	r := must(e.store.Registration(bg, set1))(t)
	// Either the REGISTER, reading the tombstone, told the HSS again after
	// the undo, or its record is marked for the sweep to.
	if len(r.Contacts) != 1 || sars[len(sars)-1] == cx.UserDeregistration && r.Reassert.IsZero() {
		t.Errorf("SARs %v; record %d contacts, Reassert %v: registered here, the HSS last told USER_DEREGISTRATION, and nothing marked", sars, len(r.Contacts), r.Reassert)
	}
}

// afterSAR runs then once after it forwards the first SAR that match takes.
type afterSAR struct {
	HSS
	match func(*cx.SAR) bool
	once  sync.Once
	then  func()
}

func (a *afterSAR) SAR(ctx context.Context, r *cx.SAR) (*cx.SAA, error) {
	saa, err := a.HSS.SAR(ctx, r)
	if a.match(r) {
		a.once.Do(a.then)
	}
	return saa, err
}

func recvWithin(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("nothing came")
	}
}

// TestASweepReassertsAnUnregisteredUsersRecord (#410 code review): a
// Reassert on an unregistered user's record, which a reassign the HSS did
// not take leaves, comes before its state ends; the sweep tells the HSS
// UNREGISTERED_USER and keeps the record.
func TestASweepReassertsAnUnregisteredUsersRecord(t *testing.T) {
	e := newEnv(t)
	reassertDue(t, e, e.instance(1))
	r := must(e.store.Registration(bg, set1))(t)
	r.Contacts, r.Unregistered = nil, e.clock.Now().Add(2*time.Hour)
	must(e.store.SaveRegistration(bg, r))(t)
	k := len(e.hss.sarsOf())
	if _, err := e.instance(3).Sweep(bg, 10); err != nil {
		t.Fatal(err)
	}
	if got := e.hss.sarsOf()[k:]; len(got) != 1 || got[0] != cx.UnregisteredUser {
		t.Errorf("SARs %v, want [UNREGISTERED_USER]", got)
	}
	left := must(e.store.Registration(bg, set1))(t)
	if !left.Unregistered.Equal(r.Unregistered) || !left.Reassert.IsZero() || !left.Deregistering.IsZero() {
		t.Errorf("after the sweep: %+v", left)
	}
}

// TestAFailedReassertIsNotUndone (#241): a SAR the HSS did not take left
// nothing to undo, whatever ended the set meanwhile.
func TestAFailedReassertIsNotUndone(t *testing.T) {
	e := newEnv(t)
	u := reassertDue(t, e, e.instance(1))
	b := &beforeSAR{HSS: &failingSARs{HSS: e.hss, kind: cx.Registration}, match: isReassertion}
	b.hook = func() { wantStatus(t, u.registerWith(e.instance(2), 0), 200) }
	m := &counts{}
	if _, err := e.instance(3, func(c *Config) { c.HSS, c.Metrics = b, m }).Sweep(bg, 10); err != nil {
		t.Fatal(err)
	}
	if got := e.hss.sarsOf(); m.get("registrar.reassert_undone") != 0 || got[len(got)-1] != cx.UserDeregistration || len(got) != 2 {
		t.Errorf("SARs %v, undone %d; want the user's deregistration last and alone after the registration", got, m.get("registrar.reassert_undone"))
	}
}

// TestAnUndoOverALeaseCrossingARegisterMarksTheSet (#410 code review): the
// set is under another deregistration's lease when the undo reads it; that
// deregistration finishes, and a new REGISTER registers the set, all before
// the undo's SAR reaches the HSS. The undo saved its tombstone over the
// lease, so the deregistration finishes nothing, the REGISTER takes the set
// over from the tombstone and is marked.
func TestAnUndoOverALeaseCrossingARegisterMarksTheSet(t *testing.T) {
	e := newEnv(t)
	u := reassertDue(t, e, e.instance(1))
	b := &beforeSAR{HSS: e.hss, match: isReassertion}
	b.hook = func() {
		// A deregistration under way: its lease holds the record, its SAR
		// has reached the HSS.
		r := must(e.store.Registration(bg, set1))(t)
		r.Contacts, r.Deregistering = nil, e.clock.Now().Add(state.SweepLease)
		must(e.store.SaveRegistration(bg, r))(t)
		must(e.hss.SAR(bg, &cx.SAR{UserName: impi1, PublicIdentities: []string{impu1}, AssignmentType: cx.UserDeregistration}))(t)
	}
	undo := &beforeSAR{HSS: b, match: func(r *cx.SAR) bool { return r.AssignmentType == cx.UserDeregistration }}
	undo.hook = func() {
		// The deregistration tries to finish, then the UE registers again.
		if err := e.store.DeleteRegistration(bg, must(e.store.Registration(bg, set1))(t)); err != nil {
			t.Logf("the deregistration's delete: %v", err)
		}
		wantStatus(t, u.registerWith(e.instance(4), 600), 200)
	}
	if _, err := e.instance(3, func(c *Config) { c.HSS = undo }).Sweep(bg, 10); err != nil {
		t.Fatal(err)
	}
	sars := e.hss.sarsOf()
	r := must(e.store.Registration(bg, set1))(t)
	if len(r.Contacts) != 1 || sars[len(sars)-1] == cx.UserDeregistration && r.Reassert.IsZero() {
		t.Errorf("SARs %v; record %d contacts, Reassert %v: registered here, the HSS last told USER_DEREGISTRATION, and nothing marked", sars, len(r.Contacts), r.Reassert)
	}
}

// TestARegisterThatTakesOverTheTombstoneIsMarked (#410 code review): a
// REGISTER that reads the undo's tombstone sends its SAR, which reaches
// the HSS before the undo's, and saves only after the undo has read the
// set again; taking the set over from a lease marks it for the sweep.
func TestARegisterThatTakesOverTheTombstoneIsMarked(t *testing.T) {
	e := newEnv(t)
	u := reassertDue(t, e, e.instance(1))
	b := &beforeSAR{HSS: e.hss, match: isReassertion}
	b.hook = func() { wantStatus(t, u.registerWith(e.instance(2), 0), 200) }
	block := &qaBlockFirstSave{Store: e.store, entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	undo := &beforeSAR{HSS: b, match: func(r *cx.SAR) bool { return r.AssignmentType == cx.UserDeregistration }}
	undo.hook = func() {
		// The tombstone is saved: the REGISTER reads it, sends its SAR,
		// and holds its save.
		go func() {
			defer close(done)
			wantStatus(t, u.registerWith(e.instance(4, func(c *Config) { c.Store = block }), 600), 200)
		}()
		recvWithin(t, block.entered)
	}
	if _, err := e.instance(3, func(c *Config) { c.HSS = undo }).Sweep(bg, 10); err != nil {
		t.Fatal(err)
	}
	close(block.release)
	<-done
	sars := e.hss.sarsOf()
	r := must(e.store.Registration(bg, set1))(t)
	if len(r.Contacts) != 1 || sars[len(sars)-1] == cx.UserDeregistration && r.Reassert.IsZero() {
		t.Errorf("SARs %v; record %d contacts, Reassert %v: registered here, the HSS last told USER_DEREGISTRATION, and nothing marked", sars, len(r.Contacts), r.Reassert)
	}
}
