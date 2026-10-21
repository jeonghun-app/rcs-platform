package registrar

import (
	"testing"
)

// TestAnAheadPointerDoesNotTakeASavedRecordsIdentity: two devices of one
// IMPI register the set {impu1, tel1} from scratch at once (QA's minor 1 on
// #196, round 5). A points both identities ahead of its record; after A pointed impu1,
// B's whole REGISTER runs (B's record commits, both identities at B's
// incarnation); A then points tel1 over B's item, and A's record save fails
// with a store error (500). A's retry lands on B's record as a
// re-registration and repairs nothing, since impu1's own item is right:
// tel1 names an incarnation that was never saved.
func TestAnAheadPointerDoesNotTakeASavedRecordsIdentity(t *testing.T) {
	e := newEnv(t)
	a := e.akaUser(impi1, impu1, tel1)
	a.instance = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>"
	b := device(a, 2)
	st := &v3Steps{at: -1}
	// A's writes: SaveProfile, SaveIdentity(impu1), SaveIdentity(tel1),
	// SaveRegistration, the fourth failing; one that leaves tel1's item to
	// B's record makes three, and its save fails with ErrExists.
	fs := &faultStore{Store: &countingStore{Store: e.store, steps: st}, at: 3, kind: "error"}
	g := e.instance(3, func(c *Config) { c.Store = fs })
	auth := a.answer(e.instance(4).Register(bg, a.request(600, ""), upstream), 0)
	st.mu.Lock()
	// Store steps: Identity TakeChallenge Registration SaveProfile
	// Identity (impu1's item, read before it is pointed ahead) Identity
	// SaveIdentity | Identity(tel1) ...: B runs before A reads tel1's item.
	st.n, st.at = 0, 7
	st.hook = func() { wantStatus(t, b.registerWith(e.instance(5), 600), 200) }
	st.mu.Unlock()
	defer func() {
		st.mu.Lock()
		defer st.mu.Unlock()
		if st.hook != nil {
			t.Error("B's REGISTER never ran")
		}
	}()
	if code := g.Register(bg, a.request(600, auth), upstream).StatusCode; code != 500 {
		t.Fatalf("A's first REGISTER: %d, want the injected 500", code)
	}
	wantStatus(t, a.registerWith(e.instance(6), 600), 200)
	// The contract (state.Identity): an item naming a record not saved is
	// as good as none.
	committed := func(impu string) bool {
		id, err := e.store.Identity(bg, impu, e.clock.Now())
		if err != nil {
			return false
		}
		r, err := e.store.Registration(bg, id.Set)
		return err == nil && r.Incarnation == id.Incarnation
	}
	for _, impu := range []string{impu1, tel1} {
		if !committed(impu) {
			t.Errorf("%s names no saved record after both devices got 200", impu)
		}
	}
}

// TestAPutBackWhoseSaveWasReportedLostPointsTheSet: a put-back whose record
// save is committed but reported lost (QA's minor 2 on #196, round 5): putBack gives
// up ("left to the sweep") though the record is live again under a new
// incarnation and holds no lease, so no sweep comes; the identities still
// name the claimed incarnation until a REGISTER of the set repairs them.
func TestAPutBackWhoseSaveWasReportedLostPointsTheSet(t *testing.T) {
	e := newEnv(t)
	u := e.akaUser(impi1, impu1, tel1)
	wantStatus(t, u.registerWith(e.instance(1), 600), 200)
	e.hss.mu.Lock()
	e.hss.unavailable = false
	e.hss.mu.Unlock()
	// Writes of the deregistration: the lease, then the put-back.
	fs := &faultStore{Store: e.store, at: 1, kind: "lost"}
	g := e.instance(3, func(c *Config) { c.Store = fs })
	auth := u.answer(e.instance(4).Register(bg, u.request(0, ""), upstream), 0)
	e.hss.mu.Lock()
	e.hss.unavailable = true
	e.hss.mu.Unlock()
	wantStatus(t, g.Register(bg, u.request(0, auth), upstream), 480)
	e.hss.mu.Lock()
	e.hss.unavailable = false
	e.hss.mu.Unlock()
	r := must(e.store.Registration(bg, set1))(t)
	if len(r.Contacts) != 1 || !r.Deregistering.IsZero() {
		t.Fatalf("record after the put-back: %+v", r)
	}
	for _, impu := range []string{impu1, tel1} {
		id := must(e.store.Identity(bg, impu, e.clock.Now()))(t)
		if id.Incarnation != r.Incarnation {
			t.Errorf("%s names incarnation %d, the record is %d (as good as none per state.Identity)", impu, id.Incarnation, r.Incarnation)
		}
	}
}
