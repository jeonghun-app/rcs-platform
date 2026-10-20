package registrar

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

var errInjected = errors.New("store: unavailable (injected)")

// faultStore applies a fault to the at-th write: "lost" commits it and then
// reports a conflict (the SDK's resend of a committed conditional write);
// "error" fails it without writing (a transient store outage).
type faultStore struct {
	state.Store
	mu    sync.Mutex
	n, at int
	kind  string
	names []string
}

func (s *faultStore) fault(what string, write func() error) error {
	s.mu.Lock()
	k := s.n
	s.n++
	s.names = append(s.names, what)
	s.mu.Unlock()
	if k != s.at {
		return write()
	}
	if s.kind == "error" {
		return errInjected
	}
	if err := write(); err != nil {
		return err
	}
	return fmt.Errorf("lost: %w", state.ErrConflict)
}

func (s *faultStore) SaveRegistration(ctx context.Context, r *state.Registration) (out *state.Registration, err error) {
	err = s.fault("SaveRegistration", func() (e error) { out, e = s.Store.SaveRegistration(ctx, r); return })
	if err != nil {
		out = nil
	}
	return
}
func (s *faultStore) DeleteRegistration(ctx context.Context, r *state.Registration) error {
	return s.fault("DeleteRegistration", func() error { return s.Store.DeleteRegistration(ctx, r) })
}
func (s *faultStore) SaveIdentity(ctx context.Context, i *state.Identity, now time.Time) (out *state.Identity, err error) {
	err = s.fault("SaveIdentity", func() (e error) { out, e = s.Store.SaveIdentity(ctx, i, now); return })
	if err != nil {
		out = nil
	}
	return
}
func (s *faultStore) KeepIdentity(ctx context.Context, impu string, until, now time.Time) error {
	return s.fault("KeepIdentity", func() error { return s.Store.KeepIdentity(ctx, impu, until, now) })
}
func (s *faultStore) DeleteIdentity(ctx context.Context, i *state.Identity) error {
	return s.fault("DeleteIdentity", func() error { return s.Store.DeleteIdentity(ctx, i) })
}
func (s *faultStore) SaveProfile(ctx context.Context, p *state.Profile) error {
	return s.fault("SaveProfile", func() error { return s.Store.SaveProfile(ctx, p) })
}
func (s *faultStore) KeepProfile(ctx context.Context, k state.SetKey, until, now time.Time) error {
	return s.fault("KeepProfile", func() error { return s.Store.KeepProfile(ctx, k, until, now) })
}
func (s *faultStore) DeleteProfile(ctx context.Context, k state.SetKey) error {
	return s.fault("DeleteProfile", func() error { return s.Store.DeleteProfile(ctx, k) })
}
func (s *faultStore) DeleteProfileIf(ctx context.Context, k state.SetKey, received time.Time) error {
	return s.fault("DeleteProfileIf", func() error { return s.Store.DeleteProfileIf(ctx, k, received) })
}

// TestAPointerAFailedRegistrationMissedIsThereAfterTheRetry: an initial
// registration whose second identity item fails to save (a store error) is
// answered 500, and nothing is committed; the client's retry registers
// afresh and points every identity (QA's F1 on #196).
func TestAPointerAFailedRegistrationMissedIsThereAfterTheRetry(t *testing.T) {
	e := newEnv(t)
	u := e.akaUser(impi1, impu1, tel1)
	u.instance = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>"
	// The writes are SaveProfile, then the identities, then the record:
	// the third is the second identity's.
	fs := &faultStore{Store: e.store, at: 2, kind: "error"}
	res := u.registerWith(e.instance(3, func(c *Config) { c.Store = fs }), 3600)
	fs.mu.Lock()
	t.Logf("first REGISTER: %d, writes %v", res.StatusCode, fs.names)
	if len(fs.names) < 3 || fs.names[2] != "SaveIdentity" || res.StatusCode != 500 {
		t.Fatalf("the fault did not hit the second identity: %d, writes %v", res.StatusCode, fs.names)
	}
	fs.mu.Unlock()
	if _, err := e.store.Registration(bg, set1); err == nil {
		t.Error("a record was committed with an identity missing")
	}
	g := e.instance(1)
	wantStatus(t, u.registerWith(g, 3600), 200)
	if _, err := regOf(e, tel1); err != nil {
		t.Errorf("after the client's retry got 200, tel1 resolves to no registration: %v", err)
	}
}

// TestPointersOutliveTheirFirstKeepUntilWhileTheSetReRegisters: just before
// each hourly re-registration, for two days, every identity still resolves
// to the record (QA's W7 and W8 on #196).
func TestPointersOutliveTheirFirstKeepUntilWhileTheSetReRegisters(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1, tel1)
	wantStatus(t, u.registerWith(g, 3600), 200)
	for h := 1; h <= 48; h++ {
		e.clock.advance(time.Hour - time.Minute)
		for _, impu := range []string{impu1, tel1} {
			if _, err := regOf(e, impu); err != nil {
				t.Fatalf("after %d h of hourly re-registrations, %s resolves to nothing: %v", h, impu, err)
			}
		}
		wantStatus(t, u.registerWith(g, 3600), 200)
	}
}

// TestAPutBackThatCannotPointEveryIdentityLeavesTheSetToTheSweep: the HSS
// could not be told of a deregistration, so the bindings go back under a new
// incarnation; when an identity cannot be pointed at it, the record is
// claimed again rather than left live with an identity naming the old one,
// and the sweep after the lease finishes the deregistration the client asked
// for (QA's minor 3 on #196).
func TestAPutBackThatCannotPointEveryIdentityLeavesTheSetToTheSweep(t *testing.T) {
	e := newEnv(t)
	u := e.akaUser(impi1, impu1, tel1)
	wantStatus(t, u.registerWith(e.instance(1), 600), 200)
	before := must(e.store.Registration(bg, set1))(t)
	e.hss.mu.Lock()
	e.hss.sarHook = func(r *cx.SAR) (*cx.SAA, error) {
		if r.AssignmentType == cx.UserDeregistration {
			return nil, errUnreachable
		}
		return nil, nil
	}
	e.hss.mu.Unlock()
	// The deregistration writes the lease, the record put back, then the
	// identities: the fourth write is the second identity's.
	fs := &faultStore{Store: e.store, at: 3, kind: "error"}
	m := &counts{}
	wantStatus(t, u.registerWith(e.instance(2, func(c *Config) { c.Store, c.Metrics = fs, m }), 0), 480)
	fs.mu.Lock()
	if len(fs.names) < 4 || fs.names[3] != "SaveIdentity" {
		t.Fatalf("the fault did not hit an identity of the put back: %v", fs.names)
	}
	fs.mu.Unlock()
	r := must(e.store.Registration(bg, set1))(t)
	if len(r.Contacts) != 0 || r.Deregistering.IsZero() || r.Incarnation == before.Incarnation {
		t.Errorf("after the half-pointed put back: %d contacts, Deregistering %v, incarnation kept %v", len(r.Contacts), r.Deregistering, r.Incarnation == before.Incarnation)
	}
	if m.get("registrar.deregistration_left_to_sweep") != 1 {
		t.Errorf("left_to_sweep = %d", m.get("registrar.deregistration_left_to_sweep"))
	}
}

// TestAReRegistrationRepairsAnIdentityNamingAnOldIncarnation: the set is
// pointed again when the request's own identity names its record but not its
// incarnation, as a deregistration would otherwise skip it (QA's minor 3 on
// #196).
func TestAReRegistrationRepairsAnIdentityNamingAnOldIncarnation(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1, tel1)
	wantStatus(t, u.registerWith(g, 600), 200)
	r := must(e.store.Registration(bg, set1))(t)
	for _, impu := range []string{impu1, tel1} {
		id := must(e.store.Identity(bg, impu, e.clock.Now()))(t)
		id.Incarnation = r.Incarnation + 1
		must(e.store.SaveIdentity(bg, id, e.clock.Now()))(t)
	}
	wantStatus(t, u.registerWith(g, 600), 200)
	wantPointed(t, e, impu1, tel1)
}

// TestAnIdentityThatMovedToASetNotSavedIsRepairedByItsNextRegister: the HSS
// moves tel1 from set A to a set of its own, B. A REGISTER for tel1 points
// it at B first, then fails to save B's record, so tel1 names a record that
// does not exist and is found nowhere. Its next REGISTER finds no set, so it
// registers B afresh and points tel1 at it; A keeps its own identity.
func TestAnIdentityThatMovedToASetNotSavedIsRepairedByItsNextRegister(t *testing.T) {
	e := newEnv(t)
	u := e.akaUser(impi1, impu1, tel1)
	wantStatus(t, u.registerWith(e.instance(1), 600), 200)
	e.hss.mu.Lock()
	e.hss.subs[impi1].set = []string{impu1}
	e.hss.subs[impi1].more = [][]string{{tel1}}
	e.hss.mu.Unlock()
	// A REGISTER asks the HSS for User-Data, and so learns of the move,
	// when the set's profile is gone.
	if err := e.store.DeleteProfile(bg, set1); err != nil {
		t.Fatal(err)
	}
	v := device(u, 2)
	v.impu = tel1
	// The writes are B's profile, tel1's item, then B's record.
	fs := &faultStore{Store: e.store, at: 2, kind: "error"}
	wantStatus(t, v.registerWith(e.instance(2, func(c *Config) { c.Store = fs }), 600), 500)
	fs.mu.Lock()
	if len(fs.names) < 3 || fs.names[2] != "SaveRegistration" {
		t.Fatalf("the fault did not hit B's record: %v", fs.names)
	}
	fs.mu.Unlock()
	if _, err := regOf(e, tel1); err == nil {
		t.Fatal("tel1 resolves although B's record was never saved")
	}
	wantStatus(t, v.registerWith(e.instance(3), 600), 200)
	b := state.SetKey{IMPI: impi1, IMPU: tel1}
	if r, err := regOf(e, tel1); err != nil || r.Key != b {
		t.Errorf("tel1 after its next REGISTER: %+v, %v", r, err)
	}
	wantPointed(t, e, impu1, tel1)
}
