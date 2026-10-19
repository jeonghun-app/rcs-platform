package registrar

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// hookStore runs a hook once, just before the named call, as another
// instance's REGISTER landing in between would. From QA's review of #196.
type hookStore struct {
	*state.Memory
	mu     sync.Mutex
	onOf   func()
	onRead map[string]func()
	onSave map[string]func()
	// afterDelete runs once after the named registration is deleted.
	afterDelete map[string]func()
	saveErr     func(r *state.Registration) error
}

func newHookStore(m *state.Memory) *hookStore {
	return &hookStore{Memory: m, onRead: map[string]func(){}, onSave: map[string]func(){}, afterDelete: map[string]func(){}}
}

func (h *hookStore) take(m map[string]func(), key string) func() {
	h.mu.Lock()
	defer h.mu.Unlock()
	f := m[key]
	delete(m, key)
	return f
}

func (h *hookStore) RegistrationsOf(ctx context.Context, impi string) ([]*state.Registration, error) {
	h.mu.Lock()
	f := h.onOf
	h.onOf = nil
	h.mu.Unlock()
	if f != nil {
		f()
	}
	return h.Memory.RegistrationsOf(ctx, impi)
}

func (h *hookStore) Registration(ctx context.Context, impu string) (*state.Registration, error) {
	if f := h.take(h.onRead, impu); f != nil {
		f()
	}
	return h.Memory.Registration(ctx, impu)
}

func (h *hookStore) DeleteRegistration(ctx context.Context, r *state.Registration) error {
	err := h.Memory.DeleteRegistration(ctx, r)
	if err == nil {
		if f := h.take(h.afterDelete, r.IMPU); f != nil {
			f()
		}
	}
	return err
}

func (h *hookStore) SaveRegistration(ctx context.Context, r *state.Registration) (*state.Registration, error) {
	if f := h.take(h.onSave, r.IMPU); f != nil {
		f()
	}
	if h.saveErr != nil {
		if err := h.saveErr(r); err != nil {
			return nil, err
		}
	}
	return h.Memory.SaveRegistration(ctx, r)
}

// device is another UE of u's IMPI, with an instance of its own.
func device(u *ue, n int) *ue {
	d := *u
	d.callID = fmt.Sprintf("device-%d", n)
	d.contact = fmt.Sprintf("sip:ue%d@192.0.2.%d:5060;transport=tcp", n, 20+n)
	d.instance = fmt.Sprintf("<urn:uuid:00000000-0000-0000-0000-0000000000%02d>", n)
	d.cseq = 0
	return &d
}

// bindingsOf returns the contact URIs stored for each identity.
func bindingsOf(t *testing.T, e *env, impus ...string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, impu := range impus {
		r, err := e.store.Registration(bg, impu)
		if err != nil {
			continue
		}
		for _, c := range r.Contacts {
			out[impu] = append(out[impu], c.URI)
		}
		slices.Sort(out[impu])
	}
	return out
}

// wantSameBindings fails unless every identity of the set holds want.
func wantSameBindings(t *testing.T, e *env, want int, impus ...string) {
	t.Helper()
	got := bindingsOf(t, e, impus...)
	for _, impu := range impus {
		if len(got[impu]) != want || !slices.Equal(got[impu], got[impus[0]]) {
			t.Errorf("bindings %v, want the same %d on every identity of the set", got, want)
			return
		}
	}
}

func TestADeregistrationRacingARegistrationOfTheSetKeepsTheNewOne(t *testing.T) {
	for _, set := range [][]string{{impu1, tel1}, {impu1}} {
		t.Run(fmt.Sprint(len(set), " identities"), func(t *testing.T) {
			e := newEnv(t)
			a := e.akaUser(impi1, set...)
			a.instance = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>"
			wantStatus(t, a.registerWith(e.instance(1), 600), 200)
			b := device(a, 2)

			hs := newHookStore(e.store)
			var bres *sip.Response
			// A's deregistration has deleted its own record when device B
			// registers, from scratch, on another instance (QA on #196).
			hs.afterDelete[impu1] = func() {
				e.clock.advance(time.Second)
				bres = b.registerWith(e.instance(2), 600)
			}
			g := e.instance(3, func(c *Config) { c.Store = hs })
			auth := a.answer(g.Register(bg, a.request(0, ""), upstream), 0)
			wantStatus(t, g.Register(bg, a.request(0, auth), upstream), 200)
			wantStatus(t, bres, 200)

			wantSameBindings(t, e, 1, set...)
			r := must(e.store.Registration(bg, impu1))(t)
			if r.Contacts[0].CallID != "device-2" {
				t.Errorf("impu1 holds %+v, want B's binding", r.Contacts)
			}
			if _, err := e.store.Profile(bg, r.ProfileKey(), e.clock.Now()); err != nil {
				t.Errorf("B got 200 but the set's profile is gone: %v", err)
			}
		})
	}
}

func TestADeregistrationLeavesTheOtherSetsOfItsIMPI(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	twoSets(t, e, g)
	u := e.akaUser(impi1, impu1, tel1)
	auth := u.answer(g.Register(bg, u.request(0, ""), upstream), 0)
	wantStatus(t, g.Register(bg, u.request(0, auth), upstream), 200)
	gone(t, e, impu1, tel1)
	for _, impu := range []string{impu2, impu3} {
		must(e.store.Registration(bg, impu))(t)
	}
	must(e.store.Profile(bg, set2, e.clock.Now()))(t)
}

func TestConcurrentREGISTERsToTwoIdentitiesOfOneSetKeepBothBindings(t *testing.T) {
	e := newEnv(t)
	a := e.akaUser(impi1, impu1, tel1)
	a.instance = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>"
	b := device(a, 2)
	b.impu = tel1

	hs := newHookStore(e.store)
	var bres *sip.Response
	g := e.instance(1, func(c *Config) { c.Store = hs })
	auth := a.answer(g.Register(bg, a.request(600, ""), upstream), 0)
	// Instance 1 has saved impu1 and is about to read tel1.
	hs.onRead[tel1] = func() { bres = b.registerWith(e.instance(2), 600) }
	wantStatus(t, g.Register(bg, a.request(600, auth), upstream), 200)
	wantStatus(t, bres, 200)
	wantSameBindings(t, e, 2, impu1, tel1)
}

func TestAThirdDeviceRegisteringBetweenTwoSavesIsKeptOnEveryIdentity(t *testing.T) {
	e := newEnv(t)
	a := e.akaUser(impi1, impu1, tel1)
	a.instance = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>"
	wantStatus(t, a.registerWith(e.instance(1), 600), 200)
	b, c := device(a, 2), device(a, 3)

	hs := newHookStore(e.store)
	var cres *sip.Response
	// B has saved impu1; before it reaches tel1, C registers completely on
	// another instance.
	hs.onRead[tel1] = func() { cres = c.registerWith(e.instance(3), 600) }
	g := e.instance(2, func(cfg *Config) { cfg.Store = hs })
	auth := b.answer(g.Register(bg, b.request(600, ""), upstream), 0)
	hs.onRead[tel1] = func() { cres = c.registerWith(e.instance(3), 600) }
	wantStatus(t, g.Register(bg, b.request(600, auth), upstream), 200)
	wantStatus(t, cres, 200)
	wantSameBindings(t, e, 3, impu1, tel1)
}

func TestAReRegistrationBetweenTwoSavesKeepsItsNewExpiryOnEveryIdentity(t *testing.T) {
	e := newEnv(t)
	a := e.akaUser(impi1, impu1, tel1)
	a.instance = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>"
	wantStatus(t, a.registerWith(e.instance(1), 600), 200)
	b := device(a, 2)

	hs := newHookStore(e.store)
	g := e.instance(2, func(cfg *Config) { cfg.Store = hs })
	auth := b.answer(g.Register(bg, b.request(600, ""), upstream), 0)
	// A re-registers, for longer, between B's two saves.
	hs.onRead[tel1] = func() { wantStatus(t, a.registerWith(e.instance(3), 900), 200) }
	wantStatus(t, g.Register(bg, b.request(600, auth), upstream), 200)
	wantSameBindings(t, e, 2, impu1, tel1)
	for _, impu := range []string{impu1, tel1} {
		for _, c := range must(e.store.Registration(bg, impu))(t).Contacts {
			if c.InstanceID == a.instance && !c.Expires.Equal(e.clock.Now().Add(900*1e9)) {
				t.Errorf("%s: A's binding expires %v, want its re-registration's", impu, c.Expires)
			}
		}
	}
}

func TestAnIdentitySaveThatLosesIsAppliedAgainToWhatWon(t *testing.T) {
	e := newEnv(t)
	a := e.akaUser(impi1, impu1, tel1)
	a.instance = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>"
	wantStatus(t, a.registerWith(e.instance(1), 600), 200)
	b := device(a, 2)
	hs := newHookStore(e.store)
	g := e.instance(2, func(cfg *Config) { cfg.Store = hs })
	auth := b.answer(g.Register(bg, b.request(600, ""), upstream), 0)
	// Another instance writes tel1 after B read it and before B saves it.
	hs.onSave[tel1] = func() { wantStatus(t, a.registerWith(e.instance(3), 600), 200) }
	wantStatus(t, g.Register(bg, b.request(600, auth), upstream), 200)
	wantSameBindings(t, e, 2, impu1, tel1)
}

// lostResponse applies a save and then reports it lost to another writer, as
// the SDK does when it resends a save whose response was lost.
func TestASaveAppliedButReportedAsAConflictIsASuccess(t *testing.T) {
	for _, impu := range []string{impu1, tel1} {
		t.Run(impu, func(t *testing.T) {
			e := newEnv(t)
			u := e.akaUser(impi1, impu1, tel1)
			hs := newHookStore(e.store)
			once := false
			hs.saveErr = func(r *state.Registration) error {
				if r.IMPU != impu || once {
					return nil
				}
				once = true
				if _, err := e.store.SaveRegistration(bg, r); err != nil {
					t.Fatal(err)
				}
				return state.ErrConflict
			}
			res := u.registerWith(e.instance(1, func(c *Config) { c.Store = hs }), 600)
			wantStatus(t, res, 200)
			wantSameBindings(t, e, 1, impu1, tel1)
		})
	}
}
