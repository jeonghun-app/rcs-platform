package registrar

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// stepStore runs hook once, just before the n-th call (1-based) of method.
type stepStore struct {
	state.Store
	mu     sync.Mutex
	method string
	n      int
	hook   func()
}

func (s *stepStore) before(m string) {
	s.mu.Lock()
	var f func()
	if m == s.method {
		s.n--
		if s.n == 0 {
			f, s.hook = s.hook, nil
		}
	}
	s.mu.Unlock()
	if f != nil {
		f()
	}
}

func (s *stepStore) Registration(ctx context.Context, k state.SetKey) (*state.Registration, error) {
	s.before("Registration")
	return s.Store.Registration(ctx, k)
}
func (s *stepStore) Identity(ctx context.Context, impu string, now time.Time) (*state.Identity, error) {
	s.before("Identity")
	return s.Store.Identity(ctx, impu, now)
}
func (s *stepStore) SaveRegistration(ctx context.Context, r *state.Registration) (*state.Registration, error) {
	s.before("SaveRegistration")
	return s.Store.SaveRegistration(ctx, r)
}
func (s *stepStore) DeleteRegistration(ctx context.Context, r *state.Registration) error {
	s.before("DeleteRegistration")
	return s.Store.DeleteRegistration(ctx, r)
}
func (s *stepStore) Profile(ctx context.Context, k state.SetKey, now time.Time) (*state.Profile, error) {
	s.before("Profile")
	return s.Store.Profile(ctx, k, now)
}

// hssView is the HSS's state as the last successful SAR left it.
type hssView struct {
	*fakeHSS
	mu   sync.Mutex
	last cx.ServerAssignmentType
}

func (h *hssView) SAR(ctx context.Context, r *cx.SAR) (*cx.SAA, error) {
	saa, err := h.fakeHSS.SAR(ctx, r)
	if err == nil && saa.Result == cx.ResultCode(2001) {
		h.mu.Lock()
		h.last = r.AssignmentType
		h.mu.Unlock()
	}
	return saa, err
}

func (h *hssView) registered() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last == cx.Registration || h.last == cx.ReRegistration
}

type race struct {
	e    *env
	hss  *hssView
	a, b *ue
}

func newRace(t *testing.T, set []string, aTo, bTo string, pre ...int) *race {
	e := newEnv(t)
	h := &hssView{fakeHSS: e.hss}
	a := e.akaUser(impi1, set...)
	a.instance = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>"
	b := device(a, 2)
	a.impu, b.impu = aTo, bTo
	r := &race{e: e, hss: h, a: a, b: b}
	for _, i := range pre {
		wantStatus(t, []*ue{a, b}[i].registerWith(r.plain(9), 600), 200)
	}
	e.clock.advance(time.Second)
	return r
}

func (r *race) plain(seed byte) *Registrar {
	return r.e.instance(seed, func(c *Config) { c.HSS = r.hss })
}

// run sends x's authenticated REGISTER through a store that, before the n-th
// call of method, lets y's whole REGISTER run on another instance.
func (r *race) run(t *testing.T, x, y *ue, xExp, yExp int, method string, n int) (xCode, yCode int) {
	t.Helper()
	ss := &stepStore{Store: r.e.store, method: method, n: n}
	ss.hook = func() {
		r.e.clock.advance(time.Second)
		yCode = y.registerWith(r.plain(5), yExp).StatusCode
	}
	g := r.e.instance(3, func(c *Config) { c.Store, c.HSS = ss, r.hss })
	auth := x.answer(r.plain(4).Register(bg, x.request(xExp, ""), upstream), 0)
	xCode = g.Register(bg, x.request(xExp, auth), upstream).StatusCode
	if ss.hook != nil {
		t.Fatal("the hook did not run")
	}
	return xCode, yCode
}

// R1: B (a new device) reads impu1 while A is registered, then A's
// deregistration runs completely. B's conditional save finds impu1 gone
// (ErrNotFound), which register no longer retries.
func TestASaveThatFindsTheSetGoneIsRetried(t *testing.T) {
	r := newRace(t, []string{impu1}, impu1, impu1, 0)
	bCode, aCode := r.run(t, r.b, r.a, 600, 0, "Profile", 1)
	got := bindingsOf(t, r.e, impu1)
	_, perr := r.e.store.Profile(bg, state.SetKey{IMPI: impi1, IMPU: impu1}, r.e.clock.Now())
	t.Logf("A %d, B %d, stored %v, HSS registered %v, profile err %v", aCode, bCode, got, r.hss.registered(), perr)
	if bCode != 200 {
		t.Errorf("B got %d", bCode)
	}
	if len(got[impu1]) == 0 && r.hss.registered() {
		t.Error("the HSS has the user registered at this S-CSCF, and nothing is stored for a sweep to end")
	}
}

// R2: B registers via tel1 while A (impu1) deregisters; A's deregistration
// runs between B's read of impu1 and B's save of it. applyTo takes the
// ErrNotFound as "nothing to do": B got 200 but impu1 lacks its binding.
func TestAnIdentityOfASetDeregisteredMeanwhileGetsTheBinding(t *testing.T) {
	r := newRace(t, []string{impu1, tel1}, impu1, tel1, 0)
	// In the set model the race is before B's one save of the set.
	bCode, aCode := r.run(t, r.b, r.a, 600, 0, "SaveRegistration", 1)
	got := bindingsOf(t, r.e, impu1, tel1)
	t.Logf("A %d, B %d, stored %v, HSS registered %v", aCode, bCode, got, r.hss.registered())
	if aCode == 200 && bCode == 200 && (len(got[impu1]) != 1 || len(got[tel1]) != 1) {
		t.Errorf("both got 200, but the set holds %v; want B's binding on both identities", got)
	}
}

// R3: the same race, one step earlier: A's deregistration runs after B saved
// tel1 and before B reads impu1. A sends SAR USER_DEREGISTRATION for the set
// although tel1 holds B's binding; the store ends with B on both identities
// and the HSS with the user not registered.
func TestNoUserDeregistrationStandsWhileTheSetKeepsABinding(t *testing.T) {
	r := newRace(t, []string{impu1, tel1}, impu1, tel1, 0)
	// In the set model: between B's read of the set and its save.
	bCode, aCode := r.run(t, r.b, r.a, 600, 0, "Profile", 1)
	got := bindingsOf(t, r.e, impu1, tel1)
	t.Logf("A %d, B %d, stored %v, HSS last SAR %v", aCode, bCode, got, r.hss.last)
	if len(got[impu1])+len(got[tel1]) > 0 && !r.hss.registered() {
		t.Errorf("the store holds %v but the HSS was last told %v", got, r.hss.last)
	}
}

// R4: both devices deregister at once, A via impu1 and B via tel1. B's
// REGISTER still sees A on tel1, so it is a re-registration (SAR
// RE_REGISTRATION after A's USER_DEREGISTRATION); then each removes the
// other's last binding. Nothing is stored, the HSS has the user registered.
func TestTwoDeregistrationsLeaveTheHSSNotRegistered(t *testing.T) {
	r := newRace(t, []string{impu1, tel1}, impu1, tel1, 0, 1)
	// In the set model: before A's one save of the set.
	aCode, bCode := r.run(t, r.a, r.b, 0, 0, "SaveRegistration", 1)
	got := bindingsOf(t, r.e, impu1, tel1)
	_, perr := r.e.store.Profile(bg, state.SetKey{IMPI: impi1, IMPU: impu1}, r.e.clock.Now())
	t.Logf("A %d, B %d, stored %v, HSS last SAR %v, profile err %v", aCode, bCode, got, r.hss.last, perr)
	if len(got) == 0 && r.hss.registered() {
		t.Error("nothing is stored, but the HSS has the user registered at this S-CSCF (no sweep will end it)")
	}
	if len(got) == 0 && perr == nil {
		t.Error("the profile outlives the set's last binding")
	}
}
