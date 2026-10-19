package registrar

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// sweepStore runs hook once, before the at-th store call.
type sweepStore struct {
	state.Store
	mu    sync.Mutex
	n, at int
	hook  func()
	names []string
}

func (s *sweepStore) step(what string) {
	s.mu.Lock()
	k := s.n
	s.n++
	s.names = append(s.names, what)
	var f func()
	if k == s.at && s.hook != nil {
		f, s.hook = s.hook, nil
	}
	s.mu.Unlock()
	if f != nil {
		f()
	}
}

func (s *sweepStore) Registration(ctx context.Context, k state.SetKey) (*state.Registration, error) {
	s.step("Registration")
	return s.Store.Registration(ctx, k)
}
func (s *sweepStore) Identity(ctx context.Context, impu string) (*state.Identity, error) {
	s.step("Identity")
	return s.Store.Identity(ctx, impu)
}
func (s *sweepStore) SaveIdentity(ctx context.Context, i *state.Identity) (*state.Identity, error) {
	s.step("SaveIdentity")
	return s.Store.SaveIdentity(ctx, i)
}
func (s *sweepStore) DeleteIdentity(ctx context.Context, i *state.Identity) error {
	s.step("DeleteIdentity")
	return s.Store.DeleteIdentity(ctx, i)
}
func (s *sweepStore) RegistrationsOf(ctx context.Context, impi string) ([]*state.Registration, error) {
	s.step("RegistrationsOf")
	return s.Store.RegistrationsOf(ctx, impi)
}
func (s *sweepStore) SaveRegistration(ctx context.Context, r *state.Registration) (*state.Registration, error) {
	s.step("SaveRegistration")
	return s.Store.SaveRegistration(ctx, r)
}
func (s *sweepStore) DeleteRegistration(ctx context.Context, r *state.Registration) error {
	s.step("DeleteRegistration")
	return s.Store.DeleteRegistration(ctx, r)
}
func (s *sweepStore) Profile(ctx context.Context, k state.SetKey, now time.Time) (*state.Profile, error) {
	s.step("Profile")
	return s.Store.Profile(ctx, k, now)
}
func (s *sweepStore) SaveProfile(ctx context.Context, p *state.Profile) error {
	s.step("SaveProfile")
	return s.Store.SaveProfile(ctx, p)
}
func (s *sweepStore) KeepProfile(ctx context.Context, k state.SetKey, until, now time.Time) error {
	s.step("KeepProfile")
	return s.Store.KeepProfile(ctx, k, until, now)
}
func (s *sweepStore) DeleteProfile(ctx context.Context, k state.SetKey) error {
	s.step("DeleteProfile")
	return s.Store.DeleteProfile(ctx, k)
}
func (s *sweepStore) DeleteProfileIf(ctx context.Context, k state.SetKey, received time.Time) error {
	s.step("DeleteProfileIf")
	return s.Store.DeleteProfileIf(ctx, k, received)
}
func (s *sweepStore) TakeChallenge(ctx context.Context, impi, nonce string, now time.Time) (*state.Challenge, error) {
	s.step("TakeChallenge")
	return s.Store.TakeChallenge(ctx, impi, nonce, now)
}

// trackHSS records the HSS's view: the last successful SAR per IMPI.
type trackHSS struct {
	*fakeHSS
	mu   sync.Mutex
	last map[string]cx.ServerAssignmentType
	// hook runs once before the at-th SAR as well (SARs are steps too).
}

func (h *trackHSS) SAR(ctx context.Context, r *cx.SAR) (*cx.SAA, error) {
	saa, err := h.fakeHSS.SAR(ctx, r)
	if err == nil && saa.Result == cx.ResultCode(2001) {
		h.mu.Lock()
		h.last[r.UserName] = r.AssignmentType
		h.mu.Unlock()
	}
	return saa, err
}

func (h *trackHSS) registered(impi string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	t := h.last[impi]
	return t == cx.Registration || t == cx.ReRegistration
}

type scenario struct {
	name string
	set  []string
	// pre registers these devices first (indexes into devs: 0 = A, 1 = B).
	pre []int
	// impu each device sends To.
	to [2]string
	// expires of each device's action.
	exp [2]int
	// want is the devices left registered.
	want []int
}

// TestEveryTwoDeviceInterleavingKeepsTheStoreAndTheHSSAgreeing is QA's sweep
// from its re-check of #196: for each scenario and each step of one device's
// REGISTER, the other device's whole REGISTER runs before that step, and the
// invariants must hold: every identity of the set has the same bindings,
// both 200s mean both devices' changes stand, the store has bindings exactly
// when the HSS was last told the set is registered, and the profile exists
// exactly when bindings do.
func TestEveryTwoDeviceInterleavingKeepsTheStoreAndTheHSSAgreeing(t *testing.T) {
	scs := []scenario{
		{"A dereg vs B initial", []string{impu1, tel1}, []int{0}, [2]string{impu1, impu1}, [2]int{0, 600}, []int{1}},
		{"A dereg vs B initial via tel", []string{impu1, tel1}, []int{0}, [2]string{impu1, tel1}, [2]int{0, 600}, []int{1}},
		{"A dereg vs B initial, one identity", []string{impu1}, []int{0}, [2]string{impu1, impu1}, [2]int{0, 600}, []int{1}},
		{"A initial impu1 vs B initial tel1", []string{impu1, tel1}, nil, [2]string{impu1, tel1}, [2]int{600, 600}, []int{0, 1}},
		{"A rereg vs B initial", []string{impu1, tel1}, []int{0}, [2]string{impu1, tel1}, [2]int{900, 600}, []int{0, 1}},
		{"both dereg", []string{impu1, tel1}, []int{0, 1}, [2]string{impu1, impu1}, [2]int{0, 0}, nil},
		{"both dereg via different identities", []string{impu1, tel1}, []int{0, 1}, [2]string{impu1, tel1}, [2]int{0, 0}, nil},
		{"A dereg vs B rereg", []string{impu1, tel1}, []int{0, 1}, [2]string{impu1, tel1}, [2]int{0, 900}, []int{1}},
		{"A dereg vs B rereg, one identity", []string{impu1}, []int{0, 1}, [2]string{impu1, impu1}, [2]int{0, 900}, []int{1}},
	}
	type outcome struct{ ok, bad int }
	var report []string
	for _, sc := range scs {
		for _, sweeper := range []int{0, 1} {
			other := 1 - sweeper
			var names []string
			run := func(at int) (steps int, problems []string, codes [2]int) {
				e := newEnv(t)
				th := &trackHSS{fakeHSS: e.hss, last: map[string]cx.ServerAssignmentType{}}
				a := e.akaUser(impi1, sc.set...)
				a.instance = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>"
				devs := []*ue{a, device(a, 2)}
				for i := range devs {
					devs[i].impu = sc.to[i]
				}
				plain := func(seed byte) *Registrar { return e.instance(seed, func(c *Config) { c.HSS = th }) }
				for _, i := range sc.pre {
					if res := devs[i].registerWith(plain(9), 600); res.StatusCode != 200 {
						t.Fatalf("pre %d: %d", i, res.StatusCode)
					}
				}
				e.clock.advance(time.Second)
				ss := &sweepStore{Store: e.store, at: -1}
				gs := e.instance(3, func(c *Config) { c.Store, c.HSS = ss, th })
				x, y := devs[sweeper], devs[other]
				auth := x.answer(plain(4).Register(bg, x.request(sc.exp[sweeper], ""), upstream), 0)
				ss.mu.Lock()
				ss.n, ss.at = 0, at
				ss.hook = func() {
					e.clock.advance(time.Second)
					codes[other] = y.registerWith(plain(5), sc.exp[other]).StatusCode
				}
				ss.mu.Unlock()
				codes[sweeper] = gs.Register(bg, x.request(sc.exp[sweeper], auth), upstream).StatusCode
				ss.mu.Lock()
				steps = ss.n
				if at < 0 {
					names = slices.Clone(ss.names)
				}
				fired := ss.hook == nil
				ss.mu.Unlock()
				if !fired {
					codes[other] = y.registerWith(plain(5), sc.exp[other]).StatusCode
				}
				// Invariants.
				got := bindingsOf(t, e, sc.set...)
				for _, impu := range sc.set {
					if !slices.Equal(got[impu], got[sc.set[0]]) {
						problems = append(problems, fmt.Sprintf("identities differ %v", got))
						break
					}
				}
				var want []string
				for _, i := range sc.want {
					want = append(want, strings.SplitN(devs[i].contact, ";", 2)[0])
				}
				slices.Sort(want)
				var have []string
				for _, u := range got[sc.set[0]] {
					have = append(have, strings.SplitN(u, ";", 2)[0])
				}
				if codes[0] == 200 && codes[1] == 200 && !slices.Equal(have, want) {
					problems = append(problems, fmt.Sprintf("both 200 but bindings %v, want %v", have, want))
				}
				stored := false
				for _, impu := range sc.set {
					stored = stored || len(got[impu]) > 0
				}
				if stored != th.registered(impi1) {
					problems = append(problems, fmt.Sprintf("store has bindings=%v but HSS registered=%v (last SAR %v)", stored, th.registered(impi1), th.last[impi1]))
				}
				_, perr := e.store.Profile(bg, state.SetKey{IMPI: impi1, IMPU: sc.set[0]}, e.clock.Now())
				if stored && perr != nil {
					problems = append(problems, "registered without a profile")
				}
				if !stored && perr == nil {
					problems = append(problems, "profile left without a registration")
				}
				for i, c := range codes {
					if c != 200 {
						problems = append(problems, fmt.Sprintf("device %d got %d", i, c))
					}
				}
				return steps, problems, codes
			}
			n, _, _ := run(-1)
			var o outcome
			for at := 0; at <= n; at++ {
				_, p, _ := run(at)
				if len(p) == 0 {
					o.ok++
					continue
				}
				o.bad++
				report = append(report, fmt.Sprintf("%s | sweep %c, hook before step %d/%d (%s): %s", sc.name, "AB"[sweeper], at, n, func() string {
					if at < len(names) {
						return names[at]
					}
					return "end"
				}(), strings.Join(p, "; ")))
			}
			t.Logf("%-40s sweep %c: %d steps, %d ok, %d with problems; steps %v", sc.name, "AB"[sweeper], n, o.ok, o.bad, names)
		}
	}
	for _, r := range report {
		t.Log(r)
	}
	if len(report) > 0 {
		t.Errorf("%d interleavings broke an invariant", len(report))
	}
}
