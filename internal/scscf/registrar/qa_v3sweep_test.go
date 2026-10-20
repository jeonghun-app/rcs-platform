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

// v3Steps counts the sweeper's store calls and SARs; the hook runs before
// the at-th one (for a SAR: after it was sent, before the HSS applies it).
type v3Steps struct {
	mu    sync.Mutex
	n, at int
	hook  func()
	names []string
}

func (s *v3Steps) step(what string) {
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

type v3Store struct {
	*sweepStore
}

// v3HSS is the sweeper's HSS: a step before each SAR, and optionally one
// failure of the sweeper's first USER_DEREGISTRATION.
type v3HSS struct {
	*trackHSS
	steps      *v3Steps
	failDereg  bool
	failedOnce bool
}

func (h *v3HSS) SAR(ctx context.Context, r *cx.SAR) (*cx.SAA, error) {
	h.steps.step(fmt.Sprintf("SAR(%d)", r.AssignmentType))
	if h.failDereg && !h.failedOnce && r.AssignmentType == cx.UserDeregistration {
		h.failedOnce = true
		return nil, errUnreachable
	}
	return h.trackHSS.SAR(ctx, r)
}

type v3Scenario struct {
	name string
	set  []string
	pre  []int
	to   [2]string
	exp  [2]int
	// star sends Contact: * for that device's action.
	star [2]bool
	want []int
	// anyOrder: the two serial orders differ, so only consistency is checked.
	anyOrder  bool
	failDereg bool
	// third, if set, registers (600 s, To impu1) inside the hook after the other device.
	third bool
}

// TestTwoDevicesOfASetAgreeWithTheHSSWhereverOneIsInterleaved: for each
// scenario, the second device's whole REGISTER runs before each store call
// or SAR of the first; the store and the HSS must agree, no lease or pointer
// may be left, and every identity must point at its set's one record. From
// QA's third check of #196 (253 interleavings).
func TestTwoDevicesOfASetAgreeWithTheHSSWhereverOneIsInterleaved(t *testing.T) {
	scs := []v3Scenario{
		{name: "A dereg vs B initial", set: []string{impu1, tel1}, pre: []int{0}, to: [2]string{impu1, impu1}, exp: [2]int{0, 600}, want: []int{1}},
		{name: "A dereg vs B initial via tel", set: []string{impu1, tel1}, pre: []int{0}, to: [2]string{impu1, tel1}, exp: [2]int{0, 600}, want: []int{1}},
		{name: "A dereg vs B initial, one identity", set: []string{impu1}, pre: []int{0}, to: [2]string{impu1, impu1}, exp: [2]int{0, 600}, want: []int{1}},
		{name: "A initial impu1 vs B initial tel1", set: []string{impu1, tel1}, to: [2]string{impu1, tel1}, exp: [2]int{600, 600}, want: []int{0, 1}},
		{name: "A initial vs B initial, same identity", set: []string{impu1, tel1}, to: [2]string{impu1, impu1}, exp: [2]int{600, 600}, want: []int{0, 1}},
		{name: "A rereg vs B initial", set: []string{impu1, tel1}, pre: []int{0}, to: [2]string{impu1, tel1}, exp: [2]int{900, 600}, want: []int{0, 1}},
		{name: "A rereg vs B rereg", set: []string{impu1, tel1}, pre: []int{0, 1}, to: [2]string{impu1, tel1}, exp: [2]int{900, 900}, want: []int{0, 1}},
		{name: "A rereg vs B dereg", set: []string{impu1, tel1}, pre: []int{0, 1}, to: [2]string{tel1, impu1}, exp: [2]int{900, 0}, want: []int{0}},
		{name: "both dereg", set: []string{impu1, tel1}, pre: []int{0, 1}, to: [2]string{impu1, impu1}, exp: [2]int{0, 0}},
		{name: "both dereg via different identities", set: []string{impu1, tel1}, pre: []int{0, 1}, to: [2]string{impu1, tel1}, exp: [2]int{0, 0}},
		{name: "A dereg vs B rereg", set: []string{impu1, tel1}, pre: []int{0, 1}, to: [2]string{impu1, tel1}, exp: [2]int{0, 900}, want: []int{1}},
		{name: "A dereg vs B rereg, one identity", set: []string{impu1}, pre: []int{0, 1}, to: [2]string{impu1, impu1}, exp: [2]int{0, 900}, want: []int{1}},
		{name: "A Contact * vs B initial", set: []string{impu1, tel1}, pre: []int{0}, to: [2]string{impu1, tel1}, exp: [2]int{0, 600}, star: [2]bool{true, false}, anyOrder: true},
		{name: "A dereg vs B initial, A's SAR fails", set: []string{impu1, tel1}, pre: []int{0}, to: [2]string{impu1, impu1}, exp: [2]int{0, 600}, anyOrder: true, failDereg: true},
		{name: "B initial vs C initial (A registered)", set: []string{impu1, tel1}, pre: []int{0}, to: [2]string{impu1, tel1}, exp: [2]int{900, 600}, want: []int{0, 1, 2}, third: true},
		{name: "A dereg vs B rereg, A's SAR fails", set: []string{impu1, tel1}, pre: []int{0, 1}, to: [2]string{impu1, tel1}, exp: [2]int{0, 900}, anyOrder: true, failDereg: true},
	}
	var report []string
	total := 0
	for _, sc := range scs {
		for _, sweeper := range []int{0, 1} {
			if sc.failDereg && sweeper == 1 {
				continue
			}
			other := 1 - sweeper
			var names []string
			run := func(at int) (steps int, problems []string) {
				e := newEnv(t)
				th := &trackHSS{fakeHSS: e.hss, last: map[string]cx.ServerAssignmentType{}}
				a := e.akaUser(impi1, sc.set...)
				a.instance = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>"
				devs := []*ue{a, device(a, 2), device(a, 3)}
				for i := range sc.to {
					devs[i].impu = sc.to[i]
				}
				plain := func(seed byte) *Registrar { return e.instance(seed, func(c *Config) { c.HSS = th }) }
				for _, i := range sc.pre {
					if res := devs[i].registerWith(plain(9), 600); res.StatusCode != 200 {
						t.Fatalf("pre %d: %d", i, res.StatusCode)
					}
				}
				e.clock.advance(time.Second)
				st := &v3Steps{at: -1}
				ss := &sweepStore{Store: e.store, at: -1}
				// Route the sweepStore's counter through st by wrapping step.
				ss.hook = nil
				vs := &countingStore{Store: e.store, steps: st}
				vh := &v3HSS{trackHSS: th, steps: st, failDereg: sc.failDereg}
				gs := e.instance(3, func(c *Config) { c.Store, c.HSS = vs, vh })
				x, y := devs[sweeper], devs[other]
				act := func(u *ue, i int, g *Registrar, auth string) int {
					if sc.star[i] {
						saved := u.contact
						u.contact = ""
						defer func() { u.contact = saved }()
						return g.Register(bg, u.request(-1, auth, "Contact: *", "Expires: 0"), upstream).StatusCode
					}
					return g.Register(bg, u.request(sc.exp[i], auth), upstream).StatusCode
				}
				full := func(u *ue, i int, g *Registrar) int {
					ch := g.Register(bg, u.request(sc.exp[i], ""), upstream)
					if ch.StatusCode != 401 {
						return ch.StatusCode
					}
					return act(u, i, g, u.answer(ch, 0))
				}
				var codes [2]int
				auth := x.answer(plain(4).Register(bg, x.request(sc.exp[sweeper], ""), upstream), 0)
				st.mu.Lock()
				st.n, st.at = 0, at
				st.hook = func() {
					e.clock.advance(time.Second)
					codes[other] = full(y, other, plain(5))
					if sc.third {
						if c := devs[2].registerWith(plain(6), 600).StatusCode; c != 200 {
							codes[other] = c
						}
					}
				}
				st.mu.Unlock()
				codes[sweeper] = act(x, sweeper, gs, auth)
				st.mu.Lock()
				steps = st.n
				if at < 0 {
					names = slices.Clone(st.names)
				}
				fired := st.hook == nil
				st.mu.Unlock()
				if !fired {
					codes[other] = full(y, other, plain(5))
					if sc.third {
						devs[2].registerWith(plain(6), 600)
					}
				}
				problems = v3Check(t, e, th, sc, devs, codes, sweeper)
				return steps, problems
			}
			n, _ := run(-1)
			bad := 0
			for at := 0; at <= n; at++ {
				total++
				if _, p := run(at); len(p) > 0 {
					bad++
					step := "end"
					if at < len(names) {
						step = names[at]
					}
					report = append(report, fmt.Sprintf("%s | sweep %c, before step %d/%d (%s): %s", sc.name, "AB"[sweeper], at, n, step, strings.Join(p, "; ")))
				}
			}
			t.Logf("%-42s sweep %c: %d steps, %d bad; %v", sc.name, "AB"[sweeper], n, bad, names)
		}
	}
	for _, r := range report {
		t.Log(r)
	}
	t.Logf("%d interleavings, %d broke an invariant", total, len(report))
	if len(report) > 0 {
		t.Fail()
	}
}

type countingStore struct {
	state.Store
	steps *v3Steps
}

func (s *countingStore) Registration(ctx context.Context, k state.SetKey) (*state.Registration, error) {
	s.steps.step("Registration")
	return s.Store.Registration(ctx, k)
}
func (s *countingStore) Identity(ctx context.Context, impu string, now time.Time) (*state.Identity, error) {
	s.steps.step("Identity")
	return s.Store.Identity(ctx, impu, now)
}
func (s *countingStore) KeepIdentity(ctx context.Context, impu string, until, now time.Time) error {
	s.steps.step("KeepIdentity")
	return s.Store.KeepIdentity(ctx, impu, until, now)
}
func (s *countingStore) SaveIdentity(ctx context.Context, i *state.Identity, now time.Time) (*state.Identity, error) {
	s.steps.step("SaveIdentity")
	return s.Store.SaveIdentity(ctx, i, now)
}
func (s *countingStore) DeleteIdentity(ctx context.Context, i *state.Identity) error {
	s.steps.step("DeleteIdentity")
	return s.Store.DeleteIdentity(ctx, i)
}
func (s *countingStore) RegistrationsOf(ctx context.Context, impi string) ([]*state.Registration, error) {
	s.steps.step("RegistrationsOf")
	return s.Store.RegistrationsOf(ctx, impi)
}
func (s *countingStore) SaveRegistration(ctx context.Context, r *state.Registration) (*state.Registration, error) {
	s.steps.step("SaveRegistration")
	return s.Store.SaveRegistration(ctx, r)
}
func (s *countingStore) DeleteRegistration(ctx context.Context, r *state.Registration) error {
	s.steps.step("DeleteRegistration")
	return s.Store.DeleteRegistration(ctx, r)
}
func (s *countingStore) Profile(ctx context.Context, k state.SetKey, now time.Time) (*state.Profile, error) {
	s.steps.step("Profile")
	return s.Store.Profile(ctx, k, now)
}
func (s *countingStore) SaveProfile(ctx context.Context, p *state.Profile) error {
	s.steps.step("SaveProfile")
	return s.Store.SaveProfile(ctx, p)
}
func (s *countingStore) KeepProfile(ctx context.Context, k state.SetKey, until, now time.Time) error {
	s.steps.step("KeepProfile")
	return s.Store.KeepProfile(ctx, k, until, now)
}
func (s *countingStore) DeleteProfile(ctx context.Context, k state.SetKey) error {
	s.steps.step("DeleteProfile")
	return s.Store.DeleteProfile(ctx, k)
}
func (s *countingStore) DeleteProfileIf(ctx context.Context, k state.SetKey, received time.Time) error {
	s.steps.step("DeleteProfileIf")
	return s.Store.DeleteProfileIf(ctx, k, received)
}
func (s *countingStore) TakeChallenge(ctx context.Context, impi, nonce string, now time.Time) (*state.Challenge, error) {
	s.steps.step("TakeChallenge")
	return s.Store.TakeChallenge(ctx, impi, nonce, now)
}

func v3Check(t *testing.T, e *env, th *trackHSS, sc v3Scenario, devs []*ue, codes [2]int, sweeper int) []string {
	var problems []string
	got := bindingsOf(t, e, sc.set...)
	for _, impu := range sc.set {
		if !slices.Equal(got[impu], got[sc.set[0]]) {
			problems = append(problems, fmt.Sprintf("identities differ %v", got))
			break
		}
	}
	var have []string
	for _, u := range got[sc.set[0]] {
		have = append(have, strings.SplitN(u, ";", 2)[0])
	}
	if !sc.anyOrder && codes[0] == 200 && codes[1] == 200 {
		var want []string
		for _, i := range sc.want {
			want = append(want, strings.SplitN(devs[i].contact, ";", 2)[0])
		}
		slices.Sort(want)
		if !slices.Equal(have, want) {
			problems = append(problems, fmt.Sprintf("both 200 but bindings %v, want %v", have, want))
		}
	}
	// A re-registration's new expiry stands: a binding of a device whose
	// action asked 900 s expires at least 901 s after t0.
	for i := 0; i < 2; i++ {
		if sc.exp[i] != 900 || codes[i] != 200 || sc.star[i] {
			continue
		}
		if r, err := regOf(e, sc.set[0]); err == nil {
			for _, c := range r.Contacts {
				if c.CallID == devs[i].callID && c.Expires.Before(t0.Add(901*time.Second)) {
					problems = append(problems, fmt.Sprintf("device %d's re-registration lost: expires %v", i, c.Expires.Sub(t0)))
				}
			}
		}
	}
	// A device that got 200 for a registration has its binding (unless the
	// other device's Contact * or a later dereg removed it: anyOrder).
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
	// Records and identity pointers agree; no lease is left behind.
	recs, err := e.store.RegistrationsOf(bg, impi1)
	if err != nil {
		problems = append(problems, "RegistrationsOf: "+err.Error())
	}
	for _, rec := range recs {
		if len(rec.Contacts) == 0 {
			problems = append(problems, fmt.Sprintf("record %v left without bindings (Deregistering %v, Unregistered %v)", rec.Key.IMPU, !rec.Deregistering.IsZero(), !rec.Unregistered.IsZero()))
		}
		for _, id := range rec.Identities {
			p, err := e.store.Identity(bg, id.IMPU, e.clock.Now())
			if err != nil || p.Set != rec.Key || p.Incarnation != rec.Incarnation {
				problems = append(problems, fmt.Sprintf("identity %s does not point at its record (%v)", id.IMPU, err))
			}
		}
	}
	if len(recs) > 1 {
		problems = append(problems, fmt.Sprintf("%d records for one set", len(recs)))
	}
	for _, impu := range sc.set {
		p, err := e.store.Identity(bg, impu, e.clock.Now())
		if err != nil {
			continue
		}
		rec, err := e.store.Registration(bg, p.Set)
		if err != nil || rec.Incarnation != p.Incarnation {
			problems = append(problems, fmt.Sprintf("identity %s dangles (%v)", impu, err))
		}
	}
	for i, c := range codes {
		want := 200
		if sc.failDereg && i == sweeper {
			continue
		}
		if c != want {
			problems = append(problems, fmt.Sprintf("device %d got %d", i, c))
		}
	}
	return problems
}

// TestAnIdentityTheHSSAddsToTheSetIsPointedAtItsRecord: learned on a
// re-registration that fetched User-Data again (QA's V14 on #196).
func TestAnIdentityTheHSSAddsToTheSetIsPointedAtItsRecord(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	wantStatus(t, u.registerWith(g, 600), 200)
	e.hss.mu.Lock()
	e.hss.subs[impi1].set = []string{impu1, impu2}
	e.hss.mu.Unlock()
	if err := e.store.DeleteProfile(bg, state.SetKey{IMPI: impi1, IMPU: impu1}); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, u.registerWith(g, 600), 200)
	if r, err := regOf(e, impu2); err != nil || len(r.Contacts) != 1 {
		t.Errorf("impu2, added to the set: %+v %v", r, err)
	}
}
