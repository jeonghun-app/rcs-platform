package registrar

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// lostStore applies the n-th write and then reports it lost to another
// writer (ErrConflict), as the SDK's resend of a committed conditional write
// does.
type lostStore struct {
	state.Store
	mu    sync.Mutex
	n, at int
	names []string
}

func (s *lostStore) lose(what string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.n
	s.n++
	s.names = append(s.names, what)
	return k == s.at
}

func (s *lostStore) SaveRegistration(ctx context.Context, r *state.Registration) (*state.Registration, error) {
	out, err := s.Store.SaveRegistration(ctx, r)
	if err == nil && s.lose("SaveRegistration") {
		return nil, fmt.Errorf("lost: %w", state.ErrConflict)
	}
	return out, err
}
func (s *lostStore) DeleteRegistration(ctx context.Context, r *state.Registration) error {
	err := s.Store.DeleteRegistration(ctx, r)
	if err == nil && s.lose("DeleteRegistration") {
		return fmt.Errorf("lost: %w", state.ErrConflict)
	}
	return err
}
func (s *lostStore) SaveIdentity(ctx context.Context, i *state.Identity) (*state.Identity, error) {
	out, err := s.Store.SaveIdentity(ctx, i)
	if err == nil && s.lose("SaveIdentity") {
		return nil, fmt.Errorf("lost: %w", state.ErrConflict)
	}
	return out, err
}
func (s *lostStore) DeleteIdentity(ctx context.Context, i *state.Identity) error {
	err := s.Store.DeleteIdentity(ctx, i)
	if err == nil && s.lose("DeleteIdentity") {
		return fmt.Errorf("lost: %w", state.ErrConflict)
	}
	return err
}
func (s *lostStore) DeleteProfileIf(ctx context.Context, k state.SetKey, received time.Time) error {
	err := s.Store.DeleteProfileIf(ctx, k, received)
	if err == nil && s.lose("DeleteProfileIf") {
		return fmt.Errorf("lost: %w", state.ErrConflict)
	}
	return err
}

// TestARegisterWhoseWriteIsAppliedButReportedLostStillEndsConsistent: each
// write of an initial registration, a re-registration and a deregistration in
// turn is applied and then reported as a conflict, as the SDK's resend of a
// committed conditional write is; the same invariants as the interleavings
// must hold, and above all no 200 to a deregistration the HSS was not told
// of. From QA's third check of #196.
func TestARegisterWhoseWriteIsAppliedButReportedLostStillEndsConsistent(t *testing.T) {
	type sc struct {
		name string
		pre  bool
		exp  int
	}
	var report []string
	total := 0
	for _, c := range []sc{{"initial", false, 600}, {"rereg", true, 900}, {"dereg", true, 0}} {
		run := func(at int) (int, []string, []string) {
			e := newEnv(t)
			th := &trackHSS{fakeHSS: e.hss, last: map[string]cx.ServerAssignmentType{}}
			a := e.akaUser(impi1, impu1, tel1)
			a.instance = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>"
			plain := e.instance(9, func(cf *Config) { cf.HSS = th })
			if c.pre {
				wantStatus(t, a.registerWith(plain, 600), 200)
			}
			e.clock.advance(time.Second)
			ls := &lostStore{Store: e.store, at: at}
			g := e.instance(3, func(cf *Config) { cf.Store, cf.HSS = ls, th })
			code := a.registerWith(g, c.exp).StatusCode
			devs := []*ue{a, a}
			want := []int{0}
			if c.exp == 0 {
				want = nil
			}
			p := v3Check(t, e, th, v3Scenario{set: []string{impu1, tel1}, want: want}, devs, [2]int{code, 200}, 1)
			return ls.n, p, ls.names
		}
		n, _, names := run(-1)
		for at := 0; at < n; at++ {
			total++
			if _, p, _ := run(at); len(p) > 0 {
				report = append(report, fmt.Sprintf("%s | lost ack of write %d/%d (%s): %s", c.name, at, n, names[at], strings.Join(p, "; ")))
			}
		}
		t.Logf("%s: writes %v", c.name, names)
	}
	for _, r := range report {
		t.Log(r)
	}
	t.Logf("%d lost acks, %d broke an invariant", total, len(report))
	if len(report) > 0 {
		t.Fail()
	}
}
