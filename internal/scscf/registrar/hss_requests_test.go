package registrar

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

var set2 = state.ProfileKey{IMPI: impi1, IMPU: impu2}

// twoSets registers impi1's two implicit registration sets, {impu1, tel1}
// and {impu2, impu3}, from two devices.
func twoSets(t *testing.T, e *env, g *Registrar) {
	t.Helper()
	u := e.akaUser(impi1, impu1, tel1)
	wantStatus(t, u.registerWith(g, 600), 200)
	other := e.akaUser(impi2, impu2, impu3)
	// The second set belongs to impi1 too; the fake HSS keys by IMPI.
	e.hss.mu.Lock()
	s := e.hss.subs[impi2]
	delete(e.hss.subs, impi2)
	e.hss.subs[impi1].set = append(e.hss.subs[impi1].set, s.set...)
	e.hss.mu.Unlock()
	other.impi = impi1
	other.callID = "set-2"
	wantStatus(t, other.registerWith(g, 600), 200)
	// The fake HSS answered both with one document; split them as the HSS
	// does, one set per profile.
	for k, ids := range map[state.ProfileKey][]string{set1: {impu1, tel1}, set2: {impu2, impu3}} {
		must(0, e.store.SaveProfile(bg, &state.Profile{Key: k, UserData: userDataOf(impi1, nil, ids...), Received: e.clock.Now(), KeepUntil: t0.Add(25 * time.Hour)}))(t)
		for _, impu := range ids {
			r := must(e.store.Registration(bg, impu))(t)
			r.DefaultIMPU = k.IMPU
			must(e.store.SaveRegistration(bg, r))(t)
		}
	}
}

func wantResult(t *testing.T, got, want cx.Result) {
	t.Helper()
	if got != want {
		t.Fatalf("result %+v, want %+v", got, want)
	}
}

func TestAnRTRForAPrivateIdentityDeregistersEverySet(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	twoSets(t, e, g)
	wantResult(t, g.HandleRTR(bg, &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}), resultSuccess)
	gone(t, e, impu1, tel1, impu2, impu3)
	for _, k := range []state.ProfileKey{set1, set2} {
		if _, err := e.store.Profile(bg, k, e.clock.Now()); err == nil {
			t.Errorf("the profile of %s is still stored", k.IMPU)
		}
	}
}

func TestAnRTRNamingAnIdentityDeregistersOnlyItsSet(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	twoSets(t, e, g)
	wantResult(t, g.HandleRTR(bg, &cx.RTR{UserName: impi1, PublicIdentities: []string{tel1}}), resultSuccess)
	gone(t, e, impu1, tel1)
	for _, impu := range []string{impu2, impu3} {
		must(e.store.Registration(bg, impu))(t)
	}
	must(e.store.Profile(bg, set2, e.clock.Now()))(t)
	if _, err := e.store.Profile(bg, set1, e.clock.Now()); err == nil {
		t.Error("the deregistered set's profile is still stored")
	}
}

func TestAServerChangeLeavesNoProfileUnderTheOldDefaultIdentity(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := registered(t, e, g, 600, impu1, tel1)
	// The HSS changed the set's default identity and moves the user.
	wantResult(t, g.HandleRTR(bg, &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.ServerChange}}), resultSuccess)
	if _, err := e.store.Profile(bg, set1, e.clock.Now()); err == nil {
		t.Fatal("the profile under the registration's key outlived the RTR")
	}
	e.hss.mu.Lock()
	e.hss.subs[impi1].set = []string{tel1, impu1}
	e.hss.mu.Unlock()
	wantStatus(t, u.registerWith(g, 600), 200)
	must(e.store.Profile(bg, state.ProfileKey{IMPI: impi1, IMPU: tel1}, e.clock.Now()))(t)
	if _, err := e.store.Profile(bg, set1, e.clock.Now()); err == nil {
		t.Error("a profile under the old default identity came back")
	}
}

func TestAnRTRRemovesUnregisteredUsersRecordsToo(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	must(e.store.SaveRegistration(bg, &state.Registration{IMPU: impu1, IMPI: impi1, DefaultIMPU: impu1, Unregistered: t0.Add(time.Hour)}))(t)
	must(0, e.store.SaveProfile(bg, &state.Profile{Key: set1, UserData: userDataOf(impi1, nil, impu1), Received: t0, KeepUntil: t0.Add(25 * time.Hour)}))(t)
	wantResult(t, g.HandleRTR(bg, &cx.RTR{UserName: impi1}), resultSuccess)
	gone(t, e, impu1)
	if _, err := e.store.Profile(bg, set1, t0); err == nil {
		t.Error("the profile is still stored")
	}
}

// changingStore saves the registration again, as a REGISTER on another
// instance would, just before the first delete.
type changingStore struct {
	*state.Memory
	once   sync.Once
	change func()
}

func (c *changingStore) DeleteRegistration(ctx context.Context, r *state.Registration) error {
	c.once.Do(c.change)
	return c.Memory.DeleteRegistration(ctx, r)
}

func TestAnRTRDeletesARegistrationThatChangedSinceItWasListed(t *testing.T) {
	e := newEnv(t)
	registered(t, e, e.instance(1), 600, impu1)
	cs := &changingStore{Memory: e.store}
	cs.change = func() {
		r := must(e.store.Registration(bg, impu1))(t)
		r.Contacts[0].Expires = r.Contacts[0].Expires.Add(time.Minute)
		must(e.store.SaveRegistration(bg, r))(t)
	}
	g := e.instance(2, func(c *Config) { c.Store = cs })
	wantResult(t, g.HandleRTR(bg, &cx.RTR{UserName: impi1}), resultSuccess)
	gone(t, e, impu1)
}

func TestAPPRReplacesOnlyItsOwnSetsProfile(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	twoSets(t, e, g)
	before := must(e.store.Profile(bg, set1, e.clock.Now()))(t)
	e.clock.advance(time.Minute)
	data := userDataOf(impi1, map[string]bool{impu3: true}, impu2, impu3)
	wantResult(t, g.HandlePPR(bg, &cx.PPR{UserName: impi1, UserData: data}), resultSuccess)
	p := must(e.store.Profile(bg, set2, e.clock.Now()))(t)
	if string(p.UserData) != string(data) || !p.Received.Equal(e.clock.Now()) {
		t.Errorf("set 2 not replaced: received %v", p.Received)
	}
	// KeepUntil follows the set's bindings, not the old profile's.
	if want := t0.Add(600*time.Second + state.ProfileGrace); !p.KeepUntil.Equal(want) {
		t.Errorf("KeepUntil %v, want %v", p.KeepUntil, want)
	}
	if after := must(e.store.Profile(bg, set1, e.clock.Now()))(t); string(after.UserData) != string(before.UserData) {
		t.Error("a PPR for set 2 changed set 1")
	}
}

func TestPPRsThisSCSCFCannotTakeAreRefusedAsTheHSSExpects(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	registered(t, e, g, 600, impu1)
	for name, tc := range map[string]struct {
		ppr  *cx.PPR
		want cx.Result
	}{
		"a user not served here":    {&cx.PPR{UserName: impi2, UserData: userDataOf(impi2, nil, impu2)}, cx.ExperimentalResult(cx.ErrorUserUnknown)},
		"a set not served here":     {&cx.PPR{UserName: impi1, UserData: userDataOf(impi1, nil, impu2)}, cx.ExperimentalResult(cx.ErrorUserUnknown)},
		"User-Data it cannot read":  {&cx.PPR{UserName: impi1, UserData: []byte("<IMSSubscription>")}, cx.ExperimentalResult(cx.ErrorNotSupportedUserData)},
		"charging information only": {&cx.PPR{UserName: impi1, ChargingInformation: &cx.ChargingInformation{}}, resultSuccess},
	} {
		if got := g.HandlePPR(bg, tc.ppr); got != tc.want {
			t.Errorf("%s: %+v, want %+v", name, got, tc.want)
		}
	}
}

func TestAPPRThatChangesTheSetMovesItsRegistrations(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	registered(t, e, g, 600, impu1, tel1)
	// impu1 leaves the set, impu3 joins it, and tel1 becomes the default.
	wantResult(t, g.HandlePPR(bg, &cx.PPR{UserName: impi1, UserData: userDataOf(impi1, nil, tel1, impu3)}), resultSuccess)
	gone(t, e, impu1)
	telKey := state.ProfileKey{IMPI: impi1, IMPU: tel1}
	for _, impu := range []string{tel1, impu3} {
		r := must(e.store.Registration(bg, impu))(t)
		if r.ProfileKey() != telKey || len(r.Contacts) != 1 {
			t.Errorf("%s: %+v", impu, r)
		}
	}
	must(e.store.Profile(bg, telKey, e.clock.Now()))(t)
	if _, err := e.store.Profile(bg, set1, e.clock.Now()); err == nil {
		t.Error("the profile under the former default identity is still stored")
	}
}
