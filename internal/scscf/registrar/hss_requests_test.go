package registrar

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

func wantResult(t *testing.T, got, want cx.Result) {
	t.Helper()
	if got != want {
		t.Fatalf("result %+v, want %+v", got, want)
	}
}

func TestAnRTRForAPrivateIdentityDeregistersEverySet(t *testing.T) {
	e := newEnv(t)
	m := &counts{}
	g := e.instance(1, func(c *Config) { c.Metrics = m })
	twoSets(t, e, g)
	wantResult(t, g.HandleRTR(bg, &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}), resultSuccess)
	gone(t, e, impu1, tel1, impu2, impu3)
	for _, k := range []state.SetKey{set1, set2} {
		if _, err := e.store.Profile(bg, k, e.clock.Now()); err == nil {
			t.Errorf("the profile of %s is still stored", k.IMPU)
		}
	}
	if got := m.get("registrar.rtr_deregistered"); got != 2 {
		t.Errorf("rtr_deregistered = %d", got)
	}
}

func TestAnRTRNamingAnIdentityDeregistersOnlyItsSet(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	twoSets(t, e, g)
	wantResult(t, g.HandleRTR(bg, &cx.RTR{UserName: impi1, PublicIdentities: []string{tel1}}), resultSuccess)
	gone(t, e, impu1, tel1)
	for _, impu := range []string{impu2, impu3} {
		must(regOf(e, impu))(t)
	}
	must(e.store.Profile(bg, set2, e.clock.Now()))(t)
	if _, err := e.store.Profile(bg, set1, e.clock.Now()); err == nil {
		t.Error("the deregistered set's profile is still stored")
	}
}

func TestAnRTRAlsoEndsItsAssociatedIdentities(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	wantStatus(t, e.akaUser(impi1, impu1).registerWith(g, 600), 200)
	wantStatus(t, e.akaUser(impi2, impu2).registerWith(g, 600), 200)
	// TS 29.228 §6.1.3.1: the RTR ends the registrations of the private
	// identities associated with UserName too.
	wantResult(t, g.HandleRTR(bg, &cx.RTR{UserName: impi1, AssociatedIdentities: []string{impi2}}), resultSuccess)
	gone(t, e, impu1, impu2)
}

func TestAServerChangeLeavesNoProfileUnderTheOldDefaultIdentity(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := registered(t, e, g, 600, impu1, tel1)
	// The HSS changed the set's default identity and moves the user.
	wantResult(t, g.HandleRTR(bg, &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.ServerChange}}), resultSuccess)
	if _, err := e.store.Profile(bg, set1, e.clock.Now()); err == nil {
		t.Fatal("the profile under the record's key outlived the RTR")
	}
	e.hss.mu.Lock()
	e.hss.subs[impi1].set = []string{tel1, impu1}
	e.hss.mu.Unlock()
	wantStatus(t, u.registerWith(g, 600), 200)
	must(e.store.Profile(bg, state.SetKey{IMPI: impi1, IMPU: tel1}, e.clock.Now()))(t)
	if _, err := e.store.Profile(bg, set1, e.clock.Now()); err == nil {
		t.Error("a profile under the old default identity came back")
	}
	if r := must(regOf(e, impu1))(t); r.Key.IMPU != tel1 {
		t.Errorf("impu1 names %+v", r.Key)
	}
}

func TestRemoveSCSCFEndsOnlyUnregisteredUsersRecords(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	twoSets(t, e, g)
	// Set 1 becomes an unregistered user's record.
	r := must(regOf(e, impu1))(t)
	r.Contacts, r.Unregistered = nil, t0.Add(time.Hour)
	must(e.store.SaveRegistration(bg, r))(t)
	wantResult(t, g.HandleRTR(bg, &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.RemoveSCSCF}}), resultSuccess)
	gone(t, e, impu1, tel1)
	for _, impu := range []string{impu2, impu3} {
		must(regOf(e, impu))(t)
	}
}

func TestAnRTRRemovesUnregisteredUsersRecordsToo(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	seed(t, e, impi1, []string{impu1}, func(r *state.Registration) { r.Unregistered = t0.Add(time.Hour) })
	must(0, e.store.SaveProfile(bg, &state.Profile{Key: set1, UserData: userDataOf(impi1, nil, impu1), Received: t0, KeepUntil: t0.Add(25 * time.Hour)}))(t)
	wantResult(t, g.HandleRTR(bg, &cx.RTR{UserName: impi1}), resultSuccess)
	gone(t, e, impu1)
	if _, err := e.store.Profile(bg, set1, t0); err == nil {
		t.Error("the profile is still stored")
	}
}

// changingStore runs change once, just before the first delete of a set.
type changingStore struct {
	*state.Memory
	once   sync.Once
	change func()
}

func (c *changingStore) DeleteRegistration(ctx context.Context, r *state.Registration) error {
	c.once.Do(c.change)
	return c.Memory.DeleteRegistration(ctx, r)
}

func TestAnRTRDeletesASetThatChangedSinceItWasRead(t *testing.T) {
	e := newEnv(t)
	registered(t, e, e.instance(1), 600, impu1)
	cs := &changingStore{Memory: e.store}
	cs.change = func() {
		// Read by its key: the RTR has deleted the identities already.
		r := must(e.store.Registration(bg, set1))(t)
		r.Contacts[0].Expires = r.Contacts[0].Expires.Add(time.Minute)
		must(e.store.SaveRegistration(bg, r))(t)
	}
	g := e.instance(2, func(c *Config) { c.Store = cs })
	wantResult(t, g.HandleRTR(bg, &cx.RTR{UserName: impi1}), resultSuccess)
	gone(t, e, impu1)
}

func TestAnRTRForASetAlreadyGoneSucceeds(t *testing.T) {
	e := newEnv(t)
	registered(t, e, e.instance(1), 600, impu1)
	cs := &changingStore{Memory: e.store}
	cs.change = func() {
		// A sweep or a REGISTER ended it between the RTR's read and delete.
		must(0, e.store.DeleteRegistration(bg, must(e.store.Registration(bg, set1))(t)))(t)
	}
	wantResult(t, e.instance(2, func(c *Config) { c.Store = cs }).HandleRTR(bg, &cx.RTR{UserName: impi1}), resultSuccess)
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
	if after := must(e.store.Profile(bg, set1, e.clock.Now()))(t); string(after.UserData) != string(before.UserData) {
		t.Error("a PPR for set 2 changed set 1")
	}
	if !must(regOf(e, impu3))(t).Identities[1].Barred {
		t.Error("the set does not record impu3 as barred")
	}
}

func TestAnOlderPPRThanTheStoredProfileChangesNothing(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	registered(t, e, g, 600, impu1)
	// An SAA received after the PPR stored a newer profile first.
	newer := &state.Profile{Key: set1, UserData: userDataOf(impi1, nil, impu1), Received: t0.Add(time.Hour), KeepUntil: t0.Add(48 * time.Hour)}
	must(0, e.store.SaveProfile(bg, newer))(t)
	wantResult(t, g.HandlePPR(bg, &cx.PPR{UserName: impi1, UserData: userDataOf(impi1, map[string]bool{impu1: false}, impu1)}), resultSuccess)
	if p := must(e.store.Profile(bg, set1, t0))(t); !p.Received.Equal(newer.Received) {
		t.Errorf("profile received %v, want the newer one's", p.Received)
	}
}

func TestPPRsThisSCSCFCannotTakeAreRefusedAsTheHSSExpects(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	registered(t, e, g, 600, impu1)
	m := &counts{}
	g = e.instance(2, func(c *Config) { c.Metrics = m })
	for name, tc := range map[string]struct {
		ppr  *cx.PPR
		want cx.Result
	}{
		"a user not served here":                          {&cx.PPR{UserName: impi2, UserData: userDataOf(impi2, nil, impu2)}, cx.ExperimentalResult(cx.ErrorUserUnknown)},
		"a set not served here of a user who has another": {&cx.PPR{UserName: impi1, UserData: userDataOf(impi1, nil, impu2)}, resultUnableToComply},
		"User-Data it cannot read":                        {&cx.PPR{UserName: impi1, UserData: []byte("<IMSSubscription>")}, cx.ExperimentalResult(cx.ErrorNotSupportedUserData)},
		"more User-Data than it keeps":                    {&cx.PPR{UserName: impi1, UserData: make([]byte, state.MaxUserData+1)}, cx.ExperimentalResult(cx.ErrorTooMuchData)},
		"charging information only":                       {&cx.PPR{UserName: impi1, ChargingInformation: &cx.ChargingInformation{}}, resultSuccess},
	} {
		if got := g.HandlePPR(bg, tc.ppr); got != tc.want {
			t.Errorf("%s: %+v, want %+v", name, got, tc.want)
		}
	}
	if m.get("registrar.ppr_unknown") != 1 || m.get("registrar.ppr_refused") != 2 {
		t.Errorf("metrics %v", m.m)
	}
}

func TestAPPRDuringADeregistrationLeaseIsUserUnknown(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	registered(t, e, g, 600, impu1)
	r := must(regOf(e, impu1))(t)
	r.Contacts, r.Deregistering = nil, t0.Add(state.SweepLease)
	must(e.store.SaveRegistration(bg, r))(t)
	wantResult(t, g.HandlePPR(bg, &cx.PPR{UserName: impi1, UserData: userDataOf(impi1, nil, impu1)}), cx.ExperimentalResult(cx.ErrorUserUnknown))
}

func TestAPPRForAnUnregisteredUsersRecordKeepsItUnregistered(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	end := t0.Add(time.Hour)
	seed(t, e, impi1, []string{impu1}, func(r *state.Registration) { r.Unregistered = end })
	must(0, e.store.SaveProfile(bg, &state.Profile{Key: set1, UserData: userDataOf(impi1, nil, impu1), Received: t0, KeepUntil: end.Add(state.ProfileGrace)}))(t)
	e.clock.advance(time.Minute)
	data := userDataOf(impi1, nil, impu1, tel1)
	wantResult(t, g.HandlePPR(bg, &cx.PPR{UserName: impi1, UserData: data}), resultSuccess)
	p := must(e.store.Profile(bg, set1, e.clock.Now()))(t)
	if string(p.UserData) != string(data) || !p.KeepUntil.Equal(end.Add(state.ProfileGrace)) {
		t.Errorf("profile kept until %v", p.KeepUntil)
	}
	r := must(regOf(e, tel1))(t)
	if !r.Unregistered.Equal(end) || len(r.Contacts) != 0 || r.Key != set1 {
		t.Errorf("the added identity names %+v", r)
	}
}

func TestAPPRThatChangesTheSetMovesItsIdentities(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	registered(t, e, g, 600, impu1, tel1)
	// tel1 leaves the set, impu3 joins it; the default stays.
	wantResult(t, g.HandlePPR(bg, &cx.PPR{UserName: impi1, UserData: userDataOf(impi1, nil, impu1, impu3)}), resultSuccess)
	gone(t, e, tel1)
	for _, impu := range []string{impu1, impu3} {
		if r := must(regOf(e, impu))(t); r.Key != set1 || len(r.Contacts) != 1 {
			t.Errorf("%s: %+v", impu, r)
		}
	}
	must(e.store.Profile(bg, set1, e.clock.Now()))(t)
}

func TestAnIdentityMovingBetweenTwoSetsEndsInTheNewOneWhicheverPPRComesFirst(t *testing.T) {
	for _, newFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "the new set's PPR first", false: "the old set's PPR first"}[newFirst], func(t *testing.T) {
			e := newEnv(t)
			g := e.instance(1)
			twoSets(t, e, g)
			// impu3 moves from set 2 {impu2, impu3} to set 1 {impu1, tel1}.
			toNew := &cx.PPR{UserName: impi1, UserData: userDataOf(impi1, nil, impu1, tel1, impu3)}
			fromOld := &cx.PPR{UserName: impi1, UserData: userDataOf(impi1, nil, impu2)}
			first, second := toNew, fromOld
			if !newFirst {
				first, second = fromOld, toNew
			}
			wantResult(t, g.HandlePPR(bg, first), resultSuccess)
			wantResult(t, g.HandlePPR(bg, second), resultSuccess)
			if r := must(regOf(e, impu3))(t); r.Key != set1 {
				t.Errorf("impu3 names %+v, want set 1", r.Key)
			}
			for _, impu := range []string{impu1, tel1, impu2} {
				must(regOf(e, impu))(t)
			}
			if r := must(regOf(e, impu2))(t); len(r.Identities) != 1 {
				t.Errorf("set 2 lists %+v", r.Identities)
			}
		})
	}
}

func TestAPPRForAnExpiredSetOfAUserWithAnotherLiveIsNotUserUnknown(t *testing.T) {
	// From the #210 re-review: set 2 has expired but no sweep has run; 5001
	// would make the HSS mark the whole user not registered while set 1
	// lives.
	e := newEnv(t)
	g := e.instance(1)
	u, _ := twoSets(t, e, g)
	e.clock.advance(5 * time.Minute)
	wantStatus(t, u.registerWith(g, 600), 200)
	e.clock.advance(6 * time.Minute)
	if live(must(regOf(e, impu2))(t), e.clock.Now()) {
		t.Fatal("set 2 should have expired")
	}
	wantResult(t, g.HandlePPR(bg, &cx.PPR{UserName: impi1, UserData: userDataOf(impi1, nil, impu2, impu3)}), resultUnableToComply)
}

// TestAnRTRLeavesNoIdentityOfTheSetsItEnds: the identity items go with
// their set, before its record (QA's H5 on #210).
func TestAnRTRLeavesNoIdentityOfTheSetsItEnds(t *testing.T) {
	for name, rtr := range map[string]*cx.RTR{
		"private identity": {UserName: impi1},
		"named identity":   {UserName: impi1, PublicIdentities: []string{tel1}},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			twoSets(t, e, e.instance(1))
			wantResult(t, e.instance(2).HandleRTR(bg, rtr), resultSuccess)
			for _, impu := range []string{impu1, tel1} {
				if id, err := e.store.Identity(bg, impu, e.clock.Now()); err == nil {
					t.Errorf("%s still names %v", impu, id.Set)
				}
			}
			if _, err := e.store.Registration(bg, set1); err == nil {
				t.Error("set 1's record is still stored")
			}
		})
	}
}

// TestAnRTRNamingAnotherUsersIdentityEndsNothing: an RTR ends the sets of its
// User-Name and Associated-Identities only; a public identity of another
// private identity it names is left alone (QA's H2 on #210).
func TestAnRTRNamingAnotherUsersIdentityEndsNothing(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	registered(t, e, g, 600, impu1)
	wantResult(t, g.HandleRTR(bg, &cx.RTR{UserName: impi2, PublicIdentities: []string{impu1}}), resultSuccess)
	must(regOf(e, impu1))(t)
	must(e.store.Profile(bg, set1, e.clock.Now()))(t)
}

// TestAPPRDuringOneSetsLeaseSparesTheUsersOtherSet: 5001 would make the HSS
// mark every identity of the user not registered (TS 29.228 §6.2.2.1),
// set 2's too, which is live here (QA's finding 1 on #210).
func TestAPPRDuringOneSetsLeaseSparesTheUsersOtherSet(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	twoSets(t, e, g)
	r := must(e.store.Registration(bg, set1))(t)
	r.Contacts, r.Deregistering = nil, t0.Add(state.SweepLease)
	must(e.store.SaveRegistration(bg, r))(t)
	wantResult(t, g.HandlePPR(bg, &cx.PPR{UserName: impi1, UserData: userDataOf(impi1, nil, impu1, tel1)}), resultUnableToComply)
}

// raceStore runs race once, just before the PPR saves the set's record.
type raceStore struct {
	state.Store
	once sync.Once
	race func()
}

func (r *raceStore) SaveRegistration(ctx context.Context, reg *state.Registration) (*state.Registration, error) {
	if len(reg.Identities) == 2 {
		r.once.Do(r.race)
	}
	return r.Store.SaveRegistration(ctx, reg)
}

// TestAPPRRetriesWhenAReRegisterSavedTheSetFirst: the PPR's save of the set
// loses to a re-REGISTER that read the old profile; it reads the set again
// and applies itself to what the REGISTER left (QA's H10 on #210).
func TestAPPRRetriesWhenAReRegisterSavedTheSetFirst(t *testing.T) {
	e := newEnv(t)
	registered(t, e, e.instance(1), 600, impu1)
	rs := &raceStore{Store: e.store}
	rs.race = func() {
		r := must(e.store.Registration(bg, set1))(t)
		r.Contacts[0].Expires = r.Contacts[0].Expires.Add(time.Minute)
		must(e.store.SaveRegistration(bg, r))(t)
	}
	g := e.instance(2, func(c *Config) { c.Store = rs })
	wantResult(t, g.HandlePPR(bg, &cx.PPR{UserName: impi1, UserData: userDataOf(impi1, nil, impu1, impu3)}), resultSuccess)
	if r := must(regOf(e, impu3))(t); r.Key != set1 || !r.Contacts[0].Expires.Equal(t0.Add(660*time.Second)) {
		t.Errorf("after the race: %+v", r)
	}
}

// TestARemoveSCSCFThatARegisterOvertakesLeavesTheSetPointedAt: REMOVE_SCSCF
// ends only unregistered users' records. One that a REGISTER turns into a
// registration after the RTR deleted its identities, and before it deleted
// the record, is a registration the RTR leaves, so its identities are
// pointed at it again.
func TestARemoveSCSCFThatARegisterOvertakesLeavesTheSetPointedAt(t *testing.T) {
	e := newEnv(t)
	seed(t, e, impi1, []string{impu1, tel1}, func(r *state.Registration) { r.Unregistered = t0.Add(time.Hour) })
	cs := &changingStore{Memory: e.store}
	cs.change = func() {
		// The REGISTER pointed the identities before the RTR deleted them.
		r := must(e.store.Registration(bg, set1))(t)
		r.Unregistered = time.Time{}
		r.Contacts = []state.Contact{{URI: "sip:ue1@192.0.2.10:5060;transport=tcp", CallID: "c", CSeq: 1, Expires: t0.Add(time.Hour)}}
		must(e.store.SaveRegistration(bg, r))(t)
	}
	g := e.instance(1, func(c *Config) { c.Store = cs })
	wantResult(t, g.HandleRTR(bg, &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.RemoveSCSCF}}), resultSuccess)
	wantSameBindings(t, e, 1, impu1, tel1)
}

// idHookStore runs hook once, after the first identity delete.
type idHookStore struct {
	state.Store
	once sync.Once
	hook func()
}

func (s *idHookStore) DeleteIdentity(ctx context.Context, id *state.Identity) error {
	err := s.Store.DeleteIdentity(ctx, id)
	s.once.Do(s.hook)
	return err
}

// TestARemoveSCSCFThatARegisterOvertakesKeepsTheRegistersProfile: the RTR
// deletes only the profile it read (DeleteProfileIf); a REGISTER that stored
// its own after the RTR's read, and turned the record into a registration,
// keeps it (QA's finding 2 on #210).
func TestARemoveSCSCFThatARegisterOvertakesKeepsTheRegistersProfile(t *testing.T) {
	e := newEnv(t)
	seed(t, e, impi1, []string{impu1, tel1}, func(r *state.Registration) { r.Unregistered = t0.Add(time.Hour) })
	must(0, e.store.SaveProfile(bg, &state.Profile{Key: set1, UserData: userDataOf(impi1, nil, impu1, tel1), Received: t0, KeepUntil: t0.Add(25 * time.Hour)}))(t)
	e.clock.advance(time.Second)
	hs := &idHookStore{Store: e.store}
	hs.hook = func() {
		// A REGISTER stores its SAA's profile and turns the record into a
		// registration.
		must(0, e.store.SaveProfile(bg, &state.Profile{Key: set1, UserData: userDataOf(impi1, nil, impu1, tel1), Received: e.clock.Now(), KeepUntil: t0.Add(26 * time.Hour)}))(t)
		r := must(e.store.Registration(bg, set1))(t)
		r.Unregistered = time.Time{}
		r.Contacts = []state.Contact{{URI: "sip:ue1@192.0.2.10:5060;transport=tcp", CallID: "c", CSeq: 1, Expires: t0.Add(time.Hour)}}
		must(e.store.SaveRegistration(bg, r))(t)
	}
	g := e.instance(1, func(c *Config) { c.Store = hs })
	wantResult(t, g.HandleRTR(bg, &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.RemoveSCSCF}}), resultSuccess)
	wantSameBindings(t, e, 1, impu1, tel1)
	if _, err := e.store.Profile(bg, set1, e.clock.Now()); err != nil {
		t.Errorf("the registered set lost its profile: %v", err)
	}
}
