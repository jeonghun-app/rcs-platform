package registrar

import (
	"slices"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// grownProfile is the User-Data of impi1's set {impu1, tel1} with impu3
// added: a profile the HSS changed while a push to this S-CSCF was lost
// (#524), which it sends on the next SAA.
func grownProfile() []byte { return userDataOf(impi1, nil, impu1, tel1, impu3) }

func hasID(r *state.Registration, impu string) bool {
	return slices.ContainsFunc(r.Identities, func(id state.SetIdentity) bool { return id.IMPU == impu })
}

// wantRoutable fails the test unless impu's item names set's record and
// the record lists impu, so that a terminating request to impu finds it.
func wantRoutable(t *testing.T, e *env, impu string, set state.SetKey) {
	t.Helper()
	r, err := regOf(e, impu)
	if err != nil || r.Key != set {
		t.Fatalf("%s: record %+v, %v; want the set %v", impu, r, err, set)
	}
	if !hasID(r, impu) {
		t.Errorf("%s is not among the set's identities %+v", impu, r.Identities)
	}
	if p, err := e.store.Profile(bg, set, e.clock.Now()); err != nil || string(p.UserData) != string(grownProfile()) {
		t.Errorf("the stored profile is not the SAA's: %v", err)
	}
}

// TestAReassertsSAAProfileIsApplied (#536): the sweep's SAR that tells the
// HSS again that this S-CSCF serves the set gets a changed profile back,
// and the identity it added becomes routable.
func TestAReassertsSAAProfileIsApplied(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	reassertDue(t, e, g)
	e.hss.sarHook = func(r *cx.SAR) (*cx.SAA, error) {
		if r.AssignmentType != cx.Registration || r.UserDataAlreadyAvailable != cx.UserDataAlreadyAvailable {
			return nil, nil
		}
		return &cx.SAA{Answer: cx.Answer{Result: cx.ResultCode(2001)}, UserData: grownProfile()}, nil
	}
	if n, err := g.Sweep(bg, 10); n != 1 || err != nil {
		t.Fatalf("swept %d, %v", n, err)
	}
	wantRoutable(t, e, impu3, set1)
}

// TestAReassignsSAAProfileIsApplied (#536): the SAR that gives the set
// back to the HSS after a deregistration a REGISTER overtook gets a changed
// profile back, and the identity it added becomes routable.
func TestAReassignsSAAProfileIsApplied(t *testing.T) {
	e := newEnv(t)
	a := e.akaUser(impi1, impu1, tel1)
	a.instance = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>"
	wantStatus(t, a.registerWith(e.instance(1), 600), 200)
	b := device(a, 2)
	ch := &crossingHSS{HSS: e.hss, kind: cx.UserDeregistration}
	ch.hook = func() { wantStatus(t, b.registerWith(e.instance(2), 600), 200) }
	reassigned := false
	e.hss.sarHook = func(r *cx.SAR) (*cx.SAA, error) {
		if r.AssignmentType != cx.Registration || r.UserDataAlreadyAvailable != cx.UserDataAlreadyAvailable {
			return nil, nil
		}
		// Only the reassign: B's own SAR asked for the User-Data.
		reassigned = true
		return &cx.SAA{Answer: cx.Answer{Result: cx.ResultCode(2001)}, UserData: grownProfile()}, nil
	}
	g := e.instance(3, func(c *Config) { c.HSS = ch })
	auth := a.answer(g.Register(bg, a.request(0, ""), upstream), 0)
	wantStatus(t, g.Register(bg, a.request(0, auth), upstream), 200)
	if !reassigned {
		t.Fatal("no reassign: the test tested nothing")
	}
	wantRoutable(t, e, impu3, set1)
}

// TestARegisteredSetsUnregisteredUserSAAProfileIsApplied (#536): a
// terminating request to an identity of a registered set whose item was
// missing asks the HSS (SAR UNREGISTERED_USER), whose answer carries a
// changed profile; the identity it added becomes routable.
func TestARegisteredSetsUnregisteredUserSAAProfileIsApplied(t *testing.T) {
	e := newEnv(t)
	e.akaUser(impi1, impu1, tel1)
	live := seed(t, e, impi1, []string{impu1, tel1}, func(r *state.Registration) {
		r.Contacts = []state.Contact{{URI: "sip:ue1@192.0.2.10:5060", Expires: t0.Add(time.Hour), CallID: "c", CSeq: 1}}
	})
	id := must(e.store.Identity(bg, tel1, t0))(t)
	if err := e.store.DeleteIdentity(bg, id); err != nil {
		t.Fatal(err)
	}
	e.hss.sarHook = func(r *cx.SAR) (*cx.SAA, error) {
		if r.AssignmentType != cx.UnregisteredUser {
			return nil, nil
		}
		return &cx.SAA{Answer: cx.Answer{Result: cx.ResultCode(2001)}, UserName: impi1, UserData: grownProfile()}, nil
	}
	rec := must(e.instance(1).Unregistered(bg, tel1))(t)
	if rec.Key != live.Key || !hasID(rec, impu3) {
		t.Errorf("Unregistered returned %+v, want the set with impu3", rec)
	}
	wantRoutable(t, e, impu3, live.Key)
}

// TestAnUnregisteredUsersRecordTakesTheSAAProfile (#536): the same for an
// unregistered user's record found after the SAR.
func TestAnUnregisteredUsersRecordTakesTheSAAProfile(t *testing.T) {
	e := newEnv(t)
	e.akaUser(impi1, impu1, tel1)
	g := e.instance(1)
	first := must(g.Unregistered(bg, impu1))(t)
	id := must(e.store.Identity(bg, tel1, e.clock.Now()))(t)
	if err := e.store.DeleteIdentity(bg, id); err != nil {
		t.Fatal(err)
	}
	e.clock.advance(time.Second)
	e.hss.sarHook = func(r *cx.SAR) (*cx.SAA, error) {
		if r.AssignmentType != cx.UnregisteredUser {
			return nil, nil
		}
		return &cx.SAA{Answer: cx.Answer{Result: cx.ResultCode(2001)}, UserName: impi1, UserData: grownProfile()}, nil
	}
	rec := must(g.Unregistered(bg, tel1))(t)
	if rec.Key != first.Key || rec.Unregistered.IsZero() || !hasID(rec, impu3) {
		t.Errorf("Unregistered returned %+v, want the unregistered record with impu3", rec)
	}
	wantRoutable(t, e, impu3, first.Key)
}
