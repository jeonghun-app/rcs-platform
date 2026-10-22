package registrar

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// TestAnUnregisteredUserGetsARecordOfItsSetAndItsProfile (TS 29.228
// §6.1.2): SAR UNREGISTERED_USER for the identity, then the set's record
// without bindings until UnregisteredTTL ahead, the profile kept past it,
// and every identity of the set pointing at the record.
func TestAnUnregisteredUserGetsARecordOfItsSetAndItsProfile(t *testing.T) {
	e := newEnv(t)
	e.akaUser(impi1, impu1, tel1)
	m := &counts{}
	g := e.instance(1, func(c *Config) { c.Metrics, c.UnregisteredTTL = m, 10*time.Minute })
	e.clock.advance(500 * time.Millisecond)
	rec, err := g.Unregistered(bg, tel1)
	if err != nil {
		t.Fatal(err)
	}
	if sar := e.hss.lastSAR(t); sar.AssignmentType != cx.UnregisteredUser || sar.PublicIdentities[0] != tel1 || sar.UserName != "" {
		t.Errorf("SAR %+v", sar)
	}
	key := state.SetKey{IMPI: impi1, IMPU: impu1}
	if rec.Key != key || len(rec.Contacts) != 0 || !rec.Unregistered.Equal(t0.Add(10*time.Minute)) || len(rec.Identities) != 2 {
		t.Errorf("record %+v", rec)
	}
	stored := must(e.store.Registration(bg, key))(t)
	if stored.Incarnation != rec.Incarnation || !stored.Unregistered.Equal(rec.Unregistered) {
		t.Errorf("stored %+v", stored)
	}
	p := must(e.store.Profile(bg, key, e.clock.Now()))(t)
	if len(p.UserData) == 0 || p.KeepUntil.Before(rec.Unregistered.Add(state.ProfileGrace)) {
		t.Errorf("profile kept until %v", p.KeepUntil)
	}
	for _, impu := range []string{impu1, tel1} {
		if id := must(e.store.Identity(bg, impu, e.clock.Now()))(t); id.Set != key || id.Incarnation != rec.Incarnation {
			t.Errorf("%s points at %+v", impu, id)
		}
	}
	if m.get("registrar.unregistered") != 1 {
		t.Errorf("metrics %v", m.m)
	}
}

// TestAnUnregisteredUsersRecordEndsWithTheHSSAtItsTTL: the sweep claims
// it and tells the HSS (SAR TIMEOUT_DEREGISTRATION).
func TestAnUnregisteredUsersRecordEndsWithTheHSSAtItsTTL(t *testing.T) {
	e := newEnv(t)
	e.akaUser(impi1, impu1, tel1)
	g := e.instance(1)
	rec := must(g.Unregistered(bg, impu1))(t)
	if !rec.Unregistered.Equal(t0.Add(DefaultUnregisteredTTL)) {
		t.Errorf("the state ends at %v", rec.Unregistered)
	}
	if n := must(g.Sweep(bg, 10))(t); n != 0 {
		t.Fatalf("swept %d sets before the TTL", n)
	}
	e.clock.advance(DefaultUnregisteredTTL + time.Second)
	if n := must(g.Sweep(bg, 10))(t); n != 1 {
		t.Fatalf("swept %d sets", n)
	}
	if sar := e.hss.lastSAR(t); sar.AssignmentType != cx.TimeoutDeregistration {
		t.Errorf("SAR %v", sar.AssignmentType)
	}
	if _, err := e.store.Registration(bg, rec.Key); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("the record is still there: %v", err)
	}
}

// TestWhatTheHSSAnswersAnUnregisteredUsersSARIsTold: an unknown user, one
// another S-CSCF serves, an HSS out of reach, and any other failure, each
// apart, with nothing stored.
func TestWhatTheHSSAnswersAnUnregisteredUsersSARIsTold(t *testing.T) {
	for name, c := range map[string]struct {
		setUp func(e *env)
		want  error
	}{
		"unknown": {func(e *env) {
			e.hss.mu.Lock()
			delete(e.hss.subs, impi1)
			e.hss.mu.Unlock()
		}, ErrUnknownUser},
		"served elsewhere": {func(e *env) { e.hss.sarResult = ptr(cx.ExperimentalResult(cx.ErrorIdentityAlreadyRegistered)) }, ErrServedElsewhere},
		"unavailable":      {func(e *env) { e.hss.unavailable = true }, ErrHSSUnavailable},
		"unable to comply": {func(e *env) { e.hss.sarResult = ptr(cx.ResultCode(diameter.ResultUnableToComply)) }, nil},
		"no user named": {func(e *env) {
			e.hss.sarHook = func(*cx.SAR) (*cx.SAA, error) {
				return &cx.SAA{Answer: cx.Answer{Result: cx.ResultCode(2001)}, UserData: userDataOf(impi1, nil, impu1)}, nil
			}
		}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.akaUser(impi1, impu1, tel1)
			c.setUp(e)
			rec, err := e.instance(1).Unregistered(bg, impu1)
			switch {
			case rec != nil || err == nil:
				t.Fatalf("record %+v, error %v", rec, err)
			case c.want != nil && !errors.Is(err, c.want):
				t.Errorf("error %v, want %v", err, c.want)
			case c.want == nil && (errors.Is(err, ErrUnknownUser) || errors.Is(err, ErrServedElsewhere) || errors.Is(err, ErrHSSUnavailable) || errors.Is(err, state.ErrInvalid)):
				t.Errorf("error %v", err)
			}
			if _, err := e.store.Identity(bg, impu1, t0); !errors.Is(err, state.ErrNotFound) {
				t.Errorf("an identity was pointed: %v", err)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

// TestARecordOfTheSetIsReturnedAsItIs: one saved before the SAR, as a
// registration is, or while it was under way, which the save loses to. The
// SAA's profile is kept for it all the same (#536).
func TestARecordOfTheSetIsReturnedAsItIs(t *testing.T) {
	t.Run("before", func(t *testing.T) {
		e := newEnv(t)
		e.akaUser(impi1, impu1, tel1)
		live := seed(t, e, impi1, []string{impu1, tel1}, func(r *state.Registration) {
			r.Contacts = []state.Contact{{URI: "sip:ue1@192.0.2.10:5060", Expires: t0.Add(time.Hour), CallID: "c", CSeq: 1}}
		})
		rec := must(e.instance(1).Unregistered(bg, tel1))(t)
		if rec.Incarnation != live.Incarnation || len(rec.Contacts) != 1 {
			t.Errorf("record %+v", rec)
		}
		if p, err := e.store.Profile(bg, live.Key, t0); err != nil || len(p.UserData) == 0 {
			t.Errorf("the SAA's profile was not kept for the registration: %v", err)
		}
	})
	t.Run("meanwhile", func(t *testing.T) {
		e := newEnv(t)
		e.akaUser(impi1, impu1, tel1)
		var other *state.Registration
		st := &savingFirst{Memory: e.store, first: func() {
			// Another instance's record, its identities already pointed.
			r := &state.Registration{Key: state.SetKey{IMPI: impi1, IMPU: impu1}, Incarnation: 77, Unregistered: t0.Add(time.Hour),
				Identities: []state.SetIdentity{{IMPU: impu1}, {IMPU: tel1}}}
			other = must(e.store.SaveRegistration(bg, r))(t)
		}}
		rec := must(e.instance(1, func(c *Config) { c.Store = st }).Unregistered(bg, impu1))(t)
		if other == nil || rec.Incarnation != other.Incarnation {
			t.Errorf("record %+v, the one saved meanwhile %+v", rec, other)
		}
	})
}

// savingFirst runs first ahead of the first SaveRegistration.
type savingFirst struct {
	*state.Memory
	first func()
}

func (s *savingFirst) SaveRegistration(ctx context.Context, r *state.Registration) (*state.Registration, error) {
	if s.first != nil {
		s.first()
		s.first = nil
	}
	return s.Memory.SaveRegistration(ctx, r)
}

// TestARegisteredSetFoundAfterTheSARIsAssertedAgain (#359 security review):
// a REGISTER cut short left an identity of a live set without its item, so
// a terminating request asked the HSS, which now holds the user
// unregistered; the item is pointed and the HSS told of the registration.
func TestARegisteredSetFoundAfterTheSARIsAssertedAgain(t *testing.T) {
	e := newEnv(t)
	e.akaUser(impi1, impu1, tel1)
	live := seed(t, e, impi1, []string{impu1, tel1}, func(r *state.Registration) {
		r.Contacts = []state.Contact{{URI: "sip:ue1@192.0.2.10:5060", Expires: t0.Add(time.Hour), CallID: "c", CSeq: 1}}
	})
	id := must(e.store.Identity(bg, tel1, t0))(t)
	if err := e.store.DeleteIdentity(bg, id); err != nil {
		t.Fatal(err)
	}
	m := &counts{}
	rec := must(e.instance(1, func(c *Config) { c.Metrics = m }).Unregistered(bg, tel1))(t)
	if rec.Incarnation != live.Incarnation {
		t.Errorf("record %+v", rec)
	}
	if sar := e.hss.lastSAR(t); sar.AssignmentType != cx.Registration {
		t.Errorf("the HSS was last told %v, want REGISTRATION", sar.AssignmentType)
	}
	if got, err := e.store.Identity(bg, tel1, t0); err != nil || got.Set != live.Key || got.Incarnation != live.Incarnation {
		t.Errorf("tel1's item %+v, %v", got, err)
	}
	if m.get("registrar.unregistered_was_registered") != 1 {
		t.Error("not counted")
	}
}
