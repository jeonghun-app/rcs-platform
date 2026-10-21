package registrar

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

// recordedThirdParty records the registrations the registrar tells of.
type recordedThirdParty struct {
	mu   sync.Mutex
	seen []ThirdPartyRegistration
}

func (r *recordedThirdParty) Registered(_ context.Context, reg ThirdPartyRegistration) {
	r.mu.Lock()
	r.seen = append(r.seen, reg)
	r.mu.Unlock()
}

func (r *recordedThirdParty) got() []ThirdPartyRegistration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ThirdPartyRegistration(nil), r.seen...)
}

func withThirdParty(r *recordedThirdParty) func(*Config) { return func(c *Config) { c.ThirdParty = r } }

// TestEveryRegistrationIsToldToTheApplicationServers (TS 24.229 §5.4.1.7):
// an initial registration, a refresh, a second device and the end of the
// set, with the UE's REGISTER, the 200 and how long the set stays
// registered; a query is not one.
func TestEveryRegistrationIsToldToTheApplicationServers(t *testing.T) {
	e := newEnv(t)
	tp := &recordedThirdParty{}
	g := e.instance(1, withThirdParty(tp))
	u := registered(t, e, g, 600, impu1)
	wantStatus(t, u.registerWith(g, 600), 200)
	e.clock.advance(time.Minute)
	other := device(u, 2)
	wantStatus(t, other.registerWith(g, 1200), 200)
	wantStatus(t, other.registerWith(g, 0), 200)
	wantStatus(t, u.registerWith(g, 0), 200)
	got := tp.got()
	want := []struct {
		t       ifc.RegistrationType
		expires time.Duration
	}{
		{ifc.InitialRegistration, 600 * time.Second},
		{ifc.ReRegistration, 600 * time.Second},
		{ifc.ReRegistration, 1200 * time.Second},
		// The second device left; the first stays until its expiry.
		{ifc.ReRegistration, 540 * time.Second},
		{ifc.DeRegistration, 0},
	}
	if len(got) != len(want) {
		t.Fatalf("%d registrations told, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		r := got[i]
		if r.Type != w.t || r.Expires != w.expires || r.IMPU != impu1 || r.Set.IMPU != impu1 || r.Request == nil || r.Response == nil || r.Response.StatusCode != 200 {
			t.Errorf("%d: %+v, want type %d, expires %v", i, r, w.t, w.expires)
		}
	}
	if got[4].Profile == nil {
		t.Error("the end of the set came without its profile, which the store no longer has")
	}
}

// TestAnEndTheNetworkMadeIsToldToo: the sweep's and an RTR's, without a
// REGISTER, for the set's default identity; an unregistered user's record
// has none to tell.
func TestAnEndTheNetworkMadeIsToldToo(t *testing.T) {
	t.Run("sweep", func(t *testing.T) {
		e := newEnv(t)
		tp := &recordedThirdParty{}
		g := e.instance(1, withThirdParty(tp))
		registered(t, e, g, 600, impu1, tel1)
		e.clock.advance(601 * time.Second)
		if _, err := g.Sweep(bg, 10); err != nil {
			t.Fatal(err)
		}
		got := tp.got()
		if len(got) != 2 || got[1].Type != ifc.DeRegistration || got[1].Expires != 0 || got[1].Request != nil || got[1].IMPU != impu1 || got[1].Profile == nil {
			t.Errorf("told %+v", got)
		}
	})
	t.Run("RTR", func(t *testing.T) {
		e := newEnv(t)
		tp := &recordedThirdParty{}
		g := e.instance(1, withThirdParty(tp))
		registered(t, e, g, 600, impu1)
		wantResult(t, g.HandleRTR(bg, &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}), resultSuccess)
		got := tp.got()
		if len(got) != 2 || got[1].Type != ifc.DeRegistration || got[1].Request != nil || got[1].Profile == nil {
			t.Errorf("told %+v", got)
		}
	})
	t.Run("unregistered user", func(t *testing.T) {
		e := newEnv(t)
		tp := &recordedThirdParty{}
		g := e.instance(1, withThirdParty(tp))
		e.akaUser(impi1, impu1)
		if _, err := g.Unregistered(bg, impu1); err != nil {
			t.Fatal(err)
		}
		e.clock.advance(DefaultUnregisteredTTL + time.Second)
		if _, err := g.Sweep(bg, 10); err != nil {
			t.Fatal(err)
		}
		if got := tp.got(); len(got) != 0 {
			t.Errorf("told %+v", got)
		}
	})
}

// TestARefusedRegistrationIsNotTold: a challenge is no registration.
func TestARefusedRegistrationIsNotTold(t *testing.T) {
	e := newEnv(t)
	tp := &recordedThirdParty{}
	g := e.instance(1, withThirdParty(tp))
	u := e.akaUser(impi1, impu1)
	wantStatus(t, g.Register(bg, u.request(600, ""), upstream), 401)
	if got := tp.got(); len(got) != 0 {
		t.Errorf("told %+v", got)
	}
}
