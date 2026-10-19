package registrar

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

func TestExpiriesAreBoundedByTheRegistrar(t *testing.T) {
	for _, tc := range []struct {
		name    string
		expires int
		header  string
		want    int
		wantSec string
	}{
		{"a contact's own expiry is kept", 600, "", 200, "expires=600"},
		{"one above MaxExpires is capped", 100000, "", 200, "expires=7200"},
		{"without any the default applies", -1, "", 200, "expires=3600"},
		{"the Expires field applies to a contact without one", -1, "Expires: 900", 200, "expires=900"},
		{"one below MinExpires gets 423", 60, "", 423, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			g := e.instance(1)
			u := e.akaUser(impi1, impu1)
			var extra []string
			if tc.header != "" {
				extra = append(extra, tc.header)
			}
			res := g.Register(bg, u.request(tc.expires, "", extra...), upstream)
			res = g.Register(bg, u.request(tc.expires, u.answer(res, 0), extra...), upstream)
			wantStatus(t, res, tc.want)
			if tc.want == 423 {
				if got := res.Header.Get("Min-Expires"); got != "300" {
					t.Errorf("Min-Expires %q", got)
				}
				if _, sars := e.hss.counts(); sars != 0 {
					t.Error("a refused REGISTER reached SAR")
				}
				return
			}
			if got := res.Header.Get("Contact"); !strings.Contains(got, ";"+tc.wantSec+";") {
				t.Errorf("Contact %q, want %s", got, tc.wantSec)
			}
		})
	}
}

func TestAnOlderREGISTERFromTheSameCallIDIsRefused(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	wantStatus(t, u.registerWith(g, 600), 200)
	auth := u.answer(g.Register(bg, u.request(600, ""), upstream), 0)
	u.cseq -= 3
	wantStatus(t, g.Register(bg, u.request(600, auth), upstream), 500)
}

func TestAnOutboundBindingIsReplacedByTheSameInstanceAndRegID(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	u.instance, u.regID = "<urn:uuid:00000000-0000-0000-0000-000000000001>", 1
	wantStatus(t, u.registerWith(g, 600), 200)
	// The UA reconnected and registers its new address under the same flow.
	u.contact = "sip:ue1@192.0.2.11:5060;transport=tcp"
	u.callID = "another-call"
	res := u.registerWith(g, 600)
	wantStatus(t, res, 200)
	if got := res.Header.Values("Contact"); len(got) != 1 || !strings.Contains(got[0], "192.0.2.11") {
		t.Errorf("Contact %q, want only the new binding", got)
	}
	// A second flow of the same instance is a second binding.
	u.regID = 2
	if got := u.registerWith(g, 600).Header.Values("Contact"); len(got) != 2 {
		t.Errorf("Contact %q, want two bindings", got)
	}
}

func TestBindingsAreBounded(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	var contacts []string
	for i := range state.MaxContacts + 1 {
		contacts = append(contacts, fmt.Sprintf("Contact: <sip:ue%d@192.0.2.10>;expires=600", i))
	}
	u.contact = ""
	// Refused before authentication: the binding rules cost the square of
	// the contacts, and an authenticated user should not get to pay that.
	wantStatus(t, g.Register(bg, u.request(-1, "", contacts...), upstream), 403)
	if mars, _ := e.hss.counts(); mars != 0 {
		t.Errorf("%d MARs for a REGISTER with too many contacts", mars)
	}
}

func TestMalformedREGISTERsAreRefusedBeforeAnyCxRequest(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra []string
		want  int
	}{
		{"reg-id without an instance", []string{"Contact: <sip:x@192.0.2.10>;reg-id=1"}, 400},
		{"reg-id 0", []string{`Contact: <sip:x@192.0.2.10>;+sip.instance="<urn:uuid:1>";reg-id=0`}, 400},
		{"Contact * with an expiry", []string{"Contact: *", "Expires: 60"}, 400},
		{"Contact * with another contact", []string{"Contact: *, <sip:x@192.0.2.10>", "Expires: 0"}, 400},
		{"a bad q", []string{"Contact: <sip:x@192.0.2.10>;q=2"}, 400},
		{"an unknown algorithm", []string{`Authorization: Digest username="` + impi1 + `", realm="` + realm + `", nonce="", uri="sip:x", response="", algorithm=AKAv2-MD5`}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			u := e.akaUser(impi1, impu1)
			u.contact = ""
			auth := ""
			if strings.HasPrefix(tc.extra[0], "Authorization") {
				u.noAuth = true
				u.contact = "sip:x@192.0.2.10"
			}
			res := e.instance(1).Register(bg, u.request(-1, auth, tc.extra...), upstream)
			if tc.want == 400 && res.StatusCode == 401 {
				// Some are found only once authenticated.
				res = e.instance(1).Register(bg, u.request(-1, u.answer(res, 0), tc.extra...), upstream)
			}
			wantStatus(t, res, tc.want)
			if _, sars := e.hss.counts(); sars != 0 {
				t.Error("a malformed REGISTER reached SAR")
			}
		})
	}
}

func TestAQueryListsTheBindingsWithoutAnAssignment(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	wantStatus(t, u.registerWith(g, 600), 200)
	_, sars := e.hss.counts()
	saved := u.contact
	u.contact = ""
	res := u.registerWith(g, -1)
	wantStatus(t, res, 200)
	if got := res.Header.Values("Contact"); len(got) != 1 || !strings.Contains(got[0], saved) {
		t.Errorf("query listed %q", got)
	}
	if _, n := e.hss.counts(); n != sars {
		t.Error("a query sent SAR")
	}
}

func TestARegistrationWithoutContactsIsAnInitialRegistration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stored func(*state.Registration)
	}{
		{"while a deregistration sweep holds it", func(r *state.Registration) { r.Deregistering = t0.Add(state.SweepLease) }},
		{"for an unregistered user's record", func(r *state.Registration) { r.Unregistered = t0.Add(time.Hour) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			r := &state.Registration{IMPU: impu1, IMPI: impi1, DefaultIMPU: impu1}
			tc.stored(r)
			if _, err := e.store.SaveRegistration(bg, r); err != nil {
				t.Fatal(err)
			}
			u := e.akaUser(impi1, impu1)
			wantStatus(t, u.registerWith(e.instance(1), 600), 200)
			if s := e.hss.lastSAR(t); s.AssignmentType != cx.Registration || s.UserDataAlreadyAvailable != cx.UserDataNotAvailable {
				t.Errorf("SAR %+v, want REGISTRATION asking for User-Data", s)
			}
			got := must(e.store.Registration(bg, impu1))(t)
			if len(got.Contacts) != 1 || !got.Unregistered.IsZero() || !got.Deregistering.IsZero() {
				t.Errorf("stored %+v", got)
			}
		})
	}
}

func TestAnIdentityRegisteredByAnotherPrivateIdentityIsForbidden(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	wantStatus(t, e.akaUser(impi1, impu1).registerWith(g, 600), 200)
	other := e.akaUser(impi2, impu1)
	// The same 401 as for anyone, so that an unauthenticated sender learns
	// nothing of who is registered; the refusal comes once authenticated.
	res := g.Register(bg, other.request(600, ""), upstream)
	wantStatus(t, res, 401)
	res = g.Register(bg, other.request(600, other.answer(res, 0)), upstream)
	wantStatus(t, res, 403)
	if res.Reason != "Forbidden" {
		t.Errorf("reason %q tells more than any other 403", res.Reason)
	}
	// Nothing of the registration changed, and the HSS heard nothing for the
	// other IMPI.
	if r := must(e.store.Registration(bg, impu1))(t); r.IMPI != impi1 || len(r.Contacts) != 1 || r.Contacts[0].CallID != "call-"+impi1[:15] {
		t.Errorf("after the refusal: %+v", r)
	}
	e.hss.mu.Lock()
	defer e.hss.mu.Unlock()
	for _, s := range e.hss.sars {
		if s.UserName == impi2 {
			t.Errorf("SAR %v for the refused IMPI", s.AssignmentType)
		}
	}
}

func TestWithoutCredentialsThePrivateIdentityIsTheIMPUWithoutItsScheme(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := &ue{t: t, impi: "unused", impu: impu1, callID: "c", contact: "sip:ue@192.0.2.10", noAuth: true}
	g.Register(bg, u.request(600, ""), upstream)
	e.hss.mu.Lock()
	got := e.hss.mars[0].UserName
	e.hss.mu.Unlock()
	if want := strings.TrimPrefix(impu1, "sip:"); got != want {
		t.Errorf("MAR User-Name %q, want %q", got, want)
	}
	u.impu = tel1
	wantStatus(t, g.Register(bg, u.request(600, ""), upstream), 403)
}

func TestAChallengeAnsweredForAnotherIdentityIsForbidden(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1, impu2)
	auth := u.answer(g.Register(bg, u.request(600, ""), upstream), 0)
	u.impu = impu2
	wantStatus(t, g.Register(bg, u.request(600, auth), upstream), 403)
}

func TestIntegrityProtectedReRegistrationsSkipTheChallengeOnlyWhenTrusted(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		t.Run(fmt.Sprint("trusted=", trusted), func(t *testing.T) {
			e := newEnv(t)
			g := e.instance(1, func(c *Config) { c.TrustIntegrityProtected = trusted })
			u := e.akaUser(impi1, impu1)
			wantStatus(t, u.registerWith(g, 600), 200)
			auth := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="", uri="sip:%s", response="", integrity-protected="tls-yes"`, impi1, realm, realm)
			res := g.Register(bg, u.request(600, auth), upstream)
			want := map[bool]int{false: 401, true: 200}[trusted]
			wantStatus(t, res, want)
			// An initial registration is always challenged.
			first := e.akaUser(impi2, impu2)
			wantStatus(t, g.Register(bg, first.request(600, strings.ReplaceAll(auth, impi1, impi2)), upstream), 401)
		})
	}
}

// racingStore saves a binding of another UA just before the registrar's
// first save, as another instance would.
type racingStore struct {
	*state.Memory
	once sync.Once
	race func()
}

func (r *racingStore) SaveRegistration(ctx context.Context, reg *state.Registration) (*state.Registration, error) {
	r.once.Do(r.race)
	return r.Memory.SaveRegistration(ctx, reg)
}

func TestConcurrentREGISTERsOfTwoDevicesKeepBothBindings(t *testing.T) {
	e := newEnv(t)
	first := e.akaUser(impi1, impu1)
	first.instance = "<urn:uuid:00000000-0000-0000-0000-00000000000a>"
	wantStatus(t, first.registerWith(e.instance(1), 600), 200)
	second := *first
	second.callID, second.contact = "device-2", "sip:ue2@192.0.2.20:5060;transport=tcp"
	second.instance = "<urn:uuid:00000000-0000-0000-0000-00000000000b>"
	rs := &racingStore{Memory: e.store}
	rs.race = func() {
		// The first device re-registers on another instance meanwhile.
		wantStatus(t, first.registerWith(e.instance(3), 600), 200)
	}
	g := e.instance(2, func(c *Config) { c.Store = rs })
	auth := second.answer(g.Register(bg, second.request(600, ""), upstream), 0)
	res := g.Register(bg, second.request(600, auth), upstream)
	wantStatus(t, res, 200)
	if got := must(e.store.Registration(bg, impu1))(t).Contacts; len(got) != 2 {
		t.Errorf("stored %d bindings, want both devices'", len(got))
	}
}

func TestNoIdentityOrCredentialIsLogged(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	res := g.Register(bg, u.request(600, ""), upstream)
	nonce := u.challengeOf(res, 0).Nonce
	e.hss.mu.Lock()
	e.hss.unavailable = true
	e.hss.mu.Unlock()
	g.Register(bg, u.request(600, u.answer(res, 0)), upstream)
	// A store failure is logged too.
	broken := e.instance(2, func(c *Config) { c.Store = failingStore{e.store} })
	broken.Register(bg, u.request(600, ""), upstream)
	if e.logs.Len() == 0 {
		t.Fatal("nothing was logged; the check below would prove nothing")
	}
	logs := e.logs.String()
	for _, secret := range []string{impi1, "+15550100001", nonce, hex.EncodeToString(testKey)} {
		if strings.Contains(logs, secret) {
			t.Errorf("the log has %q", secret)
		}
	}
}

type failingStore struct{ *state.Memory }

func (failingStore) Registration(context.Context, string) (*state.Registration, error) {
	return nil, fmt.Errorf("store: unavailable")
}

func TestNewRefusesAnInconsistentConfig(t *testing.T) {
	u, _ := sip.ParseURI("sip:scscf." + realm)
	base := Config{Store: state.NewMemory(), HSS: newFakeHSS(), Realm: realm, ServiceRoute: u, NonceKey: testKey}
	for name, tweak := range map[string]func(*Config){
		"no store":                      func(c *Config) { c.Store = nil },
		"no HSS":                        func(c *Config) { c.HSS = nil },
		"a tel service route":           func(c *Config) { c.ServiceRoute = sip.URI{Scheme: "tel", User: "+1"} },
		"a short nonce key":             func(c *Config) { c.NonceKey = testKey[:8] },
		"min above max":                 func(c *Config) { c.MinExpires, c.MaxExpires = time.Hour, time.Minute },
		"a challenge lifetime too long": func(c *Config) { c.ChallengeLifetime = time.Hour },
	} {
		c := base
		tweak(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := New(base); err != nil {
		t.Errorf("the base config: %v", err)
	}
}
