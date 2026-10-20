package registrar

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/milenage"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

var bg = context.Background()

func TestAnAKARegistrationIsChallengedThenAccepted(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1, tel1)
	u.instance, u.regID = "<urn:uuid:00000000-0000-0000-0000-000000000001>", 1

	res := g.Register(bg, u.request(600, ""), upstream)
	ch := u.challengeOf(res, 0)
	if ch.Algorithm != digest.AKAv1MD5 || ch.Realm != realm || len(res.Header.Values("WWW-Authenticate")) != 1 {
		t.Fatalf("challenge %+v", ch)
	}
	if strings.Contains(res.Header.Get("WWW-Authenticate"), "ck=") {
		t.Error("the 401 carries CK, which only an IPsec P-CSCF needs")
	}
	res = g.Register(bg, u.request(600, u.respond(ch, nil)), upstream)
	wantStatus(t, res, 200)

	if got := e.hss.lastSAR(t); got.AssignmentType != cx.Registration || got.UserName != impi1 {
		t.Errorf("SAR %+v", got)
	}
	contacts := res.Header.Values("Contact")
	if len(contacts) != 1 || !strings.Contains(contacts[0], ";expires=600") || !strings.Contains(contacts[0], ";reg-id=1") ||
		!strings.Contains(contacts[0], `+sip.instance="<urn:uuid:00000000-0000-0000-0000-000000000001>"`) {
		t.Errorf("Contact %q", contacts)
	}
	if got := res.Header.Get("Service-Route"); got != "<sip:scscf."+realm+";transport=tcp;lr;orig>" {
		t.Errorf("Service-Route %q", got)
	}
	if got := res.Header.Values("P-Associated-URI"); len(got) != 2 || got[0] != "<"+impu1+">" || got[1] != "<"+tel1+">" {
		t.Errorf("P-Associated-URI %q", got)
	}
	if got := res.Header.Get("Path"); got != "<sip:flow-token@pcscf."+realm+";lr;ob>" {
		t.Errorf("Path %q", got)
	}
	if got := res.Header.Get("Require"); got != "outbound" {
		t.Errorf("Require %q", got)
	}
	// Every identity of the implicit set is registered with the binding.
	for _, impu := range []string{impu1, tel1} {
		r, err := regOf(e, impu)
		if err != nil {
			t.Fatalf("%s: %v", impu, err)
		}
		if r.Key.IMPI != impi1 || r.Key.IMPU != impu1 || len(r.Contacts) != 1 || !r.Contacts[0].Expires.Equal(t0.Add(600*time.Second)) {
			t.Errorf("%s: %+v", impu, r)
		}
		if c := r.Contacts[0]; c.FlowToken != "flow-token" || !c.KeepAlive || c.RegID != 1 || len(c.FeatureTags) != 1 {
			t.Errorf("%s binding %+v", impu, c)
		}
	}
	p, err := e.store.Profile(bg, state.SetKey{IMPI: impi1, IMPU: impu1}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !p.KeepUntil.Equal(t0.Add(600*time.Second + state.ProfileGrace)) {
		t.Errorf("profile kept until %v", p.KeepUntil)
	}
}

func TestTheAnswerToAChallengeMayReachAnotherInstance(t *testing.T) {
	e := newEnv(t)
	a, b := e.instance(1), e.instance(2)
	u := e.akaUser(impi1, impu1)
	res := a.Register(bg, u.request(600, ""), upstream)
	wantStatus(t, b.Register(bg, u.request(600, u.answer(res, 0)), upstream), 200)

	// The same for SIP Digest, whose nonces both instances authenticate with
	// the shared key.
	d := e.digestUser(impi2, impu2)
	res = b.Register(bg, d.request(600, ""), upstream)
	wantStatus(t, a.Register(bg, d.request(600, d.answer(res, 0)), upstream), 200)
}

func TestAWrongAKAResponseIsForbiddenAndUsesUpTheChallenge(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	res := g.Register(bg, u.request(600, ""), upstream)
	ch := u.challengeOf(res, 0)
	good := u.respond(ch, nil)
	bad := tamper(good)
	wantStatus(t, g.Register(bg, u.request(600, bad), upstream), 403)
	// The vector went with the first answer: the right one now finds no
	// challenge and gets a new one, marked stale.
	res = g.Register(bg, u.request(600, good), upstream)
	if !u.challengeOf(res, 0).Stale {
		t.Error("the new challenge is not stale")
	}
	if _, sars := e.hss.counts(); sars != 0 {
		t.Error("an unauthenticated REGISTER reached SAR")
	}
}

func TestASynchronisationFailureGetsAVectorFromTheResynchronisedHSS(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	res := g.Register(bg, u.request(600, ""), upstream)
	ch := u.challengeOf(res, 0)
	rnd, _, _ := digest.ParseAKANonce(ch.Nonce)
	// The card's sequence number is ahead of the HSS's.
	ms, _ := milenage.NewSQN(1000, 0)
	auts := u.m.AUTS(rnd, ms)
	res = g.Register(bg, u.request(600, u.respond(ch, auts[:])), upstream)
	next := u.challengeOf(res, 0)
	if next.Nonce == ch.Nonce {
		t.Fatal("the resynchronisation challenged with the old vector")
	}
	e.hss.mu.Lock()
	resync := e.hss.mars[len(e.hss.mars)-1]
	e.hss.mu.Unlock()
	if got := resync.AuthDataItem.Authorization; len(got) != 30 || [16]byte(got[:16]) != rnd || [14]byte(got[16:]) != auts {
		t.Errorf("resynchronisation MAR carried %x", got)
	}
	nrand, nautn, _ := digest.ParseAKANonce(next.Nonce)
	sqn, err := u.m.CheckAUTN(nrand, nautn)
	if err != nil || sqn.SEQ() <= ms.SEQ() {
		t.Errorf("the new vector's SQN %v (%v) is not past the card's", sqn, err)
	}
	wantStatus(t, g.Register(bg, u.request(600, u.respond(next, nil)), upstream), 200)
}

func TestADigestUserIsOfferedSHA256ThenMD5(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.digestUser(impi1, impu1)
	res := g.Register(bg, u.request(600, ""), upstream)
	if c := u.challengeOf(res, 0); c.Algorithm != digest.SHA256 {
		t.Errorf("first challenge %s", c.Algorithm)
	}
	if c := u.challengeOf(res, 1); c.Algorithm != digest.MD5 {
		t.Errorf("second challenge %s", c.Algorithm)
	}
	// AKA was tried first and refused with 5006 (TS 29.228 §6.3.1).
	e.hss.mu.Lock()
	schemes := []string{e.hss.mars[0].AuthDataItem.Scheme, e.hss.mars[1].AuthDataItem.Scheme}
	e.hss.mu.Unlock()
	if schemes[0] != cx.SchemeDigestAKAv1MD5 || schemes[1] != cx.SchemeSIPDigest {
		t.Errorf("MAR schemes %v", schemes)
	}
	// Either answer authenticates.
	wantStatus(t, g.Register(bg, u.request(600, u.answer(res, 1)), upstream), 200)
	res = g.Register(bg, u.request(600, ""), upstream)
	wantStatus(t, g.Register(bg, u.request(600, u.answer(res, 0)), upstream), 200)
}

func TestAClientThatNamesMD5IsChallengedWithMD5Only(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.digestUser(impi1, impu1)
	u.algorithm = "MD5"
	res := g.Register(bg, u.request(600, ""), upstream)
	if vs := res.Header.Values("WWW-Authenticate"); len(vs) != 1 || u.challengeOf(res, 0).Algorithm != digest.MD5 {
		t.Errorf("challenges %q", vs)
	}
	e.hss.mu.Lock()
	defer e.hss.mu.Unlock()
	if len(e.hss.mars) != 1 || e.hss.mars[0].AuthDataItem.Scheme != cx.SchemeSIPDigest {
		t.Errorf("MAR went to %d schemes, want only SIP Digest", len(e.hss.mars))
	}
}

func TestAnAnswerAfterTheChallengeLifetimeGetsAStaleChallenge(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	res := g.Register(bg, u.request(600, ""), upstream)
	e.clock.advance(DefaultChallengeLifetime + time.Second)
	res = g.Register(bg, u.request(600, u.answer(res, 0)), upstream)
	if !u.challengeOf(res, 0).Stale {
		t.Error("not stale")
	}
}

func TestTheHSSDecidesWhoMayRegister(t *testing.T) {
	for _, tc := range []struct {
		name string
		hss  func(*fakeHSS)
		want int
	}{
		{"an unknown user is forbidden", func(*fakeHSS) {}, 403},
		{"an HSS out of reach makes it temporarily unavailable", func(f *fakeHSS) { f.unavailable = true }, 480},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			tc.hss(e.hss)
			u := &ue{t: t, impi: impi1, impu: impu1, callID: "c", contact: "sip:ue@192.0.2.10"}
			wantStatus(t, e.instance(1).Register(bg, u.request(600, ""), upstream), tc.want)
		})
	}
	t.Run("a refused assignment is forbidden and stores nothing", func(t *testing.T) {
		e := newEnv(t)
		r := cx.ExperimentalResult(cx.ErrorIdentitiesDontMatch)
		e.hss.sarResult = &r
		u := e.akaUser(impi1, impu1)
		wantStatus(t, u.registerWith(e.instance(1), 600), 403)
		if _, err := regOf(e, impu1); err == nil {
			t.Error("a registration was stored")
		}
	})
}

func TestAReRegistrationAsksForUserDataOnlyIfTheProfileIsGone(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1, tel1)
	wantStatus(t, u.registerWith(g, 600), 200)
	wantStatus(t, u.registerWith(g, 600), 200)
	if s := e.hss.lastSAR(t); s.AssignmentType != cx.ReRegistration || s.UserDataAlreadyAvailable != cx.UserDataAlreadyAvailable {
		t.Errorf("SAR %+v", s)
	}
	if err := e.store.DeleteProfile(bg, state.SetKey{IMPI: impi1, IMPU: impu1}); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, u.registerWith(g, 600), 200)
	if s := e.hss.lastSAR(t); s.AssignmentType != cx.ReRegistration || s.UserDataAlreadyAvailable != cx.UserDataNotAvailable {
		t.Errorf("SAR %+v", s)
	}
	if _, err := e.store.Profile(bg, state.SetKey{IMPI: impi1, IMPU: impu1}, e.clock.Now()); err != nil {
		t.Errorf("the profile was not stored again: %v", err)
	}
}

func TestReRegistrationsExtendTheProfileOnlyWhenItIsDue(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	key := state.SetKey{IMPI: impi1, IMPU: impu1}
	wantStatus(t, u.registerWith(g, 3600), 200)
	first := must(e.store.Profile(bg, key, e.clock.Now()))(t).KeepUntil
	for {
		e.clock.advance(50 * time.Minute)
		wantStatus(t, u.registerWith(g, 3600), 200)
		now := e.clock.Now()
		got := must(e.store.Profile(bg, key, now))(t).KeepUntil
		// Due once the new expiry is ProfileKeepMargin past what KeepUntil
		// covers (state.Profile.KeepDue).
		if first.Sub(now.Add(time.Hour)) >= state.ProfileGrace-state.ProfileKeepMargin {
			if !got.Equal(first) {
				t.Fatalf("KeepUntil moved to %v at %v, before it was due", got, now)
			}
			continue
		}
		if want := now.Add(time.Hour + state.ProfileGrace); !got.Equal(want) {
			t.Errorf("KeepUntil %v once due, want %v", got, want)
		}
		return
	}
}

func TestDeregistrationEndsTheSetAndDeletesItsProfile(t *testing.T) {
	for _, star := range []bool{false, true} {
		t.Run(map[bool]string{false: "expires 0", true: "Contact *"}[star], func(t *testing.T) {
			e := newEnv(t)
			g := e.instance(1)
			u := e.akaUser(impi1, impu1, tel1)
			wantStatus(t, u.registerWith(g, 600), 200)
			auth := u.answer(g.Register(bg, u.request(0, ""), upstream), 0)
			req := u.request(0, auth)
			if star {
				u.contact = ""
				req = u.request(-1, auth, "Contact: *", "Expires: 0")
			}
			res := g.Register(bg, req, upstream)
			wantStatus(t, res, 200)
			if len(res.Header.Values("Contact")) != 0 || res.Header.Has("Service-Route") {
				t.Errorf("200 to a deregistration lists %q", res.Header.Values("Contact"))
			}
			if s := e.hss.lastSAR(t); s.AssignmentType != cx.UserDeregistration {
				t.Errorf("SAR %+v", s)
			}
			for _, impu := range []string{impu1, tel1} {
				if _, err := regOf(e, impu); err == nil {
					t.Errorf("%s still registered", impu)
				}
			}
			if _, err := e.store.Profile(bg, state.SetKey{IMPI: impi1, IMPU: impu1}, e.clock.Now()); err == nil {
				t.Error("the profile is still stored")
			}
		})
	}
}

func TestADeregistrationTheHSSCannotBeToldOfKeepsTheBindings(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	wantStatus(t, u.registerWith(g, 600), 200)
	res := g.Register(bg, u.request(0, ""), upstream)
	auth := u.answer(res, 0)
	e.hss.mu.Lock()
	e.hss.unavailable = true
	e.hss.mu.Unlock()
	wantStatus(t, g.Register(bg, u.request(0, auth), upstream), 480)
	if r, err := regOf(e, impu1); err != nil || len(r.Contacts) != 1 {
		t.Errorf("after the failed deregistration: %+v, %v", r, err)
	}
	// Put back from its lease, the record is a new incarnation, and the
	// identity names it.
	wantPointed(t, e, impu1)
}

// wantPointed checks that each of impus names its set's record as it is
// now, incarnation included.
func wantPointed(t *testing.T, e *env, impus ...string) {
	t.Helper()
	for _, impu := range impus {
		id, err := e.store.Identity(bg, impu, e.clock.Now())
		if err != nil {
			t.Errorf("%s names no set: %v", impu, err)
			continue
		}
		r, err := e.store.Registration(bg, id.Set)
		if err != nil || r.Incarnation != id.Incarnation {
			t.Errorf("%s names incarnation %d of %v: %+v, %v", impu, id.Incarnation, id.Set, r, err)
		}
	}
}

func must[T any](v T, err error) func(*testing.T) T {
	return func(t *testing.T) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

// tamper changes the first digit of the response parameter.
func tamper(auth string) string {
	i := strings.Index(auth, `response="`) + len(`response="`)
	c := byte('0')
	if auth[i] == '0' {
		c = '1'
	}
	return auth[:i] + string(c) + auth[i+1:]
}

func TestABarredIdentityRegistersButIsNotAssociatedNorDefault(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1, impu2, tel1)
	e.hss.subs[impi1].barred = map[string]bool{impu1: true}
	res := u.registerWith(g, 600)
	wantStatus(t, res, 200)
	if got := res.Header.Values("P-Associated-URI"); len(got) != 2 || got[0] != "<"+impu2+">" || got[1] != "<"+tel1+">" {
		t.Errorf("P-Associated-URI %q, want the identities that are not barred, default first", got)
	}
	for _, impu := range []string{impu1, impu2, tel1} {
		if r := must(regOf(e, impu))(t); r.Key.IMPU != impu2 {
			t.Errorf("%s: default %s", impu, r.Key.IMPU)
		}
	}
}

func TestAProfileStoredUnderAnOldDefaultIdentityIsDeleted(t *testing.T) {
	e := newEnv(t)
	old := state.SetKey{IMPI: impi1, IMPU: impu1}
	seed(t, e, impi1, []string{impu1}, func(r *state.Registration) { r.Unregistered = t0.Add(time.Hour) })
	if err := e.store.SaveProfile(bg, &state.Profile{Key: old, UserData: []byte("<x/>"), Received: t0, KeepUntil: t0.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// The HSS's set now has tel1 as its default identity.
	u := e.akaUser(impi1, tel1, impu1)
	u.impu = impu1
	wantStatus(t, u.registerWith(e.instance(1), 600), 200)
	if _, err := e.store.Profile(bg, old, t0); err == nil {
		t.Error("the profile under the old default identity is still stored")
	}
	must(e.store.Profile(bg, state.SetKey{IMPI: impi1, IMPU: tel1}, t0))(t)
}

func TestCredentialsForAnotherAlgorithmAreChallengedAgainAndUseUpNothing(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.digestUser(impi1, impu1)
	res := g.Register(bg, u.request(600, ""), upstream)
	sha := u.challengeOf(res, 0)
	md5 := sha
	md5.Algorithm = digest.MD5
	// The opaque value binds the nonce to SHA-256, so this fails before any
	// table is read.
	wantStatus(t, g.Register(bg, u.request(600, u.respond(md5, nil)), upstream), 401)
	wantStatus(t, g.Register(bg, u.request(600, u.respond(sha, nil)), upstream), 200)
}

func TestAUEThatCouldNotAuthenticateTheNetworkIsForbiddenAndTheHSSIsTold(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	ch := u.challengeOf(g.Register(bg, u.request(600, ""), upstream), 0)
	// What a UE sends when AUTN did not verify, as rcs-sim does (#187): the
	// challenge's nonce and opaque, an empty response, no qop, nc or auts.
	failed := digest.Credentials{Username: impi1, Realm: realm, Nonce: ch.Nonce, URI: "sip:" + realm, Algorithm: digest.AKAv1MD5, Opaque: ch.Opaque}.Header()
	wantStatus(t, g.Register(bg, u.request(600, failed), upstream), 403)
	if s := e.hss.lastSAR(t); s.AssignmentType != cx.AuthenticationFailure || s.UserName != impi1 {
		t.Errorf("SAR %+v, want AUTHENTICATION_FAILURE", s)
	}
	// The vector is gone: the RES the card would have computed no longer
	// registers.
	res := g.Register(bg, u.request(600, u.respond(ch, nil)), upstream)
	if !u.challengeOf(res, 0).Stale {
		t.Error("the vector survived the failure report")
	}
	if _, err := regOf(e, impu1); err == nil {
		t.Error("a registration was stored")
	}
	// A nonce no instance issued is challenged again, with no store read or
	// SAR.
	_, sars := e.hss.counts()
	forged := strings.Replace(failed, ch.Nonce, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", 1)
	wantStatus(t, g.Register(bg, u.request(600, forged), upstream), 401)
	if _, n := e.hss.counts(); n != sars {
		t.Error("a forged failure report reached SAR")
	}
}

func TestTheServiceRouteKeepsAConfiguredTransport(t *testing.T) {
	e := newEnv(t)
	u, err := sip.ParseURI("sip:scscf." + realm + ";transport=tls")
	if err != nil {
		t.Fatal(err)
	}
	g := e.instance(1, func(c *Config) { c.ServiceRoute = u })
	res := e.akaUser(impi1, impu1).registerWith(g, 600)
	if got := res.Header.Get("Service-Route"); got != "<sip:scscf."+realm+";transport=tls;lr;orig>" {
		t.Errorf("Service-Route %q", got)
	}
}
