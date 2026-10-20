package registrar

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/milenage"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

func contactCount(t *testing.T, e *env, impu string) int {
	t.Helper()
	return len(must(regOf(e, impu))(t).Contacts)
}

func TestAClientThatReconnectsWithANewAddressKeepsOneBinding(t *testing.T) {
	// rcsjta: +sip.instance without reg-id, a new Call-ID and local address
	// whenever the IMS connection is made again.
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	u.instance = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>"
	for i := range state.MaxContacts + 2 {
		u.callID = fmt.Sprintf("connection-%d", i)
		u.contact = fmt.Sprintf("sip:ue@192.0.2.%d:%d;transport=tcp", 10+i%200, 5060+i)
		u.cseq = 0
		// Reconnections a few seconds apart, within the challenge limit.
		e.clock.advance(10 * time.Second)
		wantStatus(t, u.registerWith(g, 600), 200)
		if n := contactCount(t, e, impu1); n != 1 {
			t.Fatalf("after %d reconnections: %d bindings", i+1, n)
		}
	}
}

func TestAContactWithoutAnInstanceReplacesTheUEsEarlierRegistrations(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	wantStatus(t, u.registerWith(g, 600), 200)
	// TS 24.229 §5.4.1.2.2 4A): a new registration of the IMPI without an
	// instance ends the earlier one at another address.
	u.callID, u.contact, u.cseq = "again", "sip:ue@192.0.2.99:5060;transport=tcp", 0
	wantStatus(t, u.registerWith(g, 600), 200)
	if got := must(regOf(e, impu1))(t).Contacts; len(got) != 1 || got[0].CallID != "again" {
		t.Errorf("bindings %+v, want only the new one", got)
	}
	// Two contacts of one REGISTER are both kept.
	u.contact = ""
	auth := u.answer(g.Register(bg, u.request(-1, "", "Contact: <sip:a@192.0.2.1>;expires=600", "Contact: <sip:b@192.0.2.2>;expires=600"), upstream), 0)
	wantStatus(t, g.Register(bg, u.request(-1, auth, "Contact: <sip:a@192.0.2.1>;expires=600", "Contact: <sip:b@192.0.2.2>;expires=600"), upstream), 200)
	if n := contactCount(t, e, impu1); n != 3 {
		t.Errorf("%d bindings, want the two new ones besides the earlier of this Call-ID", n)
	}
}

func TestAnOutboundFlowIsNotReplacedByAContactWithTheSameURI(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	u.instance, u.regID = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>", 1
	wantStatus(t, u.registerWith(g, 600), 200)
	other := device(u, 2)
	other.instance, other.regID, other.contact = "", 0, u.contact
	wantStatus(t, other.registerWith(g, 600), 200)
	if n := contactCount(t, e, impu1); n != 2 {
		t.Errorf("%d bindings, want the outbound flow and the plain contact", n)
	}
}

func TestOutboundAppliesOnlyToARequestContactOverAnObEdgeProxy(t *testing.T) {
	t.Run("a REGISTER without reg-id gets no Require", func(t *testing.T) {
		e := newEnv(t)
		g := e.instance(1)
		a := e.akaUser(impi1, impu1)
		a.instance, a.regID = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>", 1
		wantStatus(t, a.registerWith(g, 600), 200)
		b := device(a, 2)
		b.regID = 0
		if res := b.registerWith(g, 600); res.Header.Has("Require") {
			t.Errorf("Require %q for a contact without reg-id (RFC 5626 §6)", res.Header.Get("Require"))
		}
	})
	t.Run("a reg-id over an edge proxy without ob is ignored", func(t *testing.T) {
		e := newEnv(t)
		u := e.akaUser(impi1, impu1)
		u.instance, u.regID = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>", 1
		u.path = []string{"<sip:pcscf." + realm + ";lr>"}
		res := u.registerWith(e.instance(1), 600)
		wantStatus(t, res, 200)
		if res.Header.Has("Require") {
			t.Error("Require: outbound without ob in the first Path")
		}
		if c := must(regOf(e, impu1))(t).Contacts[0]; c.RegID != 0 || c.KeepAlive {
			t.Errorf("binding %+v kept its reg-id", c)
		}
	})
	t.Run("a UA that needs outbound over such a proxy gets 439", func(t *testing.T) {
		e := newEnv(t)
		u := e.akaUser(impi1, impu1)
		u.instance, u.regID = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>", 1
		u.path = []string{"<sip:pcscf." + realm + ";lr>"}
		g := e.instance(1)
		auth := u.answer(g.Register(bg, u.request(600, "", "Supported: outbound, path"), upstream), 0)
		wantStatus(t, g.Register(bg, u.request(600, auth, "Supported: outbound, path"), upstream), 439)
	})
	t.Run("the 401 already requires outbound", func(t *testing.T) {
		e := newEnv(t)
		u := e.akaUser(impi1, impu1)
		u.instance, u.regID = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>", 1
		if got := e.instance(1).Register(bg, u.request(600, ""), upstream).Header.Get("Require"); got != "outbound" {
			t.Errorf("401 Require %q", got)
		}
	})
}

func TestTheSameCSeqFromTheSameCallIDIsRefusedToo(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	wantStatus(t, u.registerWith(g, 600), 200)
	auth := u.answer(g.Register(bg, u.request(600, ""), upstream), 0)
	// The UE resends the CSeq the registration was stored with.
	u.cseq -= 2
	wantStatus(t, g.Register(bg, u.request(600, auth), upstream), 500)
}

func TestAnOlderContactStarDoesNotUndoANewerRegistration(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	wantStatus(t, u.registerWith(g, 600), 200)
	auth := u.answer(g.Register(bg, u.request(600, ""), upstream), 0)
	u.cseq -= 3
	u.contact = ""
	wantStatus(t, g.Register(bg, u.request(-1, auth, "Contact: *", "Expires: 0"), upstream), 500)
	if n := contactCount(t, e, impu1); n != 1 {
		t.Errorf("%d bindings after a stale Contact *", n)
	}
}

func TestRemovingABindingThereIsNoneOfIs481WithoutAnSAR(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	wantStatus(t, u.registerWith(g, 600), 200)
	_, sars := e.hss.counts()
	u.contact = "sip:never@192.0.2.77"
	auth := u.answer(g.Register(bg, u.request(0, ""), upstream), 0)
	wantStatus(t, g.Register(bg, u.request(0, auth), upstream), 481)
	if _, n := e.hss.counts(); n != sars {
		t.Error("removing nothing sent SAR")
	}
}

func TestContactsAreReadAsTheirFieldsSayOnce(t *testing.T) {
	for _, tc := range []struct {
		name    string
		contact string
		want    int
		expires string
	}{
		{"a duplicate contact is 400", "Contact: <sip:a@192.0.2.1>;expires=600, <sip:a@192.0.2.1>;expires=900", 400, ""},
		{"an expiry beyond 32 bits is capped as the Expires field is", "Contact: <sip:a@192.0.2.1>;expires=99999999999", 200, "expires=7200"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			g := e.instance(1)
			u := e.akaUser(impi1, impu1)
			u.contact = ""
			auth := u.answer(g.Register(bg, u.request(-1, "", tc.contact), upstream), 0)
			res := g.Register(bg, u.request(-1, auth, tc.contact), upstream)
			wantStatus(t, res, tc.want)
			if tc.expires != "" && !strings.Contains(res.Header.Get("Contact"), tc.expires) {
				t.Errorf("Contact %q, want %s", res.Header.Get("Contact"), tc.expires)
			}
		})
	}
}

func TestAQueryLeavesOutBindingsThatHaveExpired(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	u.instance = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>"
	wantStatus(t, u.registerWith(g, 600), 200)
	long := device(u, 2)
	wantStatus(t, long.registerWith(g, 1200), 200)
	e.clock.advance(601 * time.Second)
	u.contact = ""
	res := u.registerWith(g, -1)
	wantStatus(t, res, 200)
	if got := res.Header.Values("Contact"); len(got) != 1 || !strings.Contains(got[0], "ue2@") {
		t.Errorf("query listed %q", got)
	}
}

func TestWhatTheStoreWouldRefuseIsRefusedBeforeSAR(t *testing.T) {
	many := "Contact: <sip:ue9@192.0.2.10>;expires=600"
	for i := range 33 {
		many += fmt.Sprintf(";+g.tag%d", i)
	}
	for name, u := range map[string]func(*ue) []string{
		"33 feature tags": func(*ue) []string { return []string{many} },
		"a URI over 4 KiB": func(*ue) []string {
			return []string{"Contact: <sip:" + strings.Repeat("u", 4100) + "@192.0.2.10>;expires=600"}
		},
		"nine Path entries": func(u *ue) []string {
			for i := range 9 {
				u.path = append(u.path, fmt.Sprintf("<sip:p%d.%s;lr>", i, realm))
			}
			return []string{"Contact: <sip:ue9@192.0.2.10>;expires=600"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			g := e.instance(1)
			ue := e.akaUser(impi1, impu1)
			ue.contact = ""
			extra := u(ue)
			auth := ue.answer(g.Register(bg, ue.request(-1, "", extra...), upstream), 0)
			res := g.Register(bg, ue.request(-1, auth, extra...), upstream)
			if res.StatusCode < 400 || res.StatusCode >= 500 {
				t.Errorf("got %d %s, want a 4xx", res.StatusCode, res.Reason)
			}
			if _, sars := e.hss.counts(); sars != 0 {
				t.Error("refused after SAR: the HSS keeps a registration no sweep will end")
			}
		})
	}
}

func TestAQuotedFeatureTagRoundTripsThroughThe200(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	a := e.akaUser(impi1, impu1)
	a.contact = ""
	tagged := `Contact: <sip:uea@192.0.2.10:5060;transport=tcp>;expires=600;+x.tag="a\"b";+sip.instance="<urn:uuid:a\\b>"`
	auth := a.answer(g.Register(bg, a.request(-1, "", tagged), upstream), 0)
	res := g.Register(bg, a.request(-1, auth, tagged), upstream)
	wantStatus(t, res, 200)
	// Another device's 200 lists A's binding too.
	b := device(a, 2)
	b.contact = "sip:ueb@192.0.2.20"
	for _, r := range []*sip.Response{res, b.registerWith(g, 600)} {
		cs, err := r.Header.Contact()
		if err != nil {
			t.Fatalf("200 Contact %q does not parse: %v", r.Header.Values("Contact"), err)
		}
		found := false
		for _, c := range cs {
			if v, _ := c.Params.Get("+x.tag"); v == `a"b` {
				found = true
				if inst, _ := c.Instance(); inst != `<urn:uuid:a\b>` {
					t.Errorf("instance %q", inst)
				}
			}
		}
		if !found {
			t.Errorf("A's binding is not in %q", r.Header.Values("Contact"))
		}
	}
}

func TestOnlyOneResynchronisationIsSentPerChallengeWindow(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	ch := u.challengeOf(g.Register(bg, u.request(600, ""), upstream), 0)
	ms, _ := milenage.NewSQN(1000, 0)
	rnd, _, _ := digest.ParseAKANonce(ch.Nonce)
	auts := u.m.AUTS(rnd, ms)
	next := u.challengeOf(g.Register(bg, u.request(600, u.respond(ch, auts[:])), upstream), 0)
	mars, _ := e.hss.counts()
	// Another synchronisation failure, for the resynchronised vector.
	rnd2, _, _ := digest.ParseAKANonce(next.Nonce)
	auts2 := u.m.AUTS(rnd2, ms)
	wantStatus(t, g.Register(bg, u.request(600, u.respond(next, auts2[:])), upstream), 403)
	if n, _ := e.hss.counts(); n != mars {
		t.Error("a second resynchronisation went to the HSS")
	}
}

func TestNoVectorPartOrHA1IsLogged(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	d := e.digestUser(impi2, impu2)
	ch := u.challengeOf(g.Register(bg, u.request(600, ""), upstream), 0)
	auth := u.respond(ch, nil)
	dch := d.challengeOf(g.Register(bg, d.request(600, ""), upstream), 1)
	dauth := d.respond(dch, nil)
	// Every path that logs: a Cx failure, a store failure, for either user.
	e.hss.mu.Lock()
	e.hss.unavailable = true
	e.hss.mu.Unlock()
	g.Register(bg, u.request(600, ""), upstream)
	g.Register(bg, d.request(600, ""), upstream)
	broken := e.instance(2, func(c *Config) { c.Store = failingStore{e.store} })
	broken.Register(bg, u.request(600, auth), upstream)
	broken.Register(bg, d.request(600, dauth), upstream)
	logs := e.logs.String()
	if logs == "" {
		t.Fatal("nothing was logged; the check below would prove nothing")
	}
	rnd, _, _ := digest.ParseAKANonce(ch.Nonce)
	xres, ck, ik := u.m.F2(rnd), u.m.F3(rnd), u.m.F4(rnd)
	md5, _ := digest.ComputeHA1(digest.MD5, impi2, realm, d.password)
	sha, _ := digest.ComputeHA1(digest.SHA256, impi2, realm, d.password)
	creds, _ := digest.ParseCredentials(auth)
	dcreds, _ := digest.ParseCredentials(dauth)
	secrets := map[string][]byte{
		"XRES": xres[:], "CK": ck[:], "IK": ik[:], "MD5 HA1": []byte(md5), "SHA-256 HA1": []byte(sha),
		"AKA response": []byte(creds.Response), "Digest response": []byte(dcreds.Response),
		"AKA nonce": []byte(ch.Nonce), "Digest nonce": []byte(dch.Nonce), "IMPI": []byte(impi1), "password": d.password,
	}
	for name, secret := range secrets {
		for form, v := range map[string]string{
			"as is": string(secret), "hex": hex.EncodeToString(secret),
			"base64": base64.StdEncoding.EncodeToString(secret), "base64url": base64.RawURLEncoding.EncodeToString(secret),
		} {
			if len(v) >= 8 && strings.Contains(logs, v) {
				t.Errorf("the log has the %s (%s)", name, form)
			}
		}
	}
}

func TestAContactThatCannotBeWrittenBackIsRefusedBeforeSAR(t *testing.T) {
	for _, c := range []string{"\x00", "\x01", "\x7f"} {
		for name, contact := range map[string]string{
			"feature tag": "Contact: <sip:uea@192.0.2.10:5060;transport=tcp>;expires=600;+x.tag=\"a\\" + c + "b\"",
			"instance":    "Contact: <sip:uea@192.0.2.10:5060;transport=tcp>;expires=600;+sip.instance=\"<urn:uuid:a\\" + c + "b>\"",
		} {
			t.Run(fmt.Sprintf("%s %q", name, c), func(t *testing.T) {
				e := newEnv(t)
				g := e.instance(1)
				u := e.akaUser(impi1, impu1)
				u.contact = ""
				auth := u.answer(g.Register(bg, u.request(-1, "", contact), upstream), 0)
				wantStatus(t, g.Register(bg, u.request(-1, auth, contact), upstream), 400)
				if _, sars := e.hss.counts(); sars != 0 {
					t.Error("refused after SAR")
				}
				if _, err := regOf(e, impu1); err == nil {
					t.Error("the binding was stored, and would break every 200 of the set")
				}
			})
		}
	}
}
