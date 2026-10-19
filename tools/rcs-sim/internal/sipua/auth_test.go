package sipua

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

func digestCreds(t *testing.T, password string) Credentials {
	t.Helper()
	c, err := DigestCredentials(testIMPI, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func akaCreds(t *testing.T) Credentials {
	t.Helper()
	c, err := AKACredentials(testIMPI, testK, testOPc)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// authStandIn is a stand-in whose registrar authenticates with a, and a
// config that registers with creds.
func authStandIn(t *testing.T, a *authRegistrar, creds Credentials) (*standIn, Config) {
	t.Helper()
	s := newStandIn(t, transport.TCP)
	s.auth = a
	cfg := s.config()
	cfg.Credentials = creds
	return s, cfg
}

func TestDigestChallengeIsAnsweredForTheRealm(t *testing.T) {
	for _, alg := range []digest.Algorithm{digest.MD5, digest.SHA256} {
		t.Run(string(alg), func(t *testing.T) {
			a := newAuthRegistrar(t, alg)
			_, cfg := authStandIn(t, a, digestCreds(t, testPassword))
			reg := register(t, dial(t, cfg))
			if reg.Challenges != 1 || reg.Resynchronised {
				t.Fatalf("registration = %+v", reg)
			}
			_, answered, _ := a.seen()
			if len(answered) != 1 || answered[0].Algorithm != alg || answered[0].Username != testIMPI || answered[0].Realm != testDomain || answered[0].URI != "sip:"+testDomain {
				t.Fatalf("answered %v", answered)
			}
		})
	}
}

func TestTheFirstREGISTERNamesTheIMPI(t *testing.T) {
	// TS 24.229 §5.1.1.2.2, §5.1.1.2.3: the unchallenged REGISTER carries Authorization
	// with the IMPI, the home domain as realm, and an empty nonce and
	// response, so the S-CSCF knows which private identity registers.
	a := newAuthRegistrar(t, digest.SHA256)
	_, cfg := authStandIn(t, a, digestCreds(t, testPassword))
	register(t, dial(t, cfg))
	first, _, _ := a.seen()
	if len(first) != 1 {
		t.Fatalf("%d unchallenged REGISTERs", len(first))
	}
	c, err := digest.ParseCredentials(first[0])
	if err != nil || c.Username != testIMPI || c.Realm != testDomain || c.Nonce != "" || c.Response != "" || c.URI != "sip:"+testDomain {
		t.Fatalf("first Authorization = %v, %v", c, err)
	}
}

func TestTheFirstChallengeOfferedIsTheOneAnswered(t *testing.T) {
	// RFC 8760 §2.4: the server lists its challenges by preference.
	for _, order := range [][]digest.Algorithm{{digest.SHA256, digest.MD5}, {digest.MD5, digest.SHA256}} {
		a := newAuthRegistrar(t, order...)
		_, cfg := authStandIn(t, a, digestCreds(t, testPassword))
		register(t, dial(t, cfg))
		if _, answered, _ := a.seen(); answered[0].Algorithm != order[0] {
			t.Errorf("offered %v, answered %s", order, answered[0].Algorithm)
		}
	}
}

func TestAKAChallengeIsAnsweredWithRES(t *testing.T) {
	a := newAuthRegistrar(t, digest.AKAv1MD5)
	_, cfg := authStandIn(t, a, akaCreds(t))
	reg := register(t, dial(t, cfg))
	_, answered, resyncs := a.seen()
	if reg.Challenges != 1 || reg.Resynchronised || resyncs != 0 {
		t.Fatalf("registration = %+v, resyncs %d", reg, resyncs)
	}
	if c := answered[0]; c.Algorithm != digest.AKAv1MD5 || c.Username != testIMPI || len(c.AUTS) != 0 {
		t.Fatalf("answered %v", c)
	}
}

func TestAKAResynchronisesWithAUTS(t *testing.T) {
	// The network's SQN falls behind the card's, as when the harness
	// provisions an older one: the card answers AUTS, the network
	// resynchronises from it (TS 33.102 §6.3.5) and challenges again, and
	// the second answer is RES.
	// Two registrations first, so the card's highest SQN (the second) is
	// not the one the rewound network offers next (the first), and AUTS
	// must carry the card's.
	a := newAuthRegistrar(t, digest.AKAv1MD5)
	_, cfg := authStandIn(t, a, akaCreds(t))
	ua := dial(t, cfg)
	register(t, ua)
	register(t, ua)
	a.mu.Lock()
	highest := a.sqn
	a.sqn = 0
	a.mu.Unlock()
	reg := register(t, ua)
	_, answered, resyncs := a.seen()
	if !reg.Resynchronised || reg.Challenges != 2 || resyncs != 1 {
		t.Fatalf("registration = %+v, resyncs %d", reg, resyncs)
	}
	a.mu.Lock()
	cardSQN := a.cardSQN
	a.mu.Unlock()
	if cardSQN[0] != highest {
		t.Fatalf("AUTS carried SQN %d, want the card's highest, %d", cardSQN[0], highest)
	}
	if c := answered[len(answered)-2]; len(c.AUTS) == 0 {
		t.Fatal("the answer to the old SQN carried no AUTS")
	}
}

func TestWrongCredentialsAreRefusedAndNotTriedAgain(t *testing.T) {
	for name, tc := range map[string]struct {
		algorithm digest.Algorithm
		creds     func(*testing.T) Credentials
		mutate    func(*authRegistrar)
		want      int
	}{
		"wrong password":            {digest.SHA256, func(t *testing.T) Credentials { return digestCreds(t, "not-the-password") }, nil, 403},
		"wrong password, 401 again": {digest.SHA256, func(t *testing.T) Credentials { return digestCreds(t, "not-the-password") }, func(a *authRegistrar) { a.refuseWith = 401 }, 401},
		"wrong RES":                 {digest.AKAv1MD5, akaCreds, func(a *authRegistrar) { a.wrongXRES = true }, 403},
		"wrong RES, 401 again":      {digest.AKAv1MD5, akaCreds, func(a *authRegistrar) { a.wrongXRES, a.refuseWith = true, 401 }, 401},
	} {
		t.Run(name, func(t *testing.T) {
			a := newAuthRegistrar(t, tc.algorithm)
			if tc.mutate != nil {
				tc.mutate(a)
			}
			s, cfg := authStandIn(t, a, tc.creds(t))
			_, err := dial(t, cfg).Register(context.Background())
			var se *StatusError
			if !errors.As(err, &se) || se.Code != tc.want {
				t.Fatalf("Register = %v, want %d", err, tc.want)
			}
			if s.registerCount() != 2 {
				t.Fatalf("%d REGISTERs, want 2: the refused credentials were tried again", s.registerCount())
			}
			noSecrets(t, err.Error())
		})
	}
}

func TestAKAKeysThatDoNotVerifyTheNetworkAreReportedInOneMoreREGISTER(t *testing.T) {
	// The card's K differs from the HSS's, so AUTN does not verify. TS
	// 24.229 §5.1.1.5.3: the UE says so in a further REGISTER with the
	// challenge's nonce, an empty response and no auts, and the answer to
	// that, here 403, is the result (TS 33.203 §6.1.2.2).
	a := newAuthRegistrar(t, digest.AKAv1MD5)
	other := testK
	other[0] ^= 1
	creds, err := AKACredentials(testIMPI, other, testOPc)
	if err != nil {
		t.Fatal(err)
	}
	s, cfg := authStandIn(t, a, creds)
	_, err = dial(t, cfg).Register(context.Background())
	var se *StatusError
	if !errors.Is(err, ErrNetworkNotAuthenticated) || !errors.As(err, &se) || se.Code != 403 || s.registerCount() != 2 {
		t.Fatalf("Register = %v after %d REGISTERs; want ErrNetworkNotAuthenticated with the 403, after 2", err, s.registerCount())
	}
	_, answered, _ := a.seen()
	if len(answered) != 1 {
		t.Fatalf("%d answers", len(answered))
	}
	if c := answered[0]; c.Response != "" || len(c.AUTS) != 0 || c.Nonce == "" || c.Username != testIMPI || c.Algorithm != digest.AKAv1MD5 {
		t.Fatalf("the report carried response %q, auts %v, nonce %t; want an empty response, no auts, the nonce", c.Response, len(c.AUTS) > 0, c.Nonce != "")
	}
	noSecrets(t, err.Error())
}

func TestChallengesForAnotherRealmAreNotAnswered(t *testing.T) {
	// A hop that challenges for its own realm would otherwise get a
	// response computed from the home password, to guess it from offline
	// (security review of #187).
	foreign, err := digest.NewServer(digest.ServerConfig{
		Realm: "foreign.example", NonceKey: []byte(strings.Repeat("f", digest.MinNonceKeySize)),
		NonceCounts: digest.NewMemoryNonceCounts(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []digest.Algorithm{digest.SHA256, digest.AKAv1MD5} {
		for _, proxy := range []bool{false, true} {
			name := fmt.Sprintf("%s, 407 %v", alg, proxy)
			creds := digestCreds(t, testPassword)
			if alg == digest.AKAv1MD5 {
				creds = akaCreds(t)
			}
			// Foreign alone: nothing to answer.
			a := newAuthRegistrar(t, alg)
			a.proxy, a.foreign, a.foreignOnly = proxy, foreign, true
			s, cfg := authStandIn(t, a, creds)
			if _, err := dial(t, cfg).Register(context.Background()); !errors.Is(err, ErrNoUsableChallenge) || s.registerCount() != 1 {
				t.Errorf("%s, foreign only: Register = %v after %d REGISTERs", name, err, s.registerCount())
			}
			// Foreign first, then home: the home one is answered.
			a = newAuthRegistrar(t, alg)
			a.proxy, a.foreign = proxy, foreign
			if alg == digest.AKAv1MD5 {
				creds = akaCreds(t)
			}
			_, cfg = authStandIn(t, a, creds)
			register(t, dial(t, cfg))
			if _, answered, _ := a.seen(); len(answered) != 1 || answered[0].Realm != testDomain {
				t.Errorf("%s, foreign then home: answered %v", name, answered)
			}
		}
	}
}

func TestTheTopmostChallengeWithAQOPItCanMeetIsAnswered(t *testing.T) {
	// TS 24.229 §5.1.1.5.4: the topmost one it supports. qop=auth-int,
	// or no qop for Digest, is not supported (RFC 8760 §2.6).
	for name, before := range map[string]string{
		"auth-int":          `Digest realm="` + testDomain + `", nonce="bm9uY2U=", algorithm=SHA-256, qop="auth-int"`,
		"MD5 without qop":   `Digest realm="` + testDomain + `", nonce="bm9uY2U=", algorithm=MD5`,
		"unknown algorithm": `Digest realm="` + testDomain + `", nonce="bm9uY2U=", algorithm=SHA-512-256, qop="auth"`,
	} {
		a := newAuthRegistrar(t, digest.MD5)
		a.before = []string{before}
		_, cfg := authStandIn(t, a, digestCreds(t, testPassword))
		register(t, dial(t, cfg))
		if _, answered, _ := a.seen(); answered[0].Algorithm != digest.MD5 {
			t.Errorf("%s first: answered %s", name, answered[0].Algorithm)
		}
	}
}

func TestAnAKAChallengeWithoutQOPIsAnswered(t *testing.T) {
	// TS 24.229 §5.4.1.2.1A has no qop in the S-CSCF's challenge.
	a := newAuthRegistrar(t, digest.AKAv1MD5)
	a.noQOP = true
	_, cfg := authStandIn(t, a, akaCreds(t))
	register(t, dial(t, cfg))
	if _, answered, _ := a.seen(); answered[0].QOP != "" || answered[0].NC != 0 {
		t.Fatalf("answered %v with qop or nc", answered[0])
	}
}

func TestAProxyChallengeAndARegistrarChallengeAreBothAnswered(t *testing.T) {
	// A proxy challenges with 407, then the registrar with 401. The
	// second answer is sent with the first (RFC 3261 §22.3), and the
	// Authorization with the IMPI rides along while the proxy challenges
	// (TS 24.229 §5.1.1.2.2).
	reg := newAuthRegistrar(t, digest.SHA256)
	proxy := newAuthRegistrar(t, digest.SHA256)
	proxy.proxy = true
	s, cfg := authStandIn(t, reg, digestCreds(t, testPassword))
	s.proxyAuth = proxy
	r := register(t, dial(t, cfg))
	if r.Challenges != 2 || s.registerCount() != 3 {
		t.Fatalf("registration = %+v after %d REGISTERs", r, s.registerCount())
	}
	first, _, _ := reg.seen()
	for _, v := range first {
		if c, err := digest.ParseCredentials(v); err != nil || c.Username != testIMPI {
			t.Fatalf("an unchallenged REGISTER's Authorization = %q", v)
		}
	}
}

func TestAProxyChallengeIsAnsweredInProxyAuthorization(t *testing.T) {
	// RFC 3261 §22.3: a 407's Proxy-Authenticate is answered in
	// Proxy-Authorization.
	for _, alg := range []digest.Algorithm{digest.SHA256, digest.AKAv1MD5} {
		a := newAuthRegistrar(t, alg)
		a.proxy = true
		creds := digestCreds(t, testPassword)
		if alg == digest.AKAv1MD5 {
			creds = akaCreds(t)
		}
		_, cfg := authStandIn(t, a, creds)
		if reg := register(t, dial(t, cfg)); reg.Challenges != 1 {
			t.Errorf("%s: registration = %+v", alg, reg)
		}
	}
}

func TestAStaleNonceIsAnsweredOnceMore(t *testing.T) {
	a := newAuthRegistrar(t, digest.SHA256)
	a.staleOnce = true
	_, cfg := authStandIn(t, a, digestCreds(t, testPassword))
	reg := register(t, dial(t, cfg))
	if reg.Challenges != 2 {
		t.Fatalf("registration = %+v", reg)
	}
}

func TestWithoutCredentialsTheChallengeIsTheResult(t *testing.T) {
	a := newAuthRegistrar(t, digest.SHA256)
	s, cfg := authStandIn(t, a, Credentials{})
	_, err := dial(t, cfg).Register(context.Background())
	var se *StatusError
	first, _, _ := a.seen()
	if !errors.As(err, &se) || se.Code != 401 || s.registerCount() != 1 || first[0] != "" {
		t.Fatalf("Register = %v after %d REGISTERs, Authorization %q", err, s.registerCount(), first)
	}
}

func TestAChallengeTheCredentialsCannotAnswerFails(t *testing.T) {
	for name, tc := range map[string]struct {
		offered digest.Algorithm
		creds   func(*testing.T) Credentials
	}{
		"AKA keys, Digest offered": {digest.SHA256, akaCreds},
		"password, AKA offered":    {digest.AKAv1MD5, func(t *testing.T) Credentials { return digestCreds(t, testPassword) }},
	} {
		a := newAuthRegistrar(t, tc.offered)
		_, cfg := authStandIn(t, a, tc.creds(t))
		if _, err := dial(t, cfg).Register(context.Background()); !errors.Is(err, ErrNoUsableChallenge) {
			t.Errorf("%s: Register = %v, want ErrNoUsableChallenge", name, err)
		}
	}
}

func TestUnregisterIsAuthenticatedToo(t *testing.T) {
	a := newAuthRegistrar(t, digest.AKAv1MD5)
	_, cfg := authStandIn(t, a, akaCreds(t))
	ua := dial(t, cfg)
	register(t, ua)
	reg, err := ua.Unregister(context.Background())
	if err != nil || reg.Challenges != 1 || reg.Expires != 0 {
		t.Fatalf("Unregister = %+v, %v", reg, err)
	}
}

// secrets are the values that must not reach a result line, a log or an
// error (#135 AC 1, 6).
var secrets = []string{testPassword, testKHex, testOPcHex, "001010000000001", "ims.example.com", strings.ToUpper(testKHex)}

func noSecrets(t *testing.T, s string) {
	t.Helper()
	for _, v := range secrets {
		if strings.Contains(s, v) {
			t.Errorf("%q holds %q", s, v)
		}
	}
}

func TestCredentialsNeverPrintTheirValues(t *testing.T) {
	for name, c := range map[string]Credentials{"digest": digestCreds(t, testPassword), "aka": akaCreds(t)} {
		cfg := Config{Credentials: c}
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "creds", c, "cfg", cfg)
		slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "creds", c, "cfg", cfg)
		js, _ := json.Marshal(struct{ C Credentials }{c})
		for _, out := range []string{
			fmt.Sprint(c), fmt.Sprintf("%v %+v %#v %s %q %x", c, c, c, c, c, c),
			fmt.Sprintf("%v %+v %#v", cfg, cfg, cfg), buf.String(), string(js),
		} {
			for _, v := range []string{testPassword, testKHex, testIMPI} {
				if strings.Contains(out, v) {
					t.Errorf("%s: %q holds %q", name, out, v)
				}
			}
		}
	}
}

func TestCredentialsFromTheEnvironment(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if _, err := DigestCredentialsFromEnv(testIMPI, env(map[string]string{EnvSIPPassword: testPassword})); err != nil {
		t.Fatal(err)
	}
	c, err := AKACredentialsFromEnv(testIMPI, env(map[string]string{EnvAKAK: testKHex, EnvAKAOPc: strings.ToUpper(testOPcHex)}))
	if err != nil {
		t.Fatal(err)
	}
	// The keys from the environment are the ones the registrar holds.
	a := newAuthRegistrar(t, digest.AKAv1MD5)
	_, cfg := authStandIn(t, a, c)
	register(t, dial(t, cfg))

	bad := testKHex[:31] + "g"
	for name, m := range map[string]map[string]string{
		"no password":  {},
		"no K":         {EnvAKAOPc: testOPcHex},
		"no OPc":       {EnvAKAK: testKHex},
		"short K":      {EnvAKAK: testKHex[:30], EnvAKAOPc: testOPcHex},
		"K not hex":    {EnvAKAK: bad, EnvAKAOPc: testOPcHex},
		"OPc too long": {EnvAKAK: testKHex, EnvAKAOPc: testOPcHex + "00"},
	} {
		var err error
		if name == "no password" {
			_, err = DigestCredentialsFromEnv(testIMPI, env(m))
		} else {
			_, err = AKACredentialsFromEnv(testIMPI, env(m))
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		noSecrets(t, err.Error())
		if strings.Contains(err.Error(), bad) || strings.Contains(err.Error(), testKHex[:30]) {
			t.Errorf("%s: %q quotes the value", name, err)
		}
	}
}
