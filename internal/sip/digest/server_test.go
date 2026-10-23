package digest

import (
	"bytes"
	"context"
	"errors"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

const (
	testRealm = "ims.mnc001.mcc001.3gppnetwork.org"
	testUser  = "001010000000001@ims.mnc001.mcc001.3gppnetwork.org"
	testURI   = "sip:ims.mnc001.mcc001.3gppnetwork.org"
	testPass  = "correct horse battery staple"
)

var testKey = bytes.Repeat([]byte("nonce-key/"), 4)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

type harness struct {
	server *Server
	clock  *fakeClock
	counts *MemoryNonceCounts
	// vectorExpires is when scscf's stored AKA vector expires in tests that
	// are not about expiry: well after any clock advance they make.
	vectorExpires time.Time
}

func newHarness(t testing.TB) *harness {
	t.Helper()
	clock := &fakeClock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	counts := NewMemoryNonceCounts(clock.now)
	s, err := NewServer(ServerConfig{
		Realm:       testRealm,
		NonceKey:    secret.NewKey(testKey),
		NonceCounts: counts,
		Now:         clock.now,
		Random:      rand.NewChaCha8([32]byte{1}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{server: s, clock: clock, counts: counts, vectorExpires: clock.t.Add(24 * time.Hour)}
}

func (h *harness) challenge(t *testing.T, alg Algorithm) Challenge {
	t.Helper()
	ch, err := h.server.Challenge(alg, false)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

func answer(t *testing.T, ch Challenge, password string, nc uint32) Credentials {
	t.Helper()
	c, err := Respond(ch, ClientParams{
		Username: testUser, Password: []byte(password), Method: "REGISTER", URI: testURI,
		CNonce: "cnonce-1", NC: nc,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// overWire sends credentials through their header form, as a real client
// would.
func overWire(t *testing.T, c Credentials) Credentials {
	t.Helper()
	parsed, err := ParseCredentials(c.Header())
	if err != nil {
		t.Fatalf("ParseCredentials(%q): %v", c.Header(), err)
	}
	return parsed
}

func TestCorrectPasswordIsAcceptedForMD5AndSHA256(t *testing.T) {
	for _, alg := range []Algorithm{MD5, SHA256} {
		t.Run(string(alg), func(t *testing.T) {
			h := newHarness(t)
			ch, err := ParseChallenge(h.challenge(t, alg).Header())
			if err != nil {
				t.Fatal(err)
			}
			c := overWire(t, answer(t, ch, testPass, 1))
			if err := h.server.Verify(context.Background(), "REGISTER", c, Password([]byte(testPass))); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

func TestStoredHA1IsAcceptedInPlaceOfThePassword(t *testing.T) {
	for _, alg := range []Algorithm{MD5, SHA256} {
		t.Run(string(alg), func(t *testing.T) {
			h := newHarness(t)
			c := answer(t, h.challenge(t, alg), testPass, 1)
			stored, err := ComputeHA1(alg, testUser, testRealm, []byte(testPass))
			if err != nil {
				t.Fatal(err)
			}
			secret, err := HA1(alg, strings.ToUpper(stored))
			if err != nil {
				t.Fatal(err)
			}
			if err := h.server.Verify(context.Background(), "REGISTER", c, secret); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

func TestHA1ForAnotherAlgorithmCannotVerify(t *testing.T) {
	h := newHarness(t)
	c := answer(t, h.challenge(t, SHA256), testPass, 1)
	stored, _ := ComputeHA1(MD5, testUser, testRealm, []byte(testPass))
	secret, err := HA1(MD5, stored)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.server.Verify(context.Background(), "REGISTER", c, secret); !errors.Is(err, ErrSecretAlgorithm) {
		t.Fatalf("err = %v, want ErrSecretAlgorithm", err)
	}
}

func TestMalformedHA1IsRefused(t *testing.T) {
	cases := []struct {
		alg Algorithm
		hex string
	}{
		{MD5, strings.Repeat("0", 31)},
		{MD5, strings.Repeat("0", 64)},
		{SHA256, strings.Repeat("0", 32)},
		{MD5, strings.Repeat("g", 32)},
		{"SHA-512-256", strings.Repeat("0", 64)},
	}
	for _, c := range cases {
		if _, err := HA1(c.alg, c.hex); err == nil {
			t.Errorf("HA1(%s, %q) accepted", c.alg, c.hex)
		}
	}
	if _, err := ComputeHA1("MD5-sess", "u", "r", nil); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("ComputeHA1 with an unsupported algorithm: err = %v", err)
	}
}

func TestWrongPasswordIsRejected(t *testing.T) {
	h := newHarness(t)
	c := answer(t, h.challenge(t, MD5), "wrong", 1)
	if err := h.server.Verify(context.Background(), "REGISTER", c, Password([]byte(testPass))); !errors.Is(err, ErrWrongResponse) {
		t.Fatalf("err = %v, want ErrWrongResponse", err)
	}
	if h.counts.Len() != 0 {
		t.Fatal("a wrong response consumed a nonce count")
	}
}

func TestResponseForAnotherMethodOrURIIsRejected(t *testing.T) {
	h := newHarness(t)
	c := answer(t, h.challenge(t, SHA256), testPass, 1)
	if err := h.server.Verify(context.Background(), "INVITE", c, Password([]byte(testPass))); !errors.Is(err, ErrWrongResponse) {
		t.Fatalf("other method: err = %v, want ErrWrongResponse", err)
	}
	c.URI = "sip:other.example"
	if err := h.server.Verify(context.Background(), "REGISTER", c, Password([]byte(testPass))); !errors.Is(err, ErrWrongResponse) {
		t.Fatalf("other uri: err = %v, want ErrWrongResponse", err)
	}
}

func TestResponseThatIsNotHexIsRejected(t *testing.T) {
	h := newHarness(t)
	c := answer(t, h.challenge(t, MD5), testPass, 1)
	for _, r := range []string{"", "zz", c.Response[:30], c.Response + "00"} {
		c.Response = r
		if err := h.server.Verify(context.Background(), "REGISTER", c, Password([]byte(testPass))); !errors.Is(err, ErrWrongResponse) {
			t.Errorf("response %q: err = %v, want ErrWrongResponse", r, err)
		}
	}
}

func TestUpperCaseHexResponseIsAccepted(t *testing.T) {
	h := newHarness(t)
	c := answer(t, h.challenge(t, MD5), testPass, 1)
	c.Response = strings.ToUpper(c.Response)
	if err := h.server.Verify(context.Background(), "REGISTER", c, Password([]byte(testPass))); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestExpiredNonceIsStaleOnlyWhenTheResponseIsRight(t *testing.T) {
	h := newHarness(t)
	ch := h.challenge(t, MD5)
	good := answer(t, ch, testPass, 1)
	bad := answer(t, ch, "wrong", 1)
	h.clock.advance(DefaultNonceLifetime + time.Second)

	if err := h.server.Verify(context.Background(), "REGISTER", good, Password([]byte(testPass))); !errors.Is(err, ErrStaleNonce) {
		t.Fatalf("right response, expired nonce: err = %v, want ErrStaleNonce", err)
	}
	// RFC 7616 §3.3: stale=true tells the client its password was right, so
	// a wrong answer must not get it.
	if err := h.server.Verify(context.Background(), "REGISTER", bad, Password([]byte(testPass))); !errors.Is(err, ErrWrongResponse) {
		t.Fatalf("wrong response, expired nonce: err = %v, want ErrWrongResponse", err)
	}
}

func TestNonceIsValidUntilTheEndOfItsLifetime(t *testing.T) {
	h := newHarness(t)
	c := answer(t, h.challenge(t, MD5), testPass, 1)
	h.clock.advance(DefaultNonceLifetime)
	if err := h.server.Verify(context.Background(), "REGISTER", c, Password([]byte(testPass))); err != nil {
		t.Fatalf("at exactly the lifetime: %v", err)
	}
}

func TestStaleChallengeSaysStale(t *testing.T) {
	h := newHarness(t)
	ch, err := h.server.Challenge(SHA256, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(ch.Header(), ", stale=true") {
		t.Fatalf("challenge %q has no stale=true", ch.Header())
	}
}

func TestReplayedNonceCountIsRejected(t *testing.T) {
	h := newHarness(t)
	ch := h.challenge(t, SHA256)
	secret := Password([]byte(testPass))
	ctx := context.Background()

	first := answer(t, ch, testPass, 1)
	if err := h.server.Verify(ctx, "REGISTER", first, secret); err != nil {
		t.Fatal(err)
	}
	if err := h.server.Verify(ctx, "REGISTER", first, secret); !errors.Is(err, ErrReplayed) {
		t.Fatalf("same nc again: err = %v, want ErrReplayed", err)
	}
	third := answer(t, ch, testPass, 3)
	if err := h.server.Verify(ctx, "REGISTER", third, secret); err != nil {
		t.Fatalf("nc 3 after 1: %v", err)
	}
	// A count that arrives late is accepted once, inside the window.
	second := answer(t, ch, testPass, 2)
	if err := h.server.Verify(ctx, "REGISTER", second, secret); err != nil {
		t.Fatalf("nc 2 after 3: %v", err)
	}
	if err := h.server.Verify(ctx, "REGISTER", second, secret); !errors.Is(err, ErrReplayed) {
		t.Fatalf("nc 2 again: err = %v, want ErrReplayed", err)
	}
	ahead := answer(t, ch, testPass, 4+NonceCountWindow)
	if err := h.server.Verify(ctx, "REGISTER", ahead, secret); err != nil {
		t.Fatal(err)
	}
	for _, nc := range []uint32{2, 4} { // used, and unused, both below the window now
		if err := h.server.Verify(ctx, "REGISTER", answer(t, ch, testPass, nc), secret); !errors.Is(err, ErrReplayed) {
			t.Fatalf("nc %d below the window: err = %v, want ErrReplayed", nc, err)
		}
	}
}

func TestNonceNotIssuedByThisServerIsInvalid(t *testing.T) {
	h := newHarness(t)
	ch := h.challenge(t, MD5)

	other := newHarness(t)
	otherKey := bytes.Repeat([]byte{0x55}, 32)
	other.server.key = secret.Seal(&otherKey)
	foreign := other.challenge(t, MD5)

	otherRealm, err := NewServer(ServerConfig{Realm: "other.example", NonceKey: secret.NewKey(testKey), NonceCounts: h.counts, Now: h.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	moved, err := otherRealm.Challenge(MD5, false)
	if err != nil {
		t.Fatal(err)
	}
	moved.Realm = testRealm // a nonce from another realm, presented here

	tampered := ch
	b := []byte(tampered.Nonce)
	b[10] ^= 0x01
	tampered.Nonce = string(b)

	cases := map[string]Challenge{
		"another key":            foreign,
		"another realm":          moved,
		"tampered":               tampered,
		"empty (first REGISTER)": {Realm: testRealm, Nonce: "", Opaque: ch.Opaque, QOP: []string{"auth"}},
		"not base64":             {Realm: testRealm, Nonce: "%%%", Opaque: ch.Opaque, QOP: []string{"auth"}},
		"truncated":              {Realm: testRealm, Nonce: ch.Nonce[:20], Opaque: ch.Opaque, QOP: []string{"auth"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			creds := answer(t, c, testPass, 1)
			if err := h.server.Verify(context.Background(), "REGISTER", creds, Password([]byte(testPass))); !errors.Is(err, ErrInvalidNonce) {
				t.Fatalf("err = %v, want ErrInvalidNonce", err)
			}
		})
	}
}

func TestNonceFromTheFutureIsInvalid(t *testing.T) {
	h := newHarness(t)
	h.clock.advance(maxClockSkew + time.Second)
	ch := h.challenge(t, MD5)
	h.clock.advance(-(maxClockSkew + time.Second))
	c := answer(t, ch, testPass, 1)
	if err := h.server.Verify(context.Background(), "REGISTER", c, Password([]byte(testPass))); !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("err = %v, want ErrInvalidNonce", err)
	}
}

func TestNonceFromAnInstanceSlightlyAheadIsAccepted(t *testing.T) {
	h := newHarness(t)
	h.clock.advance(maxClockSkew)
	ch := h.challenge(t, MD5)
	h.clock.advance(-maxClockSkew)
	c := answer(t, ch, testPass, 1)
	if err := h.server.Verify(context.Background(), "REGISTER", c, Password([]byte(testPass))); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestAnotherInstanceWithTheSameKeyVerifiesTheNonce(t *testing.T) {
	// ADR 0005: the second REGISTER may reach another scscf instance.
	a, b := newHarness(t), newHarness(t)
	b.server.counts = a.counts
	c := answer(t, a.challenge(t, SHA256), testPass, 1)
	if err := b.server.Verify(context.Background(), "REGISTER", c, Password([]byte(testPass))); err != nil {
		t.Fatalf("Verify on the other instance: %v", err)
	}
}

func TestOpaqueMustBeReturnedUnchanged(t *testing.T) {
	h := newHarness(t)
	ch := h.challenge(t, MD5)
	for _, opaque := range []string{"", "x", h.challenge(t, MD5).Opaque} {
		c := ch
		c.Opaque = opaque
		creds := answer(t, c, testPass, 1)
		if err := h.server.Verify(context.Background(), "REGISTER", creds, Password([]byte(testPass))); !errors.Is(err, ErrInvalidNonce) {
			t.Errorf("opaque %q: err = %v, want ErrInvalidNonce", opaque, err)
		}
	}
}

func TestCredentialsThatBreakTheProtocolAreRejectedBeforeAnyCryptography(t *testing.T) {
	h := newHarness(t)
	good := answer(t, h.challenge(t, MD5), testPass, 1)
	cases := []struct {
		name   string
		mutate func(*Credentials)
		want   error
	}{
		{"another realm", func(c *Credentials) { c.Realm = "example.org" }, ErrRealmMismatch},
		{"unsupported algorithm", func(c *Credentials) { c.Algorithm = "MD5-sess" }, ErrUnsupportedAlgorithm},
		{"no qop", func(c *Credentials) { c.QOP = "" }, ErrUnsupportedQOP},
		{"auth-int", func(c *Credentials) { c.QOP = "auth-int" }, ErrUnsupportedQOP},
		{"no nc", func(c *Credentials) { c.NC = 0 }, ErrMalformed},
		{"no cnonce", func(c *Credentials) { c.CNonce = "" }, ErrMalformed},
		{"auts with MD5", func(c *Credentials) { c.AUTS = make([]byte, 14) }, ErrMalformed},
		{"AKA credentials sent to Verify", func(c *Credentials) { c.Algorithm = AKAv1MD5 }, ErrUseVerifyAKA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			tc.mutate(&c)
			if err := h.server.Verify(context.Background(), "REGISTER", c, Password([]byte(testPass))); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestQOPIsMatchedWithoutRegardToCase(t *testing.T) {
	h := newHarness(t)
	ch := h.challenge(t, MD5)
	c := answer(t, ch, testPass, 1)
	c.QOP = "AUTH"
	c.Response = response(MD5, ha1(MD5, testUser, testRealm, []byte(testPass)), ch.Nonce, "00000001", c.CNonce, "AUTH", "REGISTER", testURI)
	if err := h.server.Verify(context.Background(), "REGISTER", c, Password([]byte(testPass))); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestZeroSecretIsRefused(t *testing.T) {
	h := newHarness(t)
	c := answer(t, h.challenge(t, MD5), testPass, 1)
	if err := h.server.Verify(context.Background(), "REGISTER", c, Secret{}); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("err = %v, want ErrNoSecret", err)
	}
}

type failingCounts struct{}

func (failingCounts) Advance(context.Context, string, string, uint32, time.Time) (bool, error) {
	return false, errors.New("table unavailable")
}

func TestNonceCountStoreFailureFailsVerification(t *testing.T) {
	h := newHarness(t)
	h.server.counts = failingCounts{}
	c := answer(t, h.challenge(t, MD5), testPass, 1)
	err := h.server.Verify(context.Background(), "REGISTER", c, Password([]byte(testPass)))
	if err == nil || !strings.Contains(err.Error(), "table unavailable") {
		t.Fatalf("err = %v, want the store's error", err)
	}
}

type recordingCounts struct {
	username string
	nonce    string
	nc       uint32
	expires  time.Time
}

func (r *recordingCounts) Advance(_ context.Context, username, nonce string, nc uint32, expires time.Time) (bool, error) {
	r.username, r.nonce, r.nc, r.expires = username, nonce, nc, expires
	return true, nil
}

func TestNonceCountIsRecordedUntilTheNonceExpires(t *testing.T) {
	h := newHarness(t)
	rec := &recordingCounts{}
	h.server.counts = rec
	issued := h.clock.now()
	ch := h.challenge(t, MD5)
	h.clock.advance(time.Minute)
	if err := h.server.Verify(context.Background(), "REGISTER", answer(t, ch, testPass, 9), Password([]byte(testPass))); err != nil {
		t.Fatal(err)
	}
	if rec.username != testUser || rec.nonce != ch.Nonce || rec.nc != 9 || !rec.expires.Equal(issued.Add(DefaultNonceLifetime)) {
		t.Fatalf("recorded %+v", rec)
	}
}

func TestChallengeIsForQOPAuthWithOpaque(t *testing.T) {
	h := newHarness(t)
	ch := h.challenge(t, SHA256)
	if ch.Realm != testRealm || ch.Algorithm != SHA256 || len(ch.QOP) != 1 || ch.QOP[0] != "auth" || ch.Opaque == "" || ch.Stale {
		t.Fatalf("challenge %+v", ch)
	}
	if again := h.challenge(t, SHA256); again.Nonce == ch.Nonce {
		t.Fatal("two challenges share a nonce")
	}
}

func TestChallengeRefusesAKAAndUnknownAlgorithms(t *testing.T) {
	h := newHarness(t)
	for _, alg := range []Algorithm{AKAv1MD5, "MD5-sess", ""} {
		if _, err := h.server.Challenge(alg, false); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Errorf("Challenge(%q): err = %v", alg, err)
		}
	}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New("entropy exhausted") }

func TestChallengeFailsWhenRandomnessFails(t *testing.T) {
	h := newHarness(t)
	h.server.random = brokenReader{}
	if _, err := h.server.Challenge(MD5, false); err == nil {
		t.Fatal("challenge issued without randomness")
	}
}

func TestServerConfigIsValidated(t *testing.T) {
	counts := NewMemoryNonceCounts(nil)
	good := ServerConfig{Realm: testRealm, NonceKey: secret.NewKey(testKey), NonceCounts: counts}
	cases := map[string]func(*ServerConfig){
		"empty realm":       func(c *ServerConfig) { c.Realm = "" },
		"realm with CR LF":  func(c *ServerConfig) { c.Realm = "a\r\nb" },
		"long realm":        func(c *ServerConfig) { c.Realm = strings.Repeat("r", maxRealmLength+1) },
		"short key":         func(c *ServerConfig) { c.NonceKey = secret.NewKey(testKey[:MinNonceKeySize-1]) },
		"negative lifetime": func(c *ServerConfig) { c.NonceLifetime = -time.Second },
		"no store":          func(c *ServerConfig) { c.NonceCounts = nil },
	}
	for name, mutate := range cases {
		cfg := good
		mutate(&cfg)
		if _, err := NewServer(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s, err := NewServer(good)
	if err != nil {
		t.Fatal(err)
	}
	if s.Realm() != testRealm || s.lifetime != DefaultNonceLifetime || s.now == nil || s.random == nil {
		t.Fatalf("defaults not applied")
	}
}

func TestServerCopiesTheNonceKey(t *testing.T) {
	key := bytes.Clone(testKey)
	s, err := NewServer(ServerConfig{Realm: testRealm, NonceKey: secret.NewKey(key), NonceCounts: NewMemoryNonceCounts(nil)})
	if err != nil {
		t.Fatal(err)
	}
	ch, err := s.Challenge(MD5, false)
	if err != nil {
		t.Fatal(err)
	}
	key[0] ^= 0xff
	if err := s.Verify(context.Background(), "REGISTER", answer(t, ch, testPass, 1), Password([]byte(testPass))); err != nil {
		t.Fatalf("changing the caller's key slice changed the server: %v", err)
	}
}

func TestCustomNonceLifetimeIsHonoured(t *testing.T) {
	h := newHarness(t)
	h.server.lifetime = 10 * time.Second
	c := answer(t, h.challenge(t, MD5), testPass, 1)
	h.clock.advance(11 * time.Second)
	if err := h.server.Verify(context.Background(), "REGISTER", c, Password([]byte(testPass))); !errors.Is(err, ErrStaleNonce) {
		t.Fatalf("err = %v, want ErrStaleNonce", err)
	}
}

func TestRespondRefusesWhatItCannotAnswer(t *testing.T) {
	ch := Challenge{Realm: "r", Nonce: "n", Algorithm: MD5, QOP: []string{"auth"}}
	ok := ClientParams{Username: "u", Password: []byte("p"), Method: "REGISTER", URI: "sip:r", CNonce: "c", NC: 1}
	cases := []struct {
		name   string
		ch     func(*Challenge)
		params func(*ClientParams)
		want   error
	}{
		{"unsupported algorithm", func(c *Challenge) { c.Algorithm = "SHA-512-256" }, nil, ErrUnsupportedAlgorithm},
		{"no qop", func(c *Challenge) { c.QOP = nil }, nil, ErrUnsupportedQOP},
		{"only auth-int", func(c *Challenge) { c.QOP = []string{"auth-int"} }, nil, ErrUnsupportedQOP},
		{"nc zero", nil, func(p *ClientParams) { p.NC = 0 }, nil},
		{"no cnonce", nil, func(p *ClientParams) { p.CNonce = "" }, nil},
		{"auts without AKA", nil, func(p *ClientParams) { p.AUTS = make([]byte, 14) }, nil},
		{"control character", nil, func(p *ClientParams) { p.Username = "u\r\nX: y" }, nil},
		{"control character in the challenge", func(c *Challenge) { c.Nonce = "n\x00" }, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, p := ch, ok
			if tc.ch != nil {
				tc.ch(&c)
			}
			if tc.params != nil {
				tc.params(&p)
			}
			_, err := Respond(c, p)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	aka := ch
	aka.Algorithm = AKAv1MD5
	short := ok
	short.AUTS = make([]byte, 13)
	if _, err := Respond(aka, short); err == nil {
		t.Fatal("13-byte AUTS accepted")
	}
}

func TestRespondTreatsAMissingAlgorithmAsMD5(t *testing.T) {
	ch := Challenge{Realm: "r", Nonce: "n", QOP: []string{"auth-int", "AUTH"}}
	c, err := Respond(ch, ClientParams{Username: "u", Password: []byte("p"), Method: "M", URI: "u", CNonce: "c", NC: 1})
	if err != nil {
		t.Fatal(err)
	}
	if c.Algorithm != MD5 || c.QOP != "auth" {
		t.Fatalf("credentials %+v", c)
	}
}

func TestNewCNonceIsRandomAndReportsReaderFailure(t *testing.T) {
	r := rand.NewChaCha8([32]byte{2})
	a, err := NewCNonce(r)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewCNonce(r)
	if a == b || len(a) != 22 || !isToken(a) {
		t.Fatalf("cnonces %q %q", a, b)
	}
	if _, err := NewCNonce(brokenReader{}); err == nil {
		t.Fatal("cnonce made without randomness")
	}
}

func TestOneUserCannotUseUpAnotherUsersNonceCount(t *testing.T) {
	// The security review's scenario: a second user answers a nonce issued to
	// the first with nc=ffffffff. Counts are per (username, nonce).
	h := newHarness(t)
	ch := h.challenge(t, SHA256)
	ctx := context.Background()
	other, err := Respond(ch, ClientParams{
		Username: "001010000000002@ims.mnc001.mcc001.3gppnetwork.org", Password: []byte("other"),
		Method: "REGISTER", URI: testURI, CNonce: "x", NC: 0xffffffff,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.server.Verify(ctx, "REGISTER", other, Password([]byte("other"))); err != nil {
		t.Fatal(err)
	}
	if err := h.server.Verify(ctx, "REGISTER", answer(t, ch, testPass, 1), Password([]byte(testPass))); err != nil {
		t.Fatalf("victim's nc 1 after another user's nc ffffffff: %v", err)
	}
}

func TestOpaqueIsBoundToAlgorithmAndRealm(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// A SHA-256 challenge answered under MD5 (a downgrade) is refused.
	ch := h.challenge(t, SHA256)
	ch.Algorithm = MD5
	if err := h.server.Verify(ctx, "REGISTER", answer(t, ch, testPass, 1), Password([]byte(testPass))); !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("algorithm switched: err = %v, want ErrInvalidNonce", err)
	}

	// A default AKA nonce, which has no tag, issued for another realm that
	// shares the key, is refused although the nonce itself decodes.
	other, err := NewServer(ServerConfig{Realm: "other.example", NonceKey: secret.NewKey(testKey), NonceCounts: h.counts, Now: h.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	aka, _ := other.AKAChallenge(make([]byte, 16), make([]byte, 16), false)
	aka.Realm = testRealm
	c, err := Respond(aka, ClientParams{Username: testUser, Password: []byte("res"), Method: "REGISTER", URI: testURI, CNonce: "c", NC: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.server.VerifyAKA(ctx, "REGISTER", c, []byte("res"), h.vectorExpires); !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("AKA nonce from another realm: err = %v, want ErrInvalidNonce", err)
	}
}

func TestFirstIMSRegisterIsAnInvalidNonceWhateverElseItLacks(t *testing.T) {
	// TS 24.229 §5.1.1.2.2/§5.1.1.2.3: identity only, no qop, nc or cnonce.
	h := newHarness(t)
	c, err := ParseCredentials(`Digest username="` + testUser + `", realm="` + testRealm +
		`", uri="` + testURI + `", nonce="", response=""`)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := h.server.Check(c); !errors.Is(err, ErrInvalidNonce) {
		t.Errorf("Check: err = %v, want ErrInvalidNonce", err)
	}
	if err := h.server.Verify(ctx, "REGISTER", c, Password([]byte(testPass))); !errors.Is(err, ErrInvalidNonce) {
		t.Errorf("Verify: err = %v, want ErrInvalidNonce", err)
	}
	c.Algorithm = AKAv1MD5
	if err := h.server.VerifyAKA(ctx, "REGISTER", c, []byte("res"), h.vectorExpires); !errors.Is(err, ErrInvalidNonce) {
		t.Errorf("VerifyAKA: err = %v, want ErrInvalidNonce", err)
	}
	if err := h.server.Verify(ctx, "REGISTER", c, Password([]byte(testPass))); !errors.Is(err, ErrInvalidNonce) {
		t.Errorf("Verify with algorithm=AKAv1-MD5: err = %v, want ErrInvalidNonce", err)
	}
	c.Realm = "another.example"
	if err := h.server.Check(c); !errors.Is(err, ErrInvalidNonce) {
		t.Errorf("empty nonce for another realm: err = %v, want ErrInvalidNonce first", err)
	}
}

func TestCheckRejectsForgedNoncesBeforeAnySecretIsRead(t *testing.T) {
	h := newHarness(t)
	ch := h.challenge(t, SHA256)
	good := answer(t, ch, testPass, 1)
	if err := h.server.Check(good); err != nil {
		t.Fatalf("Check on genuine credentials: %v", err)
	}
	forged := good
	forged.Opaque = "AAAAAAAAAAAAAAAA"
	if err := h.server.Check(forged); !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("Check on a forged opaque: err = %v, want ErrInvalidNonce", err)
	}
	if h.counts.Len() != 0 {
		t.Fatal("Check consumed a nonce count")
	}
}
