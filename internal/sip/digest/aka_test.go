package digest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/milenage"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

// TS 35.208 §4.3.1, test set 1.
const (
	set1K    = "465b5ce8b199b49faa5f0a2ee238a6bc"
	set1OPc  = "cd63cb71954a9f4e48a5994e37a02baf"
	set1RAND = "23553cbe9637a89d218ae64dae47bf35"
	set1SQN  = "ff9bb4d0b607"
	set1AMF  = "b9b9"
	set1RES  = "a54211d5e3ba50bf"
)

// set1Seen is a card counter just below test set 1's SQN, so the card
// accepts the set 1 challenge as fresh.
func set1Seen(t *testing.T) milenage.SQN {
	t.Helper()
	s, err := milenage.NewSQN(milenage.SQNFromBytes([6]byte{0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07}).SEQ()-1, 0)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// vector is a milenage.Vector unpacked into arrays the tests can slice.
type vector struct {
	RAND, AUTN [16]byte
	XRES       [8]byte
	CK, IK     [16]byte
}

func set1(t *testing.T) (milenage.Milenage, vector) {
	t.Helper()
	b := func(s string) []byte {
		v, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	m := milenage.New([16]byte(b(set1K)), [16]byte(b(set1OPc)))
	v := m.Vector([16]byte(b(set1RAND)), milenage.SQNFromBytes([6]byte(b(set1SQN))), [2]byte(b(set1AMF)))
	return m, vector{RAND: v.RAND(), AUTN: v.AUTN(), XRES: v.XRES(), CK: v.CK(), IK: v.IK()}
}

// card plays the ISIM and the client: it checks AUTN, and either answers
// with RES or reports a synchronisation failure, as tools/rcs-sim will.
func card(t *testing.T, m milenage.Milenage, ch Challenge, highest milenage.SQN) Credentials {
	t.Helper()
	rand, autn, err := ParseAKANonce(ch.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	sqn, err := m.CheckAUTN(rand, autn)
	if err != nil {
		t.Fatalf("card rejected AUTN: %v", err)
	}
	p := ClientParams{Username: testUser, Method: "REGISTER", URI: testURI, CNonce: "aka-cnonce", NC: 1}
	if milenage.Fresh(sqn, highest) {
		res := m.F2(rand)
		p.Password = secret.NewKey(res[:])
	} else {
		auts := m.AUTS(rand, highest)
		p.AUTS = auts[:]
	}
	c, err := Respond(ch, p)
	if err != nil {
		t.Fatal(err)
	}
	return overWire(t, c)
}

func TestAKARoundTripWithTestSet1Authenticates(t *testing.T) {
	h := newHarness(t)
	m, v := set1(t)
	if hex.EncodeToString(v.XRES[:]) != set1RES {
		t.Fatalf("XRES = %x, want test set 1 f2", v.XRES)
	}
	ch, err := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := ParseChallenge(ch.Header())
	if err != nil {
		t.Fatal(err)
	}
	if wire.Algorithm != AKAv1MD5 {
		t.Fatalf("algorithm = %s", wire.Algorithm)
	}

	c := card(t, m, wire, set1Seen(t))
	if err := h.server.VerifyAKA(context.Background(), "REGISTER", c, v.XRES[:], h.vectorExpires); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestDefaultAKANonceIsExactlyBase64OfRANDAndAUTN(t *testing.T) {
	h := newHarness(t)
	_, v := set1(t)
	ch, err := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	if err != nil {
		t.Fatal(err)
	}
	want := base64.StdEncoding.EncodeToString(append(v.RAND[:], v.AUTN[:]...))
	if ch.Nonce != want {
		t.Fatalf("nonce = %s, want base64(RAND ‖ AUTN) = %s", ch.Nonce, want)
	}
	rand, autn, err := ParseAKANonce(ch.Nonce)
	if err != nil || rand != v.RAND || autn != v.AUTN {
		t.Fatalf("ParseAKANonce = %x %x %v", rand, autn, err)
	}
}

func TestDefaultAKANonceLivesAsLongAsTheStoredVector(t *testing.T) {
	// The nonce has no issue time; the vector's expiry in auth-challenges
	// (ADR 0005) is the only limit, even past the nonce lifetime.
	h := newHarness(t)
	m, v := set1(t)
	expires := h.clock.now().Add(3 * DefaultNonceLifetime)
	ch, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	c := card(t, m, ch, set1Seen(t))
	h.clock.advance(2 * DefaultNonceLifetime)
	if err := h.server.VerifyAKA(context.Background(), "REGISTER", c, v.XRES[:], expires); err != nil {
		t.Fatalf("VerifyAKA before the vector expires: %v", err)
	}
}

func TestAKAAfterTheVectorExpiresIsStale(t *testing.T) {
	h := newHarness(t)
	m, v := set1(t)
	expires := h.clock.now().Add(30 * time.Second)
	ch, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	c := card(t, m, ch, set1Seen(t))
	h.clock.advance(31 * time.Second)
	if err := h.server.VerifyAKA(context.Background(), "REGISTER", c, v.XRES[:], expires); !errors.Is(err, ErrStaleNonce) {
		t.Fatalf("err = %v, want ErrStaleNonce", err)
	}
}

func TestAKASynchronisationFailureOnAnExpiredVectorIsStale(t *testing.T) {
	// A stale challenge must not keep driving resynchronisation at hss.
	h := newHarness(t)
	m, v := set1(t)
	expires := h.clock.now().Add(30 * time.Second)
	ch, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	ahead, _ := milenage.NewSQN(set1Seen(t).SEQ()+10, 0)
	c := card(t, m, ch, ahead)
	h.clock.advance(time.Minute)
	if err := h.server.VerifyAKA(context.Background(), "REGISTER", c, v.XRES[:], expires); !errors.Is(err, ErrStaleNonce) {
		t.Fatalf("err = %v, want ErrStaleNonce", err)
	}
}

func TestAKAReplayAfterTheNonceLifetimeIsStillRejected(t *testing.T) {
	// The security review's scenario: a vector kept longer than the nonce
	// lifetime, and a captured Authorization resent once a lifetime-bound
	// count would have gone. The count lives as long as the vector.
	h := newHarness(t)
	m, v := set1(t)
	expires := h.clock.now().Add(time.Hour)
	ch, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	c := card(t, m, ch, set1Seen(t))
	ctx := context.Background()
	if err := h.server.VerifyAKA(ctx, "REGISTER", c, v.XRES[:], expires); err != nil {
		t.Fatal(err)
	}
	if err := h.server.VerifyAKA(ctx, "REGISTER", c, v.XRES[:], expires); !errors.Is(err, ErrReplayed) {
		t.Fatalf("immediate replay: err = %v, want ErrReplayed", err)
	}
	h.clock.advance(DefaultNonceLifetime + 2*time.Minute)
	if err := h.server.VerifyAKA(ctx, "REGISTER", c, v.XRES[:], expires); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replay after the nonce lifetime: err = %v, want ErrReplayed", err)
	}
	h.clock.advance(time.Hour)
	if err := h.server.VerifyAKA(ctx, "REGISTER", c, v.XRES[:], expires); !errors.Is(err, ErrStaleNonce) {
		t.Fatalf("replay after the vector expired: err = %v, want ErrStaleNonce", err)
	}
}

func TestAKANonceCountIsKeptUntilTheVectorExpires(t *testing.T) {
	h := newHarness(t)
	rec := &recordingCounts{}
	h.server.counts = rec
	m, v := set1(t)
	expires := h.clock.now().Add(time.Hour)
	ch, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	c := card(t, m, ch, set1Seen(t))
	if err := h.server.VerifyAKA(context.Background(), "REGISTER", c, v.XRES[:], expires); err != nil {
		t.Fatal(err)
	}
	if !rec.expires.Equal(expires) || rec.username != testUser || rec.nonce != ch.Nonce {
		t.Fatalf("recorded %+v, want the vector's expiry for (user, nonce)", rec)
	}
}

func TestAKANonceWithServerDataEndsAtTheEarlierOfNonceAndVector(t *testing.T) {
	h := newHarness(t)
	h.server.akaServerData = true
	rec := &recordingCounts{}
	h.server.counts = rec
	m, v := set1(t)
	issued := h.clock.now()
	ch, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	c := card(t, m, ch, set1Seen(t))
	if err := h.server.VerifyAKA(context.Background(), "REGISTER", c, v.XRES[:], issued.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !rec.expires.Equal(issued.Add(DefaultNonceLifetime)) {
		t.Fatalf("count kept until %v, want the nonce lifetime", rec.expires)
	}
}

func TestVerifyAKARefusesWhatItCannotCheck(t *testing.T) {
	h := newHarness(t)
	m, v := set1(t)
	ch, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	c := card(t, m, ch, set1Seen(t))
	ctx := context.Background()
	if err := h.server.VerifyAKA(ctx, "REGISTER", c, v.XRES[:], time.Time{}); err == nil {
		t.Error("accepted without the vector's expiry")
	}
	if err := h.server.VerifyAKA(ctx, "REGISTER", c, nil, h.vectorExpires); !errors.Is(err, ErrNoSecret) {
		t.Errorf("no XRES: err = %v, want ErrNoSecret", err)
	}
	digest := answer(t, h.challenge(t, MD5), testPass, 1)
	if err := h.server.VerifyAKA(ctx, "REGISTER", digest, v.XRES[:], h.vectorExpires); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("MD5 credentials: err = %v, want ErrUnsupportedAlgorithm", err)
	}
	digestNonce := h.challenge(t, MD5)
	digestNonce.Algorithm = AKAv1MD5
	if err := h.server.VerifyAKA(ctx, "REGISTER", answer(t, digestNonce, "res", 1), []byte("res"), h.vectorExpires); !errors.Is(err, ErrInvalidNonce) {
		t.Errorf("AKA answer to a Digest nonce: err = %v, want ErrInvalidNonce", err)
	}
	if err := h.server.Verify(ctx, "REGISTER", c, Password(v.XRES[:])); !errors.Is(err, ErrUseVerifyAKA) {
		t.Errorf("Verify with AKA credentials: err = %v, want ErrUseVerifyAKA", err)
	}
}

func TestAKAServerDataIsOptIn(t *testing.T) {
	s, err := NewServer(ServerConfig{Realm: testRealm, NonceKey: secret.NewKey(testKey), NonceCounts: NewMemoryNonceCounts(nil)})
	if err != nil || s.akaServerData {
		t.Fatalf("server data on by default (err %v)", err)
	}
	s, err = NewServer(ServerConfig{Realm: testRealm, NonceKey: secret.NewKey(testKey), NonceCounts: NewMemoryNonceCounts(nil), AKAServerData: true})
	if err != nil || !s.akaServerData {
		t.Fatalf("AKAServerData not applied (err %v)", err)
	}
}

func TestAKANonceWithServerDataRoundTripsAndExpires(t *testing.T) {
	h := newHarness(t)
	h.server.akaServerData = true
	m, v := set1(t)
	ch, err := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(ch.Nonce)
	if err != nil || len(raw) != akaTaggedLen || !bytes.Equal(raw[:32], append(v.RAND[:], v.AUTN[:]...)) {
		t.Fatalf("nonce %x does not start with RAND ‖ AUTN followed by server data", raw)
	}
	c := card(t, m, ch, set1Seen(t))
	if err := h.server.VerifyAKA(context.Background(), "REGISTER", c, v.XRES[:], h.vectorExpires); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	ch, _ = h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	c = card(t, m, ch, set1Seen(t))
	h.clock.advance(DefaultNonceLifetime + time.Second)
	if err := h.server.VerifyAKA(context.Background(), "REGISTER", c, v.XRES[:], h.vectorExpires); !errors.Is(err, ErrStaleNonce) {
		t.Fatalf("expired nonce with server data: err = %v, want ErrStaleNonce", err)
	}
}

func TestAKANonceOfTheFormNotConfiguredIsInvalid(t *testing.T) {
	plain, tagged := newHarness(t), newHarness(t)
	tagged.server.akaServerData = true
	m, v := set1(t)
	for name, pair := range map[string][2]*harness{
		"server data sent to a plain server":  {tagged, plain},
		"plain nonce sent to a tagged server": {plain, tagged},
	} {
		t.Run(name, func(t *testing.T) {
			issuer, verifier := pair[0], pair[1]
			ch, _ := issuer.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
			c := card(t, m, ch, set1Seen(t))
			if err := verifier.server.VerifyAKA(context.Background(), "REGISTER", c, v.XRES[:], verifier.vectorExpires); !errors.Is(err, ErrInvalidNonce) {
				t.Fatalf("err = %v, want ErrInvalidNonce", err)
			}
		})
	}
}

func TestDefaultAKANonceOfTheWrongLengthIsInvalid(t *testing.T) {
	h := newHarness(t)
	for _, n := range []int{31, 33, akaTaggedLen} {
		nonce := base64.StdEncoding.EncodeToString(make([]byte, n))
		ch := Challenge{Realm: testRealm, Nonce: nonce, Opaque: h.server.opaqueFor(AKAv1MD5, nonce), Algorithm: AKAv1MD5, QOP: []string{"auth"}}
		c := answer(t, ch, "res", 1)
		if err := h.server.VerifyAKA(context.Background(), "REGISTER", c, []byte("res"), h.vectorExpires); !errors.Is(err, ErrInvalidNonce) {
			t.Errorf("%d-byte nonce: err = %v, want ErrInvalidNonce", n, err)
		}
	}
}

func TestAKAWithTheWrongRESIsRejected(t *testing.T) {
	h := newHarness(t)
	m, v := set1(t)
	ch, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	c := card(t, m, ch, set1Seen(t))
	wrong := v.XRES
	wrong[0] ^= 0x01
	if err := h.server.VerifyAKA(context.Background(), "REGISTER", c, wrong[:], h.vectorExpires); !errors.Is(err, ErrWrongResponse) {
		t.Fatalf("err = %v, want ErrWrongResponse", err)
	}
}

func TestAKASynchronisationFailureExposesAUTSForResynchronisation(t *testing.T) {
	h := newHarness(t)
	m, v := set1(t)
	ch, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)

	// The card has already seen a later SEQ than the one in AUTN.
	cardHighest, _ := milenage.NewSQN(set1Seen(t).SEQ()+10, 0)
	c := card(t, m, ch, cardHighest)
	if len(c.AUTS) == 0 {
		t.Fatal("card did not report a synchronisation failure")
	}

	err := h.server.VerifyAKA(context.Background(), "REGISTER", c, v.XRES[:], h.vectorExpires)
	var sync *SyncFailure
	if !errors.As(err, &sync) {
		t.Fatalf("err = %v, want *SyncFailure", err)
	}
	if sync.RAND != v.RAND {
		t.Fatalf("SyncFailure RAND = %x, want the challenge RAND", sync.RAND)
	}
	// hss verifies AUTS against the RAND of the rejected challenge.
	sqnMS, err := m.VerifyAUTS(sync.RAND, sync.AUTS)
	if err != nil {
		t.Fatalf("hss rejected AUTS: %v", err)
	}
	if sqnMS != cardHighest {
		t.Fatalf("SQN_MS = %x, want %x", uint64(sqnMS), uint64(cardHighest))
	}
	// Resending the same auts credentials must not trigger another
	// resynchronisation round trip.
	if err := h.server.VerifyAKA(context.Background(), "REGISTER", c, v.XRES[:], h.vectorExpires); !errors.Is(err, ErrReplayed) {
		t.Fatalf("resent auts: err = %v, want ErrReplayed", err)
	}
}

func TestForgedAUTSCannotBurnTheVictimsNonceCount(t *testing.T) {
	// QA's scenario on 1ac2cd9: someone who saw the 401 sends auts
	// credentials in the victim's name with nc=ffffffff. They need no secret
	// (empty password), so they must not make the victim's genuine nc=1 a
	// replay. Resending them is still refused.
	h := newHarness(t)
	m, v := set1(t)
	ch, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	forged, err := Respond(ch, ClientParams{
		Username: testUser, Method: "REGISTER", URI: testURI,
		CNonce: "evil", NC: 0xffffffff, AUTS: bytes.Repeat([]byte{0x42}, 14),
	})
	if err != nil {
		t.Fatal(err)
	}
	forged = overWire(t, forged)
	ctx := context.Background()
	var sf *SyncFailure
	if err := h.server.VerifyAKA(ctx, "REGISTER", forged, v.XRES[:], h.vectorExpires); !errors.As(err, &sf) {
		t.Fatalf("forged auts: err = %v, want *SyncFailure", err)
	}
	if err := h.server.VerifyAKA(ctx, "REGISTER", forged, v.XRES[:], h.vectorExpires); !errors.Is(err, ErrReplayed) {
		t.Fatalf("resent forged auts: err = %v, want ErrReplayed", err)
	}
	genuine := card(t, m, ch, set1Seen(t))
	if err := h.server.VerifyAKA(ctx, "REGISTER", genuine, v.XRES[:], h.vectorExpires); err != nil {
		t.Fatalf("victim's genuine answer after a forged auts: %v", err)
	}
}

func TestExpiredTaggedAKANonceWithAUTSIsStaleNotASyncFailure(t *testing.T) {
	h := newHarness(t)
	h.server.akaServerData = true
	m, v := set1(t)
	ch, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	ahead, _ := milenage.NewSQN(set1Seen(t).SEQ()+10, 0)
	c := card(t, m, ch, ahead)
	h.clock.advance(DefaultNonceLifetime + time.Second)
	if err := h.server.VerifyAKA(context.Background(), "REGISTER", c, v.XRES[:], h.vectorExpires); !errors.Is(err, ErrStaleNonce) {
		t.Fatalf("err = %v, want ErrStaleNonce", err)
	}
}

func TestAKASynchronisationFailureMustUseTheEmptyPassword(t *testing.T) {
	h := newHarness(t)
	_, v := set1(t)
	ch, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	c, err := Respond(ch, ClientParams{Username: testUser, Password: secret.NewKey(v.XRES[:]), Method: "REGISTER", URI: testURI, CNonce: "c", NC: 1})
	if err != nil {
		t.Fatal(err)
	}
	c.AUTS = make([]byte, 14) // auts added, but the response was computed with RES
	if err := h.server.VerifyAKA(context.Background(), "REGISTER", c, v.XRES[:], h.vectorExpires); !errors.Is(err, ErrWrongResponse) {
		t.Fatalf("err = %v, want ErrWrongResponse", err)
	}
}

func TestAKAAUTSOfTheWrongLengthIsMalformed(t *testing.T) {
	h := newHarness(t)
	m, v := set1(t)
	ch, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	c := card(t, m, ch, set1Seen(t))
	c.AUTS = make([]byte, 11) // the length of the illustrative auts in RFC 3310 §4
	if err := h.server.VerifyAKA(context.Background(), "REGISTER", c, v.XRES[:], h.vectorExpires); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestDigestAlgorithmOnAnAKANonceIsInvalid(t *testing.T) {
	h := newHarness(t)
	_, v := set1(t)
	ch, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	ch.Algorithm = MD5
	c := answer(t, ch, string(v.XRES[:]), 1)
	if err := h.server.Verify(context.Background(), "REGISTER", c, Password(v.XRES[:])); !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("err = %v, want ErrInvalidNonce", err)
	}
}

// forgeRAND swaps another RAND into a genuine AKA nonce and answers it with the
// RES for that RAND, as an attacker replaying a captured AUTN would.
func forgeRAND(t *testing.T, h *harness, m milenage.Milenage, v vector, fixOpaque bool) (Credentials, []byte) {
	t.Helper()
	ch, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	otherRAND := v.RAND
	otherRAND[0] ^= 0xff
	forged, _ := h.server.AKAChallenge(otherRAND[:], v.AUTN[:], false)
	raw := []byte(ch.Nonce)
	copy(raw[:20], forged.Nonce[:20])
	ch.Nonce = string(raw)
	if fixOpaque {
		// Only a holder of the nonce key could do this.
		ch.Opaque = h.server.opaqueFor(AKAv1MD5, ch.Nonce)
	}
	res := m.F2(otherRAND)
	c, err := Respond(ch, ClientParams{Username: testUser, Password: secret.NewKey(res[:]), Method: "REGISTER", URI: testURI, CNonce: "c", NC: 1})
	if err != nil {
		t.Fatal(err)
	}
	return c, res[:]
}

func TestTamperedAKANonceIsInvalid(t *testing.T) {
	h := newHarness(t)
	m, v := set1(t)
	c, res := forgeRAND(t, h, m, v, false)
	if err := h.server.VerifyAKA(context.Background(), "REGISTER", c, res, h.vectorExpires); !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("err = %v, want ErrInvalidNonce", err)
	}
}

func TestTamperedAKANonceWithServerDataIsInvalidEvenWithAMatchingOpaque(t *testing.T) {
	h := newHarness(t)
	h.server.akaServerData = true
	m, v := set1(t)
	c, res := forgeRAND(t, h, m, v, true)
	if err := h.server.VerifyAKA(context.Background(), "REGISTER", c, res, h.vectorExpires); !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("err = %v, want ErrInvalidNonce", err)
	}
}

func TestAKAChallengeRequiresSixteenByteRANDAndAUTN(t *testing.T) {
	h := newHarness(t)
	if _, err := h.server.AKAChallenge(make([]byte, 15), make([]byte, 16), false); err == nil {
		t.Error("15-byte RAND accepted")
	}
	if _, err := h.server.AKAChallenge(make([]byte, 16), make([]byte, 17), false); err == nil {
		t.Error("17-byte AUTN accepted")
	}
}

func TestStaleAKAChallengeSaysStale(t *testing.T) {
	h := newHarness(t)
	_, v := set1(t)
	ch, err := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], true)
	if err != nil || !ch.Stale {
		t.Fatalf("challenge %+v, %v", ch, err)
	}
}
