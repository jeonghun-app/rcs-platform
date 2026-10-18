package digest

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/milenage"
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

func set1(t *testing.T) (milenage.Milenage, milenage.Vector) {
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
	return m, v
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
		p.Password = res[:]
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
	wire, err := ParseChallenge(ch.String())
	if err != nil {
		t.Fatal(err)
	}
	if wire.Algorithm != AKAv1MD5 {
		t.Fatalf("algorithm = %s", wire.Algorithm)
	}

	c := card(t, m, wire, set1Seen(t))
	if err := h.server.Verify(context.Background(), "REGISTER", c, Password(v.XRES[:])); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestAKANonceCarriesRANDAndAUTNFirst(t *testing.T) {
	h := newHarness(t)
	_, v := set1(t)
	ch, err := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	if err != nil {
		t.Fatal(err)
	}
	rand, autn, err := ParseAKANonce(ch.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	if rand != v.RAND || autn != v.AUTN {
		t.Fatalf("nonce holds RAND %x AUTN %x", rand, autn)
	}
}

func TestAKAWithTheWrongRESIsRejected(t *testing.T) {
	h := newHarness(t)
	m, v := set1(t)
	ch, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	c := card(t, m, ch, set1Seen(t))
	wrong := v.XRES
	wrong[0] ^= 0x01
	if err := h.server.Verify(context.Background(), "REGISTER", c, Password(wrong[:])); !errors.Is(err, ErrWrongResponse) {
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
	if c.AUTS == nil {
		t.Fatal("card did not report a synchronisation failure")
	}

	err := h.server.Verify(context.Background(), "REGISTER", c, Password(v.XRES[:]))
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
	if h.counts.Len() != 0 {
		t.Fatal("a synchronisation failure consumed a nonce count")
	}
}

func TestAKASynchronisationFailureMustUseTheEmptyPassword(t *testing.T) {
	h := newHarness(t)
	_, v := set1(t)
	ch, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	c, err := Respond(ch, ClientParams{Username: testUser, Password: v.XRES[:], Method: "REGISTER", URI: testURI, CNonce: "c", NC: 1})
	if err != nil {
		t.Fatal(err)
	}
	c.AUTS = make([]byte, 14) // auts added, but the response was computed with RES
	if err := h.server.Verify(context.Background(), "REGISTER", c, Password(v.XRES[:])); !errors.Is(err, ErrWrongResponse) {
		t.Fatalf("err = %v, want ErrWrongResponse", err)
	}
}

func TestAKAAUTSOfTheWrongLengthIsMalformed(t *testing.T) {
	h := newHarness(t)
	m, v := set1(t)
	ch, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	c := card(t, m, ch, set1Seen(t))
	c.AUTS = make([]byte, 11) // the length of the illustrative auts in RFC 3310 §4
	if err := h.server.Verify(context.Background(), "REGISTER", c, Password(v.XRES[:])); !errors.Is(err, ErrMalformed) {
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

func TestTamperedAKANonceIsInvalid(t *testing.T) {
	h := newHarness(t)
	m, v := set1(t)
	// A RAND swapped into an otherwise genuine nonce must not verify.
	ch, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	otherRAND := v.RAND
	otherRAND[0] ^= 0xff
	forged, _ := h.server.AKAChallenge(otherRAND[:], v.AUTN[:], false)
	raw := []byte(ch.Nonce)
	copy(raw[:20], forged.Nonce[:20])
	ch.Nonce = string(raw)
	ch.Opaque = h.server.opaqueFor(ch.Nonce)
	res := m.F2(otherRAND)
	c, err := Respond(ch, ClientParams{Username: testUser, Password: res[:], Method: "REGISTER", URI: testURI, CNonce: "c", NC: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.server.Verify(context.Background(), "REGISTER", c, Password(res[:])); !errors.Is(err, ErrInvalidNonce) {
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
