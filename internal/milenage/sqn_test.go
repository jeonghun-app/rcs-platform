package milenage

import (
	"errors"
	"testing"
)

func mustSQN(t *testing.T, seq uint64, ind uint8) SQN {
	t.Helper()
	s, err := NewSQN(seq, ind)
	if err != nil {
		t.Fatalf("NewSQN(%d, %d): %v", seq, ind, err)
	}
	return s
}

func TestSQNSplitsIntoFortyThreeBitSEQAndFiveBitIND(t *testing.T) {
	s := mustSQN(t, 0x123456789, 0x1f)
	if s.SEQ() != 0x123456789 || s.IND() != 0x1f {
		t.Fatalf("SEQ, IND = %#x, %#x", s.SEQ(), s.IND())
	}
	if uint64(s) != 0x123456789<<5|0x1f {
		t.Fatalf("SQN = %#x", uint64(s))
	}
	top := mustSQN(t, MaxSEQ, MaxIND)
	if top.Bytes() != [SQNSize]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} {
		t.Fatalf("largest SQN = %x", top.Bytes())
	}
}

func TestNewSQNRejectsValuesThatDoNotFit(t *testing.T) {
	if _, err := NewSQN(MaxSEQ+1, 0); err == nil {
		t.Error("SEQ above MaxSEQ accepted")
	}
	if _, err := NewSQN(0, MaxIND+1); err == nil {
		t.Error("IND above MaxIND accepted")
	}
}

func TestSQNBytesRoundTripBigEndian(t *testing.T) {
	b := [SQNSize]byte{0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07}
	s := SQNFromBytes(b)
	if uint64(s) != 0xff9bb4d0b607 {
		t.Fatalf("SQNFromBytes = %#x", uint64(s))
	}
	if s.Bytes() != b {
		t.Fatalf("Bytes = %x, want %x", s.Bytes(), b)
	}
}

func TestBitsAboveFortyEightAreIgnored(t *testing.T) {
	s := SQN(1<<60 | 0xff9bb4d0b607)
	if s.Bytes() != SQNFromBytes([SQNSize]byte{0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07}).Bytes() {
		t.Fatalf("Bytes = %x", s.Bytes())
	}
	if s.SEQ() != 0xff9bb4d0b607>>5 {
		t.Fatalf("SEQ = %#x", s.SEQ())
	}
}

func TestNextIncrementsSEQAndKeepsIND(t *testing.T) {
	s := mustSQN(t, 41, 7)
	n, err := s.Next()
	if err != nil {
		t.Fatal(err)
	}
	if n.SEQ() != 42 || n.IND() != 7 {
		t.Fatalf("Next = SEQ %d IND %d, want 42 7", n.SEQ(), n.IND())
	}
}

func TestNextRefusesToWrapAround(t *testing.T) {
	_, err := mustSQN(t, MaxSEQ, 3).Next()
	if !errors.Is(err, ErrSQNExhausted) {
		t.Fatalf("err = %v, want ErrSQNExhausted", err)
	}
}

func TestFreshAcceptsOnlyAGreaterSEQWithinDelta(t *testing.T) {
	const ms = 1000
	cases := []struct {
		name string
		seq  uint64
		ind  uint8
		want bool
	}{
		{"next SEQ", ms + 1, 0, true},
		{"next SEQ with another IND", ms + 1, 9, true},
		{"exactly Delta ahead", ms + Delta, 0, true},
		{"one beyond Delta", ms + Delta + 1, 0, false},
		{"same SEQ", ms, 0, false},
		{"same SEQ with a higher IND", ms, MaxIND, false},
		{"older SEQ", ms - 1, 0, false},
	}
	highest := mustSQN(t, ms, 0)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Fresh(mustSQN(t, c.seq, c.ind), highest); got != c.want {
				t.Fatalf("Fresh = %v, want %v", got, c.want)
			}
		})
	}
}

func TestResynchronisationKeepsTheNetworkCounterWhenItIsStillInRange(t *testing.T) {
	he := mustSQN(t, 500, 2)
	ms := mustSQN(t, 499, 0)
	if got := Resynchronise(he, ms); got != he {
		t.Fatalf("Resynchronise = SEQ %d IND %d, want SQN_HE unchanged", got.SEQ(), got.IND())
	}
}

func TestResynchronisationJumpsToTheCardCounterWhenTheNetworkIsBehind(t *testing.T) {
	he := mustSQN(t, 10, 2)
	ms := mustSQN(t, 900, 5)
	got := Resynchronise(he, ms)
	if got.SEQ() != 900 || got.IND() != 2 {
		t.Fatalf("Resynchronise = SEQ %d IND %d, want SEQ_MS with the network's IND", got.SEQ(), got.IND())
	}
	next, err := got.Next()
	if err != nil || !Fresh(next, ms) {
		t.Fatalf("the vector after resynchronisation would still be rejected")
	}
}

func TestResynchronisationResetsANetworkCounterTooFarAhead(t *testing.T) {
	// A restored or corrupted HSS record can run ahead of the card by more
	// than Delta; the card would reject every vector until the network
	// follows SQN_MS.
	ms := mustSQN(t, 100, 0)
	he := mustSQN(t, 100+Delta+5, 0)
	got := Resynchronise(he, ms)
	if got.SEQ() != 100 {
		t.Fatalf("Resynchronise SEQ = %d, want 100", got.SEQ())
	}
}

func TestResynchronisationAtTheLastSEQFollowsTheCard(t *testing.T) {
	he := mustSQN(t, MaxSEQ, 1)
	ms := mustSQN(t, MaxSEQ-3, 0)
	if got := Resynchronise(he, ms); got.SEQ() != MaxSEQ-3 || got.IND() != 1 {
		t.Fatalf("Resynchronise = SEQ %d IND %d", got.SEQ(), got.IND())
	}
}

func TestResynchronisedCounterRoundTripsThroughAUTS(t *testing.T) {
	// The whole resynchronisation of TS 33.102 §6.3.5: the card rejects a
	// stale AUTN, answers with AUTS, the network verifies it and the next
	// vector passes the card's freshness check.
	ts := conformanceSets[0]
	m := New(key(t, ts.k), key(t, ts.opc))
	rand := rnd(t, ts.rand)
	card := mustSQN(t, 7000, 0)
	network := mustSQN(t, 12, 0)

	sent, _ := network.Next()
	v := m.Vector(rand, sent, amfOf(t, ts.amf))
	got, err := m.CheckAUTN(rand, v.AUTN)
	if err != nil {
		t.Fatal(err)
	}
	if Fresh(got, card) {
		t.Fatal("stale SQN accepted by the card")
	}
	auts := m.AUTS(rand, card)

	sqnMS, err := m.VerifyAUTS(rand, auts)
	if err != nil {
		t.Fatal(err)
	}
	network = Resynchronise(sent, sqnMS)
	next, err := network.Next()
	if err != nil {
		t.Fatal(err)
	}
	v = m.Vector(rand, next, amfOf(t, ts.amf))
	got, err = m.CheckAUTN(rand, v.AUTN)
	if err != nil || !Fresh(got, card) {
		t.Fatalf("vector after resynchronisation rejected: fresh=%v err=%v", Fresh(got, card), err)
	}
}
