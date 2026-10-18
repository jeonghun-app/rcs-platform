package digest

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func checkParseError(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unexpected error kind: %v", err)
	}
}

func FuzzParseChallenge(f *testing.F) {
	h := newHarness(f)
	for _, alg := range []Algorithm{MD5, SHA256} {
		ch, _ := h.server.Challenge(alg, true)
		f.Add(ch.Header())
	}
	f.Add(rfc2617Challenge)
	f.Add(rfc7616Challenge("SHA-256"))
	f.Add(`Digest realm="a\"b", nonce=x, qop="auth,,auth-int", stale=TRUE, algorithm="AKAv1-MD5"`)
	f.Add("Digest realm=\"a\r\n b\", nonce=\"\"")
	f.Fuzz(func(t *testing.T, value string) {
		c, err := ParseChallenge(value)
		if err != nil {
			checkParseError(t, err)
			return
		}
		again, err := ParseChallenge(c.Header())
		if err != nil {
			t.Fatalf("Header output %q does not parse: %v", c.Header(), err)
		}
		if !reflect.DeepEqual(again, c) {
			t.Fatalf("round trip changed the challenge:\n%+v\n%+v", c, again)
		}
	})
}

func FuzzParseCredentials(f *testing.F) {
	h := newHarness(f)
	ch, _ := h.server.Challenge(SHA256, false)
	c, _ := Respond(ch, ClientParams{Username: testUser, Password: []byte(testPass), Method: "REGISTER", URI: testURI, CNonce: "c", NC: 1})
	f.Add(c.Header())
	f.Add(rfc2617Authorization)
	f.Add(rfc7616Authorization("MD5", "8ca523f5e9506fed4657c9700eebdbec"))
	f.Add(`Digest username="u", realm="r", nonce="", uri="sip:r", response="", auts="AAAAAAAAAAAAAAAAAAA="`)
	f.Add(`Digest username=u, realm=r, nonce=n, uri=u, response=r, nc=0000000f, qop="auth"`)
	f.Fuzz(func(t *testing.T, value string) {
		c, err := ParseCredentials(value)
		if err != nil {
			checkParseError(t, err)
			return
		}
		again, err := ParseCredentials(c.Header())
		if err != nil {
			t.Fatalf("Header output %q does not parse: %v", c.Header(), err)
		}
		if !reflect.DeepEqual(again, c) {
			t.Fatalf("round trip changed the credentials:\n%+v\n%+v", c, again)
		}
		// Whatever arrives, the checks must return rather than panic. The
		// results are not checked: the first seed is genuine and verifies once.
		_ = h.server.Check(c)
		_ = h.server.Verify(context.Background(), "REGISTER", c, Password([]byte(testPass)))
		_ = h.server.VerifyAKA(context.Background(), "REGISTER", c, []byte("res"), h.vectorExpires)
		_ = c.String()
	})
}

func FuzzParseAKANonce(f *testing.F) {
	h := newHarness(f)
	ch, _ := h.server.AKAChallenge(make([]byte, 16), make([]byte, 16), false)
	f.Add(ch.Nonce)
	f.Add("CjPk9mRqNuT25eRkajM09uTl9nM09uTl9nMz5OX25PZz==")
	f.Fuzz(func(t *testing.T, nonce string) {
		rand, autn, err := ParseAKANonce(nonce)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("unexpected error kind: %v", err)
			}
			return
		}
		if len(rand) != 16 || len(autn) != 16 {
			t.Fatal("wrong sizes")
		}
	})
}
