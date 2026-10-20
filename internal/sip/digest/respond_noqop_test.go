package digest

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"testing"
)

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestAnAKAChallengeWithoutQOPIsAnsweredInTheFormWithoutQOP(t *testing.T) {
	// RFC 2617 §3.2.2.1 with RES as the password (RFC 3310 §3.3):
	// response = MD5(HA1:nonce:HA2), and no cnonce, nc or qop.
	res := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ch := Challenge{Realm: "ims.example.com", Nonce: "bm9uY2U=", Algorithm: AKAv1MD5, Opaque: "op"}
	c, err := Respond(ch, ClientParams{Username: "u@ims.example.com", Password: res, Method: "REGISTER", URI: "sip:ims.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	ha1 := md5hex("u@ims.example.com:ims.example.com:" + string(res))
	want := md5hex(ha1 + ":" + ch.Nonce + ":" + md5hex("REGISTER:sip:ims.example.com"))
	if c.Response != want || c.QOP != "" || c.NC != 0 || c.CNonce != "" || c.Opaque != "op" || c.Algorithm != AKAv1MD5 {
		t.Fatalf("credentials = %#v, response %s want %s", c, c.Response, want)
	}
	back, err := ParseCredentials(c.Header())
	if err != nil || back.QOP != "" || back.NC != 0 || back.Response != want {
		t.Fatalf("Header() = %q parses to %v, %v", c.Header(), back, err)
	}
	// AUTS is answered the same way, with the empty password (RFC 3310 §3.4).
	auts := make([]byte, 14)
	c, err = Respond(ch, ClientParams{Username: "u@ims.example.com", Password: res, Method: "REGISTER", URI: "sip:ims.example.com", AUTS: auts})
	if err != nil || c.Response != md5hex(md5hex("u@ims.example.com:ims.example.com:")+":"+ch.Nonce+":"+md5hex("REGISTER:sip:ims.example.com")) || len(c.AUTS) != 14 {
		t.Fatalf("AUTS credentials = %v, %v", c, err)
	}
}

func TestOnlyAKAMayGoWithoutQOP(t *testing.T) {
	p := ClientParams{Username: "u", Password: []byte("p"), Method: "REGISTER", URI: "sip:x", CNonce: "c", NC: 1}
	for name, ch := range map[string]Challenge{
		"MD5 without qop":     {Realm: "r", Nonce: "n", Algorithm: MD5},
		"SHA-256 without qop": {Realm: "r", Nonce: "n", Algorithm: SHA256},
		"AKA with auth-int":   {Realm: "r", Nonce: "n", Algorithm: AKAv1MD5, QOP: []string{"auth-int"}},
	} {
		if _, err := Respond(ch, p); !errors.Is(err, ErrUnsupportedQOP) {
			t.Errorf("%s: Respond = %v, want ErrUnsupportedQOP", name, err)
		}
	}
}

func TestVerifyAKARefusesCredentialsWithoutQOP(t *testing.T) {
	// The client answers an AKA challenge without qop in the form without
	// it; the server side, which always offers qop=auth, must still refuse
	// that form: it has no nonce-count to stop a replay (security review
	// of #187).
	h := newHarness(t)
	_, v := set1(t)
	ch, err := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	if err != nil {
		t.Fatal(err)
	}
	ch.QOP = nil
	answer, err := Respond(ch, ClientParams{Username: testUser, Password: v.XRES[:], Method: "REGISTER", URI: testURI})
	if err != nil {
		t.Fatal(err)
	}
	// As the server reads it off the wire.
	c, err := ParseCredentials(answer.Header())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.server.VerifyAKA(context.Background(), "REGISTER", c, v.XRES[:], h.vectorExpires); !errors.Is(err, ErrUnsupportedQOP) {
		t.Fatalf("VerifyAKA = %v, want ErrUnsupportedQOP", err)
	}
	if err := h.server.Check(c); !errors.Is(err, ErrUnsupportedQOP) {
		t.Fatalf("Check = %v, want ErrUnsupportedQOP", err)
	}
}
