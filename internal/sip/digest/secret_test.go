package digest

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// leakForms returns the ways a secret could show up in text: as is, as lower
// and upper hex, and as fmt's rendering of a byte slice.
func leakForms(secret []byte) []string {
	h := hex.EncodeToString(secret)
	return []string{string(secret), h, strings.ToUpper(h), fmt.Sprint(secret)[1 : len(fmt.Sprint(secret))-1]}
}

type secrets struct{ forms []string }

func (s *secrets) add(b []byte) { s.forms = append(s.forms, leakForms(b)...) }

func (s *secrets) check(t *testing.T, what, text string) {
	t.Helper()
	for _, f := range s.forms {
		if strings.Contains(text, f) {
			t.Errorf("%s leaks a secret: %q", what, text)
			return
		}
	}
}

func everyFormatting(v any) []string {
	var outs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		outs = append(outs, fmt.Sprintf(verb, v))
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("m", "v", v, "nested", struct{ V any }{v})
	slog.New(slog.NewTextHandler(&buf, nil)).Info("m", "v", v, "nested", struct{ V any }{v})
	return append(outs, buf.String())
}

func TestNoSecretAppearsInErrorsOrFormattedValues(t *testing.T) {
	h := newHarness(t)
	_, v := set1(t)
	var s secrets
	s.add([]byte(testPass))
	s.add(testKey)
	s.add(v.XRES[:])
	s.add(v.CK[:])
	s.add(v.IK[:])
	for _, alg := range []Algorithm{MD5, SHA256} {
		ha, _ := ComputeHA1(alg, testUser, testRealm, []byte(testPass))
		s.add([]byte(ha))
		raw, _ := hex.DecodeString(ha)
		s.add(raw)
	}

	md5HA1, _ := ComputeHA1(MD5, testUser, testRealm, []byte(testPass))
	ha1Secret, err := HA1(MD5, md5HA1)
	if err != nil {
		t.Fatal(err)
	}
	params := ClientParams{Username: testUser, Password: []byte(testPass), Method: "REGISTER", URI: testURI, CNonce: "c", NC: 1}
	formatted := map[string]any{
		"Password secret": Password([]byte(testPass)),
		"RES secret":      Password(v.XRES[:]),
		"HA1 secret":      ha1Secret,
		"ClientParams":    params,
		"*Server":         h.server,
	}
	for name, value := range formatted {
		for _, out := range everyFormatting(value) {
			s.check(t, name, out)
		}
	}
	for _, out := range []string{
		Password(nil).String(), Password(nil).GoString(), params.String(), params.GoString(),
		h.server.String(), h.server.GoString(),
	} {
		if !strings.Contains(out, "redacted") {
			t.Errorf("String/GoString = %q, want the placeholder", out)
		}
	}

	// Every error Verify, VerifyHTTP and the parsers can return, provoked
	// with the secrets in play.
	ch := h.challenge(t, MD5)
	good := answer(t, ch, testPass, 1)
	var errs []error
	verify := func(c Credentials, secret Secret) {
		errs = append(errs, h.server.Verify(context.Background(), "REGISTER", c, secret))
	}
	verify(answer(t, ch, "wrong", 1), Password([]byte(testPass)))
	verify(good, Secret{})
	sha, _ := HA1(SHA256, strings.Repeat("0", 64))
	verify(good, sha)
	bad := good
	bad.Realm = "x"
	verify(bad, Password([]byte(testPass)))
	bad = good
	bad.Nonce = "x"
	verify(bad, Password([]byte(testPass)))
	if err := h.server.Verify(context.Background(), "REGISTER", good, Password([]byte(testPass))); err != nil {
		t.Fatal(err)
	}
	verify(good, Password([]byte(testPass))) // replay
	h.clock.advance(DefaultNonceLifetime * 2)
	verify(answer(t, ch, testPass, 2), Password([]byte(testPass)))

	aka, _ := h.server.AKAChallenge(v.RAND[:], v.AUTN[:], false)
	sync, _ := Respond(aka, ClientParams{Username: testUser, Method: "REGISTER", URI: testURI, CNonce: "c", NC: 1, AUTS: make([]byte, 14)})
	verify(sync, Password(v.XRES[:]))
	res, _ := Respond(aka, ClientParams{Username: testUser, Password: []byte("x"), Method: "REGISTER", URI: testURI, CNonce: "c", NC: 1})
	verify(res, Password(v.XRES[:]))

	_, err = HA1(MD5, "zz"+md5HA1[2:])
	errs = append(errs, err)
	_, err = HA1(SHA256, md5HA1)
	errs = append(errs, err)
	_, err = Respond(ch, ClientParams{Username: testUser, Password: []byte(testPass)})
	errs = append(errs, err)
	_, err = ParseCredentials(`Digest username="` + testPass + `"`)
	errs = append(errs, err)
	_, err = NewServer(ServerConfig{Realm: testRealm, NonceKey: testKey[:10]})
	errs = append(errs, err)

	r := httptest.NewRequest("GET", "/f", nil)
	r.Header.Set("Authorization", answer(t, h.challenge(t, MD5), testPass, 1).String())
	_, err = h.server.VerifyHTTP(r, lookupFor(testPass))
	errs = append(errs, err)

	for i, err := range errs {
		if err == nil {
			t.Fatalf("case %d: expected an error", i)
		}
		s.check(t, fmt.Sprintf("error %d", i), err.Error())
		s.check(t, fmt.Sprintf("error %d %%+v", i), fmt.Sprintf("%+v", err))
	}
	var sf *SyncFailure
	if !slices.ContainsFunc(errs, func(err error) bool { return errors.As(err, &sf) }) {
		t.Fatal("the synchronisation failure path was not exercised")
	}

	// Header values carry the response digest but never what it was made from.
	for _, out := range []string{good.String(), ch.String(), sync.String(), aka.String()} {
		s.check(t, "header value", out)
	}
}
