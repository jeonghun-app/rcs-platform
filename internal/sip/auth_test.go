package sip

import (
	"reflect"
	"testing"
)

func TestChallengesParseOnePerField(t *testing.T) {
	h := headerWith(t, "WWW-Authenticate",
		`Digest realm="ims.example.net", nonce="CjPk9mRqNuT25eRkajM09uTl9nM09uTl9nMz5OX25PZz==", qop="auth,auth-int", algorithm=AKAv1-MD5`,
		`Digest realm="ims.example.net",nonce="b2a",algorithm=MD5,stale=TRUE`)
	cs, err := h.WWWAuthenticate()
	if err != nil || len(cs) != 2 {
		t.Fatalf("WWWAuthenticate() = %#v, %v", cs, err)
	}
	c := cs[0]
	if c.Scheme != "Digest" {
		t.Errorf("Scheme = %q", c.Scheme)
	}
	for name, want := range map[string]string{
		"realm": "ims.example.net", "NONCE": "CjPk9mRqNuT25eRkajM09uTl9nM09uTl9nMz5OX25PZz==",
		"qop": "auth,auth-int", "algorithm": "AKAv1-MD5",
	} {
		if got, ok := c.Param(name); !ok || got != want {
			t.Errorf("Param(%q) = %q, %v", name, got, ok)
		}
	}
	if s, ok := cs[1].Param("stale"); !ok || s != "TRUE" {
		t.Errorf("stale = %q, %v", s, ok)
	}
	// Writing back keeps each parameter's quoting.
	if got := c.String(); got != `Digest realm="ims.example.net", nonce="CjPk9mRqNuT25eRkajM09uTl9nM09uTl9nMz5OX25PZz==", qop="auth,auth-int", algorithm=AKAv1-MD5` {
		t.Errorf("String() = %q", got)
	}
	proxy, err := headerWith(t, "Proxy-Authenticate", `Digest realm="example.com", nonce="x"`).ProxyAuthenticate()
	if err != nil || len(proxy) != 1 {
		t.Errorf("ProxyAuthenticate() = %#v, %v", proxy, err)
	}
	var none Header
	if cs, err := none.WWWAuthenticate(); cs != nil || err != nil {
		t.Errorf("absent = %v, %v", cs, err)
	}
}

func TestCredentialsQuoteWhatDigestRequires(t *testing.T) {
	var c Credentials
	c.Scheme = "Digest"
	c.SetParam("username", "001010000000001@ims.mnc001.mcc001.3gppnetwork.org")
	c.SetParam("realm", "ims.mnc001.mcc001.3gppnetwork.org")
	c.SetParam("uri", "sip:ims.mnc001.mcc001.3gppnetwork.org")
	c.SetParam("nonce", "abc")
	c.SetParam("response", "6629fae49393a05397450978507c4ef1")
	c.SetParam("algorithm", "AKAv1-MD5")
	c.SetParam("qop", "auth")
	c.SetParam("nc", "00000001")
	c.SetParam("cnonce", "0a4f113b")
	c.SetParam("x-ext", "has space")
	want := `Digest username="001010000000001@ims.mnc001.mcc001.3gppnetwork.org", realm="ims.mnc001.mcc001.3gppnetwork.org", ` +
		`uri="sip:ims.mnc001.mcc001.3gppnetwork.org", nonce="abc", response="6629fae49393a05397450978507c4ef1", ` +
		`algorithm=AKAv1-MD5, qop=auth, nc=00000001, cnonce="0a4f113b", x-ext="has space"`
	if got := c.String(); got != want {
		t.Fatalf("String() =\n%s\nwant\n%s", got, want)
	}
	h := headerWith(t, "Authorization", c.String())
	got, err := h.Authorization()
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], c) {
		t.Errorf("Authorization() = %#v, %v", got, err)
	}
	if v, ok := got[0].Param("Username"); !ok || v != "001010000000001@ims.mnc001.mcc001.3gppnetwork.org" {
		t.Errorf("Param(Username) = %q, %v", v, ok)
	}
	pa, err := headerWith(t, "Proxy-Authorization", c.String()).ProxyAuthorization()
	if err != nil || len(pa) != 1 {
		t.Errorf("ProxyAuthorization() = %#v, %v", pa, err)
	}

	// In a challenge qop is a quoted list (RFC 3261 §25.1).
	var ch Challenge
	ch.Scheme = "Digest"
	ch.SetParam("realm", "example.com")
	ch.SetParam("qop", "auth")
	ch.SetParam("stale", "false")
	if got := ch.String(); got != `Digest realm="example.com", qop="auth", stale=false` {
		t.Errorf("challenge String() = %q", got)
	}
	ch.SetParam("REALM", "other.example.com")
	if v, _ := ch.Param("realm"); v != "other.example.com" || len(ch.Params) != 3 {
		t.Errorf("SetParam did not replace: %#v", ch.Params)
	}
}

func TestMalformedAuthenticationFieldsAreRejected(t *testing.T) {
	for _, in := range []string{
		"",
		"Digest",
		"Digest ",
		`Digest realm`,
		`Digest realm=`,
		`Digest realm="x`,
		`Digest realm="a", realm="b"`,
		`Digest realm="a" nonce="b"`,
		`Digest realm="a",, nonce="b"`,
		`Digest realm="a", Digest realm="b"`,
		`Digest realm=a b`,
		`"Digest" realm="a"`,
		`Digest, realm="a"`,
	} {
		_, err := headerWith(t, "WWW-Authenticate", in).WWWAuthenticate()
		wantMalformed(t, "WWW-Authenticate", in, err)
		_, err = headerWith(t, "Authorization", in).Authorization()
		wantMalformed(t, "Authorization", in, err)
	}
}
