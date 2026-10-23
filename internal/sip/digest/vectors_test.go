package digest

import (
	"reflect"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

// The examples below are the published examples of RFC 2617 §3.5 and
// RFC 7616 §3.9.1, laid out with line folding as in the RFCs.

const rfc2617Challenge = "Digest\r\n" +
	"        realm=\"testrealm@host.com\",\r\n" +
	"        qop=\"auth,auth-int\",\r\n" +
	"        nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\r\n" +
	"        opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""

const rfc2617Authorization = "Digest username=\"Mufasa\",\r\n" +
	"        realm=\"testrealm@host.com\",\r\n" +
	"        nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\r\n" +
	"        uri=\"/dir/index.html\",\r\n" +
	"        qop=auth,\r\n" +
	"        nc=00000001,\r\n" +
	"        cnonce=\"0a4f113b\",\r\n" +
	"        response=\"6629fae49393a05397450978507c4ef1\",\r\n" +
	"        opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""

func rfc7616Challenge(alg string) string {
	return "Digest\r\n" +
		"    realm=\"http-auth@example.org\",\r\n" +
		"    qop=\"auth, auth-int\",\r\n" +
		"    algorithm=" + alg + ",\r\n" +
		"    nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\",\r\n" +
		"    opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\""
}

func rfc7616Authorization(alg, response string) string {
	return "Digest username=\"Mufasa\",\r\n" +
		"    realm=\"http-auth@example.org\",\r\n" +
		"    uri=\"/dir/index.html\",\r\n" +
		"    algorithm=" + alg + ",\r\n" +
		"    nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\",\r\n" +
		"    nc=00000001,\r\n" +
		"    cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\",\r\n" +
		"    qop=auth,\r\n" +
		"    response=\"" + response + "\",\r\n" +
		"    opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\""
}

func TestPublishedExamplesProduceThePublishedResponse(t *testing.T) {
	cases := []struct {
		name          string
		challenge     string
		authorization string
		password      string
		cnonce        string
		want          string
	}{
		{
			name:          "RFC 2617 §3.5",
			challenge:     rfc2617Challenge,
			authorization: rfc2617Authorization,
			password:      "Circle Of Life",
			cnonce:        "0a4f113b",
			want:          "6629fae49393a05397450978507c4ef1",
		},
		{
			name:          "RFC 7616 §3.9.1 MD5",
			challenge:     rfc7616Challenge("MD5"),
			authorization: rfc7616Authorization("MD5", "8ca523f5e9506fed4657c9700eebdbec"),
			password:      "Circle of Life",
			cnonce:        "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
			want:          "8ca523f5e9506fed4657c9700eebdbec",
		},
		{
			name:          "RFC 7616 §3.9.1 SHA-256",
			challenge:     rfc7616Challenge("SHA-256"),
			authorization: rfc7616Authorization("SHA-256", "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"),
			password:      "Circle of Life",
			cnonce:        "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
			want:          "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ch, err := ParseChallenge(c.challenge)
			if err != nil {
				t.Fatalf("ParseChallenge: %v", err)
			}
			got, err := Respond(ch, ClientParams{
				Username: "Mufasa",
				Password: secret.NewKey([]byte(c.password)),
				Method:   "GET",
				URI:      "/dir/index.html",
				CNonce:   c.cnonce,
				NC:       1,
			})
			if err != nil {
				t.Fatalf("Respond: %v", err)
			}
			if got.Response != c.want {
				t.Fatalf("response = %s, want %s", got.Response, c.want)
			}

			// The client's credentials are exactly the published header.
			published, err := ParseCredentials(c.authorization)
			if err != nil {
				t.Fatalf("ParseCredentials: %v", err)
			}
			if !reflect.DeepEqual(got, published) {
				t.Fatalf("Respond = %+v\nRFC     = %+v", got, published)
			}
		})
	}
}

func TestStoredHA1GivesTheSameResponseAsThePassword(t *testing.T) {
	// RFC 7616 §3.9.1 through the HA1 path: H(Mufasa:http-auth@example.org:Circle of Life).
	h, err := ComputeHA1(SHA256, "Mufasa", "http-auth@example.org", []byte("Circle of Life"))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := HA1(SHA256, h)
	if err != nil {
		t.Fatal(err)
	}
	ha, err := secret.ha1For(SHA256, "Mufasa", "http-auth@example.org")
	if err != nil {
		t.Fatal(err)
	}
	got := response(SHA256, ha, "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", "00000001",
		"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ", "auth", "GET", "/dir/index.html")
	if want := "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"; got != want {
		t.Fatalf("response = %s, want %s", got, want)
	}
}

func TestRFC3310ExampleCredentialsParse(t *testing.T) {
	// RFC 3310 §4, the REGISTER that reports a synchronisation failure.
	const value = "Digest\r\n" +
		"      username=\"jon.dough@mobile.biz\",\r\n" +
		"      realm=\"RoamingUsers@mobile.biz\",\r\n" +
		"      nonce=\"CjPk9mRqNuT25eRkajM09uTl9nM09uTl9nMz5OX25PZz==\",\r\n" +
		"      uri=\"sip:home.mobile.biz\",\r\n" +
		"      qop=auth,\r\n" +
		"      nc=00000001,\r\n" +
		"      cnonce=\"0a4f113b\",\r\n" +
		"      response=\"4429ffe49393c02397450934607c4ef1\",\r\n" +
		"      opaque=\"5ccc069c403ebaf9f0171e9517f40e41\",\r\n" +
		"      auts=\"5PYxMuX2NOT2NeQ=\""
	c, err := ParseCredentials(value)
	if err != nil {
		t.Fatal(err)
	}
	if c.Username != "jon.dough@mobile.biz" || c.URI != "sip:home.mobile.biz" || c.NC != 1 || c.Algorithm != MD5 {
		t.Fatalf("parsed %+v", c)
	}
	if want := []byte{0xe4, 0xf6, 0x31, 0x32, 0xe5, 0xf6, 0x34, 0xe4, 0xf6, 0x35, 0xe4}; !reflect.DeepEqual(c.AUTS, want) {
		t.Fatalf("auts = %x, want %x", c.AUTS, want)
	}
}

func TestRFC3310ExampleChallengeParses(t *testing.T) {
	const value = "Digest\r\n" +
		"      realm=\"RoamingUsers@mobile.biz\",\r\n" +
		"      qop=\"auth\",\r\n" +
		"      nonce=\"CjPk9mRqNuT25eRkajM09uTl9nM09uTl9nMz5OX25PZz==\",\r\n" +
		"      opaque=\"5ccc069c403ebaf9f0171e9517f40e41\",\r\n" +
		"      algorithm=AKAv1-MD5"
	c, err := ParseChallenge(value)
	if err != nil {
		t.Fatal(err)
	}
	want := Challenge{
		Realm:     "RoamingUsers@mobile.biz",
		Nonce:     "CjPk9mRqNuT25eRkajM09uTl9nM09uTl9nMz5OX25PZz==",
		Opaque:    "5ccc069c403ebaf9f0171e9517f40e41",
		Algorithm: AKAv1MD5,
		QOP:       []string{"auth"},
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("parsed %+v, want %+v", c, want)
	}
}
