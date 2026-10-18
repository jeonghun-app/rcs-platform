package digest

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestChallengeParametersAreReadWhateverTheirCaseAndQuoting(t *testing.T) {
	c, err := ParseChallenge(`dIgEsT REALM=example.org,NONCE="n\"1\\",Algorithm=sha-256,  qop="auth , auth-int",stale=TRUE, domain="sip:x", unknown=1`)
	if err != nil {
		t.Fatal(err)
	}
	want := Challenge{
		Realm:     "example.org",
		Nonce:     `n"1\`,
		Algorithm: SHA256,
		QOP:       []string{"auth", "auth-int"},
		Stale:     true,
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("parsed %+v, want %+v", c, want)
	}
}

func TestEmptyListElementsAreSkipped(t *testing.T) {
	// RFC 7230 §7: recipients ignore empty elements of a # list.
	want := Challenge{Realm: "r", Nonce: "n", Algorithm: MD5}
	for _, value := range []string{
		`Digest realm="r",, nonce="n"`,
		`Digest realm="r", nonce="n",`,
		`Digest realm="r", nonce="n" , , `,
		`Digest ,realm="r" , ,nonce="n"`,
	} {
		c, err := ParseChallenge(value)
		if err != nil || !reflect.DeepEqual(c, want) {
			t.Errorf("ParseChallenge(%q) = %+v, %v", value, c, err)
		}
	}
}

func TestChallengeWithoutAlgorithmMeansMD5(t *testing.T) {
	c, err := ParseChallenge(`Digest realm="r", nonce="n"`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Algorithm != MD5 || c.Stale || c.QOP != nil {
		t.Fatalf("parsed %+v", c)
	}
}

func TestStaleOtherThanTrueIsFalse(t *testing.T) {
	for _, v := range []string{"false", "FALSE", "yes", `"1"`} {
		c, err := ParseChallenge(`Digest realm="r", nonce="n", stale=` + v)
		if err != nil {
			t.Fatalf("stale=%s: %v", v, err)
		}
		if c.Stale {
			t.Errorf("stale=%s read as true", v)
		}
	}
}

func TestMalformedHeadersAreRejected(t *testing.T) {
	cases := map[string]string{
		"empty":                     ``,
		"only the scheme":           `Digest`,
		"only the scheme and space": `Digest   `,
		"Basic scheme":              `Basic realm="r"`,
		"scheme glued to a param":   `Digestrealm="r"`,
		"missing equals":            `Digest realm "r"`,
		"missing value":             `Digest realm=, nonce="n"`,
		"missing comma":             `Digest realm="r" nonce="n"`,
		"only empty elements":       `Digest , ,`,
		"unterminated quote":        `Digest realm="r, nonce="n`,
		"escape at the end":         `Digest realm="r\`,
		"escaped line feed":         "Digest realm=\"r\\\n\", nonce=\"n\"",
		"control char in quote":     "Digest realm=\"r\x01\", nonce=\"n\"",
		"bare line feed":            "Digest realm=\"r\",\n nonce=\"n\"",
		"CR LF without folding":     "Digest realm=\"r\",\r\nnonce=\"n\"",
		"DEL in quote":              "Digest realm=\"r\x7f\", nonce=\"n\"",
		"second challenge":          `Digest realm="r", nonce="n", Basic realm="x"`,
		"separator in token value":  `Digest realm=a/b, nonce="n"`,
		"duplicate parameter":       `Digest realm="r", nonce="n", REALM="s"`,
		"no realm":                  `Digest nonce="n"`,
		"no nonce":                  `Digest realm="r"`,
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if c, err := ParseChallenge(value); !errors.Is(err, ErrMalformed) {
				t.Fatalf("ParseChallenge = %+v, %v; want ErrMalformed", c, err)
			}
		})
	}
}

func TestLimitsOnSizeAndParameterCountAreEnforced(t *testing.T) {
	long := `Digest realm="` + strings.Repeat("a", MaxHeaderLength) + `", nonce="n"`
	if _, err := ParseChallenge(long); !errors.Is(err, ErrMalformed) {
		t.Fatalf("oversized header: err = %v", err)
	}
	many := `Digest realm="r", nonce="n"` + strings.Repeat(", x=1", maxParams)
	if _, err := ParseChallenge(many); !errors.Is(err, ErrMalformed) {
		t.Fatalf("too many parameters: err = %v", err)
	}
	if _, _, err := ParseAKANonce(strings.Repeat("A", MaxHeaderLength+4)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("oversized AKA nonce: err = %v", err)
	}
}

func TestUnknownAlgorithmsAreUnsupportedNotMalformed(t *testing.T) {
	for _, alg := range []string{"MD5-sess", "SHA-512-256", "AKAv2-MD5", `"MD5 "`} {
		if _, err := ParseChallenge(`Digest realm="r", nonce="n", algorithm=` + alg); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Errorf("challenge algorithm=%s: err = %v, want ErrUnsupportedAlgorithm", alg, err)
		}
		if _, err := ParseCredentials(`Digest username="u", realm="r", nonce="n", uri="u", response="", algorithm=` + alg); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Errorf("credentials algorithm=%s: err = %v, want ErrUnsupportedAlgorithm", alg, err)
		}
	}
}

func TestFoldedLineInsideAQuotedStringBecomesASpace(t *testing.T) {
	c, err := ParseChallenge("Digest realm=\"a\r\n\tb\", nonce=\"n\"")
	if err != nil {
		t.Fatal(err)
	}
	if c.Realm != "a \tb" {
		t.Fatalf("realm = %q", c.Realm)
	}
}

func TestNonASCIIIsAllowedInQuotedStrings(t *testing.T) {
	c, err := ParseCredentials(`Digest username="jürgen", realm="r", nonce="n", uri="sip:r", response=""`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Username != "jürgen" {
		t.Fatalf("username = %q", c.Username)
	}
}

func TestFirstIMSRegisterCredentialsWithEmptyNonceParse(t *testing.T) {
	const value = `Digest username="001010000000001@ims.mnc001.mcc001.3gppnetwork.org", ` +
		`realm="ims.mnc001.mcc001.3gppnetwork.org", uri="sip:ims.mnc001.mcc001.3gppnetwork.org", ` +
		`nonce="", response=""`
	c, err := ParseCredentials(value)
	if err != nil {
		t.Fatal(err)
	}
	if c.Nonce != "" || c.Response != "" || c.Username == "" {
		t.Fatalf("parsed %+v", c)
	}
	if again, err := ParseCredentials(c.Header()); err != nil || !reflect.DeepEqual(again, c) {
		t.Fatalf("Header did not round-trip: %q, %v", c.Header(), err)
	}
}

func TestMalformedCredentialsAreRejected(t *testing.T) {
	base := `Digest username="u", realm="r", nonce="n", uri="sip:r", response="00"`
	cases := map[string]string{
		"no username":       `Digest realm="r", nonce="n", uri="sip:r", response="00"`,
		"no realm":          `Digest username="u", nonce="n", uri="sip:r", response="00"`,
		"no nonce":          `Digest username="u", realm="r", uri="sip:r", response="00"`,
		"no uri":            `Digest username="u", realm="r", nonce="n", response="00"`,
		"no response":       `Digest username="u", realm="r", nonce="n", uri="sip:r"`,
		"short nc":          base + `, nc=0001`,
		"long nc":           base + `, nc=000000001`,
		"upper-case nc":     base + `, nc=0000000A`,
		"non-hex nc":        base + `, nc=0000000g`,
		"auts not base64":   base + `, auts="!!!"`,
		"auts unpadded":     base + `, auts="5PYxMuX2NOT2NeQ"`,
		"empty auts":        base + `, auts=""`,
		"duplicate nc":      base + `, nc=00000001, nc=00000002`,
		"duplicate auts":    base + `, auts="AAAA", auts="AAAA"`,
		"not digest at all": `Bearer abc`,
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if c, err := ParseCredentials(value); !errors.Is(err, ErrMalformed) {
				t.Fatalf("ParseCredentials = %+v, %v; want ErrMalformed", c, err)
			}
		})
	}
}

func TestParseErrorsDoNotQuoteTheInput(t *testing.T) {
	const identity = "001010000000002@ims.mnc001.mcc001.3gppnetwork.org"
	for _, value := range []string{
		`Digest username="` + identity + `", username="` + identity + `"`,
		`Digest username="` + identity + `" realm="r"`,
		`Digest username="` + identity,
		`Digest username="` + identity + "\x01\"",
		`Digest username="` + identity + `", nc=` + identity,
	} {
		_, err := ParseCredentials(value)
		if err == nil {
			t.Fatalf("%q parsed", value)
		}
		if strings.Contains(err.Error(), "00101") {
			t.Errorf("error %q quotes the input", err)
		}
	}
}

func TestChallengeHeaderQuotesAsRFC7616Requires(t *testing.T) {
	c := Challenge{Realm: `r"\`, Nonce: "n", Opaque: "o", Algorithm: SHA256, QOP: []string{"auth"}, Stale: true}
	want := `Digest realm="r\"\\", nonce="n", opaque="o", algorithm=SHA-256, qop="auth", stale=true`
	if got := c.Header(); got != want {
		t.Fatalf("Header = %s\nwant     %s", got, want)
	}
}

func TestCredentialsHeaderQuotesAsRFC7616Requires(t *testing.T) {
	c := Credentials{
		Username: "u", Realm: "r", Nonce: "n", URI: "sip:r", Response: "ab",
		Algorithm: AKAv1MD5, CNonce: "c", NC: 0x1a, QOP: "auth", Opaque: "o", AUTS: []byte{1, 2, 3},
	}
	want := `Digest username="u", realm="r", nonce="n", uri="sip:r", response="ab", algorithm=AKAv1-MD5, ` +
		`cnonce="c", opaque="o", qop=auth, nc=0000001a, auts="AQID"`
	if got := c.Header(); got != want {
		t.Fatalf("Header = %s\nwant     %s", got, want)
	}
}

func TestHeaderNeverWritesALineBreak(t *testing.T) {
	// A hand-built value with CR LF must not be able to add a header line.
	c := Credentials{Username: "u\r\nVia: x", Realm: "r", Nonce: "n", URI: "u", Response: "", QOP: "a\r\nb", Algorithm: "X\r\nY"}
	ch := Challenge{Realm: "r\r\nX: y", Nonce: "n", Algorithm: "A\nB", QOP: []string{"auth\r\n"}}
	for _, s := range []string{c.Header(), ch.Header()} {
		if strings.ContainsAny(s, "\r\n") {
			t.Fatalf("Header wrote a line break: %q", s)
		}
	}
}

func TestHeaderOutputParsesBackToTheSameValue(t *testing.T) {
	ch := Challenge{Realm: "r", Nonce: "n", Opaque: "o", Algorithm: AKAv1MD5, QOP: []string{"auth", "auth-int"}, Stale: true}
	if got, err := ParseChallenge(ch.Header()); err != nil || !reflect.DeepEqual(got, ch) {
		t.Fatalf("challenge round trip = %+v, %v", got, err)
	}
	cr := Credentials{
		Username: "u", Realm: "r", Nonce: "n", URI: "sip:r", Response: "ab", Algorithm: SHA256,
		CNonce: "c", NC: 7, QOP: "a b", Opaque: "o", AUTS: make([]byte, 14),
	}
	if got, err := ParseCredentials(cr.Header()); err != nil || !reflect.DeepEqual(got, cr) {
		t.Fatalf("credentials round trip = %+v, %v", got, err)
	}
}

func TestEmptyAUTSIsTreatedAsAbsent(t *testing.T) {
	c := Credentials{Username: "u", Realm: "r", Nonce: "n", URI: "sip:r", Response: "", AUTS: []byte{}}
	if strings.Contains(c.Header(), "auts") {
		t.Fatalf("Header wrote an empty auts: %s", c.Header())
	}
	again, err := ParseCredentials(c.Header())
	if err != nil || len(again.AUTS) != 0 {
		t.Fatalf("round trip = %+v, %v", again, err)
	}
	if strings.Contains(c.String(), "auts=true") {
		t.Fatalf("summary reports auts: %s", c)
	}
}

func TestAKANonceYieldsRANDAndAUTN(t *testing.T) {
	// base64 of 0x00..0x1f followed by server data.
	nonce := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh/w8Q=="
	rand, autn, err := ParseAKANonce(nonce)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 16 {
		if rand[i] != byte(i) || autn[i] != byte(16+i) {
			t.Fatalf("RAND %x AUTN %x", rand, autn)
		}
	}
	for _, bad := range []string{"", "AAEC", "not base64!", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg=="} {
		if _, _, err := ParseAKANonce(bad); !errors.Is(err, ErrMalformed) {
			t.Errorf("ParseAKANonce(%q): err = %v, want ErrMalformed", bad, err)
		}
	}
}
