package pii

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"regexp"
	goruntime "runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// Test identifiers come from .github/allowed-test-identifiers.txt: IMSIs from the
// reserved test network MCC 001 / MNC 01 and +1 555 0100-0199 phone numbers.
const (
	testIMSI   = "001010000000001"
	testIMSI2  = "001010000000002"
	testMSISDN = "+15550100001"
	testDomain = "ims.mnc001.mcc001.3gppnetwork.org"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestUnkeyedRedactMasksIdentifiersAndKeepsTheirLastTwoCharacters(t *testing.T) {
	r := NewRedactor(nil)
	tests := []struct {
		name, in, want string
	}{
		{"plain text is untouched", "REGISTER accepted", "REGISTER accepted"},
		{"short digit runs are untouched", "SIP/2.0 200 OK, CSeq: 1234567 INVITE", "SIP/2.0 200 OK, CSeq: 1234567 INVITE"},
		{"IMSI of 15 digits", "imsi=" + testIMSI, "imsi=***01"},
		{"IMSI of 14 digits", "imsi=00101000000001", "imsi=***01"},
		{"IMPI built from an IMSI keeps the domain", testIMSI + "@" + testDomain, "***01@" + testDomain},
		{"IMEI of 15 digits", "imei " + testIMSI2 + ".", "imei ***02."},
		{"IMEISV of 16 digits", "imeisv=" + testIMSI + "7", "imeisv=***17"},
		{"E.164 with 11 digits keeps the plus", "caller " + testMSISDN, "caller +***01"},
		{"E.164 with 8 digits", "caller +15550100", "caller +***00"},
		{"national number without plus", "msisdn=05550100001", "msisdn=***01"},
		{"digit run inside a word", "id:abc15550100001xyz", "id:abc***01xyz"},
		{"tel URI", "tel:" + testMSISDN, "tel:+***01"},
		{"tel URI with visual separators and parameters", "<tel:+1-555-010-0001;verstat=TN-Validation-Passed>", "<tel:+***01;verstat=TN-Validation-Passed>"},
		{"tel URI with a local number", "tel:7042;phone-context=example.com", "tel:***;phone-context=example.com"},
		{"tel scheme is case-insensitive", "TEL:+15550100002", "TEL:+***02"},
		{"sip user part", "sip:alice.smith@" + testDomain, "sip:***th@" + testDomain},
		{"short sip user part gets no hint", "sip:bob@" + testDomain, "sip:***@" + testDomain},
		{"sips user part", "sips:" + testMSISDN + "@" + testDomain + ";user=phone", "sips:***01@" + testDomain + ";user=phone"},
		{"sip scheme is case-insensitive", "SIP:carol.jones@" + testDomain, "SIP:***es@" + testDomain},
		{"sip password never survives", "sip:alice.smith:secret@" + testDomain, "sip:***th@" + testDomain},
		{"sip user with parameters", "sip:+15550100003;phone-context=" + testDomain + "@" + testDomain, "sip:***03@" + testDomain},
		{"sip URI without a user part names a host", "Route: <sip:scscf.rcs.internal;lr>", "Route: <sip:scscf.rcs.internal;lr>"},
		{"sip URI without a user part still masks digit runs", "sip:" + testMSISDN, "sip:+***01"},
		{"empty sip user part", "sip:@" + testDomain, "sip:@" + testDomain},
		{"a terminator ends the URI before a later @", "sip:host> mail alice@" + testDomain, "sip:host> mail alice@" + testDomain},
		{"gsma imei URN masks every group", `+sip.instance="<urn:gsma:imei:00101000-000003-1>"`, `+sip.instance="<urn:gsma:imei:***31>"`},
		{"gsma imei URN keeps the svn parameter", "urn:gsma:imei:00101000-000003-1;svn=42", "urn:gsma:imei:***31;svn=42"},
		{"several identifiers in one line", "sip:" + testMSISDN + "@" + testDomain + " -> tel:+15550100002 imsi " + testIMSI2, "sip:***01@" + testDomain + " -> tel:+***02 imsi ***02"},
		{"non-ASCII text passes through", "メッセージ 受信 sip:alice.smith@例え.jp", "メッセージ 受信 sip:***th@例え.jp"},
		{"empty input", "", ""},
		{"a scheme at the end of the input", "to tel:", "to tel:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.Redact(tt.in); got != tt.want {
				t.Fatalf("Redact(%q)\n got %q\nwant %q", tt.in, got, tt.want)
			}
		})
	}
}

// UK numbers are from Ofcom's range reserved for drama (07700 900000-900999);
// the Korean-shaped one is all zero groups, not a plausible subscriber.
func TestRedactMasksNumbersWrittenWithSeparators(t *testing.T) {
	r := NewRedactor(nil)
	tests := []struct {
		name, in, want string
	}{
		{"E.164 with hyphens", "msisdn=+1-555-010-0001", "msisdn=+***01"},
		{"E.164 with spaces", "+1 555 010 0001 rejected", "+***01 rejected"},
		{"E.164 with dots", "call +1.555.010.0002 failed", "call +***02 failed"},
		{"E.164 with parentheses in a display name", `"+1 (555) 010-0003" <sip:alice.smith@` + testDomain + `>`, `"+***03" <sip:***th@` + testDomain + `>`},
		{"national mobile number with a space", "from 07700 900001", "from ***01"},
		{"national number in parentheses", "(07700) 900-002", "(***02"},
		{"Korean-style national groups", "msisdn=010-0000-0001", "msisdn=***01"},
		{"national number after a label with a dot", "Tel.010-0000-0001", "Tel.***01"},
		{"national number after an abbreviation", "H.P.010-0000-0001", "H.P.***01"},
		{"national number after No.", "No.010-0000-0001", "No.***01"},
		{"national number after a label with a hyphen", "phone-010-0000-0001", "phone-***01"},
		{"IMEI with separators", "imei=00-101000-000003-1", "imei=***31"},
		{"tel URI written with spaces", "tel:+1 555 010 0004", "tel:+***04"},
		{"a long run anywhere masks the whole group", "2026-10-19 15550100001", "***01"},
		{"dates do not start with 0 or +", "on 2026-10-19 at 10.0.255.255", "on 2026-10-19 at 10.0.255.255"},
		{"zero groups inside a token are not a number", "v0.1234.5678 and 10.0.255.255", "v0.1234.5678 and 10.0.255.255"},
		{"too few digits", "+1 555 010 and 0 1 2 3", "+1 555 010 and 0 1 2 3"},
		{"a byte range is not a number", "Range: bytes=0-1048575", "Range: bytes=0-1048575"},
		{"a list of small integers is not a number", "[0 1 2 3 4 5 6 7]", "[0 1 2 3 4 5 6 7]"},
		{"a list of fractions is not a number", "[0.25 0.5 0.75 0.95]", "[0.25 0.5 0.75 0.95]"},
		{"a lone 0 group does not stop a later trunk prefix", "0 010-0000-0001", "0 ***01"},
		{"three separators end the number", "+1 555   0100001", "+1 555   0100001"},
		{"status lines are untouched", "SIP/2.0 200 OK", "SIP/2.0 200 OK"},
		{"a group after a URI value is part of it", "urn:gsma:imei:000A00 000000", "urn:gsma:imei:***00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.Redact(tt.in); got != tt.want {
				t.Fatalf("Redact(%q)\n got %q\nwant %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRedactMasksSIPHeaderLines(t *testing.T) {
	r := NewRedactor(nil)
	tests := []struct {
		in, want string
	}{
		{
			`From: <sip:` + testMSISDN + `@` + testDomain + `>;tag=a73kszlfl`,
			`From: <sip:***01@` + testDomain + `>;tag=a73kszlfl`,
		},
		{
			`To: "Test User" <sip:+15550100002@` + testDomain + `;user=phone>`,
			`To: "Test User" <sip:***02@` + testDomain + `;user=phone>`,
		},
		{
			`P-Asserted-Identity: <sip:` + testMSISDN + `@` + testDomain + `>, <tel:` + testMSISDN + `>`,
			`P-Asserted-Identity: <sip:***01@` + testDomain + `>, <tel:+***01>`,
		},
		{
			`Contact: <sip:` + testIMSI + `@10.0.0.7:5060;transport=tcp>;+sip.instance="<urn:gsma:imei:00101000-000003-1>"`,
			`Contact: <sip:***01@10.0.0.7:5060;transport=tcp>;+sip.instance="<urn:gsma:imei:***31>"`,
		},
		{
			`Authorization: Digest username="` + testIMSI + `@` + testDomain + `", realm="` + testDomain + `"`,
			`Authorization: Digest username="***01@` + testDomain + `", realm="` + testDomain + `"`,
		},
		{
			`INVITE tel:+15550100004 SIP/2.0`,
			`INVITE tel:+***04 SIP/2.0`,
		},
		{
			`Via: SIP/2.0/TCP 10.0.0.7:5060;branch=z9hG4bK776asdhds`,
			`Via: SIP/2.0/TCP 10.0.0.7:5060;branch=z9hG4bK776asdhds`,
		},
	}
	for _, tt := range tests {
		if got := r.Redact(tt.in); got != tt.want {
			t.Errorf("Redact(%q)\n got %q\nwant %q", tt.in, got, tt.want)
		}
	}
}

func TestKeyedHintsCorrelateOneIdentifierAcrossItsForms(t *testing.T) {
	r := NewRedactor(testKey)
	forms := []string{
		"msisdn=15550100001",
		"tel:" + testMSISDN,
		"tel:+1-555-010-0001",
		"+1 (555) 010-0001",
		"+1 555 010 0001",
		"sip:" + testMSISDN + "@" + testDomain,
		"sips:" + testMSISDN + ";user=phone@" + testDomain,
	}
	var hints []string
	for _, f := range forms {
		hints = append(hints, hintOf(t, r.Redact(f)))
	}
	for i, h := range hints {
		if h != hints[0] {
			t.Fatalf("form %q has hint %q, form %q has %q", forms[i], h, forms[0], hints[0])
		}
	}
	if len(hints[0]) != 8 {
		t.Fatalf("keyed hint %q, want 8 characters", hints[0])
	}
}

func TestKeyedHintsDifferForDifferentIdentifiersAndKeys(t *testing.T) {
	a := NewRedactor(testKey)
	b := NewRedactor([]byte("another key that is also long enough"))
	h1 := hintOf(t, a.Redact("tel:+15550100001"))
	h2 := hintOf(t, a.Redact("tel:+15550100002"))
	h3 := hintOf(t, b.Redact("tel:+15550100001"))
	if h1 == h2 {
		t.Fatalf("two numbers share hint %q", h1)
	}
	if h1 == h3 {
		t.Fatalf("two keys give the same hint %q", h1)
	}
}

func TestKeyedHintsContainNoDigits(t *testing.T) {
	r := NewRedactor(testKey)
	for i := range 100 {
		h := hintOf(t, r.Redact(fmt.Sprintf("tel:+155501000%02d", i)))
		if strings.ContainsAny(h, "0123456789") {
			t.Fatalf("hint %q contains a digit", h)
		}
	}
}

func TestKeyedRedactorKeepsNoClearHint(t *testing.T) {
	r := NewRedactor(testKey)
	got := r.Redact("imsi=" + testIMSI)
	if strings.HasSuffix(got, "01") {
		t.Fatalf("keyed output %q still shows the last digits", got)
	}
}

func TestRedactorCopiesTheKey(t *testing.T) {
	key := bytes.Clone(testKey)
	r := NewRedactor(key)
	before := r.Redact("tel:+15550100001")
	key[0] ^= 0xff
	if after := r.Redact("tel:+15550100001"); after != before {
		t.Fatalf("changing the caller's key slice changed the hint: %q then %q", before, after)
	}
}

func TestRedactorNeverPrintsItsKey(t *testing.T) {
	r := NewRedactor(testKey)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(verb, r) + fmt.Sprintf(verb, *r) + fmt.Sprintf(verb, struct{ R *Redactor }{r})
		if strings.Contains(out, string(testKey)) || strings.Contains(out, fmt.Sprint(testKey)) {
			t.Fatalf("%s printed the key: %s", verb, out)
		}
	}
}

func TestZeroRedactorIsUnkeyed(t *testing.T) {
	var r Redactor
	if got := r.Redact("tel:+15550100001"); got != "tel:+***01" {
		t.Fatalf("zero Redactor gave %q", got)
	}
}

func TestIdentityAlwaysMasksTheWholeValue(t *testing.T) {
	r := NewRedactor(nil)
	tests := []struct{ in, want string }{
		{testIMSI, "***01"},
		{testIMSI + "@" + testDomain, "***rg"},
		{"alice", "***"},
		{"", "***"},
		{testMSISDN, "***01"},
		{"+1 555 010 0001", "***01"},
	}
	for _, tt := range tests {
		a := r.Identity("impi", tt.in)
		if a.Key != "impi" || a.Value.String() != tt.want {
			t.Errorf("Identity(%q) = %s=%q, want impi=%q", tt.in, a.Key, a.Value.String(), tt.want)
		}
	}
}

func TestURIMasksTheIdentifyingPartAndKeepsTheHost(t *testing.T) {
	r := NewRedactor(nil)
	tests := []struct{ in, want string }{
		{"sip:" + testMSISDN + "@" + testDomain, "sip:***01@" + testDomain},
		{"tel:" + testMSISDN, "tel:+***01"},
		{"sip:conference-factory." + testDomain, "sip:conference-factory." + testDomain},
		{"urn:gsma:imei:00101000-000003-1", "urn:gsma:imei:***31"},
		// A value that is not a URI could be anything, so none of it is kept.
		{`"Alice Smith" <sip:alice.smith@` + testDomain + `>`, "***"},
		{"alice.smith@" + testDomain, "***rg"},
		{"", "***"},
	}
	for _, tt := range tests {
		a := r.URI("from", tt.in)
		if a.Key != "from" || a.Value.String() != tt.want {
			t.Errorf("URI(%q) = %s=%q, want from=%q", tt.in, a.Key, a.Value.String(), tt.want)
		}
	}
}

func TestPackageFunctionsUseTheDefaultRedactor(t *testing.T) {
	t.Cleanup(func() { SetDefault(nil) })

	if got := Redact("tel:+15550100001"); got != "tel:+***01" {
		t.Fatalf("unkeyed default gave %q", got)
	}
	SetDefault(NewRedactor(testKey))
	want := NewRedactor(testKey).Redact("tel:+15550100001")
	if got := Redact("tel:+15550100001"); got != want {
		t.Fatalf("keyed default gave %q, want %q", got, want)
	}
	if got := URI("to", "tel:+15550100001").Value.String(); got != want {
		t.Fatalf("URI used another redactor: %q, want %q", got, want)
	}
	if got := Identity("msisdn", testMSISDN).Value.String(); got != NewRedactor(testKey).Identity("x", testMSISDN).Value.String() {
		t.Fatalf("Identity used another redactor: %q", got)
	}
	SetDefault(nil)
	if got := Redact("tel:+15550100001"); got != "tel:+***01" {
		t.Fatalf("SetDefault(nil) did not restore the unkeyed default: %q", got)
	}
}

func TestAttributesNeverCarryTheRawValueIntoALogLine(t *testing.T) {
	var buf bytes.Buffer
	log := untimedJSONLogger(&buf)
	log.Info("registered",
		URI("impu", "sip:"+testMSISDN+"@"+testDomain),
		Identity("impi", testIMSI+"@"+testDomain),
	)
	line := buf.String()
	if strings.Contains(line, `"time"`) {
		t.Fatalf("the line has a timestamp whose digits could match a secret:\n%s", line)
	}
	for _, raw := range []string{testMSISDN, testIMSI, "15550100001"} {
		if strings.Contains(line, raw) {
			t.Fatalf("log line contains %q: %s", raw, line)
		}
	}
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["impu"] != "sip:***01@"+testDomain {
		t.Fatalf("impu = %v", rec["impu"])
	}
}

// hintOf returns what follows the mask marker in a redacted string that has
// exactly one masked identifier.
func hintOf(t *testing.T, redacted string) string {
	t.Helper()
	_, after, ok := strings.Cut(redacted, mark)
	if !ok {
		t.Fatalf("%q has no mask", redacted)
	}
	end := strings.IndexFunc(after, func(r rune) bool {
		return !('a' <= r && r <= 'z' || '0' <= r && r <= '9')
	})
	if end < 0 {
		end = len(after)
	}
	return after[:end]
}

// A quadratic scan would take minutes on this input; a linear one takes
// milliseconds, so a regression shows up as a test timeout, not a flaky timing.
func TestRedactStaysLinearOnAdversarialInput(t *testing.T) {
	r := NewRedactor(nil)
	for _, unit := range []string{"sip:", "sips:a", "tel:", "1234567x", "0 ", "1-", "+1 (", "tel:1 1", "urn:gsma:imei:a 1", `im:"`, `pres:"\`, `im:"a"`, "１２３", "＋１\u3000", "（０）－", "1\u00a0", "1ー", "（１２", "(1", "tel:－", "１—\u202f", "1 \u2013", "＋", "1\u200b", "\u200b", "+\u200b", "1\u200b-", "sip:a\u00a01", "＋（", "\ufeff1",
		"sip:\u00a0", "SIM:\u3000１", "sip:a\u00a0@", "1 \u200b", "+\u200b(", "tel:)\u200b(", "1 \u200b \u200b", "\u200b ", "#\u2002\u061c(",
		"si\u200b", "sip\u00ad", "1\u0301", "sip:\u200b1@", "tel:\u200b+"} {
		in := strings.Repeat(unit, (1<<20)/len(unit))
		if out := r.Redact(in); len(out) == 0 {
			t.Fatalf("empty output for %q", unit)
		}
	}
}

// Redact's scans that could go on to the end of the line from every start
// remember where they ended: 64 times the input costs at most 8 times the
// CPU time of 64 reads of the small one, the best of five, in one of three
// attempts (the method of reginfo's linearity test, #317). A scan from
// every start costs 64 times as much (review of #398).
func TestRedactIsLinear(t *testing.T) {
	cpu := func() time.Duration {
		var ru syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
			t.Fatal(err)
		}
		return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
	}
	r := NewRedactor(nil)
	read := func(text string, n int) time.Duration {
		start := cpu()
		for range n {
			_ = r.Redact(text)
		}
		return cpu() - start
	}
	for name, unit := range map[string]string{
		"sip without a user":                "sip:1",
		"user scheme in a word":             "SIM:\u3000１",
		"invisible after a space":           "1 \u200b",
		"invisible after a plus":            "+\u200b(",
		"invisible in a tel number":         "tel:)\u200b(",
		"invisibles between digits":         "1\u200b\u2060",
		"a scheme split by invisibles":      "s\u200bi\u200b",
		"invisibles before a scheme's rest": "u\u200b\u200b\u200b",
		"marks after digits":                "1\u0301\u20e3",
		"invisibles in a user":              "sip:\u200ba",
	} {
		t.Run(name, func(t *testing.T) {
			small := strings.Repeat(unit, max(1, 1024/len(unit)))
			large := strings.Repeat(small, 64)
			var ratios []string
			for range 3 {
				s, l := time.Duration(1<<62), time.Duration(1<<62)
				for range 5 {
					s = min(s, read(small, 64))
					l = min(l, read(large, 1))
				}
				if l <= 8*s {
					return
				}
				ratios = append(ratios, fmt.Sprintf("%v against %v (%.1f×)", l, s, float64(l)/float64(s)))
			}
			t.Fatalf("64× the input once took, against 64 of the small, three times over: %s: not linear", strings.Join(ratios, "; "))
		})
	}
}

// Where dropInvisibles removed characters is kept as a list of positions,
// not as a set the size of the text (review of #398): a long text with one
// removed run costs its copies only, about twice its length.
func TestOneRemovedRunCostsNoTextLengthSet(t *testing.T) {
	r := NewRedactor(nil)
	in := "1\u200b2 " + strings.Repeat("a", 4<<20)
	var best uint64 = 1 << 62
	for range 3 {
		var before, after goruntime.MemStats
		goruntime.ReadMemStats(&before)
		_ = r.Redact(in)
		goruntime.ReadMemStats(&after)
		best = min(best, after.TotalAlloc-before.TotalAlloc)
	}
	if limit := uint64(len(in)) * 5 / 2; best > limit {
		t.Fatalf("Redact allocated %d bytes for %d, more than %d", best, len(in), limit)
	}
}

// CPIM From and To carry im: and pres: URIs (RFC 3862 §3.4, RFC 3860,
// RFC 3859), whose user part names the subscriber as a sip URI's does.
func TestRedactMasksTheUserOfImAndPresURIs(t *testing.T) {
	r := NewRedactor(nil)
	for _, tt := range []struct{ in, want string }{
		{"From: Alice <im:alice.smith@" + testDomain + ">", "From: Alice <im:***th@" + testDomain + ">"},
		{"To: <pres:bob.jones@" + testDomain + ">", "To: <pres:***es@" + testDomain + ">"},
		{"IM:carol.jones@" + testDomain, "IM:***es@" + testDomain},
		{"Pres:" + testMSISDN + "@" + testDomain, "Pres:***01@" + testDomain},
		{"im:conference-factory", "im:conference-factory"},
		// RFC 3860 §3: the user is an RFC 5322 local part, which may be a
		// quoted string with spaces and escaped quotes.
		{`From: <im:"bob smith"@` + testDomain + ">", "From: <im:***th@" + testDomain + ">"},
		{`pres:"a \"b\" c"@` + testDomain, "pres:***@" + testDomain},
		{`im:"` + testMSISDN + `"@` + testDomain, "im:***01@" + testDomain},
		// A quoted string not followed by '@' is not a user.
		{`im:"bob smith" said`, `im:"bob smith" said`},
		{`sip:"bob smith"@` + testDomain, `sip:"bob smith"@` + testDomain},
	} {
		if got := r.Redact(tt.in); got != tt.want {
			t.Errorf("Redact(%q)\n got %q\nwant %q", tt.in, got, tt.want)
		}
	}
	if got := r.URI("from", "im:alice.smith@"+testDomain).Value.String(); got != "im:***th@"+testDomain {
		t.Errorf("URI(im:…) = %q, want the host kept", got)
	}
}

// Digits from other scripts identify a subscriber as well as ASCII ones: a
// phone number typed on a phone in a CJK input mode arrives in full-width
// digits, and Arabic-script locales use Arabic-Indic digits.
func TestRedactMasksDigitRunsInEveryScript(t *testing.T) {
	r := NewRedactor(nil)
	for _, tt := range []struct{ name, in, want string }{
		{"full-width MSISDN", "msisdn=１５５５０１００００１", "msisdn=***01"},
		{"full-width with an ASCII plus", "caller +１５５５０１００００２", "caller +***02"},
		{"ASCII and full-width mixed", "id 1555０１０0003 seen", "id ***03 seen"},
		{"Arabic-Indic IMSI", "imsi ٠٠١٠١٠٠٠٠٠٠٠٠٠١", "imsi ***01"},
		{"Extended Arabic-Indic digits", "شماره ۱۵۵۵۰۱۰۰۰۰۴", "شماره ***04"},
		{"short full-width numbers read the same in ASCII", "２０２６年１０月", "2026年10月"},
		{"eight full-width digits are a run", "２０２６１０１９", "***19"},
		{"seven full-width digits are not", "２０２６１０１", "2026101"},
		{"full-width trunk number with ASCII hyphens", "０１０-１２３４-５６７８", "***78"},
		{"ASCII trunk prefix and full-width groups", "010-１２３４-５６７８", "***78"},
		{"a short run after a tel number", "tel:+15550100001-２３４５６７", "tel:+***67"},
		{"a short run after a digit run", "0000000 0０１0000", "***00"},
		{"full-width IMEI groups", "urn:gsma:imei:00101000-１７６１４８-１", "urn:gsma:imei:***81"},
		{"full-width national number in ASCII groups", "call ０１０-００００-０００１", "call ***01"},
		{"full-width international number in ASCII groups", "call +１ ５５５ ０１００ ００１", "call +***01"},
		{"full-width inside a sip URI user", "sip:１５５５０１００００１@" + testDomain, "sip:***01@" + testDomain},
		// Full-width separators group a number as ASCII ones do (#85).
		{"full-width hyphens", "call ０１０－００００－０００１", "call ***01"},
		{"full-width plus and ideographic spaces", "call ＋１\u3000５５５\u3000０１０\u3000０００１", "call +***01"},
		{"full-width parentheses and full stops", "（０７７００）\u3000９００．００１", "(***01"},
		{"full-width separators around ASCII digits", "010－0000－0001", "***01"},
		{"full-width parentheses and a space between groups", "＋１\u3000（５５５）\u3000０１０－０００１", "+***01"},
		// Every Unicode space and dash groups a number too (#110): a number
		// copied from a formatter or a web page may carry no-break or thin
		// spaces, and the "-" key of a Japanese IME in kana mode types "ー".
		{"no-break spaces", "call +1\u00a0555\u00a0010\u00a00001", "call +***01"},
		{"narrow no-break spaces", "010\u202f0000\u202f0001", "***01"},
		{"thin spaces", "+1\u2009555\u2009010\u20090001", "+***01"},
		{"hyphens", "010\u20100000\u20100001", "***01"},
		{"non-breaking hyphens", "010\u20110000\u20110001", "***01"},
		{"figure dashes", "010\u20120000\u20120001", "***01"},
		{"en dashes", "010\u20130000\u20130001", "***01"},
		{"em dashes", "010\u20140000\u20140001", "***01"},
		{"horizontal bars", "010\u20150000\u20150001", "***01"},
		{"minus signs", "010\u22120000\u22120001", "***01"},
		{"katakana long vowel marks", "０１０ー１２３４ー５６７８", "***78"},
		{"half-width long vowel marks", "010ｰ0000ｰ0001", "***01"},
		{"an en dash and a space", "+1\u2013 555\u2013 010\u2013 0001", "+***01"},
		// Inside a tel URI every number character counts, as in ASCII.
		{"full-width parentheses in a tel URI", "tel:（０３）１２３４", "tel:***34"},
		{"full-width hyphens in a tel URI", "tel:１２－－－３４５６", "tel:***56"},
		{"a dash after a tel URI's scheme", "tel:\u2010123456", "tel:***56"},
		{"a space after a tel URI's scheme", "tel:\u3000１２３４５６", "tel:***56"},
		// Invisible format characters inside a number do not split it, as a
		// log viewer shows the digits joined (#154).
		{"a zero-width space", "call +1555\u200b0100001", "call +***01"},
		{"a word joiner, a soft hyphen and a BOM", "+1\u2060555\u00ad010\ufeff0001", "+***01"},
		{"a run of invisibles", "1555\u200b\u200c\u200d0100001", "***01"},
		{"a variation selector", "1555\ufe0f0100001", "***01"},
		{"an invisible after the plus", "+\u200b15550100001", "+***01"},
		{"an invisible next to a separator", "010-\u200b0000\u2060-0001", "***01"},
		{"an invisible in a tel URI", "tel:+1555\u200b0100001", "tel:+***01"},
		{"an invisible in a sip user", "sip:+1555\u200b0100001@" + testDomain, "sip:***01@" + testDomain},
		// Between two separators, or a "+" and a bracket, as long as digits
		// are within two separators either way (review of #398).
		{"an invisible after a space", "+1 \u200b(555) 010-0001", "+***01"},
		{"an invisible before a space", "+1 (555)\u200b 010-0001", "+***01"},
		{"isolates around a bracketed group", "+1 \u2066(555)\u2069 010-0001", "+***01"},
		{"an invisible between two dashes", "010-\u200b-0000-0001", "***01"},
		{"an invisible between a plus and a bracket", "+\u200b(1)555 010 0001", "+***01"},
		{"an invisible between a star and a hash in a tel URI", "tel:123*\u200b#456789", "tel:***89"},
		{"an invisible right after a tel scheme", "tel:\u200b123456*78#9", "tel:***"},
		{"an invisible between the separators after a tel number", "tel:12#\u2002\u061c(0698)", "tel:***98)"},
		{"an invisible before a bracketed country code", "+\u200b(81)3 1234 5678", "+***78"},
		{"a full-width plus, a joiner and a bracket", "＋\u2060（１）５５５ ０１０ ０００１", "+***01"},
		// A removed invisible still ends the word before it, as it did
		// before #154: the trunk prefix after it is masked.
		{"an invisible before a dash and a trunk prefix", "1\u200b-010-0000-0001", "1-***01"},
		{"a BOM before a trunk prefix", "8\ufeff010 0000 0001", "8***01"},
		{"a BOM inside digits before a trunk prefix", "30\ufeff010-0000-0001", "30***01"},
		// A Unicode space inside a URI user is not a separator there: the
		// user goes on to its "@" (#154), whatever schemes it holds.
		{"a no-break space in a sip user", "sip:alice.smith1\u00a02@" + testDomain, "sip:***@" + testDomain},
		{"a no-break space after a sip user", "sip:a@" + testDomain + " 010\u00a00000\u00a00001", "sip:***@" + testDomain + " ***01"},
		{"an ideographic space in a user holding a scheme", "sips:urn:gsma:imei:\u3000555\u3000010@x", "sips:***@x"},
		// Without an "@", there is no user, and a Unicode space groups the
		// number after the scheme, also one inside a word (review of #398).
		{"no-break spaces after a sip URI without a user", "sip:a\u00a0+1\u00a0555\u00a0010\u00a00001", "sip:a\u00a0+***01"},
		{"a number in brackets after a sip URI", "From: sip:alice\u00a0(+1\u00a0555\u00a0010\u00a00001)", "From: sip:alice\u00a0(+***01)"},
		{"a scheme inside a word", "SIM:\u00a0+1\u00a0555\u00a0010\u00a00001", "SIM:\u00a0+***01"},
		{"another scheme inside a word", "Interim:\u00a0010\u00a00000\u00a00001", "Interim: ***01"},
		{"after URI parameters", "sips:pcscf;lr\u00a0010\u00a00000\u00a00001", "sips:pcscf;lr\u00a0***01"},
		{"full-width digits right after an im scheme", "im:\u3000０１０\u3000００００\u3000０００１", "im: ***01"},
		{"ideographic spaces after a host", "sip:ims.example.com\u3000+1\u3000555\u3000010\u30000001", "sip:ims.example.com\u3000+***01"},
		{"after a host and a word", "sip:ims.example.com経由\u3000０３\u3000１２３４\u3000５６７８", "sip:ims.example.com経由\u3000***78"},
		{"thin spaces after a host and a comma", "sip:ims.example.com、+1\u2009555\u2009010\u20090001", "sip:ims.example.com、+***01"},
		{"ideographic spaces right after an im scheme", "im:\u3000+1\u3000555\u3000010\u30000001", "im:\u3000+***01"},
		// The full-width star and hash of a tel number, and the small plus.
		{"a full-width star and hash in a tel URI", "tel:123456＊78＃9", "tel:***"},
		{"a small plus sign", "call ﹢15550100001", "call +***01"},
		// A country code in brackets after the plus starts a number.
		{"a bracketed country code", "+(81)3 1234 5678", "+***78"},
		{"a full-width bracketed country code", "＋（８１）３\u3000１２３４\u3000５６７８", "+***78"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.Redact(tt.in); got != tt.want {
				t.Fatalf("Redact(%q)\n got %q\nwant %q", tt.in, got, tt.want)
			}
		})
	}
	// The keyed hint is the same whichever digits the number was written in,
	// so one subscriber's log lines still correlate.
	k := NewRedactor(testKey)
	if a, b := k.Redact(testMSISDN), k.Redact("+１５５５０１００００１"); a != b {
		t.Errorf("hints differ: %q and %q", a, b)
	}
	// So is that of a numeric URI user with Unicode spaces, which
	// asciiNumberChars keeps inside a user (review of #398).
	if a, b := k.Redact("tel:"+testMSISDN), k.Redact("sip:+1\u00a0555\u3000010\u20090001@"+testDomain); keyedMask.FindString(a) != keyedMask.FindString(b) {
		t.Errorf("hints differ: %q and %q", a, b)
	}
	// A number written with full-width separators is masked as its ASCII
	// form is, hint included.
	for ascii, wide := range map[string]string{
		"+1 555 010 0001":   "＋１\u3000５５５\u3000０１０\u3000０００１",
		"010-0000-0001":     "０１０－００００－０００１",
		"(07700) 900.001":   "（０７７００）\u3000９００．００１",
		"tel:+1-555-0100-1": "tel:＋１－５５５－０１００－１",
		"+1 555 010 0002":   "+1\u00a0555\u202f010\u20090002",
		"010-0000-0002":     "０１０ー００００\u2212０００２",
		"+1 (555) 010-0001": "＋１\u3000（５５５）\u00a0０１０\u2013０００１",
		"tel:(03)1234-5678": "tel:（０３）１２３４—５６７８",
		"+1 555 010 0003":   "+1\u200b 555 010\u2060 0003",
		"010-0000-0003":     "010\u00ad-0000-\ufeff0003",
	} {
		if a, b := k.Redact(ascii), k.Redact(wide); a != b || !strings.Contains(a, mark) {
			t.Errorf("%q gives %q but %q gives %q", ascii, a, wide, b)
		}
	}
}

// Every character of the classes a log viewer shows as nothing, or as a
// space, is read inside a number as its plain form is (#413), with the same
// keyed hint: a format character (Cf), a variation selector or another
// default-ignorable one as nothing; a combining mark (Mn, Me) right after a
// digit as part of the digit, as the viewer draws it over the digit (a
// keycap "1\ufe0f\u20e3"); and every space (Zs, Zl, Zp, U+2800 BRAILLE
// PATTERN BLANK) as a space. Every character of each class is tried.
func TestRedactReadsEveryHiddenCharacterAsItsPlainForm(t *testing.T) {
	k := NewRedactor(testKey)
	templates := []string{
		"call +1555X0100001",
		"msisdn=010X0000-0001",
		"imsi 0010100X00000001",
		"tel:+1555X0100001;phone-context=example.net",
		"sip:+1555X0100001@" + testDomain,
	}
	// In a user that is not a number, a hidden character is dropped too,
	// so the hint is the plain user's.
	userTemplates := []string{"sip:Xalice.smith@" + testDomain, "sip:alice.smiXth@" + testDomain, "sip:alice.smithX@" + testDomain}
	type class struct {
		name  string
		table *unicode.RangeTable
		plain string
		user  bool // also tried in userTemplates
	}
	classes := []class{
		{"Cf", unicode.Cf, "", true},
		{"Variation_Selector", unicode.Variation_Selector, "", true},
		{"Other_Default_Ignorable_Code_Point", unicode.Other_Default_Ignorable_Code_Point, "", true},
		{"Mn", unicode.Mn, "", false},
		{"Me", unicode.Me, "", false},
		{"Zs", unicode.Zs, " ", false},
		{"Zl", unicode.Zl, " ", false},
		{"Zp", unicode.Zp, " ", false},
		{"U+2800", &unicode.RangeTable{R16: []unicode.Range16{{Lo: 0x2800, Hi: 0x2800, Stride: 1}}}, " ", false},
	}
	for _, cl := range classes {
		t.Run(cl.name, func(t *testing.T) {
			tried := 0
			for _, rs := range [][]unicode.Range32{r32(cl.table)} {
				for _, rg := range rs {
					for r := rune(rg.Lo); r <= rune(rg.Hi); r += rune(rg.Stride) {
						if r < utf8.RuneSelf || unicode.IsDigit(r) {
							continue
						}
						tried++
						ts := templates
						if cl.user {
							ts = append(slices.Clone(templates), userTemplates...)
						}
						for _, tmpl := range ts {
							wide := strings.Replace(tmpl, "X", string(r), 1)
							plain := strings.Replace(tmpl, "X", cl.plain, 1)
							got, want := k.Redact(wide), k.Redact(plain)
							if g, w := keyedMask.FindAllString(got, -1), keyedMask.FindAllString(want, -1); !slices.Equal(g, w) || len(g) == 0 {
								t.Fatalf("U+%04X: Redact(%q) = %q, want the hints of %q", r, wide, got, want)
							}
							if strings.ContainsFunc(got, unicode.IsDigit) && !strings.ContainsFunc(want, unicode.IsDigit) {
								t.Fatalf("U+%04X: Redact(%q) = %q keeps a digit", r, wide, got)
							}
						}
					}
				}
			}
			if tried == 0 {
				t.Fatal("no character tried")
			}
		})
	}
}

// r32 returns the ranges of a table as Range32s.
func r32(t *unicode.RangeTable) []unicode.Range32 {
	var out []unicode.Range32
	for _, r := range t.R16 {
		out = append(out, unicode.Range32{Lo: uint32(r.Lo), Hi: uint32(r.Hi), Stride: uint32(r.Stride)})
	}
	return append(out, t.R32...)
}

// An invisible character inside a URI scheme, or around a URI user, leaves
// the URI read as it is without it (#413): the user or the number is
// masked, with the plain form's keyed hint.
func TestRedactReadsAURIWithInvisiblesAsWithout(t *testing.T) {
	k := NewRedactor(testKey)
	for wide, plain := range map[string]string{
		"sip\u200b:alice.smith@x":               "sip:alice.smith@x",
		"si\u00adp:alice.smith@x":               "sip:alice.smith@x",
		"s\u200bi\u2060p:alice.smith@x":         "sip:alice.smith@x",
		"From: <SIP\u2060:alice.smith@x>":       "From: <SIP:alice.smith@x>",
		"sips\ufeff:alice.smith@x":              "sips:alice.smith@x",
		"im\u200b:alice.smith@x":                "im:alice.smith@x",
		"pre\u200bs:alice.smith@x":              "pres:alice.smith@x",
		"te\u200bl:123456*78#9":                 "tel:123456*78#9",
		"tel\u200b:+15550100001":                "tel:+15550100001",
		"urn:gsma\u200b:imei:00101000-000003-1": "urn:gsma:imei:00101000-000003-1",
		"tel:\u200b123456*78#9":                 "tel:123456*78#9",
		"tel:\u200b*31#":                        "tel:*31#",
		"sip:\u200balice.smith@x":               "sip:alice.smith@x",
		"sip:alice.smith\u200b@x":               "sip:alice.smith@x",
		"sip:ali\u200bce.smith@x":               "sip:alice.smith@x",
		"im:\u2060alice.smith\u00ad@x":          "im:alice.smith@x",
		"sip:+1555\u200b0100001\u200b@x":        "sip:+15550100001@x",
	} {
		got, want := k.Redact(wide), k.Redact(plain)
		if asciiForm(withoutInvisibles(got)) != want {
			t.Errorf("Redact(%q) = %q, want it read as %q, %q", wide, got, plain, want)
		}
	}
	// Elsewhere such a character stays, as text.
	for _, in := range []string{"si\u200bx:alice", "sip:host\u200b>", "s\u200bi"} {
		if got := k.Redact(in); got != in {
			t.Errorf("Redact(%q) = %q, want it unchanged", in, got)
		}
	}
}

// Only the characters of a number are rewritten: brackets, spaces and dashes
// in the text around it keep the form they were written in (#110).
func TestRedactKeepsTheTextAroundANumber(t *testing.T) {
	r := NewRedactor(nil)
	for _, in := range []string{
		"名前\u3000（注）\u300010",
		"failed \u2014 retry 3 times",
		"pages 10 \u2013 20",
		"1\u3000\u2212\u30002",
		"ゲーム10本",
		"データー 10",
		"＋ 1",
		"（注1）",
		"（1",
		"1）",
		"10\u00a0€",
		"欄（）1",
		// Invisibles outside a number are text (#154).
		"a\u200bb",
		"-\u200b-",
		"id\u200b 7",
		"x\u200b1",
		"1\u200bx",
	} {
		if got := r.Redact(in); got != in {
			t.Errorf("Redact(%q) = %q, want it unchanged", in, got)
		}
	}
	for in, want := range map[string]string{
		"（１）":        "(1)",
		"（１)":        "(1)",
		"12\u200b34": "1234",
		"(１）":        "(1)",
		"（注１）２":      "（注1)2",
		"10\u201320": "10-20",
		"コード１ー２ー３":   "コード1-2-3",
		"２０２６年":      "2026年",
		// A URI's number ends where it does in ASCII.
		"tel:１２３４５６\u3000（注）": "tel:***56\u3000（注）",
		// The wave dashes are dashes, as before #154: a range of hours that
		// starts with 0 reads as a national number (review of #398).
		"営業時間 0900〜1800": "営業時間 ***00",
		"0900\u30301800": "***00",
	} {
		if got := r.Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

// Redact masks a number written in any digits and any Unicode spaces and
// dashes as it masks the number written in ASCII, hint included: the
// differential check from the QA of #106, with the separators of #110. Each
// text is built from numbers, URIs and words in ASCII, then every digit and
// separator in it is replaced at random by a form from another script, and
// invisible characters are put between number characters (#154). As only
// the characters of a number are rewritten, the output is compared after
// the remaining forms are read back as ASCII; see readsAsASCII.
func TestRedactReadsANumberInAnyFormAsInASCII(t *testing.T) {
	n := 20_000
	if testing.Short() {
		n = 2_000
	}
	rng := rand.New(rand.NewPCG(110, 106))
	for range n {
		ascii := asciiNumberText(rng)
		if bad := readsAsASCII(ascii, anyFormOf(rng, ascii)); bad != "" {
			t.Fatal(bad)
		}
	}
}

// readsAsASCII describes how Redact reads wide, a form of the ASCII text
// ascii, otherwise than ascii, or returns "". Both Redactors give the same
// output for both, once the forms left in wide's are read as ASCII and its
// invisible characters left out; or, where an invisible character Redact
// removed still ends a word (startsWord), wide's keeps strictly less of the
// text than ascii's.
func readsAsASCII(ascii, wide string) string {
	same := true
	for _, r := range []*Redactor{NewRedactor(nil), headKeyed} {
		same = same && asciiForm(withoutInvisibles(r.Redact(wide))) == r.Redact(ascii)
	}
	if same {
		return ""
	}
	want, got := headKeyed.Redact(ascii), headKeyed.Redact(wide)
	if k := keptOf(got); len([]rune(k)) < len([]rune(keptOf(want))) && isSubsequence(k, keptOf(want)) {
		return ""
	}
	return fmt.Sprintf("Redact(%q) = %q\nRedact(%q) = %q", ascii, want, wide, got)
}

// withoutInvisibles returns s without the invisible characters that
// anyFormOf puts in.
func withoutInvisibles(s string) string {
	return strings.Map(func(r rune) rune {
		if slices.Contains(invisibles, r) || slices.Contains(marks, r) {
			return -1
		}
		return r
	}, s)
}

// asciiNumberText returns a text of numbers, number URIs and words, joined
// as they may be in a log line. A text holds URI users ending in "@", or
// sip, sips, im and pres schemes without a user, also inside a word ("SIM:"),
// followed by numbers; not both, since a space outside ASCII does not end a
// user (Redact) and so would join the two.
func asciiNumberText(rng *rand.Rand) string {
	pick := func(xs ...string) string { return xs[rng.IntN(len(xs))] }
	digits := func() string {
		var b strings.Builder
		for range 1 + rng.IntN(5) {
			b.WriteByte(byte('0' + rng.IntN(10)))
		}
		return b.String()
	}
	number := func(seps ...string) string {
		var b strings.Builder
		b.WriteString(pick("", "", "+", "(", "0"))
		b.WriteString(digits())
		for range rng.IntN(6) {
			b.WriteString(pick(seps...))
			b.WriteString(digits())
		}
		return b.String()
	}
	grouping := []string{" ", "-", ".", "(", ")", "  ", " (", ") ", ")-", "--", " - ", "-.", ".("}
	// A sip user cannot hold a space (RFC 3261 §25.1).
	userGrouping := []string{"-", ".", "(", ")", ")-", "--", "-.", "---"}
	withUsers := rng.IntN(2) == 0
	var b strings.Builder
	for range 1 + rng.IntN(5) {
		switch rng.IntN(6) {
		case 0, 1:
			b.WriteString(number(grouping...))
		case 2:
			b.WriteString(pick("tel:", "TEL:", "urn:gsma:imei:"))
			b.WriteString(number(grouping...))
			b.WriteString(pick("", ";phone-context=example.net", "-", ")"))
		case 3:
			if !withUsers {
				b.WriteString(pick("sip:", "SIPS:", "im:", "pres:", "SIM:", "Interim:"))
				b.WriteString(pick("", "a", "pcscf;lr", "ims.example.net", "alice"))
				b.WriteString(pick(" ", "(", " (", " -", ""))
				b.WriteString(number(grouping...))
				break
			}
			b.WriteString(pick("sip:", "sips:", "im:", "pres:"))
			b.WriteString(number(userGrouping...))
			b.WriteString("@" + testDomain)
		default:
			b.WriteString(pick("call", "msisdn=", "id", "x", "abc", "Tel.", "v", "a-b", "(x)", "#", "*", "-", "+", "."))
		}
		b.WriteString(pick("", " ", " ", "-", " (", ") ", ", ", " - ", "(", ")", "."))
	}
	return b.String()
}

// The forms anyFormOf writes for each ASCII character of a number, and the
// invisible characters it puts inside a number.
var (
	invisibles = []rune{'\u200b', '\u200c', '\u200d', '\u2060', '\u00ad', '\ufeff', '\ufe0f', '\u180e', '\u061c'}
	// marks are combining marks a digit may carry (#413).
	marks      = []rune{'\u0301', '\u0300', '\u20e3', '\u0338', '\u3099', '\u034f'}
	digitZeros = []rune{'0', '０', '٠', '۰', '०', '০', '𝟎', '𝟘'}
	otherForms = map[byte][]rune{
		' ': {' ', '\u3000', '\u00a0', '\u202f', '\u2009', '\u2002', '\u205f', '\u2800', '\u2028', '\u2029', '\u1680'},
		'-': {'-', '－', '\u2010', '\u2011', '\u2012', '\u2013', '\u2014', '\u2015', '\u2212', 'ー', 'ｰ', '\ufe63'},
		'.': {'.', '．'},
		'(': {'(', '（'},
		')': {')', '）'},
		'+': {'+', '＋', '﹢'},
	}
)

// anyFormOf replaces every digit and number character in s, outside URI
// schemes and the domain, by a form chosen at random.
func anyFormOf(rng *rand.Rand, s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if n := schemeLen(s[i:]); n > 0 {
			// An invisible character may sit inside the scheme, or right
			// after it (#413).
			for j := range n {
				b.WriteByte(s[i+j])
				if rng.IntN(8) == 0 {
					b.WriteRune(invisibles[rng.IntN(len(invisibles))])
				}
			}
			i += n - 1
			continue
		}
		if strings.HasPrefix(s[i:], "@"+testDomain) {
			// And right before a user's "@".
			if rng.IntN(8) == 0 {
				b.WriteRune(invisibles[rng.IntN(len(invisibles))])
			}
			b.WriteString("@" + testDomain)
			i += len(testDomain)
			continue
		}
		c := s[i]
		switch {
		case isDigit(c):
			b.WriteRune(digitZeros[rng.IntN(len(digitZeros))] + rune(c-'0'))
			// A combining mark the digit carries (#413).
			if rng.IntN(8) == 0 {
				b.WriteRune(marks[rng.IntN(len(marks))])
			}
		case otherForms[c] != nil:
			forms := otherForms[c]
			b.WriteRune(forms[rng.IntN(len(forms))])
		default:
			b.WriteByte(c)
			continue
		}
		// Invisible format characters a log viewer hides, between this
		// number character and one after it (#154).
		if i+1 < len(s) && (isDigit(s[i+1]) || otherForms[s[i+1]] != nil) && rng.IntN(4) == 0 {
			for range 1 + rng.IntN(2) {
				b.WriteRune(invisibles[rng.IntN(len(invisibles))])
			}
		}
	}
	return b.String()
}

// asciiForm writes every character that Redact can read as a number
// character in its ASCII form, wherever it is.
func asciiForm(s string) string {
	var b strings.Builder
	for _, r := range s {
		if c, ok := asciiNumberChar(r); ok {
			b.WriteByte(c)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func TestDigitValuesFollowTheUnicodeDecimalDigits(t *testing.T) {
	for r, want := range map[rune]byte{'7': '7', '٣': '3', '۹': '9', '９': '9', '０': '0', '𝟗': '9', '𝟘': '0', '߃': '3'} {
		if got := asciiDigit(r); got != want {
			t.Errorf("asciiDigit(%q) = %q, want %q", r, got, want)
		}
	}
	// asciiDigit relies on every block of decimal digits starting at a zero
	// and running in tens.
	for _, rg := range unicode.Nd.R16 {
		if rg.Stride != 1 || (rg.Hi-rg.Lo+1)%10 != 0 {
			t.Errorf("Nd range %#x-%#x is not whole blocks of ten", rg.Lo, rg.Hi)
		}
	}
	for _, rg := range unicode.Nd.R32 {
		if rg.Stride != 1 || (rg.Hi-rg.Lo+1)%10 != 0 {
			t.Errorf("Nd range %#x-%#x is not whole blocks of ten", rg.Lo, rg.Hi)
		}
	}
}

// untimedJSONLogger writes JSON lines without the time attribute, so that a
// test searching a line for leaked digits cannot find them in the
// timestamp's nanoseconds (#99).
func untimedJSONLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}))
}

// Redact never masks less than main did before #154 (review of #398): on a
// random corpus of number characters of every form, invisible characters,
// URI schemes, also inside words and without a user, and words, what the
// keyed Redactor leaves of a text is part of what main's left, read in the
// same form. The keyed hint has no digits, so nothing a mask writes can be
// taken for a kept character.
func TestRedactMasksAtLeastWhatMainMasked(t *testing.T) {
	n := 200_000
	if testing.Short() {
		n = 20_000
	}
	rng := rand.New(rand.NewPCG(154, 398))
	for range n {
		s := mixedText(rng)
		if lost := maskedLessThanMain(s); lost != "" {
			t.Fatalf("%s", lost)
		}
	}
}

var (
	headKeyed = NewRedactor(testKey)
	mainKeyed = mainNewRedactor(testKey)
)

// maskedLessThanMain describes how the keyed Redactor masks less of s than
// main's did, or returns "".
func maskedLessThanMain(s string) string {
	head, old := headKeyed.Redact(s), mainKeyed.Redact(s)
	if keptOf(head) == keptOf(old) || isSubsequence(keptOf(head), keptOf(old)) {
		return ""
	}
	return fmt.Sprintf("Redact(%q)\n  = %q\nmain gave %q", s, head, old)
}

var keyedMask = regexp.MustCompile(`\*\*\*[a-p]{8}`)

// keptOf returns what a keyed output keeps of its input: the text without
// its masks, every number character read in its ASCII form, and invisible
// characters and combining marks left out, as neither Redact rewrites them
// all. The text
// between two masks is read on its own, so that bytes of invalid UTF-8 on
// either side of a mask cannot form a rune.
func keptOf(out string) string {
	var b strings.Builder
	for _, piece := range keyedMask.Split(out, -1) {
		keptPiece(&b, piece)
	}
	return b.String()
}

func keptPiece(b *strings.Builder, piece string) {
	for _, r := range piece {
		switch {
		case unicode.In(r, unicode.Cf, unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point, unicode.Mn, unicode.Me):
		case r < utf8.RuneSelf:
			b.WriteRune(r)
		case unicode.IsDigit(r):
			b.WriteByte(mainAsciiDigit(r))
		case unicode.In(r, unicode.Zs, unicode.Zl, unicode.Zp), r == '\u2800':
			b.WriteByte(' ')
		case unicode.Is(unicode.Pd, r), r == '−', r == 'ー', r == 'ｰ':
			b.WriteByte('-')
		case '！' <= r && r <= '～':
			b.WriteRune(r - '！' + '!')
		case r == '﹢':
			b.WriteByte('+')
		default:
			b.WriteRune(r)
		}
	}
}

// isSubsequence reports whether a is b with some characters left out.
func isSubsequence(a, b string) bool {
	ra, rb := []rune(a), []rune(b)
	j := 0
	for i := 0; i < len(rb) && j < len(ra); i++ {
		if ra[j] == rb[i] {
			j++
		}
	}
	return j == len(ra)
}

// mixedText returns a short text of tokens a log line may hold, in no
// particular order: digits of several scripts, the characters that group a
// number in every form, invisible characters, URI schemes and the
// characters around a URI user, and words.
func mixedText(rng *rand.Rand) string {
	tokens := []string{
		"0", "1", "5", "9", "010", "0000", "555", "0100001", "０", "１", "５５５", "٠", "٣",
		" ", " ", "-", ".", "(", ")", "\u00a0", "\u3000", "\u2009", "－", "ー", "〜", "〰", "—", "（", "）", "．",
		"+", "＋", "﹢", "*", "＊", "#", "＃",
		"\u200b", "\u2060", "\u00ad", "\ufeff", "\ufe0f", "\u200d", "\u200e", "\u2068", "\u2069",
		"\u0301", "\u20e3", "\u2800", "\u2028", "si", "p:", "te", "l:", "s", "ip:",
		"sip:", "SIP:", "sips:", "im:", "pres:", "tel:", "urn:gsma:imei:", "SIM:", "Interim:",
		"@", "@x", ";lr", ";", ":", "<", ">", `"`, ",", "x", "zz", "Tel.", "ims.example.net",
	}
	var b strings.Builder
	for range 1 + rng.IntN(24) {
		b.WriteString(tokens[rng.IntN(len(tokens))])
	}
	return b.String()
}
