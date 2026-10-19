package pii

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"unicode"
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
	for _, unit := range []string{"sip:", "sips:a", "tel:", "1234567x", "0 ", "1-", "+1 (", "tel:1 1", "urn:gsma:imei:a 1", `im:"`, `pres:"\`, `im:"a"`, "１２３"} {
		in := strings.Repeat(unit, (1<<20)/len(unit))
		if out := r.Redact(in); len(out) == 0 {
			t.Fatalf("empty output for %q", unit)
		}
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
