package pii

import (
	"math/rand/v2"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// FuzzRedact checks the guarantee services rely on: whatever the input, keyed
// or not, the output has no run of minRun or more decimal digits of any
// script and no number written in groups, in any script's digits, that
// Redact promises to mask, and valid UTF-8 stays valid. The grouped
// rules are restated here independently of numberAt: a national number is any
// group of two or more digits starting with 0, not preceded by a letter or
// digit, followed by eight digits in total. The one documented exception is
// checked separately in nationalNumberIn, so a mistake in it cannot hide behind
// the same mistake in the pattern.
var (
	groupedInternational = regexp.MustCompile(`\+[0-9](?:[ ().-]{0,2}[0-9]){7,}`)
	groupedNational      = regexp.MustCompile(`^0[0-9](?:[ ().-]{0,2}[0-9]){6,}`)
)

// nationalNumberIn returns a national number left in s, if any. A match counts
// unless what comes before it makes it part of a word: a letter or digit, or a
// '.' or '-' that itself follows a digit (an address, version or date).
func nationalNumberIn(s string) string {
	for p := range len(s) {
		if s[p] == '0' && !partOfWord(s, p) {
			if m := groupedNational.FindString(s[p:]); m != "" {
				return m
			}
		}
	}
	return ""
}

func partOfWord(s string, p int) bool {
	if p == 0 {
		return false
	}
	c := s[p-1]
	if '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' {
		return true
	}
	return (c == '.' || c == '-') && p >= 2 && '0' <= s[p-2] && s[p-2] <= '9'
}

func FuzzRedact(f *testing.F) {
	for _, s := range []string{
		"",
		"imsi=" + testIMSI,
		testIMSI + "@" + testDomain,
		"From: <sip:" + testMSISDN + "@" + testDomain + ">;tag=1",
		"tel:+1-555-010-0001;phone-context=example.com",
		"sip:sip:sip:alice@",
		"SIPS:" + testMSISDN + ":pw@host",
		"urn:gsma:imei:00101000-000003-1;svn=42",
		"1234567.1234567",
		"1234\u200b5678 +\u2060155501\u00ad00001 sip:a\u00a01@x",
		"tel:12345678tel:12345678",
		"+15550100sip:@1234567890",
		"メッセージ 15550100002",
		"+1 (555) 010-0001",
		"tel:+1 555 010 0001",
		"msisdn=010-0000-0001",
		"(07700) 900-001",
		"2026-10-19 10.0.255.255",
		"+1 555   0100001",
		"0.0.0.0 0 1 2 3 4 5 6 7",
		"Tel.010-0000-0001 H.P.010 0000 0001",
		"bytes=0-1048575 [0.25 0.5 0.75]",
		"From: <im:alice.smith@" + testDomain + ">",
		"pres:" + testMSISDN + "@" + testDomain,
		"msisdn=１５５５０１００００１ ２０２６年",
		"imsi ٠٠١٠١٠٠٠٠٠٠٠٠٠١ 1555０１００\xff００1",
		"tel:+15550100001-２３４５６７",
		"0000000 0０１0000",
		"urn:gsma:imei:00101000-１７６１４８-１",
		"０１０-００００-０００１ +１ ５５５ ０１００ ００１",
		"call ０１０－００００－０００１ ＋１\u3000５５５\u3000０１０\u3000０００１ （０７７００）９００．００１",
		"+1\u00a0555\u202f010\u20090001 ０１０ー００００\u2212０００１ 010\u2013 0000\u2014 0001 名前\u3000（注）\u300010 tel:（０３）１２３４",
		`From: <im:"bob smith"@` + testDomain + `> pres:"a \"" im:"x`,
		`im:"` + testMSISDN + `"@` + testDomain,
		// From the reviews of #398.
		"sip:a\u00a0+1\u00a0555\u00a0010\u00a00001 SIM:\u00a0+1\u00a0555\u00a0010\u00a00001",
		"Interim:\u00a0010\u00a00000\u00a00001 im:\u3000０１０\u3000００００\u3000０００１",
		"1\u200b-010-0000-0001 8\ufeff010 0000 0001 +\u200b(1)555 010 0001",
		"+1 \u200b(555) 010-0001 +1 \u2066(555)\u2069 010-0001 010-\u200b-0000-0001",
		"sips:urn:gsma:imei:\u3000555\u3000010@x sip:ims.example.com経由\u3000０３\u3000１２３４",
		"0900〜1800 sip:+1\u00a0555\u00a0010\u00a00001@x",
	} {
		f.Add(s, false)
		f.Add(s, true)
	}
	unkeyed := NewRedactor(nil)
	keyed := NewRedactor(testKey)
	f.Fuzz(func(t *testing.T, s string, withKey bool) {
		r := unkeyed
		if withKey {
			r = keyed
		}
		out := r.Redact(s)
		if utf8.ValidString(s) && !utf8.ValidString(out) {
			t.Fatalf("Redact(%q) = %q is not valid UTF-8", s, out)
		}
		for _, a := range []string{out, r.URI("k", s).Value.String(), r.Identity("k", s).Value.String()} {
			if run := longestDigitRun(a); run >= minRun {
				t.Fatalf("redacting %q gave %q, which keeps a %d-digit run", s, a, run)
			}
			// The grouped rules read ASCII; a number in another script's
			// digits, spaces or dashes must be masked as well. asciiForm
			// reads every such character as ASCII wherever it is, which
			// is stricter than Redact's reading of a number.
			if m := groupedInternational.FindString(asciiForm(a)); m != "" {
				t.Fatalf("redacting %q gave %q, which keeps the number %q", s, a, m)
			}
			if m := nationalNumberIn(asciiForm(a)); m != "" {
				t.Fatalf("redacting %q gave %q, which keeps the number %q", s, a, m)
			}
		}
		if !strings.ContainsRune(s, ':') && !strings.ContainsFunc(s, unicode.IsDigit) && out != s {
			t.Fatalf("Redact(%q) = %q changed text with no digits or schemes", s, out)
		}
		// Never less than main masked at the frozen copy's commit (review
		// of #398, #490).
		if lost := maskedLessThanMain(s); lost != "" {
			t.Fatal(lost)
		}
	})
}

// FuzzRedactAnyForm is the differential check of
// TestRedactReadsANumberInAnyFormAsInASCII on any ASCII text: the ASCII
// characters of s, with every digit and number character replaced at random
// (from seed) by a form from another script and with invisible characters
// between number characters, are redacted as the ASCII text is
// (readsAsASCII). Texts with a sip, sips, im or pres scheme followed by an
// "@" are left to the test: Redact masks such a user whole whatever its
// characters, and when it is not a number written as asciiNumberChars reads
// one, a form left in it changes the hint, or a space outside ASCII does not
// end it. A scheme without an "@" after it, as in "SIM: +1 555 010 0001",
// is no user, and is checked here.
func FuzzRedactAnyForm(f *testing.F) {
	for _, s := range []string{
		"call +1 (555) 010-0001 or 010-0000-0001.",
		"tel:(03)1234-5678;phone-context=example.net tel: 0000000",
		"urn:gsma:imei:35-209900-176148-1 (1) 10-20 1 - 2",
		"+0 (000) 000 0000 tel:1.736-.4-.5)) (1)-89553",
		"sip:a +1 555 010 0001 SIM: 010 0000 0001 sips:pcscf;lr (0) 1-010-0000-0001",
	} {
		f.Add(s, uint64(0))
		f.Add(s, uint64(1))
	}
	f.Fuzz(func(t *testing.T, s string, seed uint64) {
		var b strings.Builder
		for i := range len(s) {
			if s[i] < utf8.RuneSelf {
				b.WriteByte(s[i])
			}
		}
		ascii := b.String()
		if !strings.ContainsAny(ascii, "0123456789") {
			return
		}
		for i := range len(ascii) {
			if n := schemeLen(ascii[i:]); n > 0 && hasUserinfo(ascii[i:i+n]) && strings.Contains(ascii[i:], "@") {
				return
			}
		}
		if bad := readsAsASCII(ascii, anyFormOf(rand.New(rand.NewPCG(seed, 0)), ascii)); bad != "" {
			t.Fatal(bad)
		}
	})
}

// longestDigitRun counts decimal digits of every script, as Redact promises
// to mask runs of any of them, and reads past the invisible characters a log
// viewer hides between them (#154). It names those characters itself, not
// with the code under test.
func longestDigitRun(s string) int {
	longest, run := 0, 0
	for _, r := range s {
		switch {
		case unicode.IsDigit(r):
			run++
			longest = max(longest, run)
		case unicode.In(r, unicode.Cf, unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point):
		default:
			run = 0
		}
	}
	return longest
}

// TruncateIPsIn leaves no whole IPv4 address standing alone in text, is
// idempotent, and leaves text without an address character as it was.
func FuzzTruncateIPsIn(f *testing.F) {
	for _, s := range []string{
		"http: TLS handshake error from 203.0.113.5:51234: EOF",
		"error reading preface from client [2001:db8::1]:443: EOF",
		"10.0.0.0/8 192.0.2.7/32 1.2.3.4.5 go1.2.3.4 ::ffff:1.2.3.4",
		"a:b:c::1 ::: [::1] [::1%25lo]:5 1.02.003.4:00",
		"peer 203.0.113.250 closed, 255.255.255.254.",
		"http: panic serving [2001:db8:5:6::8]:51234: boom; from 203.0.113.5:51234.",
		"remote:2001:db8:5:6::8 cafe:2001:db8:5:6:7:8:9:a conn...203.0.113.9 来自203.0.113.9。",
		"2002:cb00:7109::/48 203.0.113.5/24x ::ffff:cb00:7105/96 udp/2001:db8::1",
	} {
		f.Add(s)
	}
	run := regexp.MustCompile(`[0-9A-Fa-f:.]+`)
	ipv4Port := regexp.MustCompile(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0/24(:[0-9]{1,5})([^0-9.]|\.[^0-9]|\.$|$)`)
	bracketPort := regexp.MustCompile(`\[[0-9A-Fa-f:.]+/[0-9]+\](:[0-9]{1,5})([^0-9.]|\.[^0-9]|\.$|$)`)
	// letter is what makes a run part of a longer word: an ASCII letter
	// past f, or "_" (digits and hex letters are in the run itself).
	letter := func(c byte) bool { return 'g' <= c && c <= 'z' || 'G' <= c && c <= 'Z' || c == '_' }
	alnum := func(c byte) bool {
		return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_'
	}
	sixToFour := netip.MustParsePrefix("2002::/16")
	// leftWhole is the oracle, which reads addresses its own way, with
	// netip and not the code under test: every maximal run of
	// [0-9A-Fa-f:.] in got, and every part of one after a colon, that
	// netip reads as an address with the dots or colons around it
	// trimmed, is a network as wide as a truncated one or text the input
	// s did not hold, unless the run is part of a longer word. It returns
	// the addresses of s that got leaves whole.
	leftWhole := func(s, got string) (left []string) {
		for _, m := range run.FindAllStringIndex(got, -1) {
			if m[1] < len(got) && letter(got[m[1]]) {
				continue // a longer word, as 1.2.3.4x
			}
			r := got[m[0]:m[1]]
			var cands []string
			// Nor is a run right after an address's "/" ("/24::1", "::/0::1"),
			// whose start may be a length rather than an address.
			afterLength := m[0] >= 2 && got[m[0]-1] == '/' && run.MatchString(got[m[0]-2:m[0]-1])
			if (m[0] == 0 || !letter(got[m[0]-1])) && !afterLength {
				cands = append(cands, r)
			}
			for k := 0; k < len(r); k++ {
				if r[k] == ':' {
					cands = append(cands, r[k+1:])
				}
			}
			// An address may be followed by dots (the end of a sentence) and
			// by one colon (the end of a field), and preceded by dots
			// unless a word or number is before them (x.1.2.3.4).
			trimEnd := func(v string) []string {
				v = strings.TrimRight(v, ".")
				if n := len(v); n > 1 && v[n-1] == ':' && v[n-2] != ':' {
					return []string{v, v[:n-1]}
				}
				return []string{v}
			}
			for ci, c := range cands {
				vs := append([]string{c}, trimEnd(c)...)
				if lead := strings.TrimLeft(c, "."); lead != c && (ci > 0 || m[0] == 0 || !alnum(got[m[0]-1])) {
					vs = append(vs, trimEnd(lead)...)
				}
				for _, v := range vs {
					ip, err := netip.ParseAddr(v)
					if err != nil {
						continue
					}
					ip = ip.Unmap()
					bits := 48
					switch {
					case ip.Is4():
						bits = 24
					case sixToFour.Contains(ip):
						bits = 16
					}
					wide := func() bool {
						if strings.Contains(v, ".") && ip.Is6() {
							// An embedded IPv4 address is as wide as its /24,
							// and the bits above it as their /48.
							b := ip.As16()
							v4 := netip.AddrFrom4([4]byte(b[12:16]))
							p, _ := v4.Prefix(24)
							return p.Addr() == v4 && [6]byte(b[6:12]) == [6]byte{}
						}
						p, err := ip.Prefix(bits)
						return err == nil && p.Addr() == ip
					}
					// A leak is an address of the input that survives
					// whole; text the output makes up, such as a hex word
					// before a network (cafe:2001:db8::), is none.
					if !wide() && strings.Contains(s, v) {
						left = append(left, v)
					}
				}
			}
		}
		return left
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := TruncateIPsIn(s)
		if again := TruncateIPsIn(got); again != got {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, got, again)
		}
		if !strings.ContainsAny(s, ".:[") && got != s {
			t.Fatalf("%q changed to %q", s, got)
		}
		// Every round masks at least what the round before it did, and the
		// last one is stable within maxRounds (#528): truncated again, the
		// result reads the same.
		var rounds []string
		got, stable := truncateRounds(s, func(o string) { rounds = append(rounds, o) })
		if !stable {
			t.Fatalf("%q not stable after %d rounds: %q", s, maxRounds, rounds)
		}
		if got != TruncateIPsIn(s) {
			t.Fatalf("TruncateIPsIn(%q) is not its last round", s)
		}
		// From the second round on: the first reads the input itself,
		// whose words and tokens are what the oracle reads, not a round's.
		prev := rounds[0]
		for _, o := range rounds[1:] {
			was := map[string]bool{}
			for _, v := range leftWhole(s, prev) {
				was[v] = true
			}
			for _, v := range leftWhole(s, o) {
				if !was[v] {
					t.Fatalf("%q: a round left %q whole in %q, which the round before truncated in %q", s, v, o, prev)
				}
			}
			prev = o
		}
		if left := leftWhole(s, got); len(left) > 0 {
			t.Fatalf("%q left %q whole in %q", s, left[0], got)
		}
		// No port (one to five digits, not followed by another or by a dot
		// and a digit, which make a number) is left after an address the
		// function truncated: the
		// digits after such a network are not the port the input had right
		// after an address ("]:51234", ".5:51234"), unless the input held
		// the network as written.
		// count counts the places the input has the port text with what
		// followed it, by whether an address's last part or a bracketed
		// address is right before it.
		count := func(port, after string, address func(head string) bool) (atAddress, elsewhere int) {
			for i := 0; i <= len(s); i++ {
				j := strings.Index(s[i:], port+after)
				if j < 0 {
					break
				}
				i += j
				if after == "" && i+len(port) != len(s) {
					continue
				}
				if address(s[:i]) {
					atAddress++
				} else {
					elsewhere++
				}
			}
			return atAddress, elsewhere
		}
		digitsAfter := func(head, sep string, most int) bool {
			k := len(head)
			for k > 0 && len(head)-k < most && '0' <= head[k-1] && head[k-1] <= '9' {
				k--
			}
			return k < len(head) && strings.HasSuffix(head[:k], sep)
		}
		lastPart := func(head string) bool { return digitsAfter(head, ".", 3) }
		bracketed := func(head string) bool {
			if !strings.HasSuffix(head, "]") {
				return false
			}
			k := strings.LastIndexByte(head, '[')
			if k < 0 || len(head)-k > 66 {
				return false
			}
			_, err := netip.ParseAddr(head[k+1 : len(head)-1])
			return err == nil
		}
		// A leak is more such texts after a network in the output than
		// the input had other than after an address, or as a network
		// written out: some port the input had after an address is left.
		for re, address := range map[*regexp.Regexp]func(string) bool{ipv4Port: lastPart, bracketPort: bracketed} {
			outs := map[[2]string]int{}
			written := map[[2]string]int{}
			for _, m := range re.FindAllStringSubmatch(got, -1) {
				k := [2]string{m[1], m[2]}
				outs[k]++
				written[k] += strings.Count(s, m[0])
			}
			for k, n := range outs {
				atAddress, elsewhere := count(k[0], k[1], address)
				if atAddress > 0 && n > elsewhere+written[k] {
					t.Fatalf("%q left the port %q in %q", s, k[0], got)
				}
			}
		}
	})
}
