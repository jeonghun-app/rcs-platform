package maap

import (
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// numericLabel is a label inet_aton or the WHATWG URL parser reads as a
// number: the fuzz oracle's own reading, apart from the code's.
var numericLabel = regexp.MustCompile(`^([0-9]+|0[xX][0-9a-fA-F]*)$`)

func TestWebhookURLsFollowTheRulesOfADR0009Section8(t *testing.T) {
	ports := []uint16{8443}
	for _, tc := range []struct {
		url      string
		http     bool
		reason   string
		internal bool
	}{
		{"https://bot.example.com/hook?a=b", false, "", false},
		{"https://bot.example.com:443/hook", false, "", false},
		{"https://bot.example.com:8443/hook", false, "", false},
		{"https://[2001:db8::1]/hook", false, "", false},
		{"", false, "", false}, // no webhook
		{"http://bot.example.com:8443/hook", true, "", false},
		{"http://bot.example.com:8443/hook", false, "not https", false},
		{"http://bot.example.com/hook", true, "a port other than 443", false}, // 80
		{"https://bot.example.com:8080/hook", false, "a port other than 443", false},
		{"https://bot.example.com:0/hook", false, "a port other than 443", false},
		{"https://bot.example.com:0443/hook", false, "a port other than 443", false},
		{"https://bot.example.com:/hook", false, "an empty port", false},
		{"https://user:pass@bot.example.com/hook", false, "userinfo", false},
		{"https://@bot.example.com/hook", false, "userinfo", false},
		{"https:///hook", false, "no host", false},
		{"https:bot.example.com", false, "no host", false},
		{"https://:443/hook", false, "no host", false},
		{"ftp://bot.example.com/hook", false, "not https", false},
		{"/hook", false, "not https", false},
		{"HTTPS://bot.example.com/hook", false, "not a URL in the form", false},
		{"https://bot.example.com/a b", false, "not a URL in the form", false},
		{"https://bot.example.com/%zz", false, "not a URL in the form", false},
		{"https://bot.example.com/\x7f", false, "a control character", false},
		{"https://bot.example.com/\r\nX: y", false, "a control character", false},
		{"https://bot.example.com/" + strings.Repeat("a", 488), false, "", false}, // 512 bytes
		{"https://169.254.169.254/latest/meta-data/", false, "an address that is not global unicast", true},
		{"https://127.0.0.1/hook", false, "a loopback or private address", false},
		{"https://127.0.0.1/hook", false, "", true}, // dev
		{"https://[::1]/hook", false, "a loopback or private address", false},
		{"https://10.0.0.5/hook", false, "a loopback or private address", false},
		{"https://10.0.0.5/hook", false, "", true},
		{"https://172.16.0.1/hook", false, "a loopback or private address", false},
		{"https://192.168.1.1/hook", false, "a loopback or private address", false},
		{"https://[fd00::1]/hook", false, "a loopback or private address", false},
		{"https://[fe80::1]/hook", false, "an address that is not global unicast", true},
		{"https://0.0.0.0/hook", false, "an address that is not global unicast", true},
		{"https://[::]/hook", false, "an address that is not global unicast", true},
		{"https://224.0.0.1/hook", false, "an address that is not global unicast", false},
		{"https://[::ffff:10.0.0.5]/hook", false, "an IPv4 address inside IPv6", true},
		{"https://[::ffff:198.51.100.7]/hook", false, "an IPv4 address inside IPv6", false},
		{"https://[64:ff9b::a00:5]/hook", false, "an IPv4 address inside IPv6", false},
		{"https://[::10.0.0.5]/hook", false, "an IPv4 address inside IPv6", true},
		{"https://[fe80::1%25eth0]/hook", false, "a % in the host", true},
		{"https://[2001:db8::1%25eth0]:8443/hook", false, "a % in the host", false},
		{"https://2130706433/hook", false, "an IP address in a form other than dotted decimal", true},
		{"https://127.1/hook", false, "an IP address in a form other than dotted decimal", true},
		{"https://0x7f000001/hook", false, "an IP address in a form other than dotted decimal", true},
		{"https://0X7F.1/hook", false, "an IP address in a form other than dotted decimal", false},
		{"https://bot.example.0x10/hook", false, "an IP address in a form other than dotted decimal", false},
		{"https://198.51.100.7./hook", false, "an IP address in a form other than dotted decimal", false},
		{"https://198.51.100.7/hook", false, "", false},
		{"https://0x.example.com/hook", false, "", false},   // a label, not the last one
		{"https://bot.example.com./hook", false, "", false}, // names are #683's
		{"https://bot.example.com/" + strings.Repeat("a", 489), false, "longer than 512 bytes", false},
	} {
		if got := webhookProblem(tc.url, ports, tc.http, tc.internal); tc.reason == "" && got != "" || !strings.HasPrefix(got, tc.reason) {
			t.Errorf("%q (http %v): %q, want %q", tc.url, tc.http, got, tc.reason)
		}
	}
}

// FuzzWebhookURL checks that no input panics the check and that every URL
// it accepts meets each rule, judged here by net/url alone.
func FuzzWebhookURL(f *testing.F) {
	for _, s := range []string{"https://bot.example.com/hook", "https://bot.example.com:8443/a?b#c", "https://u@h/", "https://h:/", "http://h/", "https://[::1%25e]:8443/",
		"https://169.254.169.254/latest/meta-data/", "https://127.0.0.1/", "https://[::1]/", "https://10.0.0.5/", "https://[fd00::1]/",
		"https://[::ffff:10.0.0.5]/", "https://[64:ff9b::a00:5]/", "https://[fe80::1%25eth0]/", "https://2130706433/",
		"https://127.1/", "https://0x7f000001/", "https://0.0.0.0/", "https://198.51.100.7./"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if webhookProblem(raw, []uint16{8443}, false, false) != "" || raw == "" {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || len(raw) > 512 || strings.ContainsFunc(raw, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			t.Fatalf("accepted %q: %v", raw, err)
		}
		if p := u.Port(); u.Scheme != "https" || u.User != nil || u.Hostname() == "" || p != "" && p != "443" && p != "8443" {
			t.Fatalf("accepted %q: scheme %q, user %v, host %q, port %q", raw, u.Scheme, u.User, u.Hostname(), p)
		}
		if strings.Contains(u.Host, "%") {
			t.Fatalf("accepted %q: a %% in the host", raw)
		}
		host := u.Hostname()
		addr, err := netip.ParseAddr(host)
		if err == nil && (!addr.IsGlobalUnicast() || addr.IsPrivate() || addr.Is4In6() || netip.MustParsePrefix("64:ff9b::/96").Contains(addr)) {
			t.Fatalf("accepted %q: internal address %v", raw, addr)
		}
		labels := strings.Split(strings.TrimSuffix(host, "."), ".")
		if err != nil && numericLabel.MatchString(labels[len(labels)-1]) {
			t.Fatalf("accepted %q: a numeric host not in dotted decimal", raw)
		}
	})
}

// Display names refuse every character that shows as nothing or as space
// between others, but keep emoji sequences and the ZWNJ of Persian and
// Indic words (T13; lead decisions on #709).
func TestDisplayNamesRefuseInvisibleCharacters(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		refused    bool
	}{
		{"plain", "Acme Support", false},
		{"Hangul", "\uD53C\uC790 \uBD07", false},
		{"empty", "", false},
		{"ZWJ family emoji", "Acme \U0001F468\u200d\U0001F469\u200d\U0001F467", false},
		{"ZWJ after a skin tone", "\U0001F469\U0001F3FD\u200d\U0001F4BB Help", false},
		{"ZWJ after VS16 (rainbow flag)", "\U0001F3F3\ufe0f\u200d\U0001F308", false},
		{"VS16 after an emoji", "\u2764\ufe0f Acme", false},
		{"VS16 in a keycap", "Line 1\ufe0f\u20e3", false},
		{"ZWNJ in a Persian word", "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645", false},
		{"ZWNJ after a virama", "\u0915\u094d\u200c\u0937", false},
		{"subdivision flag", "\U0001F3F4\U000E0067\U000E0062\U000E0073\U000E0063\U000E0074\U000E007F Bot", false},
		{"ZWJ between letters", "Pay\u200dPal", true},
		{"ZWJ at the end", "\U0001F468\u200d", true},
		{"ZWJ after a letter, before an emoji", "Acme\u200d\U0001F468", true},
		{"VS16 after a letter", "Acme\ufe0f", true},
		{"VS15", "\u2764\ufe0e", true},
		{"VS17", "\u2764\U000E0100", true},
		{"ZWNJ between spaces", "Acme \u200c Bot", true},
		{"ZWNJ at the start", "\u200cAcme", true},
		{"ZWNJ after a letter, before a space", "Acme\u200c Bot", true},
		{"tag outside a flag", "Acme\U000E0067", true},
		{"flag without CANCEL TAG", "\U0001F3F4\U000E0067\U000E0062", true},
		{"flag with a tag that is not a letter or digit", "\U0001F3F4\U000E0047\U000E007F", true},
		{"LRE", "a\u202ab", true},
		{"RLE", "a\u202bb", true},
		{"PDF", "a\u202cb", true},
		{"LRO", "a\u202db", true},
		{"RLO", "a\u202eb", true},
		{"LRI", "a\u2066b", true},
		{"RLI", "a\u2067b", true},
		{"FSI", "a\u2068b", true},
		{"PDI", "a\u2069b", true},
		{"LRM", "a\u200eb", true},
		{"RLM", "a\u200fb", true},
		{"ALM", "a\u061cb", true},
		{"ZWSP", "a\u200bb", true},
		{"BOM", "\ufeffab", true},
		{"soft hyphen", "a\u00adb", true},
		{"NEL", "a\u0085b", true},
		{"DEL", "a\u007fb", true},
		{"CGJ", "a\u034fb", true},
		{"Khmer inherent vowel", "a\u17b4b", true},
		{"Mongolian FVS", "a\u180bb", true},
		{"Hangul filler", "Pay\u3164Pal", true},
		{"Hangul choseong filler", "\u115f", true},
		{"Hangul jungseong filler", "\u1160", true},
		{"halfwidth Hangul filler", "a\uffa0b", true},
		{"braille blank", "\u2800", true},
		{"line separator", "Acme\u2028Bot", true},
		{"paragraph separator", "Acme\u2029Bot", true},
		{"spaces only", "   ", true},
		{"NBSPs only", "\u00a0\u00a0", true},
		{"ideographic space only", "\u3000", true},
	} {
		if got := displayNameProblem(tc.text); (got != "") != tc.refused {
			t.Errorf("%s: %q, want refused %v", tc.name, got, tc.refused)
		}
	}
}

// The out-of-service text, a message body, keeps the narrower rule: DEL,
// C1 and Cf, the zero-width joiner apart.
func TestTheOutOfServiceTextRefusesFormatCharactersButTheZeroWidthJoiner(t *testing.T) {
	for _, tc := range []struct {
		text    string
		refused bool
	}{
		{"Back soon \U0001F468\u200d\U0001F4BB", false},
		{"Back\u2028soon", false},
		{"Back\u202esoon", true},
		{"Back\u200bsoon", true},
		{"Back\u0085soon", true},
	} {
		if err := refuseInvisible("out_of_service", tc.text); (err != nil) != tc.refused {
			t.Errorf("%q: %v, want refused %v", tc.text, err, tc.refused)
		}
	}
}

// A limit added to store.Limits without a default here would accept only 0.
func TestEveryLimitHasADefault(t *testing.T) {
	v := reflect.ValueOf(defaultLimits)
	for i := range v.NumField() {
		if v.Field(i).Int() <= 0 {
			t.Errorf("%s has no default", v.Type().Field(i).Name)
		}
	}
}
