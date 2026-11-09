package maap

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestWebhookURLsFollowTheRulesOfADR0009Section8(t *testing.T) {
	ports := []uint16{8443}
	for _, tc := range []struct {
		url    string
		http   bool
		reason string
	}{
		{"https://bot.example.com/hook?a=b", false, ""},
		{"https://bot.example.com:443/hook", false, ""},
		{"https://bot.example.com:8443/hook", false, ""},
		{"https://[2001:db8::1]/hook", false, ""},
		{"", false, ""}, // no webhook
		{"http://bot.example.com:8443/hook", true, ""},
		{"http://bot.example.com:8443/hook", false, "not https"},
		{"http://bot.example.com/hook", true, "a port other than 443"}, // 80
		{"https://bot.example.com:8080/hook", false, "a port other than 443"},
		{"https://bot.example.com:0/hook", false, "a port other than 443"},
		{"https://bot.example.com:0443/hook", false, "a port other than 443"},
		{"https://bot.example.com:/hook", false, "an empty port"},
		{"https://user:pass@bot.example.com/hook", false, "userinfo"},
		{"https://@bot.example.com/hook", false, "userinfo"},
		{"https:///hook", false, "no host"},
		{"https:bot.example.com", false, "no host"},
		{"https://:443/hook", false, "no host"},
		{"ftp://bot.example.com/hook", false, "not https"},
		{"/hook", false, "not https"},
		{"HTTPS://bot.example.com/hook", false, "not a URL in the form"},
		{"https://bot.example.com/a b", false, "not a URL in the form"},
		{"https://bot.example.com/%zz", false, "not a URL in the form"},
		{"https://bot.example.com/\x7f", false, "a control character"},
		{"https://bot.example.com/\r\nX: y", false, "a control character"},
		{"https://bot.example.com/" + strings.Repeat("a", 488), false, ""}, // 512 bytes
		{"https://bot.example.com/" + strings.Repeat("a", 489), false, "longer than 512 bytes"},
	} {
		if got := webhookProblem(tc.url, ports, tc.http); tc.reason == "" && got != "" || !strings.HasPrefix(got, tc.reason) {
			t.Errorf("%q (http %v): %q, want %q", tc.url, tc.http, got, tc.reason)
		}
	}
}

// FuzzWebhookURL checks that no input panics the check and that every URL
// it accepts meets each rule, judged here by net/url alone.
func FuzzWebhookURL(f *testing.F) {
	for _, s := range []string{"https://bot.example.com/hook", "https://bot.example.com:8443/a?b#c", "https://u@h/", "https://h:/", "http://h/", "https://[::1%25e]:8443/"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if webhookProblem(raw, []uint16{8443}, false) != "" || raw == "" {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || len(raw) > 512 || strings.ContainsFunc(raw, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			t.Fatalf("accepted %q: %v", raw, err)
		}
		if p := u.Port(); u.Scheme != "https" || u.User != nil || u.Hostname() == "" || p != "" && p != "443" && p != "8443" {
			t.Fatalf("accepted %q: scheme %q, user %v, host %q, port %q", raw, u.Scheme, u.User, u.Hostname(), p)
		}
	})
}

// Every bidi control is refused, and so is every other format character
// but the zero-width joiner, which emoji sequences need (lead decision on
// #709).
func TestFormatCharactersAreRefusedButTheZeroWidthJoiner(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		refused    bool
	}{
		{"ZWJ emoji (family)", "Acme \U0001F468\u200d\U0001F469\u200d\U0001F467", false},
		{"ZWJ emoji (technologist)", "\U0001F9D1\u200d\U0001F4BB Support", false},
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
		{"ZWNJ", "a\u200cb", true},
		{"BOM", "\ufeffab", true},
		{"soft hyphen", "a\u00adb", true},
	} {
		if err := refuseInvisible("display_name", tc.text); (err != nil) != tc.refused {
			t.Errorf("%s: %v, want refused %v", tc.name, err, tc.refused)
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
