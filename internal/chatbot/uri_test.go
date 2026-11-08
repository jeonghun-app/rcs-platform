package chatbot

import (
	"errors"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

const (
	botDomain = "botplatform.mnc001.mcc001.3gppnetwork.org"
	imsDomain = "ims.mnc001.mcc001.3gppnetwork.org"
)

func testDomain(t testing.TB) Domain {
	t.Helper()
	d, err := NewDomain(botDomain, imsDomain)
	if err != nil {
		t.Fatalf("NewDomain: %v", err)
	}
	return d
}

func reasonOf(err error) string {
	var r *refusal
	if errors.As(err, &r) {
		return r.reason
	}
	return ""
}

func TestEachURIAtTheChatbotDomainOutOfNormalFormHasItsReason(t *testing.T) {
	d := testDomain(t)
	label := strings.Repeat("a", 63)
	tests := map[string]struct{ uri, reason string }{
		"sips":                 {"sips:mybot@" + botDomain, "not a sip: URI"},
		"port":                 {"sip:mybot@" + botDomain + ":5060", "a port"},
		"header":               {"sip:mybot@" + botDomain + "?Subject=hi", "URI headers"},
		"escape":               {"sip:my%62ot@" + botDomain, "an escape in the user part"},
		"user=phone":           {"sip:mybot@" + botDomain + ";user=phone", "a parameter other than tk=on or tk=off"},
		"upper-case user":      {"sip:MyBot@" + botDomain, "a character of the user part outside a-z, 0-9 and -"},
		"three labels":         {"sip:my.bot.pub@" + botDomain, "more than two labels in the user part"},
		"64-character label":   {"sip:" + label + "a@" + botDomain, "a label of the user part that is empty or longer than 63 bytes"},
		"empty label":          {"sip:.pub@" + botDomain, "a label of the user part that is empty or longer than 63 bytes"},
		"underscore":           {"sip:my_bot@" + botDomain, "a character of the user part outside a-z, 0-9 and -"},
		"no user part":         {"sip:" + botDomain, "no user part"},
		"password":             {"sip:mybot:secret@" + botDomain, "a password"},
		"empty password":       {"sip:mybot:@" + botDomain, "a password"},
		"other tk value":       {"sip:mybot@" + botDomain + ";tk=yes", "a parameter other than tk=on or tk=off"},
		"tk without value":     {"sip:mybot@" + botDomain + ";tk", "a parameter other than tk=on or tk=off"},
		"tk and another":       {"sip:mybot@" + botDomain + ";tk=on;lr", "a parameter other than tk=on or tk=off"},
		"trailing dot":         {"sip:mybot@" + botDomain + ".", "a host that is not the chatbot domain as written"},
		"empty port":           {"sip:mybot@" + botDomain + ":", "not a valid SIP URI"},
		"two @":                {"sip:my@bot@" + botDomain, "not a valid SIP URI"},
		"escape in parameters": {"sip:mybot@" + botDomain + ";t%6b=on", "a parameter other than tk=on or tk=off"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := d.Normalise(tc.uri)
			if !errors.Is(err, ErrNotNormal) || reasonOf(err) != tc.reason {
				t.Fatalf("Normalise = %q, %v; want ErrNotNormal for %q", got, err, tc.reason)
			}
			if strings.Contains(err.Error(), "mybot") {
				t.Errorf("the error %q repeats the URI", err)
			}
		})
	}
}

func TestNormaliseLowersTheHostAndDropsTk(t *testing.T) {
	d := testDomain(t)
	want := "sip:my-bot.pub1@" + botDomain
	for _, uri := range []string{
		want,
		"sip:my-bot.pub1@" + strings.ToUpper(botDomain),
		"sip:my-bot.pub1@" + botDomain + ";tk=on",
		"sip:my-bot.pub1@" + botDomain + ";tk=off",
		"sip:my-bot.pub1@" + botDomain + ";TK=On",
		"SIP:my-bot.pub1@" + botDomain,
	} {
		if got, err := d.Normalise(uri); err != nil || got != want {
			t.Errorf("Normalise(%q) = %q, %v; want %q", uri, got, err, want)
		}
	}
	label := strings.Repeat("9", 63)
	if got, err := d.Normalise("sip:" + label + "." + label + "@" + botDomain); err != nil || len(got) > MaxURIBytes {
		t.Errorf("two 63-byte labels: %q (%d bytes), %v", got, len(got), err)
	}
}

func TestURIsElsewhereAndTelURIsAreNotChatbots(t *testing.T) {
	d := testDomain(t)
	for _, uri := range []string{
		"tel:+15550100001",
		"sip:mybot@" + imsDomain,
		"sip:mybot@" + botDomain + ".example.net",
		"sip:+15550100001@" + imsDomain + ";user=phone",
		"urn:service:sos",
		"im:mybot@" + botDomain,
		"sip:mybot@" + botDomain[1:],
		"no-scheme",
		"",
	} {
		if got, err := d.Normalise(uri); !errors.Is(err, ErrNotChatbot) {
			t.Errorf("Normalise(%q) = %q, %v; want ErrNotChatbot", uri, got, err)
		}
	}
	if _, err := (Domain{}).Normalise("sip:mybot@" + botDomain); !errors.Is(err, ErrNotChatbot) {
		t.Errorf("with the domain unset: %v, want ErrNotChatbot", err)
	}
}

// userPartMatcher reads UserPartERE as POSIX regcomp would, matched against
// a whole value.
func userPartMatcher(t testing.TB) *regexp.Regexp {
	t.Helper()
	tree, err := syntax.Parse("^("+UserPartERE+")$", syntax.POSIX|syntax.OneLine)
	if err != nil {
		t.Fatalf("UserPartERE is not an ERE: %v", err)
	}
	return regexp.MustCompile(tree.String())
}

func TestTheUserPartERECompilesUnderTheIFCRules(t *testing.T) {
	if len(UserPartERE) > 256 {
		t.Errorf("UserPartERE is %d bytes, over 256", len(UserPartERE))
	}
	_, err := ifc.Compile([]ifc.FilterCriteria{{
		TriggerPoint: &ifc.TriggerPoint{ConditionTypeCNF: true, SPTs: []ifc.SPT{
			{Groups: []int{0}, Condition: ifc.SIPHeader{Header: "To", Content: UserPartERE}},
		}},
		ApplicationServer: ifc.ApplicationServer{ServerName: "sip:rcs-as.example.net"},
	}})
	if err != nil {
		t.Fatalf("ifc.Compile: %v", err)
	}
}

func TestTheUserPartEREAndNormaliseAcceptTheSameUserParts(t *testing.T) {
	d, ere := testDomain(t), userPartMatcher(t)
	label := strings.Repeat("z", 63)
	users := []string{label, label + "z", label + "." + label, label + ".", "a..b", "-", "0.-", "a.b.c", "é", "a\n"}
	// Every string of up to four characters over an alphabet that has each
	// class of character the grammar treats apart.
	alphabet := []string{"a", "Z", "0", "-", ".", "_", "%", ";", "@", ":"}
	level := []string{""}
	for range 4 {
		var next []string
		for _, s := range level {
			for _, c := range alphabet {
				next = append(next, s+c)
			}
		}
		users, level = append(users, next...), next
	}
	for _, u := range users {
		_, err := d.Normalise("sip:" + u + "@" + botDomain)
		if (err == nil) != ere.MatchString(u) {
			t.Errorf("user part %q: Normalise error %v, ERE match %v", u, err, ere.MatchString(u))
		}
	}
}

func TestTheChatbotDomainIsALowerCaseDNSNameOtherThanTheIMSDomain(t *testing.T) {
	tests := map[string]struct{ value, ims string }{
		"upper case":                     {"Botplatform.mnc001.mcc001.3gppnetwork.org", imsDomain},
		"not a DNS name":                 {"bot_platform.example.net", imsDomain},
		"trailing dot":                   {botDomain + ".", imsDomain},
		"the IMS domain":                 {imsDomain, imsDomain},
		"the IMS domain in another case": {imsDomain, "IMS.mnc001.mcc001.3gppnetwork.org."},
		"too long":                       {strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + ".net", imsDomain},
	}
	for name, tc := range tests {
		if d, err := NewDomain(tc.value, tc.ims); err == nil {
			t.Errorf("%s: NewDomain accepted it as %q", name, d.Name())
		} else if strings.Contains(err.Error(), "mnc001") {
			t.Errorf("%s: the error %q repeats the value", name, err)
		}
	}
	if d, err := NewDomain(strings.Repeat("a", 60)+"."+strings.Repeat("b", 59)+".net", imsDomain); err != nil || len(d.Name()) != MaxDomainBytes {
		t.Errorf("a domain of MaxDomainBytes: %v", err)
	}
}

func TestAnUnsetChatbotDomainIsOffAndABadOneStopsTheService(t *testing.T) {
	load := func(vars map[string]string) (Domain, error) {
		shared := runtime.NewEnv("RCS_", func(k string) (string, bool) { v, ok := vars[k]; return v, ok })
		d := LoadDomain(shared, imsDomain)
		return d, shared.Err()
	}
	if d, err := load(nil); err != nil || d != (Domain{}) {
		t.Errorf("unset: %+v, %v; want the zero Domain", d, err)
	}
	if d, err := load(map[string]string{"RCS_CHATBOT_DOMAIN": botDomain}); err != nil || d.Name() != botDomain {
		t.Errorf("set: %q, %v", d.Name(), err)
	}
	_, err := load(map[string]string{"RCS_CHATBOT_DOMAIN": imsDomain})
	if err == nil || !strings.Contains(err.Error(), "RCS_CHATBOT_DOMAIN: the same as RCS_IMS_DOMAIN") {
		t.Errorf("the IMS domain: %v", err)
	}
}
