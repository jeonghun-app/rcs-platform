package hss

import (
	"errors"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

const botDomain = "botplatform.mnc001.mcc001.3gppnetwork.org"

// chatbotPSI is the PSI the platform provisions: the user-part grammar of
// internal/chatbot at the chatbot domain.
const chatbotPSI = "sip:!" + chatbot.UserPartERE + "!@" + botDomain

func testChatbotDomain(t testing.TB) chatbot.Domain {
	t.Helper()
	d, err := chatbot.NewDomain(botDomain, "ims.mnc001.mcc001.3gppnetwork.org")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func testChatbotRange(t testing.TB, psi string) *chatbotRange {
	t.Helper()
	r, err := parseChatbotRange(psi, testChatbotDomain(t))
	if err != nil {
		t.Fatalf("%s: %v", psi, err)
	}
	return r
}

func TestAWildcardedPSIIsAnEREAtTheChatbotDomain(t *testing.T) {
	d := testChatbotDomain(t)
	// With the domain unset, "sip:!a!@" is a PSI at the (empty) domain in
	// every other respect, so only the guard refuses it.
	if _, err := parseChatbotRange("sip:!a!@", chatbot.Domain{}); err == nil {
		t.Error("a PSI was accepted with RCS_CHATBOT_DOMAIN unset")
	}
	at := func(ere string) string { return "sip:!" + ere + "!@" + botDomain }
	refused := map[string]string{
		"too long":                     at(strings.Repeat("a", store.MaxPSILength-len(at(""))+1)),
		"another host":                 "sip:!" + chatbot.UserPartERE + "!@ims.mnc001.mcc001.3gppnetwork.org",
		"the host in upper case":       "sip:!" + chatbot.UserPartERE + "!@" + strings.ToUpper(botDomain),
		"a subdomain of the host":      "sip:!" + chatbot.UserPartERE + "!@x." + botDomain,
		"sips":                         "sips:!" + chatbot.UserPartERE + "!@" + botDomain,
		"no delimiters":                "sip:" + chatbot.UserPartERE + "@" + botDomain,
		"one delimiter":                "sip:!" + chatbot.UserPartERE + "@" + botDomain,
		"a parameter":                  at(chatbot.UserPartERE) + ";tk=on",
		"an empty ERE":                 at(""),
		"the delimiter inside the ERE": at("a!b"),
		"white space":                  at("a b"),
		"a control character":          at("a\nb"),
		"DEL":                          at("a\x7fb"),
		"not ASCII":                    at("é"),
		"a POSIX departure":            at(`[\.]bot`),
		"Perl syntax":                  at(`(?i)bot`),
		"an unclosed group":            at(`(bot`),
		"over the instruction budget":  at(`[ab]{1000}[cd]{1000}`),
	}
	for name, psi := range refused {
		if _, err := parseChatbotRange(psi, d); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	longest := at(strings.Repeat("a", store.MaxPSILength-len(at(""))))
	// "~" is the last printable ASCII character.
	for _, psi := range []string{chatbotPSI, longest, at("bot|news"), at(".*"), at("a~")} {
		if r, err := parseChatbotRange(psi, d); err != nil || r.psi != psi {
			t.Errorf("%s: %v", psi, err)
		}
	}
}

// TestEveryNormalFormIsMatchedWithinTheWorkBudget pins why contains never
// fails for want of budget: a match costs at most its program's
// instructions a byte, a PSI's ERE compiles to at most
// ifc.MaxPatternInstructions, and contains matches only the user part of a
// normal form, which the longest RCS_CHATBOT_DOMAIN's room in
// chatbot.MaxURIBytes bounds.
func TestEveryNormalFormIsMatchedWithinTheWorkBudget(t *testing.T) {
	longestUser := chatbot.MaxURIBytes - chatbot.MaxDomainBytes - len("sip:@")
	if got := ifc.MaxPatternInstructions * longestUser; got > ifc.DefaultMaxWork {
		t.Fatalf("%d instructions × %d bytes = %d, over DefaultMaxWork (%d)", ifc.MaxPatternInstructions, longestUser, got, ifc.DefaultMaxWork)
	}
	// The bound is the longest user part Normalise accepts: two labels of
	// 63 and the dot.
	user := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63)
	if _, err := testChatbotDomain(t).Normalise("sip:" + user + "@" + botDomain); err != nil || len(user) != longestUser {
		t.Fatalf("a %d-byte user part: %v; the bound is %d", len(user), err, longestUser)
	}
}

// TestTheChatbotRangeIsMatchedWholeAndWithRegardToCase follows the
// handover from #686: the ERE must not be read as internal/ifc reads a
// trigger's pattern by default, anywhere in the value and, for a
// Request-URI, without regard to case.
func TestTheChatbotRangeIsMatchedWholeAndWithRegardToCase(t *testing.T) {
	r := testChatbotRange(t, chatbotPSI)
	bot := testChatbotRange(t, "sip:!bot!@"+botDomain)
	all := testChatbotRange(t, "sip:!.*!@"+botDomain)
	tests := []struct {
		r    *chatbotRange
		uri  string
		want bool
	}{
		{r, "sip:mybot@" + botDomain, true},
		{r, "sip:my-bot.publisher@" + botDomain, true},
		{r, "sip:" + strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "@" + botDomain, true},
		{r, "sip:" + strings.Repeat("a", 64) + "@" + botDomain, false},
		{r, "sip:a.b.c@" + botDomain, false},
		{r, "sip:MyBot@" + botDomain, false},
		{bot, "sip:bot@" + botDomain, true},
		{bot, "sip:mybot@" + botDomain, false},
		{bot, "sip:bots@" + botDomain, false},
		{bot, "sip:BOT@" + botDomain, false},
		// Only the normal form itself is in the range, whatever the ERE.
		{all, "sip:anything@" + botDomain, true},
		{all, "sip:Anything@" + botDomain, false},
		{all, "sip:bot@" + strings.ToUpper(botDomain), false},
		{all, "SIP:bot@" + botDomain, false},
		{all, "sip:bot@" + botDomain + ";tk=on", false},
		{all, "sips:bot@" + botDomain, false},
		{all, "sip:bot@ims.mnc001.mcc001.3gppnetwork.org", false},
		{all, "tel:+15550100001", false},
	}
	for _, tc := range tests {
		if got, err := tc.r.contains(tc.uri); err != nil || got != tc.want {
			t.Errorf("%s contains %s = %t, %v; want %t", tc.r.psi, tc.uri, got, err, tc.want)
		}
	}
	for user, want := range map[string]bool{"bot": true, "Bot": false, "BOT": false, "xbot": false, "botx": false, "x.bot": false} {
		if got, err := bot.userMatches(user); err != nil || got != want {
			t.Errorf("user part %q = %t, %v; want %t", user, got, err, want)
		}
	}
}

// TestTheStoredEREAndNormaliseAcceptTheSameUserParts repeats internal/
// chatbot's equivalence check through the matcher hss uses, on every user
// part of up to four characters over an alphabet with each class of
// character the grammar treats apart.
func TestTheStoredEREAndNormaliseAcceptTheSameUserParts(t *testing.T) {
	r, d := testChatbotRange(t, chatbotPSI), testChatbotDomain(t)
	label := strings.Repeat("z", 63)
	users := []string{label, label + "z", label + "." + label, label + ".", "a..b", "-", "0.-", "a.b.c", "é", "a\n", "A", "aB"}
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
		checkSameUserPart(t, r, d, u)
	}
}

func checkSameUserPart(t *testing.T, r *chatbotRange, d chatbot.Domain, user string) {
	t.Helper()
	uri := "sip:" + user + "@" + botDomain
	_, err := d.Normalise(uri)
	matched, merr := r.userMatches(user)
	var limit *ifc.LimitError
	switch {
	case errors.As(merr, &limit) && err != nil && len(uri) > chatbot.MaxURIBytes:
		// Past the work budget the matcher answers neither way, as it must;
		// only a user part far longer than any normal form gets there, and
		// contains, below, refuses it before matching.
	case merr != nil || matched != (err == nil):
		t.Fatalf("user part %q: Normalise error %v, hss matched %t (%v)", user, err, matched, merr)
	}
	if in, cerr := r.contains(uri); cerr != nil || in != (err == nil) {
		t.Fatalf("%q: Normalise error %v, in the range %t (%v)", uri, err, in, cerr)
	}
}

// FuzzChatbotRange checks, with the input as a user part, that hss's
// matcher and Normalise accept the same ones, and, with it as an ERE, that
// a PSI the parser accepts is matched within the work budget.
func FuzzChatbotRange(f *testing.F) {
	for _, s := range []string{"mybot", "my-bot.pub", "MyBot", "a.b.c", "my%62ot", "a@b", "[a-z]+", `(?i)a`, "a{1000}"} {
		f.Add(s)
	}
	r, d := testChatbotRange(f, chatbotPSI), testChatbotDomain(f)
	f.Fuzz(func(t *testing.T, s string) {
		checkSameUserPart(t, r, d, s)
		wild, err := parseChatbotRange("sip:!"+s+"!@"+botDomain, d)
		if err != nil {
			return
		}
		for _, uri := range []string{"sip:" + strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "@" + botDomain, "sip:" + s + "@" + botDomain} {
			if _, err := wild.contains(uri); err != nil {
				t.Fatalf("ERE %q over %q: %v", s, uri, err)
			}
		}
	})
}
