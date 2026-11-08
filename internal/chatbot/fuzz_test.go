package chatbot

import (
	"errors"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// FuzzNormalise checks that a normal form is a fixed point inside the bound,
// that an accepted URI writes back as received, that the strict parse never
// reads a URI as at the chatbot domain that the loose check misses, and,
// with the input as a user part, that Normalise and UserPartERE accept the
// same ones.
func FuzzNormalise(f *testing.F) {
	for _, s := range []string{
		"sip:mybot@" + botDomain, "sip:my-bot.pub@" + botDomain + ";tk=on", "sips:mybot@" + botDomain,
		"sip:mybot@" + botDomain + ":5060", "sip:a@b@" + botDomain, "tel:+15550100001", "mybot", "a.b.c", "my%62ot",
		"sip:sips:@" + botDomain, "sip:mybot@" + botDomain + ";x=@evil.example.net",
	} {
		f.Add(s)
	}
	d, ere := testDomain(f), userPartMatcher(f)
	f.Fuzz(func(t *testing.T, s string) {
		got, err := d.Normalise(s)
		switch {
		case err == nil:
			user, ok := strings.CutPrefix(strings.TrimSuffix(got, "@"+botDomain), "sip:")
			if !ok || !ere.MatchString(user) || len(got) > MaxURIBytes {
				t.Fatalf("Normalise(%q) = %q, not a normal form", s, got)
			}
			if again, err := d.Normalise(got); err != nil || again != got {
				t.Fatalf("Normalise(%q) = %q, %v; want it unchanged", got, again, err)
			}
			if u, _ := sip.ParseURI(s); u.String() != "sip"+s[len("sip"):] {
				t.Fatalf("Normalise accepted %q, which writes back as %q", s, u.String())
			}
		case errors.Is(err, ErrNotChatbot):
			if u, perr := sip.ParseURI(s); perr == nil && (u.Scheme == "sip" || u.Scheme == "sips") && strings.EqualFold(u.Host, botDomain) {
				t.Fatalf("Normalise(%q): ErrNotChatbot for a URI parsed at the chatbot domain", s)
			}
		case !errors.Is(err, ErrNotNormal):
			t.Fatalf("Normalise(%q): unexpected error %v", s, err)
		}
		_, err = d.Normalise("sip:" + s + "@" + botDomain)
		if (err == nil) != ere.MatchString(s) {
			t.Fatalf("user part %q: Normalise error %v, ERE match %v", s, err, ere.MatchString(s))
		}
	})
}
