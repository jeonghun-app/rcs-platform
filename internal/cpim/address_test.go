package cpim

import (
	"errors"
	"testing"
)

func TestParseAddressAcceptsEveryFormalNameForm(t *testing.T) {
	tests := []struct {
		in   string
		want Address
	}{
		{"<" + alice + ">", Address{URI: alice}},
		{"Alice <" + alice + ">", Address{Name: "Alice", URI: alice}},
		{"Alice B. Smith <" + alice + ">", Address{Name: "Alice B. Smith", URI: alice}},
		{"앨리스 <" + alice + ">", Address{Name: "앨리스", URI: alice}},
		{`"Smith, Alice" <` + alice + ">", Address{Name: "Smith, Alice", URI: alice}},
		{`"Smith, Alice"<` + alice + ">", Address{Name: "Smith, Alice", URI: alice}},
		{`"say \"hi\"\\ é\t" <` + alice + ">", Address{Name: "say \"hi\"\\ é\t", URI: alice}},
		{`"" <` + carol + ">", Address{URI: carol}},
		{"<sip:anonymous@anonymous.invalid>", Address{URI: "sip:anonymous@anonymous.invalid"}},
		{"<im:alice@example.com>", Address{URI: "im:alice@example.com"}},
	}
	for _, tt := range tests {
		got, err := ParseAddress(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("ParseAddress(%q) = %+v, %v; want %+v", tt.in, got, err, tt.want)
		}
	}
}

func TestParseAddressRejectsMalformedValues(t *testing.T) {
	for _, in := range []string{
		"",
		alice,
		"<" + alice,
		alice + ">",
		"Alice<" + alice + ">",
		"Alice  <" + alice + ">",
		"Smith, Alice <" + alice + ">",
		`"Alice <` + alice + ">",
		`"Alice"  <` + alice + ">",
		"<>",
		"<:x>",
		"<sip:>",
		"<1sip:x>",
		"<si p:x>",
		"<sip:a b>",
		"<sip:a<b>",
		"<sip:a\"b>",
		"Alice\t<" + alice + ">",
		"<sip:\xff>",
	} {
		if _, err := ParseAddress(in); !errors.Is(err, ErrMalformed) {
			t.Errorf("ParseAddress(%q) error = %v, want ErrMalformed", in, err)
		}
	}
}

func TestAddressStringQuotesOnlyWhenTheNameNeedsIt(t *testing.T) {
	tests := []struct {
		in   Address
		want string
	}{
		{Address{URI: alice}, "<" + alice + ">"},
		{Address{Name: "Alice B. Smith", URI: alice}, "Alice B. Smith <" + alice + ">"},
		{Address{Name: "Smith, Alice", URI: alice}, `"Smith, Alice" <` + alice + ">"},
		{Address{Name: " padded ", URI: alice}, `" padded " <` + alice + ">"},
		{Address{Name: "two  spaces", URI: alice}, `"two  spaces" <` + alice + ">"},
		{Address{Name: "a \"q\" \\ \n\x01", URI: alice}, `"a \"q\" \\ \n\u0001" <` + alice + ">"},
	}
	for _, tt := range tests {
		got := tt.in.String()
		if got != tt.want {
			t.Errorf("%+v.String() = %q, want %q", tt.in, got, tt.want)
		}
		back, err := ParseAddress(got)
		if err != nil || back != tt.in {
			t.Errorf("ParseAddress(%q) = %+v, %v; want %+v", got, back, err, tt.in)
		}
	}
}

func TestUnescapeFollowsTheReceiverRules(t *testing.T) {
	tests := []struct{ in, want string }{
		{`plain`, "plain"},
		{`\\ \" \' \b \t \n \r`, "\\ \" ' \b \t \n \r"},
		{`\u0041\u00e9\u4E2D`, "Aé中"},
		{`\ud83d\ude00`, "😀"},
		{`\ud83d\u0041`, "�A"},
		{`\ud83d`, "�"},
		{`\ud83dx`, "�x"},
		{`\ud83dA`, "�A"},
		{`\ude00`, "�"},
		{`\u12`, "u12"},
		{`\uzzzz`, "uzzzz"},
		{`\q`, "q"},
		{`\é`, "é"},
		{`trailing\`, "trailing"},
	}
	for _, tt := range tests {
		if got := Unescape(tt.in); got != tt.want {
			t.Errorf("Unescape(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestEscapeLeavesNoControlCharacters(t *testing.T) {
	in := "a\\b\bc\td\ne\rf\x00g\x7fh\"é"
	got := Escape(in)
	if want := `a\\b\bc\td\ne\rf\u0000g\u007fh"é`; got != want {
		t.Errorf("Escape(%q) = %q, want %q", in, got, want)
	}
	if hasControl(got, false) {
		t.Errorf("Escape left a control character in %q", got)
	}
	if back := Unescape(got); back != in {
		t.Errorf("Unescape(Escape(%q)) = %q", in, back)
	}
}

func TestIsTokenMatchesTheTokenGrammar(t *testing.T) {
	for s, want := range map[string]bool{
		"Kd3Pq8sXw2":        true,
		"a.b-c_d~e!#$%&'*+": true,
		"한글":                true,
		"":                  false,
		"a b":               false,
		"a,b":               false,
		"a;b":               false,
		"a\"b":              false,
		"a\x01":             false,
		"\xff":              false,
	} {
		if got := IsToken(s); got != want {
			t.Errorf("IsToken(%q) = %v, want %v", s, got, want)
		}
	}
}
