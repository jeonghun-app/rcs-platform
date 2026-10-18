package sip

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// lines joins message lines with CRLF and ends the header section with an empty
// line, so tests read like the messages they stand for.
func lines(ls ...string) string { return strings.Join(ls, "\r\n") + "\r\n\r\n" }

func TestLookupIgnoresCaseAndCompactForms(t *testing.T) {
	compact := map[string]string{
		"a": "Accept-Contact", "b": "Referred-By", "c": "Content-Type", "d": "Request-Disposition",
		"e": "Content-Encoding", "f": "From", "i": "Call-ID", "j": "Reject-Contact", "k": "Supported",
		"l": "Content-Length", "m": "Contact", "n": "Identity-Info", "o": "Event", "r": "Refer-To",
		"s": "Subject", "t": "To", "u": "Allow-Events", "v": "Via", "x": "Session-Expires", "y": "Identity",
	}
	for short, full := range compact {
		var h Header
		h.fields = append(h.fields, field{name: short, key: headerKey(short), value: "x"})
		for _, name := range []string{full, strings.ToUpper(full), strings.ToLower(full), strings.ToUpper(short)} {
			if got := h.Get(name); got != "x" {
				t.Errorf("compact %q: Get(%q) = %q", short, name, got)
			}
		}
		if got := CanonicalName(short); got != full {
			t.Errorf("CanonicalName(%q) = %q, want %q", short, got, full)
		}
	}
	if got := CanonicalName("cseq"); got != "CSeq" {
		t.Errorf("CanonicalName(cseq) = %q", got)
	}
	if got := CanonicalName("X-Unknown"); got != "X-Unknown" {
		t.Errorf("CanonicalName(X-Unknown) = %q", got)
	}
	if got := CanonicalName("q"); got != "q" {
		t.Errorf("CanonicalName(q) = %q", got)
	}
}

func TestHeaderKeepsOrderAndOriginalNames(t *testing.T) {
	m := mustParse(t, lines(
		"OPTIONS sip:example.com SIP/2.0",
		"v: SIP/2.0/UDP a.example.com;branch=z9hG4bK1",
		"X-Custom: one",
		"VIA: SIP/2.0/UDP b.example.com;branch=z9hG4bK2",
		"x-custom: two",
	))
	h := m.Headers()
	want := []HeaderField{
		{"v", "SIP/2.0/UDP a.example.com;branch=z9hG4bK1"},
		{"X-Custom", "one"},
		{"VIA", "SIP/2.0/UDP b.example.com;branch=z9hG4bK2"},
		{"x-custom", "two"},
	}
	if got := h.Fields(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Fields() = %q", got)
	}
	if got := h.Values("Via"); !reflect.DeepEqual(got, []string{want[0].Value, want[2].Value}) {
		t.Errorf("Values(Via) = %q", got)
	}
	if got := h.Get("X-CUSTOM"); got != "one" {
		t.Errorf("Get = %q", got)
	}
	if h.Len() != 4 || !h.Has("via") || h.Has("Route") || h.Get("Route") != "" || h.Values("Route") != nil {
		t.Error("Len/Has/Get disagree with the fields")
	}
}

func TestAddWritesCanonicalNamesAndRefusesInjection(t *testing.T) {
	var h Header
	for _, add := range []struct{ name, value string }{
		{"call-id", "  abc@example.com "},
		{"v", "SIP/2.0/UDP a.example.com;branch=z9hG4bK1"},
		{"X-Mine", "1"},
		{"Subject", ""},
	} {
		if err := h.Add(add.name, add.value); err != nil {
			t.Fatalf("Add(%q): %v", add.name, err)
		}
	}
	want := []HeaderField{{"Call-ID", "abc@example.com"}, {"Via", "SIP/2.0/UDP a.example.com;branch=z9hG4bK1"}, {"X-Mine", "1"}, {"Subject", ""}}
	if got := h.Fields(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Fields() = %q", got)
	}

	for _, bad := range []struct{ name, value string }{
		{"", "x"},
		{"Bad Name", "x"},
		{"Bad:Name", "x"},
		{"Subject", "hi\r\nVia: SIP/2.0/UDP evil.example.com"},
		{"Subject", "hi\nthere"},
		{"Subject", "hi\rthere"},
	} {
		if err := h.Add(bad.name, bad.value); !errors.Is(err, ErrMalformed) {
			t.Errorf("Add(%q, %q) = %v, want ErrMalformed", bad.name, bad.value, err)
		}
		if err := h.Set(bad.name, bad.value); err == nil {
			t.Errorf("Set(%q, %q) succeeded", bad.name, bad.value)
		}
		if err := h.Prepend(bad.name, bad.value); err == nil {
			t.Errorf("Prepend(%q, %q) succeeded", bad.name, bad.value)
		}
	}
	if h.Len() != 4 {
		t.Errorf("a refused field was added")
	}
}

func TestSetReplacesEveryFieldAtTheFirstPosition(t *testing.T) {
	var h Header
	mustAdd(t, &h, "Route", "<sip:a.example.com;lr>")
	mustAdd(t, &h, "To", "<sip:bob@example.com>")
	mustAdd(t, &h, "route", "<sip:b.example.com;lr>")
	if err := h.Set("ROUTE", "<sip:c.example.com;lr>"); err != nil {
		t.Fatal(err)
	}
	want := []HeaderField{{"Route", "<sip:c.example.com;lr>"}, {"To", "<sip:bob@example.com>"}}
	if got := h.Fields(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Fields() = %q", got)
	}
	if err := h.Set("Max-Forwards", "70"); err != nil {
		t.Fatal(err)
	}
	if got := h.Fields()[2]; got != (HeaderField{"Max-Forwards", "70"}) {
		t.Errorf("Set of a new name appended %q", got)
	}
}

func TestPrependPutsTheFieldAboveItsNamesakes(t *testing.T) {
	var h Header
	mustAdd(t, &h, "From", "<sip:alice@example.com>;tag=1")
	mustAdd(t, &h, "Via", "SIP/2.0/UDP b.example.com;branch=z9hG4bK2")
	if err := h.Prepend("v", "SIP/2.0/UDP a.example.com;branch=z9hG4bK1"); err != nil {
		t.Fatal(err)
	}
	if err := h.Prepend("Record-Route", "<sip:p.example.com;lr>"); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range h.Fields() {
		names = append(names, f.Name)
	}
	if want := []string{"From", "Via", "Via", "Record-Route"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("names = %q, want %q", names, want)
	}
	if vias := h.Values("Via"); !strings.Contains(vias[0], "a.example.com") {
		t.Errorf("Prepend did not put the new Via on top: %q", vias)
	}
}

func TestDelRemovesEveryFieldWithTheName(t *testing.T) {
	var h Header
	mustAdd(t, &h, "Route", "<sip:a.example.com;lr>")
	mustAdd(t, &h, "To", "<sip:bob@example.com>")
	mustAdd(t, &h, "Route", "<sip:b.example.com;lr>")
	h.Del("route")
	if got := h.Fields(); !reflect.DeepEqual(got, []HeaderField{{"To", "<sip:bob@example.com>"}}) {
		t.Fatalf("Fields() = %q", got)
	}
}

func TestCloneIsIndependent(t *testing.T) {
	var h Header
	mustAdd(t, &h, "To", "<sip:bob@example.com>")
	c := h.Clone()
	mustAdd(t, &c, "From", "<sip:alice@example.com>")
	if err := c.Set("To", "<sip:carol@example.com>"); err != nil {
		t.Fatal(err)
	}
	if h.Len() != 1 || h.Get("To") != "<sip:bob@example.com>" {
		t.Errorf("modifying the clone changed the original: %q", h.Fields())
	}
	var empty Header
	if c := empty.Clone(); c.Len() != 0 {
		t.Error("clone of an empty header is not empty")
	}
}

func TestElementsSplitOnlyOnSeparatingCommas(t *testing.T) {
	var h Header
	mustAdd(t, &h, "Contact", `"Smith, J" <sip:a@example.com;x=1,2>;p="a,b", <sip:b@example.com>`)
	mustAdd(t, &h, "m", `sip:c@example.com`)
	got, err := h.Elements("Contact")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`"Smith, J" <sip:a@example.com;x=1,2>;p="a,b"`, `<sip:b@example.com>`, `sip:c@example.com`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Elements = %q, want %q", got, want)
	}
	if got, err := h.Elements("Route"); got != nil || err != nil {
		t.Errorf("Elements of an absent field = %q, %v", got, err)
	}
}

func TestElementsRejectEmptyAndUnbalancedLists(t *testing.T) {
	for _, v := range []string{
		"a,,b",
		"a,",
		",a",
		"a, ,b",
		`"unterminated, a`,
		`<sip:a@example.com, b`,
		`"escaped quote \", a`,
	} {
		var h Header
		mustAdd(t, &h, "Contact", v)
		_, err := h.Elements("m")
		var pe *ParseError
		if !errors.As(err, &pe) || pe.Header != "Contact" || !errors.Is(err, ErrMalformed) {
			t.Errorf("Elements(%q) error = %v, want a malformed Contact", v, err)
		}
	}
}

func TestParseErrorsNameTheFieldButNotItsValue(t *testing.T) {
	var h Header
	mustAdd(t, &h, "From", "Secret Name <sip:+15550100001@example.com;user=phone> junk")
	_, err := h.From()
	if err == nil {
		t.Fatal("From() accepted trailing junk")
	}
	msg := err.Error()
	if !strings.Contains(msg, "From") || strings.Contains(msg, "Secret") || strings.Contains(msg, "15550100001") {
		t.Errorf("error %q does not name the field, or leaks the value", msg)
	}
}

func mustAdd(t *testing.T, h *Header, name, value string) {
	t.Helper()
	if err := h.Add(name, value); err != nil {
		t.Fatalf("Add(%q, %q): %v", name, value, err)
	}
}
