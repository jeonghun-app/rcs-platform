package resourcelists

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// rcsjtaList is the resource list rcsjta puts in a group INVITE to the
// conference factory (RFC 5366 §6).
const rcsjtaList = `<?xml version="1.0" encoding="UTF-8"?>
<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists" xmlns:cp="urn:ietf:params:xml:ns:copycontrol">
<list>
<entry uri="tel:+15550100002" cp:copyControl="to"/>
<entry uri="sip:+15550100003@ims.mnc001.mcc001.3gppnetwork.org" cp:copyControl="to"><display-name>Carol</display-name></entry>
</list>
</resource-lists>`

func TestTheEntriesOfAListAreRead(t *testing.T) {
	got, _, err := Parse([]byte(rcsjtaList), 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{{URI: "tel:+15550100002"}, {URI: "sip:+15550100003@ims.mnc001.mcc001.3gppnetwork.org", DisplayName: "Carol"}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestNestedListsAreReadInOrderAndReferencesLeftOut(t *testing.T) {
	doc := `<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list>
<entry uri="tel:+15550100002"/><list name="b"><entry uri="tel:+15550100003"/></list>
<entry-ref ref="x"/><external anchor="http://example.invalid/l"/></list></resource-lists>`
	got, _, err := Parse([]byte(doc), 10)
	if err != nil || len(got) != 2 || got[1].URI != "tel:+15550100003" {
		t.Fatalf("got %v, %v", got, err)
	}
}

// A list beyond the limit is refused at the first entry past it.
func TestAListBeyondTheLimitIsRefused(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list>`)
	for _, n := range []string{"+15550100001", "+15550100002", "+15550100003", "+15550100004"} {
		fmt.Fprintf(&b, `<entry uri="tel:%s"/>`, n)
	}
	// What follows the third entry does not parse: it is never reached.
	b.WriteString(`<<<`)
	if _, _, err := Parse([]byte(b.String()), 3); !errors.Is(err, ErrTooMany) {
		t.Fatalf("got %v", err)
	}
}

func TestWhatIsNotAResourceListIsRefused(t *testing.T) {
	for name, c := range map[string]struct {
		doc  string
		want error
	}{
		"a DTD":         {`<!DOCTYPE x [<!ENTITY a "b">]><resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"/>`, ErrDTD},
		"too large":     {strings.Repeat(" ", MaxDocumentSize+1), ErrTooLarge},
		"another root":  {`<lists xmlns="urn:ietf:params:xml:ns:resource-lists"/>`, ErrMalformed},
		"no namespace":  {`<resource-lists><list><entry uri="tel:+15550100002"/></list></resource-lists>`, ErrMalformed},
		"two roots":     {`<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"/><resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"/>`, ErrMalformed},
		"no root":       {` `, ErrMalformed},
		"repeated attr": {`<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list><entry uri="a" uri="b"/></list></resource-lists>`, ErrMalformed},
		"text outside":  {`<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"/>x`, ErrMalformed},
		"unclosed":      {`<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list>`, ErrMalformed},
		"deep":          {`<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists">` + strings.Repeat("<list>", maxDepth) + strings.Repeat("</list>", maxDepth) + `</resource-lists>`, ErrMalformed},
		"long name":     {`<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list><entry uri="a"><display-name>` + strings.Repeat("n", maxNameBytes+1) + `</display-name></entry></list></resource-lists>`, ErrMalformed},
	} {
		if _, _, err := Parse([]byte(c.doc), 10); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

// One bad entry does not refuse a list (docs/rcs-as.md): an entry whose
// uri is missing, not text, or has white space or control characters is
// left out and counted, and still counts toward the limit; a name that is
// not text is dropped and its entry kept.
func TestABadEntryIsSkippedNotRefused(t *testing.T) {
	for name, doc := range map[string]string{
		"entry, no uri":  `<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list><entry/></list></resource-lists>`,
		"CR LF in a uri": `<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list><entry uri="sip:a@b&#13;&#10;Via: x"/></list></resource-lists>`,
		"space in a uri": `<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list><entry uri="sip:a b@c"/></list></resource-lists>`,
		"DEL in a uri":   `<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list><entry uri="sip:a&#x7f;@b"/></list></resource-lists>`,
		"a surrogate":    `<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list><entry uri="sip:a&#xD800;@b"/></list></resource-lists>`,
	} {
		doc = strings.Replace(doc, "</list>", `<entry uri="tel:+15550100002"/></list>`, 1)
		got, skipped, err := Parse([]byte(doc), 10)
		if err != nil || skipped != 1 || len(got) != 1 || got[0].URI != "tel:+15550100002" {
			t.Errorf("%s: %v, %d skipped, %v", name, got, skipped, err)
		}
		if _, _, err := Parse([]byte(doc), 1); !errors.Is(err, ErrTooMany) {
			t.Errorf("%s: a skipped entry did not count toward the limit: %v", name, err)
		}
	}
	got, skipped, err := Parse([]byte(`<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list><entry uri="sip:a@b"><display-name>&#xDFFF;</display-name></entry></list></resource-lists>`), 10)
	if err != nil || skipped != 0 || len(got) != 1 || got[0].DisplayName != "" {
		t.Errorf("a name that is not text: %v, %d skipped, %v", got, skipped, err)
	}
}

// An error never quotes the input.
func TestAnErrorDoesNotQuoteTheDocument(t *testing.T) {
	_, _, err := Parse([]byte(`<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list><entry uri="tel:+15550100002"></bad></list></resource-lists>`), 10)
	if err == nil || strings.Contains(err.Error(), "+1555") || strings.Contains(err.Error(), "bad") {
		t.Fatalf("error %v", err)
	}
}
