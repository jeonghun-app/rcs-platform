package xmlsafe_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/conference"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/sip/reginfo"
	"github.com/jeonghun-app/rcs-platform/internal/xmlsafe"
)

// #17 (lead, from #233 QA): every reader of a document refuses, as not
// well-formed, a character reference to a surrogate, which encoding/xml
// reads as U+FFFD (two contact ids c&#xD800; and c&#xDBFF; would become
// one); attributes with no white space between them; and an XML
// declaration not in lower case. Each package reports its own
// ErrMalformed, and its ErrDTD and ErrTooLarge match the shared ones.
func TestEveryReaderRefusesWhatIsNotWellFormed(t *testing.T) {
	for _, p := range []struct {
		name string
		// doc has a {} in a value and a {sp} between two attributes.
		doc                  string
		parse                func([]byte) error
		malformed, dtd, size error
	}{
		{"conference", `<conference-info xmlns="urn:ietf:params:xml:ns:conference-info"{sp}entity="sip:chat-1@conf.example.org" state="full" version="1">` +
			`<conference-description><subject>Lunch</subject></conference-description>` +
			`<users><user entity="tel:+15550100001" state="full"><display-text>{}</display-text></user></users></conference-info>`,
			func(b []byte) error { _, err := conference.Parse(b); return err }, conference.ErrMalformed, conference.ErrDTD, conference.ErrTooLarge},
		{"imdn", `<imdn xmlns="urn:ietf:params:xml:ns:imdn"{sp}xmlns:x="urn:example:x"><message-id>abc</message-id><datetime>2026-10-18T00:30:00Z</datetime>` +
			`<delivery-notification><status><delivered/></status></delivery-notification><x:note>{}</x:note></imdn>`,
			func(b []byte) error { _, err := imdn.ParseNotification(b); return err }, imdn.ErrMalformed, imdn.ErrDTD, imdn.ErrTooLarge},
		{"reginfo", `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo"{sp}version="1" state="full">` +
			`<registration aor="sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org" id="a" state="active">` +
			`<contact id="c{}" state="active" event="registered"><uri>sip:alice@192.0.2.10:40000;transport=tcp;ob</uri></contact></registration></reginfo>`,
			func(b []byte) error { _, err := reginfo.Parse(b); return err }, reginfo.ErrMalformed, reginfo.ErrDTD, reginfo.ErrTooLarge},
	} {
		doc := func(value, sp string) string {
			return strings.Replace(strings.Replace(p.doc, "{}", value, 1), "{sp}", sp, 1)
		}
		plain := doc("", " ")
		if err := p.parse([]byte(plain)); err != nil {
			t.Fatalf("%s: the plain document: %v", p.name, err)
		}
		if err := p.parse([]byte(`<?xml version="1.0"?>` + doc("&#xD7FF;", "\t"))); err != nil {
			t.Fatalf("%s: with a declaration, a tab and a reference: %v", p.name, err)
		}
		refused := map[string]string{
			"a surrogate":               doc("&#xD800;", " "),
			"attributes run together":   doc("", ""),
			"an upper-case declaration": `<?XML version="1.0"?>` + plain,
		}
		for what, d := range refused {
			if err := p.parse([]byte(d)); !errors.Is(err, p.malformed) {
				t.Errorf("%s, %s: %v", p.name, what, err)
			}
		}
		root := p.doc[1:strings.IndexAny(p.doc, " >{")]
		if err := p.parse([]byte(`<!DOCTYPE ` + root + `>` + plain)); !errors.Is(err, p.dtd) || !errors.Is(err, xmlsafe.ErrDTD) {
			t.Errorf("%s, a DTD: %v", p.name, err)
		}
		if err := p.parse([]byte(doc(strings.Repeat("x", 300<<10), " "))); !errors.Is(err, p.size) || !errors.Is(err, xmlsafe.ErrTooLarge) {
			t.Errorf("%s, too large: %v", p.name, err)
		}
	}
}
