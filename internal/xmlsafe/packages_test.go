package xmlsafe_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/conference"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/sh"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/resourcelists"
	"github.com/jeonghun-app/rcs-platform/internal/sip/reginfo"
	"github.com/jeonghun-app/rcs-platform/internal/xmlsafe"
)

// #17 (lead, from #233 QA; security review on #403): every reader of a
// document refuses, as not well-formed, a character reference to a
// surrogate, which encoding/xml reads as U+FFFD (two contact ids
// c&#xD800; and c&#xDBFF; would become one); attributes with no white
// space between them; and an XML declaration not in lower case or not at
// the start. Each package reports its own ErrMalformed, and its ErrDTD and
// ErrTooLarge match the shared ones. resourcelists skips the entry with a
// surrogate rather than refusing the list (Doc.SurrogateRefs).
func TestEveryReaderRefusesWhatIsNotWellFormed(t *testing.T) {
	for _, p := range []struct {
		name string
		// doc has a {} in a value and a {sp} between two attributes.
		doc string
		// parse returns the entries skipped, for resourcelists.
		parse                func([]byte) (int, error)
		malformed, dtd, size error
		skipsSurrogate       bool
	}{
		{name: "conference", doc: `<conference-info xmlns="urn:ietf:params:xml:ns:conference-info"{sp}entity="sip:chat-1@conf.example.org" state="full" version="1">` +
			`<conference-description><subject>Lunch</subject></conference-description>` +
			`<users><user entity="tel:+15550100001" state="full"><display-text>{}</display-text></user></users></conference-info>`,
			parse:     func(b []byte) (int, error) { _, err := conference.Parse(b); return 0, err },
			malformed: conference.ErrMalformed, dtd: conference.ErrDTD, size: conference.ErrTooLarge},
		{name: "imdn", doc: `<imdn xmlns="urn:ietf:params:xml:ns:imdn"{sp}xmlns:x="urn:example:x"><message-id>abc</message-id><datetime>2026-10-18T00:30:00Z</datetime>` +
			`<delivery-notification><status><delivered/></status></delivery-notification><x:note>{}</x:note></imdn>`,
			parse:     func(b []byte) (int, error) { _, err := imdn.ParseNotification(b); return 0, err },
			malformed: imdn.ErrMalformed, dtd: imdn.ErrDTD, size: imdn.ErrTooLarge},
		{name: "reginfo", doc: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo"{sp}version="1" state="full">` +
			`<registration aor="sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org" id="a" state="active">` +
			`<contact id="c{}" state="active" event="registered"><uri>sip:alice@192.0.2.10:40000;transport=tcp;ob</uri></contact></registration></reginfo>`,
			parse:     func(b []byte) (int, error) { _, err := reginfo.Parse(b); return 0, err },
			malformed: reginfo.ErrMalformed, dtd: reginfo.ErrDTD, size: reginfo.ErrTooLarge},
		{name: "ifc", doc: `<IMSSubscription xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"{sp}xsi:noNamespaceSchemaLocation="CxDataType.xsd">` +
			`<PrivateID>001010000000001@ims.mnc001.mcc001.3gppnetwork.org</PrivateID><ServiceProfile><PublicIdentity>` +
			`<Identity>sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org</Identity><Extension>{}</Extension></PublicIdentity></ServiceProfile></IMSSubscription>`,
			parse:     func(b []byte) (int, error) { _, err := ifc.ParseSubscription(b); return 0, err },
			malformed: ifc.ErrMalformed, dtd: ifc.ErrDTD, size: ifc.ErrTooLarge},
		{name: "sh", doc: `<Sh-Data xmlns:x="urn:example:x"{sp}xmlns:y="urn:example:y"><RepositoryData><ServiceIndication>a</ServiceIndication>` +
			`<SequenceNumber>1</SequenceNumber><ServiceData><x:d>{}</x:d></ServiceData></RepositoryData></Sh-Data>`,
			parse:     func(b []byte) (int, error) { _, err := sh.ParseData(b); return 0, err },
			malformed: sh.ErrMalformed, dtd: sh.ErrDTD, size: sh.ErrTooLarge},
		{name: "resourcelists", doc: `<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"{sp}xmlns:x="urn:example:x">` +
			`<list><entry uri="tel:+15550100002{}"/><entry uri="tel:+15550100003"/></list></resource-lists>`,
			parse:     func(b []byte) (int, error) { _, skipped, err := resourcelists.Parse(b, 10); return skipped, err },
			malformed: resourcelists.ErrMalformed, dtd: resourcelists.ErrDTD, size: resourcelists.ErrTooLarge, skipsSurrogate: true},
	} {
		doc := func(value, sp string) string {
			return strings.Replace(strings.Replace(p.doc, "{}", value, 1), "{sp}", sp, 1)
		}
		plain := doc("", " ")
		if skipped, err := p.parse([]byte(plain)); err != nil || skipped != 0 {
			t.Fatalf("%s: the plain document: %d skipped, %v", p.name, skipped, err)
		}
		if _, err := p.parse([]byte(`<?xml version="1.0"?>` + doc("&#xD7FF;", "\t"))); err != nil {
			t.Fatalf("%s: with a declaration, a tab and a reference: %v", p.name, err)
		}
		// A CR LF before the declaration, as clients send, is taken (lead
		// on #403); a comment before it, or one in the document, is not.
		if _, err := p.parse([]byte("\r\n" + `<?xml version="1.0"?>` + plain)); err != nil {
			t.Fatalf("%s: a CR LF, then the declaration: %v", p.name, err)
		}
		refused := map[string]string{
			"attributes run together":       doc("", ""),
			"an upper-case declaration":     `<?XML version="1.0"?>` + plain,
			"a comment, then a declaration": `<!-- c --><?xml version="1.0"?>` + plain,
			"a declaration in the document": strings.Replace(plain, "><", `><?xml version="1.0"?><`, 1),
		}
		if !p.skipsSurrogate {
			refused["a surrogate"] = doc("&#xD800;", " ")
		} else if skipped, err := p.parse([]byte(doc("&#xD800;", " "))); err != nil || skipped != 1 {
			t.Errorf("%s, a surrogate: %d skipped, %v", p.name, skipped, err)
		}
		for what, d := range refused {
			if _, err := p.parse([]byte(d)); !errors.Is(err, p.malformed) {
				t.Errorf("%s, %s: %v", p.name, what, err)
			}
		}
		root := p.doc[1:strings.IndexAny(p.doc, " >{")]
		if _, err := p.parse([]byte(`<!DOCTYPE ` + root + `>` + plain)); !errors.Is(err, p.dtd) || !errors.Is(err, xmlsafe.ErrDTD) {
			t.Errorf("%s, a DTD: %v", p.name, err)
		}
		if _, err := p.parse([]byte(doc(strings.Repeat("x", 300<<10), " "))); !errors.Is(err, p.size) || !errors.Is(err, xmlsafe.ErrTooLarge) {
			t.Errorf("%s, too large: %v", p.name, err)
		}
	}
}
