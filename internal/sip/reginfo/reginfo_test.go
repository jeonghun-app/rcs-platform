package reginfo

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

const (
	alice    = "sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org"
	aliceTel = "tel:+15550100001"
	contact  = "sip:alice@192.0.2.10:40000;transport=tcp;ob"
)

// fullDoc is the RFC 3680 §5.3 example, with a test identity, an extension
// element and attribute, and an unknown parameter.
const fullDoc = `<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" xmlns:gr="urn:ietf:params:xml:ns:gruuinfo"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" version="0" state="full">
  <registration aor="` + alice + `" id="as9" state="active">
    <contact gr:state="terminated" gr:id="x" id="76" state="active" event="registered" duration-registered="7322" q="0.8"
        callid="reg-1" cseq="3" gr:extra="ignored">
      <uri>` + contact + `</uri>
      <display-name xml:lang="en">Alice</display-name>
      <unknown-param name="+sip.instance">"&lt;urn:uuid:00000000-0000-1000-8000-000000000001&gt;"</unknown-param>
      <gr:pub-gruu uri="sip:alice@example.com;gr=x"/>
    </contact>
    <contact id="77" state="terminated" event="expired" duration-registered="3600" q="0.5">
      <uri>sip:alice@192.0.2.11</uri>
    </contact>
  </registration>
  <registration aor="` + aliceTel + `" id="as10" state="init"/>
  <gr:extension/>
</reginfo>`

func u64(n uint64) *uint64 { return &n }

func TestTheRFCExampleParses(t *testing.T) {
	got, err := Parse([]byte(fullDoc))
	if err != nil {
		t.Fatal(err)
	}
	want := &Info{Version: 0, State: Full, Registrations: []Registration{
		{AOR: alice, ID: "as9", State: Active, Contacts: []Contact{
			{ID: "76", State: ContactActive, Event: Registered, URI: contact, DisplayName: "Alice", Language: "en",
				DurationRegistered: u64(7322), Q: "0.8", CallID: "reg-1", CSeq: u64(3),
				Params: []Param{{Name: "+sip.instance", Value: `"<urn:uuid:00000000-0000-1000-8000-000000000001>"`}}},
			{ID: "77", State: ContactTerminated, Event: Expired, URI: "sip:alice@192.0.2.11", DurationRegistered: u64(3600), Q: "0.5"},
		}},
		{AOR: aliceTel, ID: "as10", State: Init},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

// What Marshal writes Parse reads back unchanged, partial documents and
// every optional attribute included.
func TestADocumentRoundTrips(t *testing.T) {
	for _, info := range []*Info{
		{Version: 7, State: Partial, Registrations: []Registration{{AOR: alice, ID: "a", State: Terminated, Contacts: []Contact{
			{ID: "c1", State: ContactActive, Event: Shortened, URI: contact, Expires: u64(30)},
			{ID: "c2", State: ContactTerminated, Event: Probation, URI: contact + ";x=2", RetryAfter: u64(60)},
			{ID: "c3", State: ContactTerminated, Event: Deactivated, URI: aliceTel, Params: []Param{{Name: "flag"}}},
		}}}},
		{Version: 4294967295, State: Full},
		{Version: 0, State: Full, Registrations: []Registration{{AOR: alice, ID: "a", State: Active, Contacts: []Contact{
			{ID: "c", State: ContactActive, Event: Created, URI: contact, DisplayName: "A & <B>", Language: "ko"},
		}}}},
	} {
		out, err := info.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		back, err := Parse(out)
		if err != nil || !reflect.DeepEqual(back, info) {
			t.Fatalf("round trip:\n%s\n%+v\n%+v, %v", out, info, back, err)
		}
	}
	out, err := (&Info{Version: 1, State: Full}).Marshal()
	if err != nil || !strings.Contains(string(out), `<reginfo xmlns="`+Namespace+`" version="1" state="full">`) {
		t.Fatalf("%s, %v", out, err)
	}
}

func doc(registrations string) string {
	return `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">` + registrations + `</reginfo>`
}

func reg(contacts string) string {
	return `<registration aor="` + alice + `" id="a" state="active">` + contacts + `</registration>`
}

func TestDocumentsOutsideRFC3680AreRefused(t *testing.T) {
	ok := `<contact id="c" state="active" event="registered"><uri>` + contact + `</uri></contact>`
	for name, text := range map[string]string{
		"DTD":                     `<!DOCTYPE r [<!ENTITY a "b">]>` + doc(""),
		"another root":            `<reginfo xmlns="urn:other" version="1" state="full"/>`,
		"no namespace":            `<reginfo version="1" state="full"/>`,
		"no version":              `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" state="full"/>`,
		"a negative version":      `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="-1" state="full"/>`,
		"a 33-bit version":        `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="4294967296" state="full"/>`,
		"no state":                `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1"/>`,
		"a padded state":          `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state=" full"/>`,
		"no aor":                  doc(`<registration id="a" state="active"/>`),
		"an aor not a URI":        doc(`<registration aor="alice" id="a" state="active"/>`),
		"an http aor":             doc(`<registration aor="http://example.com/" id="a" state="active"/>`),
		"no registration id":      doc(`<registration aor="` + alice + `" state="active"/>`),
		"a registration state":    doc(`<registration aor="` + alice + `" id="a" state="gone"/>`),
		"a repeated registration": doc(reg("") + reg("")),
		"no contact id":           doc(reg(`<contact state="active" event="registered"><uri>` + contact + `</uri></contact>`)),
		"a contact state":         doc(reg(`<contact id="c" state="init" event="registered"><uri>` + contact + `</uri></contact>`)),
		"an event":                doc(reg(`<contact id="c" state="active" event="moved"><uri>` + contact + `</uri></contact>`)),
		"no uri":                  doc(reg(`<contact id="c" state="active" event="registered"/>`)),
		"two uris":                doc(reg(`<contact id="c" state="active" event="registered"><uri>` + contact + `</uri><uri>` + contact + `</uri></contact>`)),
		"a contact not a URI":     doc(reg(`<contact id="c" state="active" event="registered"><uri>x</uri></contact>`)),
		"a repeated contact":      doc(reg(ok + ok)),
		"shortened, no expires":   doc(reg(`<contact id="c" state="active" event="shortened"><uri>` + contact + `</uri></contact>`)),
		"probation, no retry":     doc(reg(`<contact id="c" state="terminated" event="probation"><uri>` + contact + `</uri></contact>`)),
		"expires not a number":    doc(reg(`<contact id="c" state="active" event="registered" expires="soon"><uri>` + contact + `</uri></contact>`)),
		"two display names":       doc(reg(`<contact id="c" state="active" event="registered"><uri>` + contact + `</uri><display-name>a</display-name><display-name>b</display-name></contact>`)),
		"an unnamed param":        doc(reg(`<contact id="c" state="active" event="registered"><uri>` + contact + `</uri><unknown-param>x</unknown-param></contact>`)),
		"an empty param name":     doc(reg(`<contact id="c" state="active" event="registered"><uri>` + contact + `</uri><unknown-param name="">x</unknown-param></contact>`)),
		"a repeated attribute":    `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" version="2" state="full"/>`,
		"two roots":               doc("") + doc(""),
		"text outside":            doc("") + "x",
		"syntax":                  doc("<registration"),
		"too large":               doc(strings.Repeat(" ", MaxDocumentSize)),
		"too deep":                doc(reg(strings.Repeat("<x:a xmlns:x='urn:x'>", maxDepth) + strings.Repeat("</x:a>", maxDepth))),
		"too many registrations":  doc(manyRegistrations(maxRegistrations + 1)),
		"too many contacts":       doc(reg(manyContacts(maxContacts + 1))),
	} {
		if _, err := Parse([]byte(text)); !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrDTD) && !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Parse([]byte(doc(manyRegistrations(maxRegistrations)))); err != nil {
		t.Errorf("at the limit of registrations: %v", err)
	}
}

func manyRegistrations(n int) string {
	var b strings.Builder
	for i := range n {
		b.WriteString(`<registration aor="` + alice + `" id="r` + itoa(i) + `" state="active"/>`)
	}
	return b.String()
}

func manyContacts(n int) string {
	var b strings.Builder
	for i := range n {
		b.WriteString(`<contact id="c` + itoa(i) + `" state="active" event="registered"><uri>` + contact + `</uri></contact>`)
	}
	return b.String()
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}

// Marshal refuses what Parse would, so a notifier cannot send a document a
// subscriber must reject.
func TestMarshalRefusesWhatParseWould(t *testing.T) {
	good := Contact{ID: "c", State: ContactActive, Event: Registered, URI: contact}
	for name, info := range map[string]*Info{
		"a state":            {State: "none"},
		"an aor":             {State: Full, Registrations: []Registration{{AOR: "alice", ID: "a", State: Active}}},
		"a repeated id":      {State: Full, Registrations: []Registration{{AOR: alice, ID: "a", State: Active}, {AOR: aliceTel, ID: "a", State: Active}}},
		"an event":           {State: Full, Registrations: []Registration{{AOR: alice, ID: "a", State: Active, Contacts: []Contact{{ID: "c", State: ContactActive, Event: "x", URI: contact}}}}},
		"shortened":          {State: Full, Registrations: []Registration{{AOR: alice, ID: "a", State: Active, Contacts: []Contact{{ID: "c", State: ContactActive, Event: Shortened, URI: contact}}}}},
		"a control in text":  {State: Full, Registrations: []Registration{{AOR: alice, ID: "a", State: Active, Contacts: []Contact{{ID: "c", State: ContactActive, Event: Registered, URI: contact, DisplayName: "a\x00b"}}}}},
		"a repeated contact": {State: Full, Registrations: []Registration{{AOR: alice, ID: "a", State: Active, Contacts: []Contact{good, good}}}},
		"too many registrations": {State: Full, Registrations: func() []Registration {
			var regs []Registration
			for i := range maxRegistrations + 1 {
				regs = append(regs, Registration{AOR: alice, ID: itoa(i), State: Active})
			}
			return regs
		}()},
		"too many contacts": {State: Full, Registrations: []Registration{{AOR: alice, ID: "a", State: Active, Contacts: func() []Contact {
			var cs []Contact
			for i := range maxContacts + 1 {
				c := good
				c.ID = itoa(i)
				cs = append(cs, c)
			}
			return cs
		}()}}},
	} {
		if _, err := info.Marshal(); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
