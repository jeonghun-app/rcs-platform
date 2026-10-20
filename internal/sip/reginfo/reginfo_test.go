package reginfo

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
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
		{Version: 7, State: Partial, Registrations: []Registration{{AOR: alice, ID: "a", State: Active, Contacts: []Contact{
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
		"DTD":                             `<!DOCTYPE r [<!ENTITY a "b">]>` + doc(""),
		"another root":                    `<reginfo xmlns="urn:other" version="1" state="full"/>`,
		"no namespace":                    `<reginfo version="1" state="full"/>`,
		"no version":                      `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" state="full"/>`,
		"a negative version":              `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="-1" state="full"/>`,
		"a 33-bit version":                `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="4294967296" state="full"/>`,
		"no state":                        `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1"/>`,
		"a padded state":                  `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state=" full"/>`,
		"no aor":                          doc(`<registration id="a" state="active"/>`),
		"an aor not a URI":                doc(`<registration aor="alice" id="a" state="active"/>`),
		"an http aor":                     doc(`<registration aor="http://example.com/" id="a" state="active"/>`),
		"no registration id":              doc(`<registration aor="` + alice + `" state="active"/>`),
		"a registration state":            doc(`<registration aor="` + alice + `" id="a" state="gone"/>`),
		"a repeated registration":         doc(reg("") + reg("")),
		"a repeated aor":                  doc(reg("") + `<registration aor="sip:+15550100001@IMS.mnc001.mcc001.3gppnetwork.org;x=1" id="b" state="terminated"/>`),
		"a repeated tel aor":              doc(`<registration aor="tel:+15550100001" id="a" state="active"/><registration aor="tel:+1-555-010-0001" id="b" state="active"/>`),
		"a negative zero":                 `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="-0" state="full"/>`,
		"a second declaration":            doc("") + `<?xml version="1.0"?>`,
		"a declaration in capitals after": doc("") + `<?XML version="1.0"?>`,
		"a contact out of place":          doc(`<contact id="c" state="active" event="registered"><uri>` + contact + `</uri></contact>`),
		"a uri out of place":              doc(`<registration aor="` + alice + `" id="a" state="active"><uri>` + contact + `</uri></registration>`),
		"an unknown element":              doc(reg(`<foo/>`)),
		"one more contact than the limit": doc(reg(manyContacts(maxContacts + 1))),
		"one level too deep":              doc(reg(`<contact id="c" state="active" event="registered"><uri>` + contact + `</uri>` + nest(maxDepth-3+1) + `</contact>`)),
		"one byte too large":              sized(MaxDocumentSize + 1),
		"a version of NBSP":               "<reginfo xmlns=\"urn:ietf:params:xml:ns:reginfo\" version=\"\u00a05\" state=\"full\"/>",
		"a version of two signs":          `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="++5" state="full"/>`,
		"a negative sign":                 `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="+-5" state="full"/>`,
		"no contact id":                   doc(reg(`<contact state="active" event="registered"><uri>` + contact + `</uri></contact>`)),
		"a contact state":                 doc(reg(`<contact id="c" state="init" event="registered"><uri>` + contact + `</uri></contact>`)),
		"an event":                        doc(reg(`<contact id="c" state="active" event="moved"><uri>` + contact + `</uri></contact>`)),
		"no uri":                          doc(reg(`<contact id="c" state="active" event="registered"/>`)),
		"two uris":                        doc(reg(`<contact id="c" state="active" event="registered"><uri>` + contact + `</uri><uri>` + contact + `</uri></contact>`)),
		"a contact not a URI":             doc(reg(`<contact id="c" state="active" event="registered"><uri>x</uri></contact>`)),
		"a repeated contact":              doc(reg(ok + ok)),
		"shortened, no expires":           doc(reg(`<contact id="c" state="active" event="shortened"><uri>` + contact + `</uri></contact>`)),
		"probation, no retry":             doc(reg(`<contact id="c" state="terminated" event="probation"><uri>` + contact + `</uri></contact>`)),
		"expires not a number":            doc(reg(`<contact id="c" state="active" event="registered" expires="soon"><uri>` + contact + `</uri></contact>`)),
		"two display names":               doc(reg(`<contact id="c" state="active" event="registered"><uri>` + contact + `</uri><display-name>a</display-name><display-name>b</display-name></contact>`)),
		"an unnamed param":                doc(reg(`<contact id="c" state="active" event="registered"><uri>` + contact + `</uri><unknown-param>x</unknown-param></contact>`)),
		"an empty param name":             doc(reg(`<contact id="c" state="active" event="registered"><uri>` + contact + `</uri><unknown-param name="">x</unknown-param></contact>`)),
		"a repeated attribute":            `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" version="2" state="full"/>`,
		"two roots":                       doc("") + doc(""),
		"text outside":                    doc("") + "x",
		"a NUL after the root":            doc("") + "\x00",
		"a tag cut short after":           doc("") + "<",
		"another element after":           doc("") + "<reginfo/>",
		"a DOCTYPE after":                 doc("") + "<!DOCTYPE r>",
		"syntax":                          doc("<registration"),
		"too large":                       doc(strings.Repeat(" ", MaxDocumentSize)),
		"too deep":                        doc(reg(strings.Repeat("<x:a xmlns:x='urn:x'>", maxDepth) + strings.Repeat("</x:a>", maxDepth))),
		"too many registrations":          doc(manyRegistrations(maxRegistrations + 1)),
		"too many contacts":               doc(reg(manyContacts(maxContacts + 1))),
	} {
		if _, err := Parse([]byte(text)); !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrDTD) && !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// XML allows comments and white space after the root (XML 1.0 §2.1).
	if _, err := Parse([]byte(doc("") + "\n<!-- end -->\n")); err != nil {
		t.Errorf("a comment after the root: %v", err)
	}
	for name, text := range map[string]string{
		"contacts at the limit":       doc(reg(manyContacts(maxContacts))),
		"nesting at the limit":        doc(reg(`<contact id="c" state="active" event="registered"><uri>` + contact + `</uri>` + nest(maxDepth-3) + `</contact>`)),
		"the largest document":        sized(MaxDocumentSize),
		"a byte order mark":           "\xef\xbb\xbf" + doc(""),
		"reginfo inside an extension": `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" xmlns:x="urn:x" version="1" state="full"><x:e><registration aor="x" id="x" state="x"/></x:e></reginfo>`,
	} {
		if _, err := Parse([]byte(text)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Parse([]byte(doc(manyRegistrations(maxRegistrations)))); err != nil {
		t.Errorf("at the limit of registrations: %v", err)
	}
}

// nest is n levels of an extension element.
func nest(n int) string {
	return strings.Repeat("<x:a xmlns:x='urn:x'>", n) + strings.Repeat("</x:a>", n)
}

// sized is an empty document padded with white space to n bytes.
func sized(n int) string {
	d := doc("")
	return d + strings.Repeat(" ", n-len(d))
}

func manyRegistrations(n int) string {
	var b strings.Builder
	for i := range n {
		b.WriteString(`<registration aor="sip:user` + itoa(i) + `@ims.mnc001.mcc001.3gppnetwork.org" id="r` + itoa(i) + `" state="active"/>`)
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

func uri(t *testing.T, s string) sip.URI {
	t.Helper()
	u, err := sip.ParseURI(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// A subscriber finds its identity and its contact as URIs, not as text
// (RFC 3261 §19.1.4, RFC 3966 §4): the case of the host, an escaped user
// part, a parameter one side lacks or a tel URI's separators do not hide
// them, and a different transport or port does. Every contact at the URI
// is returned, since one contact URI may be bound more than once (RFC
// 5626 §6).
func TestASubscriberFindsItsRegistrationAndContactAsURIs(t *testing.T) {
	info := &Info{State: Full, Registrations: []Registration{
		{AOR: alice, ID: "a", State: Active, Contacts: []Contact{
			{ID: "c1", State: ContactActive, Event: Registered, URI: contact},
			{ID: "c2", State: ContactTerminated, Event: Deactivated, URI: "sip:alice@192.0.2.10:40000;transport=TCP;reg-id=2"},
			{ID: "c3", State: ContactActive, Event: Registered, URI: "sip:alice@192.0.2.10:40001;transport=tcp"},
		}},
		{AOR: aliceTel, ID: "t", State: Terminated},
	}}
	for _, aor := range []string{
		"sip:+%3155501000%301@IMS.mnc001.mcc001.3gppnetwork.org",
		"sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org;x=1",
		"sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org;user=phone",
		"sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org;transport=tcp",
	} {
		if got, ok := info.ByAOR(uri(t, aor)); !ok || got.ID != "a" {
			t.Errorf("%s: %+v", aor, got)
		}
	}
	if got, ok := info.ByAOR(uri(t, "tel:+1-555-010-0001")); !ok || got.ID != "t" {
		t.Errorf("tel: %+v", got)
	}
	for _, other := range []string{"sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org", "sips:+15550100001@ims.mnc001.mcc001.3gppnetwork.org", "tel:+15550100002"} {
		if got, ok := info.ByAOR(uri(t, other)); ok {
			t.Errorf("%s: %+v", other, got)
		}
	}
	// The identity in the document may carry the parameters, and one with
	// no canonical form, without a user part, compares as a URI.
	withParams := &Info{State: Full, Registrations: []Registration{
		{AOR: alice + ";user=phone", ID: "a", State: Active},
		{AOR: "sip:IMS.mnc001.mcc001.3gppnetwork.org", ID: "h", State: Active},
	}}
	if got, ok := withParams.ByAOR(uri(t, alice)); !ok || got.ID != "a" {
		t.Errorf("an aor with user=phone: %+v", got)
	}
	if got, ok := withParams.ByAOR(uri(t, "sip:ims.mnc001.mcc001.3gppnetwork.org")); !ok || got.ID != "h" {
		t.Errorf("an aor without a user: %+v", got)
	}

	reg := info.Registrations[0]
	var ids []string
	for _, c := range reg.ByURI(uri(t, "sip:alice@192.0.2.10:40000;transport=tcp")) {
		ids = append(ids, c.ID)
	}
	if !reflect.DeepEqual(ids, []string{"c1", "c2"}) {
		t.Errorf("contacts %q", ids)
	}
	for _, other := range []string{"sip:alice@192.0.2.10:40000;transport=tls", "sip:alice@192.0.2.10:40002;transport=tcp", "sip:Alice@192.0.2.10:40000;transport=tcp"} {
		if got := reg.ByURI(uri(t, other)); len(got) != 0 {
			t.Errorf("%s: %+v", other, got)
		}
	}
}

// A sender is held to RFC 3680 §4.7.1 as well: the state and event of a
// contact pair as its state machine has them, an expires is only on an
// active contact, and an active contact only under an active registration.
// A receiver takes such a document, and Active, by its state, decides.
func TestASenderIsStricterThanAReceiver(t *testing.T) {
	for name, tt := range map[string]struct {
		regState RegistrationState
		c        Contact
	}{
		"active, unregistered":    {Active, Contact{ID: "c", State: ContactActive, Event: Unregistered, URI: contact}},
		"terminated, registered":  {Active, Contact{ID: "c", State: ContactTerminated, Event: Registered, URI: contact}},
		"expires, terminated":     {Active, Contact{ID: "c", State: ContactTerminated, Event: Expired, URI: contact, Expires: u64(0)}},
		"active under init":       {Init, Contact{ID: "c", State: ContactActive, Event: Created, URI: contact}},
		"active under terminated": {Terminated, Contact{ID: "c", State: ContactActive, Event: Registered, URI: contact}},
	} {
		info := &Info{State: Full, Registrations: []Registration{{AOR: alice, ID: "a", State: tt.regState, Contacts: []Contact{tt.c}}}}
		if _, err := info.Marshal(); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: Marshal %v", name, err)
		}
	}
	got, err := Parse([]byte(doc(reg(`<contact id="c" state="active" event="expired" expires="+30"><uri>` + contact + `</uri></contact>`))))
	if err != nil {
		t.Fatal(err)
	}
	if c := got.Registrations[0].Contacts[0]; !c.Active() || *c.Expires != 30 {
		t.Errorf("%+v", c)
	}
	got, _ = Parse([]byte(doc(reg(`<contact id="c" state="terminated" event="registered"><uri>` + contact + `</uri></contact>`))))
	if got.Registrations[0].Contacts[0].Active() {
		t.Error("a terminated contact is active")
	}
	// Two registrations of one address-of-record, written two ways.
	two := &Info{State: Full, Registrations: []Registration{
		{AOR: alice, ID: "a", State: Active},
		{AOR: "sip:+15550100001@IMS.mnc001.mcc001.3gppnetwork.org", ID: "b", State: Terminated},
	}}
	if _, err := two.Marshal(); !errors.Is(err, ErrMalformed) {
		t.Errorf("a repeated aor: %v", err)
	}
}

// Param finds an unknown parameter by name without case and unquotes it,
// so +sip.instance reads the same however a notifier writes it.
func TestAParamIsReadWithoutCaseAndUnquoted(t *testing.T) {
	c := Contact{Params: []Param{
		{Name: "+SIP.Instance", Value: `"<urn:uuid:00000000-0000-1000-8000-000000000001>"`},
		{Name: "reg-id", Value: "1"},
		{Name: "flag"},
		{Name: "escaped", Value: `"a\"b\\c"`},
	}}
	for name, want := range map[string]string{
		"+sip.instance": "<urn:uuid:00000000-0000-1000-8000-000000000001>",
		"Reg-ID":        "1",
		"FLAG":          "",
		"escaped":       `a"b\c`,
	} {
		if got, ok := c.Param(name); !ok || got != want {
			t.Errorf("%s: %q, %v", name, got, ok)
		}
	}
	if _, ok := c.Param("expires"); ok {
		t.Error("a parameter that is not there")
	}
	if got := unquote(`"`); got != `"` {
		t.Errorf("a lone quote: %q", got)
	}
}

// docs/architecture.md §8: a parser is linear on a maximum-size adversarial
// input. Times are compared, not bounded, so a loaded host slows both
// alike; the best of three runs smooths out the rest.
func TestMaximumSizeAdversarialDocumentsParseInLinearTime(t *testing.T) {
	for name, build := range map[string]func(n int) string{
		"attributes on the root": func(n int) string {
			var b strings.Builder
			b.WriteString(`<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full"`)
			for i := 0; b.Len() < n-64; i++ {
				b.WriteString(` x` + itoa(i) + `="v"`)
			}
			b.WriteString(`/>`)
			return b.String()
		},
		"unknown params": func(n int) string {
			var b strings.Builder
			b.WriteString(`<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">` + `<registration aor="` + alice + `" id="a" state="active">` +
				`<contact id="c" state="active" event="registered"><uri>` + contact + `</uri>`)
			for b.Len() < n-128 {
				b.WriteString(`<unknown-param name="p">v</unknown-param>`)
			}
			b.WriteString(`</contact></registration></reginfo>`)
			return b.String()
		},
		// Addresses-of-record with no canonical form, each with many
		// parameters: QA of #233 found the duplicate check quadratic.
		"aors with parameters": func(n int) string {
			var b strings.Builder
			b.WriteString(`<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">`)
			params := ""
			for i := range 63 {
				params += ";p" + itoa(i) + "=%41bcdefgh"
			}
			for i := 0; ; i++ {
				r := `<registration aor="sip:u@h.example:5070` + params + `;z=` + itoa(i) + `" id="r` + itoa(i) + `" state="active"/>`
				if b.Len()+len(r) > n-16 || i == maxRegistrations {
					break
				}
				b.WriteString(r)
			}
			b.WriteString(`</reginfo>`)
			return b.String()
		},
		"foreign elements": func(n int) string {
			var b strings.Builder
			b.WriteString(`<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" xmlns:x="urn:x" version="1" state="full">`)
			for b.Len() < n-64 {
				b.WriteString(`<x:e a="1"><x:f/></x:e>`)
			}
			b.WriteString(`</reginfo>`)
			return b.String()
		},
	} {
		t.Run(name, func(t *testing.T) {
			parse := func(text string) time.Duration {
				start := time.Now()
				_, _ = Parse([]byte(text))
				return time.Since(start)
			}
			best := func(n int) time.Duration {
				text := build(n)
				if len(text) > MaxDocumentSize {
					t.Fatalf("input of %d bytes", len(text))
				}
				d := parse(text)
				for range 2 {
					d = min(d, parse(text))
				}
				return d
			}
			// 64 times the input: about 64 times the time if linear, 4096
			// if quadratic; the bound between needs no absolute slack.
			small, large := best(MaxDocumentSize/64), best(MaxDocumentSize)
			if large > 512*small {
				t.Fatalf("64× the input took %v against %v: not linear", large, small)
			}
		})
	}
}

// Values whose white space XML Schema collapses are read trimmed of space,
// tab, CR and LF, and an unsigned integer may carry a "+" (XML Schema Part 2
// §3.3.13); an xml:lang is the one in the XML namespace.
func TestValuesAreReadAsTheSchemaTypesHaveThem(t *testing.T) {
	text := `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" xmlns:x="urn:x" version="` + "\t+5 " + `" state="full">` +
		`<registration aor=" ` + alice + "\n" + `" id="a" state="active">` +
		`<contact id="c" state="active" event="shortened" expires="` + " 30\r\n" + `"><uri> ` + contact + "\t" + `</uri>` +
		`<display-name x:lang="ko">A</display-name></contact>` +
		`<contact id="d" state="active" event="registered"><uri>` + contact + `;x</uri><display-name xml:lang="en">B</display-name></contact>` +
		`</registration></reginfo>`
	got, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	r := got.Registrations[0]
	if got.Version != 5 || r.AOR != alice || r.Contacts[0].URI != contact || *r.Contacts[0].Expires != 30 {
		t.Errorf("%+v", got)
	}
	if r.Contacts[0].Language != "" || r.Contacts[1].Language != "en" {
		t.Errorf("languages %q, %q", r.Contacts[0].Language, r.Contacts[1].Language)
	}
}

// Marshal refuses text XML cannot carry in any field, and a document past
// MaxDocumentSize, which Parse would refuse.
func TestMarshalRefusesTextXMLCannotCarryAndDocumentsTooLarge(t *testing.T) {
	good := Contact{ID: "c", State: ContactActive, Event: Registered, URI: contact}
	for name, c := range map[string]Contact{
		"an id":         {ID: "a\x00", State: ContactActive, Event: Registered, URI: contact},
		"a param value": {ID: "c", State: ContactActive, Event: Registered, URI: contact, Params: []Param{{Name: "p", Value: "\x00"}}},
		"a param name":  {ID: "c", State: ContactActive, Event: Registered, URI: contact, Params: []Param{{Name: "p\x00"}}},
		"a language":    {ID: "c", State: ContactActive, Event: Registered, URI: contact, DisplayName: "a", Language: "\x01"},
		"a call id":     {ID: "c", State: ContactActive, Event: Registered, URI: contact, CallID: "\x02"},
	} {
		info := &Info{State: Full, Registrations: []Registration{{AOR: alice, ID: "a", State: Active, Contacts: []Contact{c}}}}
		if _, err := info.Marshal(); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	big := good
	big.DisplayName = strings.Repeat("x", MaxDocumentSize)
	info := &Info{State: Full, Registrations: []Registration{{AOR: alice, ID: "a", State: Active, Contacts: []Contact{big}}}}
	if _, err := info.Marshal(); !errors.Is(err, ErrTooLarge) {
		t.Errorf("a document too large: %v", err)
	}
}

// The same binding under the sip and tel identities of an implicit set
// has two ids, made from the binding and the AOR (#233): the document is
// written and read back. A writer must keep ids unique in the whole
// document (RFC 3680 §5.1); a reader takes one with an id repeated across
// registrations, and refuses one repeated within a registration.
func TestOneBindingUnderTwoIdentitiesHasTwoIDs(t *testing.T) {
	binding := Contact{ID: "binding-1-sip", State: ContactActive, Event: Registered, URI: contact,
		Params: []Param{{Name: "+sip.instance", Value: `"<urn:uuid:00000000-0000-1000-8000-000000000001>"`}, {Name: "reg-id", Value: "1"}}}
	tel := binding
	tel.ID = "binding-1-tel"
	info := &Info{Version: 3, State: Full, Registrations: []Registration{
		{AOR: alice, ID: "a", State: Active, Contacts: []Contact{binding}},
		{AOR: aliceTel, ID: "t", State: Active, Contacts: []Contact{tel}},
	}}
	out, err := info.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(out)
	if err != nil || !reflect.DeepEqual(back, info) {
		t.Fatalf("%+v, %v", back, err)
	}
	info.Registrations[1].Contacts[0].ID = binding.ID
	if _, err := info.Marshal(); !errors.Is(err, ErrNotWritable) {
		t.Errorf("one id in two registrations, written: %v", err)
	}
	shared := doc(reg(`<contact id="c" state="active" event="registered"><uri>`+contact+`</uri></contact>`) +
		`<registration aor="` + aliceTel + `" id="t" state="active"><contact id="c" state="active" event="registered"><uri>` + contact + `</uri></contact></registration>`)
	if _, err := Parse([]byte(shared)); err != nil {
		t.Errorf("one id in two registrations, read: %v", err)
	}
	twice := doc(reg(`<contact id="c" state="active" event="registered"><uri>` + contact + `</uri></contact><contact id="c" state="active" event="registered"><uri>` + contact + `;x</uri></contact>`))
	if _, err := Parse([]byte(twice)); !errors.Is(err, ErrMalformed) {
		t.Errorf("an id twice in one registration: %v", err)
	}
}

// A contact's parameter names compare without ASCII case alone, and a
// writer may not repeat one.
func TestParamNamesCompareByASCIICase(t *testing.T) {
	c := Contact{Params: []Param{{Name: "+\u017fip.instance", Value: "x"}}}
	if _, ok := c.Param("+sip.instance"); ok {
		t.Error("a Unicode fold matched")
	}
	dup := &Info{State: Full, Registrations: []Registration{{AOR: alice, ID: "a", State: Active, Contacts: []Contact{
		{ID: "c", State: ContactActive, Event: Registered, URI: contact, Params: []Param{{Name: "+sip.instance", Value: "a"}, {Name: "+SIP.INSTANCE", Value: "b"}}}}}}}
	if _, err := dup.Marshal(); !errors.Is(err, ErrNotWritable) {
		t.Errorf("a parameter twice: %v", err)
	}
}

// An address-of-record without a canonical form, one with a port, is
// found by its scheme and host in any case and its parameters in any
// order, and two such spellings are one AOR.
func TestAnAORWithoutACanonicalFormIsFoundAsWritten(t *testing.T) {
	info := &Info{State: Full, Registrations: []Registration{{AOR: "sip:u@h.example:5070;b=2;a=1", ID: "a", State: Active}}}
	if _, ok := info.ByAOR(uri(t, "SIP:u@H.EXAMPLE:5070;a=1;b=2")); !ok {
		t.Error("not found")
	}
	if _, ok := info.ByAOR(uri(t, "sip:u@h.example:5071;a=1;b=2")); ok {
		t.Error("another port found")
	}
	two := doc(`<registration aor="sip:u@h.example:5070;b=2;a=1" id="a" state="active"/><registration aor="sip:u@H.example:5070;a=1;b=2" id="b" state="active"/>`)
	if _, err := Parse([]byte(two)); !errors.Is(err, ErrMalformed) {
		t.Errorf("one AOR twice: %v", err)
	}
}

// Everything inside an extension element is the extension's, reginfo
// elements nested in it at any depth included.
func TestAnExtensionHoldsWhatIsInsideIt(t *testing.T) {
	text := `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" xmlns:x="urn:x" version="1" state="full">` +
		`<x:e><registration aor="x" id="x" state="x"><bogus/><contact/></registration></x:e></reginfo>`
	if _, err := Parse([]byte(text)); err != nil {
		t.Errorf("%v", err)
	}
}

// What Marshal alone refuses is ErrNotWritable, which is ErrMalformed too.
func TestASenderOnlyRefusalIsNotWritable(t *testing.T) {
	info := &Info{State: Full, Registrations: []Registration{{AOR: alice, ID: "a", State: Active, Contacts: []Contact{
		{ID: "c", State: ContactActive, Event: Expired, URI: contact}}}}}
	if _, err := info.Marshal(); !errors.Is(err, ErrNotWritable) || !errors.Is(err, ErrMalformed) {
		t.Errorf("%v", err)
	}
	if _, err := (&Info{State: "x"}).Marshal(); errors.Is(err, ErrNotWritable) {
		t.Errorf("a document Parse refuses too: %v", err)
	}
}
