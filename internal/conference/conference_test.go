package conference

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

const (
	chat  = "sip:chat-1@ims.mnc001.mcc001.3gppnetwork.org"
	alice = "sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org"
	bob   = "sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org"
	carol = "sip:+15550100003@ims.mnc001.mcc001.3gppnetwork.org"
	dave  = "tel:+15550100004"
)

// fullDoc is a group chat roster in the shape a focus sends first.
const fullDoc = `<?xml version="1.0" encoding="UTF-8"?>
<conference-info xmlns="urn:ietf:params:xml:ns:conference-info"
    entity="` + chat + `" state="full" version="1">
  <conference-description>
    <display-text>Weekend plans</display-text>
    <subject>Hiking &amp; dinner</subject>
  </conference-description>
  <users>
    <user entity="` + alice + `" state="full">
      <display-text>Alice</display-text>
      <roles><entry>chairman</entry><entry>participant</entry></roles>
      <endpoint entity="alice-phone" state="full">
        <display-text>Alice's phone</display-text>
        <status>connected</status>
        <joining-method>dialed-in</joining-method>
      </endpoint>
    </user>
    <user entity="` + bob + `">
      <display-text>Bob</display-text>
      <roles><entry>participant</entry></roles>
      <endpoint entity="bob-phone">
        <status>disconnected</status>
        <joining-method>dialed-out</joining-method>
        <disconnection-method>booted</disconnection-method>
      </endpoint>
    </user>
    <user entity="` + carol + `" state="full">
      <endpoint entity="carol-phone"><status>pending</status></endpoint>
    </user>
  </users>
</conference-info>`

func fullInfo() *Info {
	return &Info{
		Entity:      chat,
		State:       Full,
		Version:     1,
		Description: &Description{DisplayText: "Weekend plans", Subject: "Hiking & dinner"},
		Users: &Users{State: Full, List: []User{
			{Entity: alice, State: Full, DisplayText: "Alice", Roles: []string{"chairman", "participant"}, Endpoints: []Endpoint{
				{Entity: "alice-phone", State: Full, DisplayText: "Alice's phone", Status: Connected, JoiningMethod: DialedIn},
			}},
			{Entity: bob, State: Full, DisplayText: "Bob", Roles: []string{"participant"}, Endpoints: []Endpoint{
				{Entity: "bob-phone", State: Full, Status: Disconnected, JoiningMethod: DialedOut, DisconnectionMethod: Booted},
			}},
			{Entity: carol, State: Full, Endpoints: []Endpoint{{Entity: "carol-phone", State: Full, Status: Pending}}},
		}},
	}
}

func mustParse(t *testing.T, doc string) *Info {
	t.Helper()
	c, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return c
}

func TestParseReadsEveryModelledElement(t *testing.T) {
	got := mustParse(t, fullDoc)
	if want := fullInfo(); !reflect.DeepEqual(got, want) {
		t.Errorf("Parse() =\n%+v\nwant\n%+v", got, want)
	}
}

func TestMarshalWritesSchemaOrderWithExplicitStates(t *testing.T) {
	c := &Info{
		Entity:      chat,
		Version:     7,
		Description: &Description{Subject: "a < b"},
		Users: &Users{List: []User{{
			Entity:      alice,
			DisplayText: "Alice",
			Roles:       []string{"participant"},
			Endpoints:   []Endpoint{{Entity: "alice-phone", Status: Connected, DisconnectionMethod: Departed}},
		}}},
	}
	out, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="` + chat + `" state="full" version="7">` +
		`<conference-description><subject>a &lt; b</subject></conference-description>` +
		`<users state="full">` +
		`<user entity="` + alice + `" state="full">` +
		`<display-text>Alice</display-text>` +
		`<roles><entry>participant</entry></roles>` +
		`<endpoint entity="alice-phone" state="full"><status>connected</status><disconnection-method>departed</disconnection-method></endpoint>` +
		`</user></users></conference-info>`
	if string(out) != want {
		t.Errorf("Marshal() =\n%s\nwant\n%s", out, want)
	}
}

func TestDocumentsRoundTrip(t *testing.T) {
	tests := map[string]string{
		"full roster": fullDoc,
		"partial update": `<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="` + chat + `" state="partial" version="2">
  <users state="partial">
    <user entity="` + alice + `" state="partial"><endpoint entity="alice-phone" state="partial"><status>disconnected</status></endpoint></user>
    <user entity="` + bob + `" state="deleted"/>
    <user entity="` + dave + `" state="full"><display-text>Dave</display-text></user>
  </users>
</conference-info>`,
		"description only":   `<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="` + chat + `" state="partial" version="3"><conference-description/></conference-info>`,
		"deleted conference": `<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="` + chat + `" state="deleted" version="4"/>`,
		"empty roster":       `<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="` + chat + `" version="4294967295"><conference-description/><users/></conference-info>`,
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			c := mustParse(t, doc)
			out, err := c.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if back := mustParse(t, string(out)); !reflect.DeepEqual(back, c) {
				t.Errorf("round trip changed the document:\n%+v\n%+v", c, back)
			}
		})
	}
}

func TestAMissingStateAttributeMeansFull(t *testing.T) {
	c := mustParse(t, `<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="`+chat+`" version="1">
<conference-description/><users><user entity="`+alice+`"><endpoint entity="e"/></user></users></conference-info>`)
	if c.State != Full || c.Users.State != Full || c.Users.List[0].State != Full || c.Users.List[0].Endpoints[0].State != Full {
		t.Errorf("states = %+v", c)
	}
}

func TestDocumentTypeDeclarationsAreRejected(t *testing.T) {
	tests := map[string]string{
		"plain DOCTYPE": `<!DOCTYPE conference-info>` + fullDoc[strings.Index(fullDoc, "<conference-info"):],
		"external entity": `<?xml version="1.0"?><!DOCTYPE c [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="` + chat + `" version="1"><conference-description><subject>&x;</subject></conference-description><users/></conference-info>`,
		"entity expansion": `<!DOCTYPE c [<!ENTITY a "aaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]>
<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="&b;" version="1"/>`,
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); !errors.Is(err, ErrDTD) {
				t.Errorf("Parse() error = %v, want ErrDTD", err)
			}
		})
	}
}

func root(attrs, inner string) string {
	return `<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="` + chat + `" ` + attrs + `>` + inner + `</conference-info>`
}

func partial(inner string) string {
	return root(`state="partial" version="2"`, inner)
}

func TestMalformedDocumentsAreRejected(t *testing.T) {
	const desc = `<conference-description/>`
	tests := map[string]string{
		"not XML":                      "roster",
		"empty":                        "",
		"wrong namespace":              `<conference-info xmlns="urn:example:other" entity="` + chat + `" version="1"/>`,
		"wrong root":                   `<conference xmlns="urn:ietf:params:xml:ns:conference-info" entity="` + chat + `" version="1"/>`,
		"two roots":                    partial("") + partial(""),
		"text outside the root":        partial("") + "x",
		"undefined entity":             partial(`<conference-description><subject>&x;</subject></conference-description>`),
		"repeated attribute":           `<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="` + chat + `" version="1" version="2"/>`,
		"nested too deep":              partial(`<x:e xmlns:x="urn:x">` + strings.Repeat("<x:e>", maxDepth) + strings.Repeat("</x:e>", maxDepth) + `</x:e>`),
		"no entity":                    `<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" version="1" state="partial"/>`,
		"empty entity":                 `<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity=" " version="1" state="partial"/>`,
		"entity with a space":          `<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="sip:a b" version="1" state="partial"/>`,
		"no version":                   root(`state="partial"`, ""),
		"negative version":             root(`state="partial" version="-1"`, ""),
		"version beyond 32 bits":       root(`state="partial" version="4294967296"`, ""),
		"version not a number":         root(`state="partial" version="two"`, ""),
		"unknown state":                root(`state="incremental" version="2"`, ""),
		"state with white space":       root(`state=" partial" version="2"`, ""),
		"full without description":     root(`version="1"`, `<users/>`),
		"full without users":           root(`version="1"`, desc),
		"partial users in full":        root(`version="1"`, desc+`<users state="partial"/>`),
		"partial user in full":         root(`version="1"`, desc+`<users><user entity="`+alice+`" state="partial"/></users>`),
		"deleted endpoint in full":     root(`version="1"`, desc+`<users><user entity="`+alice+`"><endpoint entity="e" state="deleted"/></user></users>`),
		"two descriptions":             partial(desc + desc),
		"two display-texts":            partial(`<conference-description><display-text>a</display-text><display-text>b</display-text></conference-description>`),
		"two subjects":                 partial(`<conference-description><subject>a</subject><subject>b</subject></conference-description>`),
		"two users elements":           partial(`<users state="partial"/><users state="partial"/>`),
		"invalid users state":          partial(`<users state="some"/>`),
		"user without entity":          partial(`<users state="partial"><user state="partial"/></users>`),
		"user entity with a space":     partial(`<users state="partial"><user entity="sip:a b"/></users>`),
		"repeated user":                partial(`<users state="partial"><user entity="` + alice + `"/><user entity="` + alice + `" state="deleted"/></users>`),
		"invalid user state":           partial(`<users state="partial"><user entity="` + alice + `" state="gone"/></users>`),
		"two user display-texts":       partial(`<users state="partial"><user entity="` + alice + `"><display-text>a</display-text><display-text>b</display-text></user></users>`),
		"roles without entries":        partial(`<users state="partial"><user entity="` + alice + `"><roles/></user></users>`),
		"two roles elements":           partial(`<users state="partial"><user entity="` + alice + `"><roles><entry>a</entry></roles><roles><entry>b</entry></roles></user></users>`),
		"endpoint without entity":      partial(`<users state="partial"><user entity="` + alice + `"><endpoint/></user></users>`),
		"repeated endpoint":            partial(`<users state="partial"><user entity="` + alice + `"><endpoint entity="e"/><endpoint entity="e"/></user></users>`),
		"invalid endpoint state":       partial(`<users state="partial"><user entity="` + alice + `" state="partial"><endpoint entity="e" state="x"/></user></users>`),
		"unknown endpoint status":      partial(`<users state="partial"><user entity="` + alice + `"><endpoint entity="e"><status>online</status></endpoint></user></users>`),
		"two endpoint statuses":        partial(`<users state="partial"><user entity="` + alice + `"><endpoint entity="e"><status>pending</status><status>connected</status></endpoint></user></users>`),
		"two endpoint display-texts":   partial(`<users state="partial"><user entity="` + alice + `"><endpoint entity="e"><display-text>a</display-text><display-text>b</display-text></endpoint></user></users>`),
		"unknown joining method":       partial(`<users state="partial"><user entity="` + alice + `"><endpoint entity="e"><joining-method>walked-in</joining-method></endpoint></user></users>`),
		"two joining methods":          partial(`<users state="partial"><user entity="` + alice + `"><endpoint entity="e"><joining-method>dialed-in</joining-method><joining-method>dialed-in</joining-method></endpoint></user></users>`),
		"unknown disconnection method": partial(`<users state="partial"><user entity="` + alice + `"><endpoint entity="e"><disconnection-method>left</disconnection-method></endpoint></user></users>`),
		"two disconnection methods":    partial(`<users state="partial"><user entity="` + alice + `"><endpoint entity="e"><disconnection-method>busy</disconnection-method><disconnection-method>busy</disconnection-method></endpoint></user></users>`),
		"status with white space":      partial(`<users state="partial"><user entity="` + alice + `"><endpoint entity="e"><status> connected</status></endpoint></user></users>`),
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); !errors.Is(err, ErrMalformed) {
				t.Errorf("Parse() error = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestTheContentOfDeletedElementsIsIgnored(t *testing.T) {
	c := mustParse(t, partial(`<users state="partial">
<user entity="`+alice+`" state="deleted"><display-text>Alice</display-text><endpoint entity="e"/></user>
<user entity="`+bob+`" state="partial"><endpoint entity="e" state="deleted"><status>bogus</status></endpoint></user>
</users>`))
	want := []User{
		{Entity: alice, State: Deleted},
		{Entity: bob, State: Partial, Endpoints: []Endpoint{{Entity: "e", State: Deleted}}},
	}
	if !reflect.DeepEqual(c.Users.List, want) {
		t.Errorf("users = %+v", c.Users.List)
	}
	gone := mustParse(t, root(`state="deleted" version="9"`, `<conference-description><subject>x</subject></conference-description><users/>`))
	if gone.Description != nil || gone.Users != nil {
		t.Errorf("deleted conference kept content: %+v", gone)
	}
	emptied := mustParse(t, partial(`<users state="deleted"><user entity="`+alice+`"/></users>`))
	if emptied.Users.State != Deleted || emptied.Users.List != nil {
		t.Errorf("deleted users kept content: %+v", emptied.Users)
	}
}

func TestElementsOutsideTheModelAreSkipped(t *testing.T) {
	c := mustParse(t, `<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" xmlns:x="urn:example:ext" entity="`+chat+`" version="1">
  <conference-description>
    <x:display-text>not this</x:display-text>
    <display-text>Chat</display-text>
    <maximum-user-count>100</maximum-user-count>
  </conference-description>
  <host-info><display-text>Host</display-text></host-info>
  <conference-state><user-count>1</user-count><active>true</active></conference-state>
  <users>
    <user entity="`+alice+`">
      <associated-aors><entry><uri>`+dave+`</uri></entry></associated-aors>
      <endpoint entity="alice-phone">
        <referred><when>2026-10-18T00:30:00Z</when></referred>
        <status>connected</status>
        <joining-info><when>2026-10-18T00:30:00Z</when></joining-info>
        <media id="1"><type>message</type><status>sendrecv</status></media>
        <call-info><sip><call-id>abc</call-id><from-tag>1</from-tag><to-tag>2</to-tag></sip></call-info>
      </endpoint>
      <x:extension/>
    </user>
  </users>
  <sidebars-by-ref/>
</conference-info>`)
	want := &Info{Entity: chat, State: Full, Version: 1, Description: &Description{DisplayText: "Chat"},
		Users: &Users{State: Full, List: []User{{Entity: alice, State: Full, Endpoints: []Endpoint{{Entity: "alice-phone", State: Full, Status: Connected}}}}}}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("Parse() = %+v", c)
	}
}

func TestOversizedDocumentsAreRejectedBeforeDecoding(t *testing.T) {
	doc := partial("<!--" + strings.Repeat("x", MaxDocumentSize) + "-->")
	if _, err := Parse([]byte(doc)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Parse() error = %v, want ErrTooLarge", err)
	}
}

func TestMarshalRejectsWhatParseWouldReject(t *testing.T) {
	tests := map[string]func(c *Info){
		"no entity":                  func(c *Info) { c.Entity = "" },
		"invalid state":              func(c *Info) { c.State = "gone" },
		"full without users":         func(c *Info) { c.Users = nil },
		"full without description":   func(c *Info) { c.Description = nil },
		"deleted with content":       func(c *Info) { c.State = Deleted },
		"description not XML text":   func(c *Info) { c.Description.Subject = "\x00" },
		"partial users in full":      func(c *Info) { c.Users.State = Partial },
		"partial user in full":       func(c *Info) { c.Users.List[0].State = Partial },
		"user without entity":        func(c *Info) { c.Users.List[0].Entity = "" },
		"repeated user":              func(c *Info) { c.Users.List[1].Entity = alice },
		"user display text not text": func(c *Info) { c.Users.List[0].DisplayText = "￾" },
		"role not text":              func(c *Info) { c.Users.List[0].Roles = []string{"\x01"} },
		"endpoint without entity":    func(c *Info) { c.Users.List[0].Endpoints[0].Entity = "" },
		"endpoint display not text":  func(c *Info) { c.Users.List[0].Endpoints[0].DisplayText = "\x02" },
		"repeated endpoint": func(c *Info) {
			c.Users.List[0].Endpoints = append(c.Users.List[0].Endpoints, c.Users.List[0].Endpoints[0])
		},
		"unknown status":       func(c *Info) { c.Users.List[0].Endpoints[0].Status = "online" },
		"unknown joining":      func(c *Info) { c.Users.List[0].Endpoints[0].JoiningMethod = "walked-in" },
		"unknown disconnect":   func(c *Info) { c.Users.List[0].Endpoints[0].DisconnectionMethod = "left" },
		"invalid users state":  func(c *Info) { c.State, c.Users.State = Partial, "x" },
		"deleted users listed": func(c *Info) { c.State, c.Users.State = Partial, Deleted },
		"deleted user with content": func(c *Info) {
			c.State, c.Users.State, c.Users.List[0].State = Partial, Partial, Deleted
		},
		"deleted endpoint with content": func(c *Info) {
			c.State, c.Users.State, c.Users.List[0].State, c.Users.List[0].Endpoints[0].State = Partial, Partial, Partial, Deleted
		},
	}
	for name, breakIt := range tests {
		t.Run(name, func(t *testing.T) {
			c := fullInfo()
			breakIt(c)
			if _, err := c.Marshal(); !errors.Is(err, ErrMalformed) {
				t.Errorf("Marshal() error = %v, want ErrMalformed", err)
			}
		})
	}
	if _, err := fullInfo().Marshal(); err != nil {
		t.Errorf("the unbroken document marshals: %v", err)
	}
}
