package sip

import (
	"errors"
	"reflect"
	"testing"
)

func sipURI(user, host string, params ...Param) URI {
	return URI{Scheme: "sip", User: user, Host: host, Params: params}
}

func TestParseAddressReadsBothForms(t *testing.T) {
	tests := []struct {
		in   string
		want Address
	}{
		{"sip:alice@example.com", Address{URI: sipURI("alice", "example.com")}},
		{"sip:alice@example.com;tag=88sja8x", Address{URI: sipURI("alice", "example.com"), Params: Params{{Name: "tag", Value: "88sja8x"}}}},
		{"<sip:alice@example.com;transport=tcp>;tag=1", Address{
			URI:    sipURI("alice", "example.com", Param{Name: "transport", Value: "tcp"}),
			Params: Params{{Name: "tag", Value: "1"}}}},
		{`"Alice \"A\" Liddell" <sip:alice@example.com>`, Address{DisplayName: `Alice "A" Liddell`, URI: sipURI("alice", "example.com")}},
		{`""<sip:alice@example.com>`, Address{URI: sipURI("alice", "example.com")}},
		{"Alice   Liddell <sip:alice@example.com>", Address{DisplayName: "Alice Liddell", URI: sipURI("alice", "example.com")}},
		// RFC 4475 §3.1.1.6: no LWS between display name and "<".
		{"caller<sip:caller@example.com>;tag=323", Address{DisplayName: "caller", URI: sipURI("caller", "example.com"), Params: Params{{Name: "tag", Value: "323"}}}},
		{"<tel:+15550100001>", Address{URI: URI{Scheme: "tel", User: "+15550100001"}}},
		// In an addr-spec the ";" starts header parameters, even after a tel number.
		{"tel:+15550100001;x=1", Address{URI: URI{Scheme: "tel", User: "+15550100001"}, Params: Params{{Name: "x", Value: "1"}}}},
		{"<urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>", Address{URI: URI{Scheme: "urn", Opaque: "uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6"}}},
		// A quoted parameter may contain "<" without making the address a name-addr.
		{`sip:a@example.com;+sip.instance="<urn:uuid:1>"`, Address{URI: sipURI("a", "example.com"), Params: Params{{Name: "+sip.instance", Value: "<urn:uuid:1>", Quoted: true}}}},
		{"  <sip:a@example.com>  ;  tag  =  x  ", Address{URI: sipURI("a", "example.com"), Params: Params{{Name: "tag", Value: "x"}}}},
	}
	for _, tt := range tests {
		got, err := ParseAddress(tt.in)
		if err != nil {
			t.Errorf("ParseAddress(%q): %v", tt.in, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ParseAddress(%q) = %#v, want %#v", tt.in, got, tt.want)
		}
	}
}

func TestMalformedAddressesAreRejected(t *testing.T) {
	for _, in := range []string{
		"",
		"   ",
		`"unterminated <sip:a@example.com>`,
		`"Alice" sip:a@example.com`,
		`"Alice"`,
		"<sip:a@example.com",
		"< sip:a@example.com>",
		"<sip:a@example.com >",
		"<>",
		"Bell, Alexander <sip:a.g.bell@example.com>",
		"sip:a@example.com?Route=%3Csip:example.com%3E",
		"<sip:a@example.com> junk",
		"<sip:a@example.com>;",
		"<sip:a@example.com>;;tag=1",
		"<sip:a@example.com>;tag=1;tag=2",
		"<sip:a@example.com>;tag=",
		`<sip:a@example.com>;x="unterminated`,
		// qdtext has no control characters; only a quoted-pair may carry one.
		"\"a\x00b\" <sip:a@example.com>",
		"\"a\x7fb\" <sip:a@example.com>",
		"\"a\x1bb\" <sip:a@example.com>",
		"<sip:a@example.com>;x=a b",
		"sip:a b@example.com",
		"not a uri",
	} {
		if _, err := ParseAddress(in); !errors.Is(err, ErrMalformed) {
			t.Errorf("ParseAddress(%q) error = %v, want ErrMalformed", in, err)
		}
	}
}

func TestAddressStringRoundTrips(t *testing.T) {
	for _, in := range []string{
		"sip:alice@example.com;tag=1",
		`"Alice \\ \"A\"" <sip:alice@example.com;lr>;tag=1;x="a b"`,
		`"BEL:` + "\\\x07" + ` NUL:` + "\\\x00" + ` DEL:` + "\\\x7f" + `" <sip:a@example.com>`,
		"Name <tel:+15550100001;phone-context=example.com>",
		"<sip:a@example.com>;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"",
	} {
		a, err := ParseAddress(in)
		if err != nil {
			t.Fatalf("ParseAddress(%q): %v", in, err)
		}
		b, err := ParseAddress(a.String())
		if err != nil {
			t.Fatalf("reparse of %q: %v", a.String(), err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%q: round trip %#v != %#v", in, a, b)
		}
	}
	a := Address{DisplayName: "Bob", URI: sipURI("bob", "example.com"), Params: Params{{Name: "tag", Value: "abc"}}}
	if got, want := a.String(), `"Bob" <sip:bob@example.com>;tag=abc`; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if a.Tag() != "abc" || (Address{}).Tag() != "" {
		t.Error("Tag()")
	}
}

func TestContactReadsIMSParameters(t *testing.T) {
	var h Header
	mustAdd(t, &h, "Contact", `<sip:+15550100001@192.0.2.10:5060;transport=tcp>;expires=600;q=0.5;+sip.instance="<urn:uuid:00000000-0000-1000-8000-000000000001>";reg-id=1;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session";+g.oma.sip-im`)
	mustAdd(t, &h, "m", "sip:second@example.com;q=1")
	cs, err := h.Contact()
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 2 {
		t.Fatalf("got %d contacts", len(cs))
	}
	c := cs[0]
	if e, ok, err := c.Expires(); !ok || e != 600 || err != nil {
		t.Errorf("Expires() = %d, %v, %v", e, ok, err)
	}
	if q, ok, err := c.Q(); !ok || q != 500 || err != nil {
		t.Errorf("Q() = %d, %v, %v", q, ok, err)
	}
	if inst, ok := c.Instance(); !ok || inst != "<urn:uuid:00000000-0000-1000-8000-000000000001>" {
		t.Errorf("Instance() = %q, %v", inst, ok)
	}
	if id, ok, err := c.RegID(); !ok || id != 1 || err != nil {
		t.Errorf("RegID() = %d, %v, %v", id, ok, err)
	}
	if v, ok := c.Params.Get("+g.3gpp.icsi-ref"); !ok || v != "urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session" {
		t.Errorf("icsi-ref = %q, %v", v, ok)
	}
	if !c.Params.Has("+g.oma.sip-im") {
		t.Error("feature flag missing")
	}
	if q, ok, err := cs[1].Q(); !ok || q != 1000 || err != nil {
		t.Errorf("second Q() = %d, %v, %v", q, ok, err)
	}
	if _, ok, err := cs[1].Expires(); ok || err != nil {
		t.Errorf("second contact has expires: %v", err)
	}
	if _, ok, err := cs[1].RegID(); ok || err != nil {
		t.Errorf("second contact has reg-id: %v", err)
	}
	if _, ok := cs[1].Instance(); ok {
		t.Error("second contact has an instance")
	}
	// The feature tag stays quoted when written back.
	again, err := ParseContacts(c.String())
	if err != nil || !reflect.DeepEqual(again[0], c) {
		t.Errorf("round trip: %v %#v", err, again)
	}
}

func TestContactStarStandsAlone(t *testing.T) {
	var h Header
	mustAdd(t, &h, "Contact", " * ")
	cs, err := h.Contact()
	if err != nil || len(cs) != 1 || !cs[0].Star || cs[0].String() != "*" {
		t.Fatalf("Contact() = %#v, %v", cs, err)
	}
	for _, v := range []string{"*, <sip:a@example.com>", "<sip:a@example.com>, *", "*;expires=0"} {
		if _, err := ParseContacts(v); !errors.Is(err, ErrMalformed) {
			t.Errorf("ParseContacts(%q) = %v, want ErrMalformed", v, err)
		}
	}
	var none Header
	if cs, err := none.Contact(); cs != nil || err != nil {
		t.Errorf("absent Contact = %v, %v", cs, err)
	}
}

func TestMalformedContactParametersFailOnlyTheirAccessor(t *testing.T) {
	tests := []struct {
		param string
		get   func(c Contact) (bool, error)
	}{
		{"expires=4294967296", func(c Contact) (bool, error) { _, ok, err := c.Expires(); return ok, err }},
		{"expires=-1", func(c Contact) (bool, error) { _, ok, err := c.Expires(); return ok, err }},
		{"q=1.5", func(c Contact) (bool, error) { _, ok, err := c.Q(); return ok, err }},
		{"q=1.001", func(c Contact) (bool, error) { _, ok, err := c.Q(); return ok, err }},
		{"q=0.1234", func(c Contact) (bool, error) { _, ok, err := c.Q(); return ok, err }},
		{"q=2", func(c Contact) (bool, error) { _, ok, err := c.Q(); return ok, err }},
		{"q=.5", func(c Contact) (bool, error) { _, ok, err := c.Q(); return ok, err }},
		{"q=0.x", func(c Contact) (bool, error) { _, ok, err := c.Q(); return ok, err }},
		{"reg-id=0", func(c Contact) (bool, error) { _, ok, err := c.RegID(); return ok, err }},
		{"reg-id=2147483648", func(c Contact) (bool, error) { _, ok, err := c.RegID(); return ok, err }},
		{"reg-id=x", func(c Contact) (bool, error) { _, ok, err := c.RegID(); return ok, err }},
	}
	for _, tt := range tests {
		// The other contact and the rest of this one stay readable, so a registrar
		// can apply its default (RFC 3261 §10.2.1).
		cs, err := ParseContacts("<sip:a@example.com>;" + tt.param + ", <sip:b@example.com>")
		if err != nil || len(cs) != 2 || cs[0].URI.User != "a" {
			t.Fatalf("%s: ParseContacts = %#v, %v", tt.param, cs, err)
		}
		present, err := tt.get(cs[0])
		var pe *ParseError
		if !present || !errors.As(err, &pe) || pe.Header != "Contact" || !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: accessor = %v, %v, want a malformed Contact", tt.param, present, err)
		}
	}
	for _, v := range []string{
		"<sip:a@example.com>;;",
		"<sip:a@example.com>;q=0,5",
		"Bell, Alexander <sip:a@example.com>",
	} {
		var h Header
		mustAdd(t, &h, "Contact", v)
		_, err := h.Contact()
		var pe *ParseError
		if !errors.As(err, &pe) || pe.Header != "Contact" || !errors.Is(err, ErrMalformed) {
			t.Errorf("Contact %q: error = %v, want a malformed Contact", v, err)
		}
	}
	for _, q := range []struct {
		in   string
		want int
	}{{"0", 0}, {"1", 1000}, {"0.", 0}, {"0.7", 700}, {"0.25", 250}, {"0.125", 125}, {"1.000", 1000}} {
		if got, ok := parseQValue(q.in); !ok || got != q.want {
			t.Errorf("parseQValue(%q) = %d, %v", q.in, got, ok)
		}
	}
	if _, ok := parseQValue("1.0000"); ok {
		t.Error("four decimals accepted")
	}
}

func TestFromAndToAreSingleAddresses(t *testing.T) {
	m := mustParse(t, basicInvite)
	from, err := m.Headers().From()
	if err != nil || from.DisplayName != "Alice" || from.Tag() != "9fxced76sl" {
		t.Errorf("From() = %#v, %v", from, err)
	}
	to, err := m.Headers().To()
	if err != nil || to.URI.User != "bob" || to.Tag() != "" {
		t.Errorf("To() = %#v, %v", to, err)
	}
	var h Header
	if _, err := h.From(); !errors.Is(err, ErrMissingHeader) {
		t.Errorf("absent From: %v", err)
	}
}

func TestRouteSetsRequireNameAddrs(t *testing.T) {
	var h Header
	mustAdd(t, &h, "Route", "<sip:p1.example.com;lr>, <sip:p2.example.com;lr;x=1>")
	mustAdd(t, &h, "Record-Route", "<sip:p1.example.com;lr>")
	mustAdd(t, &h, "Path", "<sip:term@pcscf.example.com;lr;ob>")
	mustAdd(t, &h, "Service-Route", "<sip:orig@scscf.example.com;lr>")
	mustAdd(t, &h, "P-Associated-URI", "<sip:+15550100001@ims.example.net>, <tel:+15550100001>")
	for name, get := range map[string]func() ([]Address, error){
		"Route": h.Route, "Record-Route": h.RecordRoute, "Path": h.Path,
		"Service-Route": h.ServiceRoute, "P-Associated-URI": h.PAssociatedURI,
	} {
		as, err := get()
		if err != nil || len(as) == 0 {
			t.Errorf("%s: %v, %v", name, as, err)
			continue
		}
		if name != "P-Associated-URI" {
			if _, lr := as[0].URI.Param("lr"); !lr {
				t.Errorf("%s: lr missing", name)
			}
		}
	}
	routes, _ := h.Route()
	if len(routes) != 2 || routes[1].URI.Host != "p2.example.com" {
		t.Errorf("Route() = %#v", routes)
	}

	var bad Header
	mustAdd(t, &bad, "Route", "sip:p1.example.com;lr")
	if _, err := bad.Route(); !errors.Is(err, ErrMalformed) {
		t.Errorf("addr-spec Route: %v", err)
	}
	var none Header
	if as, err := none.Route(); as != nil || err != nil {
		t.Errorf("absent Route = %v, %v", as, err)
	}
}

func TestIdentityHeadersParse(t *testing.T) {
	var h Header
	mustAdd(t, &h, "P-Asserted-Identity", `"Alice" <sip:+15550100001@ims.example.net;user=phone>, tel:+15550100001`)
	mustAdd(t, &h, "P-Preferred-Identity", "<sip:alice@ims.example.net>")
	mustAdd(t, &h, "P-Called-Party-ID", "<sip:+15550100002@ims.example.net;user=phone>")
	pai, err := h.PAssertedIdentity()
	if err != nil || len(pai) != 2 {
		t.Fatalf("PAssertedIdentity() = %v, %v", pai, err)
	}
	k1, _ := pai[0].URI.E164()
	k2, _ := pai[1].URI.E164()
	if k1 != "+15550100001" || k1 != k2 {
		t.Errorf("E.164 keys %q and %q", k1, k2)
	}
	ppi, err := h.PPreferredIdentity()
	if err != nil || len(ppi) != 1 || ppi[0].URI.User != "alice" {
		t.Errorf("PPreferredIdentity() = %v, %v", ppi, err)
	}
	cpi, err := h.PCalledPartyID()
	if err != nil || cpi.URI.User != "+15550100002" {
		t.Errorf("PCalledPartyID() = %v, %v", cpi, err)
	}
	var bad Header
	mustAdd(t, &bad, "P-Called-Party-ID", "sip:+15550100002@ims.example.net")
	if _, err := bad.PCalledPartyID(); !errors.Is(err, ErrMalformed) {
		t.Errorf("addr-spec P-Called-Party-ID: %v", err)
	}
}
