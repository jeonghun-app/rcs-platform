package sip

import (
	"errors"
	"reflect"
	"strconv"
	"testing"
)

func headerWith(t *testing.T, name string, values ...string) *Header {
	t.Helper()
	var h Header
	for _, v := range values {
		mustAdd(t, &h, name, v)
	}
	return &h
}

func wantMalformed(t *testing.T, name, value string, err error) {
	t.Helper()
	var pe *ParseError
	if !errors.As(err, &pe) || !errors.Is(err, ErrMalformed) || pe.Header != name {
		t.Errorf("%s %q: error = %v, want a malformed %s", name, value, err, name)
	}
}

func TestCSeqParsesNumberAndMethod(t *testing.T) {
	tests := []struct {
		in   string
		want CSeq
	}{
		{"1 INVITE", CSeq{1, "INVITE"}},
		{"0009  \t INVITE", CSeq{9, "INVITE"}},
		{"2147483647 REGISTER", CSeq{1<<31 - 1, "REGISTER"}},
		{"139122385 !interesting-Method0123456789_*+`.%indeed'~", CSeq{139122385, "!interesting-Method0123456789_*+`.%indeed'~"}},
	}
	for _, tt := range tests {
		got, err := headerWith(t, "CSeq", tt.in).CSeq()
		if err != nil || got != tt.want {
			t.Errorf("CSeq %q = %#v, %v", tt.in, got, err)
		}
		if again, err := headerWith(t, "CSeq", got.String()).CSeq(); err != nil || again != got {
			t.Errorf("round trip of %q = %#v, %v", got.String(), again, err)
		}
	}
	for _, in := range []string{"", "1", "INVITE", "1INVITE", "-1 INVITE", "2147483648 INVITE", "36893488147419103232 INVITE", "1 IN VITE", "1 INVITE;x"} {
		_, err := headerWith(t, "CSeq", in).CSeq()
		wantMalformed(t, "CSeq", in, err)
	}
}

func TestScalarHeadersEnforceTheirRanges(t *testing.T) {
	mf, err := headerWith(t, "Max-Forwards", "0068").MaxForwards()
	if err != nil || mf != 68 {
		t.Errorf("Max-Forwards = %d, %v", mf, err)
	}
	for _, in := range []string{"", "256", "300", "-1", "7 0", "x"} {
		_, err := headerWith(t, "Max-Forwards", in).MaxForwards()
		wantMalformed(t, "Max-Forwards", in, err)
	}

	// Max-Breadth: a positive integer (RFC 5393 §5.3.1), held to 2^20.
	for in, want := range map[string]int{"60": 60, "0001": 1, "4294967295": 1 << 20} {
		if mb, err := headerWith(t, "Max-Breadth", in).MaxBreadth(); err != nil || mb != want {
			t.Errorf("Max-Breadth %q = %d, %v, want %d", in, mb, err, want)
		}
	}
	for _, in := range []string{"", "0", "-1", "7 0", "x", "4294967296"} {
		_, err := headerWith(t, "Max-Breadth", in).MaxBreadth()
		wantMalformed(t, "Max-Breadth", in, err)
	}

	ex, err := headerWith(t, "Expires", "4294967295").Expires()
	if err != nil || ex != 1<<32-1 {
		t.Errorf("Expires = %d, %v", ex, err)
	}
	for _, in := range []string{"", "1.5", "Thu, 01 Dec 1994 16:00:00 GMT"} {
		_, err := headerWith(t, "Expires", in).Expires()
		wantMalformed(t, "Expires", in, err)
	}
	for _, in := range []string{"4294967296", "10000000000000000000000"} {
		n, err := headerWith(t, "Expires", in).Expires()
		if n != 1<<32-1 || !errors.Is(err, ErrOutOfRange) {
			t.Errorf("Expires %q = %d, %v, want 2^32-1 and ErrOutOfRange", in, n, err)
		}
	}
	var none Header
	if _, err := none.Expires(); !errors.Is(err, ErrMissingHeader) {
		t.Errorf("absent Expires: %v", err)
	}
	if _, err := headerWith(t, "Expires", "1", "2").Expires(); !errors.Is(err, ErrMalformed) {
		t.Errorf("two Expires: %v", err)
	}

	for _, in := range []string{"f81d4fae-7dec@foo.example.com", "intmeth.word%ZK-!.*_+'@word`~)(><:\\/\"][?}{", "abc"} {
		if id, err := headerWith(t, "i", in).CallID(); err != nil || id != in {
			t.Errorf("Call-ID %q = %q, %v", in, id, err)
		}
	}
	for _, in := range []string{"", "a b", "@host", "a@", "a@b@c", "a;b"} {
		_, err := headerWith(t, "Call-ID", in).CallID()
		wantMalformed(t, "Call-ID", in, err)
	}
}

func TestOptionTagListsSplitOnCommas(t *testing.T) {
	h := headerWith(t, "Supported", "path, outbound,gruu", "timer")
	got, err := h.Supported()
	if err != nil || !reflect.DeepEqual(got, []string{"path", "outbound", "gruu", "timer"}) {
		t.Errorf("Supported() = %q, %v", got, err)
	}
	allow, err := headerWith(t, "Allow", "INVITE, ACK, CANCEL, OPTIONS, BYE, MESSAGE").Allow()
	if err != nil || len(allow) != 6 {
		t.Errorf("Allow() = %q, %v", allow, err)
	}
	// An empty Allow or Supported is valid; an empty Require is not.
	if got, err := headerWith(t, "Allow", "").Allow(); got != nil || err != nil {
		t.Errorf("empty Allow = %q, %v", got, err)
	}
	if got, err := headerWith(t, "k", "").Supported(); got != nil || err != nil {
		t.Errorf("empty Supported = %q, %v", got, err)
	}
	req, err := headerWith(t, "Require", "sec-agree").Require()
	if err != nil || !reflect.DeepEqual(req, []string{"sec-agree"}) {
		t.Errorf("Require() = %q, %v", req, err)
	}
	for _, in := range []string{"", "a,,b", "a b", "<x>"} {
		_, err := headerWith(t, "Require", in).Require()
		wantMalformed(t, "Require", in, err)
	}
}

func TestContentTypeParsesTypeSubtypeAndParameters(t *testing.T) {
	ct, err := headerWith(t, "c", `multipart/mixed ; boundary="unique boundary 1"`).ContentType()
	if err != nil || !ct.Is("Multipart", "MIXED") || ct.Is("multipart", "related") {
		t.Fatalf("ContentType() = %#v, %v", ct, err)
	}
	if b, _ := ct.Params.Get("boundary"); b != "unique boundary 1" {
		t.Errorf("boundary = %q", b)
	}
	if got := ct.String(); got != `multipart/mixed;boundary="unique boundary 1"` {
		t.Errorf("String() = %q", got)
	}
	cpim, err := headerWith(t, "Content-Type", "message / cpim").ContentType()
	if err != nil || cpim.Type != "message" || cpim.Subtype != "cpim" {
		t.Errorf("ContentType() = %#v, %v", cpim, err)
	}
	for _, in := range []string{"", "text", "text/", "/plain", "text/plain;", "text/plain x"} {
		_, err := headerWith(t, "Content-Type", in).ContentType()
		wantMalformed(t, "Content-Type", in, err)
	}
}

func TestIMSChargingAndNetworkHeadersParse(t *testing.T) {
	pcv, err := headerWith(t, "P-Charging-Vector", "icid-value=1234bc9876e;icid-generated-at=192.0.6.8;orig-ioi=home1.example.net").PChargingVector()
	if err != nil || pcv.ICID() != "1234bc9876e" || len(pcv.Params) != 3 {
		t.Fatalf("PChargingVector() = %#v, %v", pcv, err)
	}
	if got := pcv.String(); got != "icid-value=1234bc9876e;icid-generated-at=192.0.6.8;orig-ioi=home1.example.net" {
		t.Errorf("String() = %q", got)
	}
	quoted, err := headerWith(t, "P-Charging-Vector", `icid-value="AyretyU0dm+6O2IrT5tAFrbHLso=" ; term-ioi=x`).PChargingVector()
	if err != nil || quoted.ICID() != "AyretyU0dm+6O2IrT5tAFrbHLso=" {
		t.Errorf("quoted icid = %#v, %v", quoted, err)
	}
	if again, err := headerWith(t, "P-Charging-Vector", quoted.String()).PChargingVector(); err != nil || !reflect.DeepEqual(again, quoted) {
		t.Errorf("round trip = %#v, %v", again, err)
	}
	if (ChargingVector{}).String() != "" {
		t.Error("empty charging vector is not empty")
	}
	for _, in := range []string{"", "orig-ioi=x", "icid-value", "icid-value=", "icid-value=a;icid-value=b", "icid-value=a;", "icid-value=a b"} {
		_, err := headerWith(t, "P-Charging-Vector", in).PChargingVector()
		wantMalformed(t, "P-Charging-Vector", in, err)
	}

	vn, err := headerWith(t, "P-Visited-Network-ID", `other.example.net, "Visited network number 1";x=1`).PVisitedNetworkID()
	want := []VisitedNetwork{{Name: "other.example.net"}, {Name: "Visited network number 1", Quoted: true, Params: Params{{Name: "x", Value: "1"}}}}
	if err != nil || !reflect.DeepEqual(vn, want) {
		t.Fatalf("PVisitedNetworkID() = %#v, %v", vn, err)
	}
	if got := vn[1].String(); got != `"Visited network number 1";x=1` {
		t.Errorf("String() = %q", got)
	}
	if got := (VisitedNetwork{Name: "a b"}).String(); got != `"a b"` {
		t.Errorf("unquoted name with a space: String() = %q", got)
	}
	for _, in := range []string{"", `"unterminated`, "a b", "<x>"} {
		_, err := headerWith(t, "P-Visited-Network-ID", in).PVisitedNetworkID()
		wantMalformed(t, "P-Visited-Network-ID", in, err)
	}
}

func TestAcceptContactCarriesFeaturePreferences(t *testing.T) {
	ac, err := headerWith(t, "a", `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session";require;explicit`, "*;+g.oma.sip-im").AcceptContact()
	if err != nil || len(ac) != 2 {
		t.Fatalf("AcceptContact() = %#v, %v", ac, err)
	}
	if !ac[0].Require() || !ac[0].Explicit() || ac[1].Require() || ac[1].Explicit() {
		t.Error("require/explicit flags")
	}
	if got := ac[0].String(); got != `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session";require;explicit` {
		t.Errorf("String() = %q", got)
	}
	for _, in := range []string{"", "+g.oma.sip-im", "*x", "*;"} {
		_, err := headerWith(t, "Accept-Contact", in).AcceptContact()
		wantMalformed(t, "Accept-Contact", in, err)
	}
}

func TestEventAndSubscriptionStateParse(t *testing.T) {
	ev, err := headerWith(t, "o", "presence.winfo;id=abc").Event()
	if err != nil || ev.Type != "presence.winfo" || ev.ID() != "abc" || ev.String() != "presence.winfo;id=abc" {
		t.Errorf("Event() = %#v, %v", ev, err)
	}
	if (Event{Type: "reg"}).ID() != "" {
		t.Error("ID() of an event without id")
	}
	for _, in := range []string{"", ";id=1", "reg;", "reg x"} {
		_, err := headerWith(t, "Event", in).Event()
		wantMalformed(t, "Event", in, err)
	}

	ss, err := headerWith(t, "Subscription-State", "active;expires=600").SubscriptionState()
	if err != nil || ss.State != "active" || ss.String() != "active;expires=600" {
		t.Fatalf("SubscriptionState() = %#v, %v", ss, err)
	}
	if e, ok := ss.Expires(); !ok || e != 600 {
		t.Errorf("Expires() = %d, %v", e, ok)
	}
	if _, ok := ss.RetryAfter(); ok || ss.Reason() != "" {
		t.Error("unexpected retry-after or reason")
	}
	term, err := headerWith(t, "Subscription-State", "terminated;reason=timeout;retry-after=30").SubscriptionState()
	if r, ok := term.RetryAfter(); err != nil || !ok || r != 30 || term.Reason() != "timeout" {
		t.Errorf("terminated = %#v, %v", term, err)
	}
	for _, in := range []string{"", "active;expires=x", "active;retry-after=-1", "active;expires=4294967296"} {
		_, err := headerWith(t, "Subscription-State", in).SubscriptionState()
		wantMalformed(t, "Subscription-State", in, err)
	}
}

func TestSessionTimerHeadersParse(t *testing.T) {
	se, err := headerWith(t, "x", "1800;refresher=UAC").SessionExpires()
	if err != nil || se.Delta != 1800 || se.Refresher() != "uac" {
		t.Fatalf("SessionExpires() = %#v, %v", se, err)
	}
	if got := se.String(); got != "1800;refresher=UAC" {
		t.Errorf("String() = %q", got)
	}
	plain, err := headerWith(t, "Session-Expires", "90").SessionExpires()
	if err != nil || plain.Refresher() != "" {
		t.Errorf("plain = %#v, %v", plain, err)
	}
	for _, in := range []string{"", "x", "-1", "1800;refresher=proxy", "4294967296", "1800 x"} {
		_, err := headerWith(t, "Session-Expires", in).SessionExpires()
		wantMalformed(t, "Session-Expires", in, err)
	}
	mse, err := headerWith(t, "Min-SE", "90 ;x=y").MinSE()
	if err != nil || mse.Delta != 90 || mse.String() != "90;x=y" {
		t.Errorf("MinSE() = %#v, %v", mse, err)
	}
	for _, in := range []string{"", "ninety", "90;"} {
		_, err := headerWith(t, "Min-SE", in).MinSE()
		wantMalformed(t, "Min-SE", in, err)
	}
}

func TestReasonCarriesProtocolCauseAndText(t *testing.T) {
	rs, err := headerWith(t, "Reason", `SIP ;cause=200 ;text="Call completed elsewhere", Q.850;cause=16;text="Terminated"`).Reason()
	if err != nil || len(rs) != 2 {
		t.Fatalf("Reason() = %#v, %v", rs, err)
	}
	if c, ok := rs[0].Cause(); rs[0].Protocol != "SIP" || !ok || c != 200 || rs[0].Text() != "Call completed elsewhere" {
		t.Errorf("first = %#v", rs[0])
	}
	if c, ok := rs[1].Cause(); rs[1].Protocol != "Q.850" || !ok || c != 16 {
		t.Errorf("second = %#v", rs[1])
	}
	var built Reason
	built.Protocol = "SIP"
	built.Params.Set("cause", "487")
	built.Params.SetQuoted("text", "Cancelled")
	if got := built.String(); got != `SIP;cause=487;text="Cancelled"` {
		t.Errorf("String() = %q", got)
	}
	if _, ok := (Reason{Protocol: "SIP"}).Cause(); ok {
		t.Error("Cause() without cause")
	}
	for _, in := range []string{"", "SIP;cause=abc", `SIP;text="x`, "SIP;cause=1;cause=2", "SIP;cause=99999999999999999999", "SIP;cause=2147483648"} {
		_, err := headerWith(t, "Reason", in).Reason()
		wantMalformed(t, "Reason", in, err)
	}
}

func TestParamsSetChoosesQuoting(t *testing.T) {
	var ps Params
	ps.Set("tag", "abc")
	ps.Set("+sip.instance", "<urn:uuid:1>")
	ps.Set("+g.3gpp.smsip", "x")
	ps.Set("text", "two words")
	ps.Set("empty", "")
	ps.SetFlag("lr")
	want := Params{
		{Name: "tag", Value: "abc"},
		{Name: "+sip.instance", Value: "<urn:uuid:1>", Quoted: true},
		{Name: "+g.3gpp.smsip", Value: "x", Quoted: true},
		{Name: "text", Value: "two words", Quoted: true},
		{Name: "empty", Quoted: true},
		{Name: "lr"},
	}
	if !reflect.DeepEqual(ps, want) {
		t.Fatalf("Params = %#v", ps)
	}
	// Replacing a quoted value keeps the quotes; replacing keeps the position.
	ps.Set("TEXT", "one")
	if ps[3] != (Param{Name: "TEXT", Value: "one", Quoted: true}) {
		t.Errorf("replaced = %#v", ps[3])
	}
	ps.Del("Tag")
	ps.Del("missing")
	if ps.Has("tag") || len(ps) != 5 {
		t.Errorf("Del: %#v", ps)
	}
	if got := string(ps.appendHeaderParams(nil)); got != `;+sip.instance="<urn:uuid:1>";+g.3gpp.smsip="x";TEXT="one";empty="";lr` {
		t.Errorf("written = %q", got)
	}
	// A value that cannot be bare is quoted however the Param was built.
	if got := string(Params{{Name: "x", Value: "a b"}}.appendHeaderParams(nil)); got != `;x="a b"` {
		t.Errorf("written = %q", got)
	}
}

func TestParameterCountIsBounded(t *testing.T) {
	params := func(n int, sep string) string {
		var b []byte
		for i := 0; i < n; i++ {
			if i > 0 {
				b = append(b, sep...)
			}
			b = append(b, 'p')
			b = strconv.AppendInt(b, int64(i), 10)
			b = append(b, "=1"...)
		}
		return string(b)
	}
	for _, n := range []int{maxParams, maxParams + 1} {
		ok := n <= maxParams
		_, err := ParseAddress("<sip:a@example.com>;" + params(n, ";"))
		if (err == nil) != ok {
			t.Errorf("%d header parameters: %v", n, err)
		}
		_, err = ParseURI("sip:a@example.com;" + params(n, ";"))
		if (err == nil) != ok {
			t.Errorf("%d SIP URI parameters: %v", n, err)
		}
		_, err = ParseURI("tel:+15550100001;" + params(n, ";"))
		if (err == nil) != ok {
			t.Errorf("%d tel URI parameters: %v", n, err)
		}
		_, err = ParseURI("sip:a@example.com?" + params(n, "&"))
		if (err == nil) != ok {
			t.Errorf("%d URI headers: %v", n, err)
		}
		_, err = headerWith(t, "Authorization", "Digest "+params(n, ", ")).Authorization()
		if (err == nil) != ok {
			t.Errorf("%d auth-params: %v", n, err)
		}
	}
}
