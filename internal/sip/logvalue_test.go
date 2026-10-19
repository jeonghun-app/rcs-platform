package sip

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestLoggedValuesLeaveOutIdentitiesAndCredentials(t *testing.T) {
	// 192.0.2.1 is the UE's public address in its Contact, 10.20.30.40 its
	// APN address in a second Contact, and fe80::211:22ff:fe33:4455 an
	// EUI-64 link-local Via host carrying the MAC 00:11:22:33:44:55 (#36).
	secrets := []string{"15550100001", "001010000000001", "Alice Secret", "n0nce-value", "r3sponse-value", "cn0nce", "0paque", "s3cret",
		"192.0.2.1", "10.20.30.40", "22ff:fe33", "4455"}
	m := mustParse(t, lines(
		"REGISTER sip:+15550100001@ims.example.net;user=phone SIP/2.0",
		"Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK1",
		"Via: SIP/2.0/UDP [fe80::211:22ff:fe33:4455]:5060;branch=z9hG4bK2;received=192.0.2.1",
		`From: "Alice Secret" <sip:+15550100001@ims.example.net>;tag=1`,
		"To: <tel:+15550100001>",
		"Call-ID: a@b",
		"CSeq: 1 REGISTER",
		`Contact: <sip:001010000000001:s3cret@192.0.2.1>;expires=600, <sip:10.20.30.40:5060>`,
		`Authorization: Digest username="001010000000001@ims.example.net", realm="ims.example.net", nonce="n0nce-value", uri="sip:ims.example.net", response="r3sponse-value", cnonce="cn0nce", algorithm=AKAv1-MD5, qop=auth, nc=00000001`,
		`WWW-Authenticate: Digest realm="ims.example.net", nonce="n0nce-value", opaque="0paque", qop="auth"`,
		"Content-Length: 0",
	))
	req := m.(*Request)
	from, _ := req.Header.From()
	to, _ := req.Header.To()
	cs, _ := req.Header.Contact()
	creds, _ := req.Header.Authorization()
	chs, _ := req.Header.WWWAuthenticate()
	vias, _ := req.Header.Via()
	res := &Response{StatusCode: 200, Reason: "OK", Body: []byte("n0nce-value")}

	var buf bytes.Buffer
	log := untimedJSONLogger(&buf)
	log.Info("x", "req", req, "reqv", *req, "res", res, "resv", *res, "header", req.Header, "headerp", &req.Header, "uri", req.URI, "from", from, "to", to,
		"contact", cs[0], "apn", cs[1], "vias", vias, "star", Contact{Star: true}, "creds", creds[0], "challenge", chs[0], "zero", URI{},
		"urn", URI{Scheme: "urn", Opaque: "uuid:s3cret"})
	out := buf.String()
	if strings.Contains(out, `"time"`) {
		t.Fatalf("the line has a timestamp whose digits could match a secret:\n%s", out)
	}
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("log contains %q:\n%s", s, out)
		}
	}
	for _, want := range []string{
		`"method":"REGISTER"`, `"uri":"sip:***@ims.example.net"`, `"status":200`, `"to":{"uri":"tel:***","tag":""}`,
		`"contact":{"uri":"sip:***@192.0.2.0/24","tag":""}`, `"apn":{"uri":"sip:10.20.30.0/24","tag":""}`,
		`"vias":{"0":{"transport":"TCP","host":"client.example.com","branch":"z9hG4bK1"},"1":{"transport":"UDP","host":"fe80::/48","branch":"z9hG4bK2"}}`,
		`"star":"*"`, `"realm":"ims.example.net"`, `"algorithm":"AKAv1-MD5"`,
		`"zero":""`, `"urn":"urn:***"`, `"body_bytes":11`, `"reqv":{"method":"REGISTER"`, `"resv":{"status":200`,
		`"header":{"fields":10}`, `"headerp":{"fields":10}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %s:\n%s", want, out)
		}
	}
	if got := (URI{Scheme: "sip", Host: "example.com"}).LogValue().String(); got != "sip:example.com" {
		t.Errorf("URI without user logs %q", got)
	}
}

func TestIPHostsAreLoggedAsTheirNetworkOnly(t *testing.T) {
	for host, want := range map[string]string{
		"198.51.100.23":     "198.51.100.0/24",
		"[2001:db8:5:6::9]": "2001:db8:5::/48",
		// Private, loopback and link-local hosts are clients' too.
		"10.0.1.5":                   "10.0.1.0/24",
		"[fd00::5]":                  "fd00::/48",
		"127.0.0.1":                  "127.0.0.0/24",
		"[fe80::211:22ff:fe33:4455]": "fe80::/48",
		// SIP accepts leading zeros (RFC 3261 §25.1); netip does not.
		"192.000.002.001":             "192.0.2.0/24",
		"[2002:c000:201::1]":          "2002::/16",
		"pcscf-1.rcs.internal":        "pcscf-1.rcs.internal",
		"15550100001.ims.example.net": "***01.ims.example.net",
	} {
		if got := (URI{Scheme: "sip", User: "alice", Host: host}).LogValue().String(); got != "sip:***@"+want {
			t.Errorf("URI host %s logs %q, want sip:***@%s", host, got, want)
		}
		// Path, Record-Route and a Contact without a user have no user part.
		if got := (URI{Scheme: "sip", Host: host}).LogValue().String(); got != "sip:"+want {
			t.Errorf("URI host %s without a user logs %q, want sip:%s", host, got, want)
		}
	}
	// A host that looks like an address but does not parse is masked, not
	// kept as a name.
	if got := loggedHost("[not-an-address]"); got != "***" {
		t.Errorf("unreadable bracketed host logs %q", got)
	}
}

// A URI carried as text by another protocol, such as a CPIM From, logs as
// a parsed one does: scheme and host, the user masked, parameters and
// headers left out, and a scheme it cannot read masked whole after the
// scheme (review of #132).
func TestLoggedURIKeepsTheSchemeAndHostOnly(t *testing.T) {
	for in, want := range map[string]string{
		"sip:+15550100001@10.20.30.40":                                             "sip:***@10.20.30.0/24",
		"sip:alice@198.51.100.7:5061;transport=tls":                                "sip:***@198.51.100.0/24",
		"sip:[fe80::0211:22ff:fe33:4455]":                                          "sip:fe80::/48",
		"SIPS:bob@ims.example.net?Subject=Alice%20Secret":                          "sips:***@ims.example.net",
		"sip:bob@ims.example.net;gr=urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6": "sip:***@ims.example.net",
		"tel:+15550100001;phone-context=ims.example.net":                           "tel:***",
		"im:alice.secret@ims.example.net":                                          "im:***@ims.example.net",
		"im:alice@[2001:db8:5:6::7]":                                               "im:***@2001:db8:5::/48",
		"pres:alice@10.20.30.40?subject=x":                                         "pres:***@10.20.30.0/24",
		"im:alice@secret@ims.example.net":                                          "im:***@ims.example.net",
		"im:alice.secret":                                                          "im:***",
		`im:"bob@smith"@ims.example.net`:                                           "im:***",
		"mailto:alice.secret@example.com":                                          "mailto:***",
		"xmpp:alice.secret@example.com":                                            "xmpp:***",
		"http://alice.secret:pw@example.com/":                                      "http:***",
		"urn:gsma:imei:00101000-000003-1":                                          "urn:***",
		"x15550100001:alice":                                                       "x***01:***",
		"sip:":                                                                     "sip:***",
		"not a uri":                                                                "***",
	} {
		if got := LoggedURI(in); got != want {
			t.Errorf("LoggedURI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestViaLogsItsHostLikeAURIAndLeavesOutTheReceivedAddress(t *testing.T) {
	vias := mustParseVias(t, "SIP/2.0/TCP 198.51.100.23:40001;branch=z9hG4bK77;received=198.51.100.23;rport=40001")
	var buf bytes.Buffer
	untimedJSONLogger(&buf).Info("x", "via", vias[0], "all", vias)
	out := buf.String()
	if strings.Contains(out, `"time"`) {
		t.Fatalf("the line has a timestamp whose digits could match a secret:\n%s", out)
	}
	if strings.Contains(out, "198.51.100.23") || strings.Contains(out, "40001") {
		t.Errorf("Via log has the client address: %s", out)
	}
	if !strings.Contains(out, `"via":{"transport":"TCP","host":"198.51.100.0/24","branch":"z9hG4bK77"}`) ||
		!strings.Contains(out, `"all":{"0":{"transport":"TCP","host":"198.51.100.0/24","branch":"z9hG4bK77"}}`) {
		t.Errorf("Via log = %s", out)
	}
}

func mustParseVias(t *testing.T, s string) Vias {
	t.Helper()
	vias, err := ParseVia(s)
	if err != nil {
		t.Fatal(err)
	}
	return vias
}

// slog does not apply LogValue to a slice's elements, so the lists the
// accessors return must log each element through it (#95). Only the
// attributes are searched, not the line's time.
func TestWholeHeaderListsLogTheirElementsRedacted(t *testing.T) {
	m := mustParse(t, lines(
		"INVITE sip:bob@ims.example.net SIP/2.0",
		"Via: SIP/2.0/TCP 198.51.100.7:5060;branch=z9hG4bK1",
		"From: <sip:alice@ims.example.net>;tag=1",
		"To: <sip:bob@ims.example.net>",
		"Call-ID: a@b",
		"CSeq: 1 INVITE",
		`Contact: "Alice Secret" <sip:+15550100001@198.51.100.7:5060;transport=tcp>;+sip.instance="<urn:gsma:imei:00101000-000003-1>", <sip:001010000000001@10.20.30.40>`,
		"Route: <sip:pcscf-1.rcs.internal;lr>, <sip:+15550100002@198.51.100.9;lr>",
		"Record-Route: <sip:scscf.rcs.internal;lr;secretparam=r0ute>",
		"Path: <sip:term@pcscf-1.rcs.internal;lr;ob>",
		"P-Asserted-Identity: <tel:+15550100001>",
		`Authorization: Digest username="001010000000001@ims.example.net", realm="ims.example.net", nonce="n0nce-value", uri="sip:ims.example.net", response="r3sponse-value"`,
		`WWW-Authenticate: Digest realm="ims.example.net", nonce="n0nce-value", opaque="0paque"`,
		"Content-Length: 0",
	))
	h := &m.(*Request).Header
	contacts, err1 := h.Contact()
	route, err2 := h.Route()
	rr, err3 := h.RecordRoute()
	path, err4 := h.Path()
	pai, err5 := h.PAssertedIdentity()
	creds, err6 := h.Authorization()
	chs, err7 := h.WWWAuthenticate()
	parsed, err8 := ParseContacts("<sip:+15550100003@192.0.2.44>;expires=600")
	if err := errors.Join(err1, err2, err3, err4, err5, err6, err7, err8); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	untimedJSONLogger(&buf).Info("x", "contacts", contacts, "route", route, "rr", rr, "path", path, "pai", pai,
		"creds", creds, "challenges", chs, "parsed", parsed)
	out := buf.String()
	if strings.Contains(out, `"time"`) {
		t.Fatalf("the line has a timestamp whose digits could match a secret:\n%s", out)
	}
	for _, secret := range []string{
		"15550100001", "15550100002", "15550100003", "001010000000001", "00101000-000003-1", "Alice Secret",
		"198.51.100.7", "198.51.100.9", "10.20.30.40", "192.0.2.44", ":5060", "transport", "instance", ";lr", ";ob",
		"secretparam", "r0ute", "expires", "n0nce-value", "r3sponse-value", "0paque", "term@",
	} {
		if strings.Contains(out, secret) {
			t.Errorf("log contains %q:\n%s", secret, out)
		}
	}
	for _, want := range []string{
		`"contacts":{"0":{"uri":"sip:***@198.51.100.0/24","tag":""},"1":{"uri":"sip:***@10.20.30.0/24","tag":""}}`,
		`"route":{"0":{"uri":"sip:pcscf-1.rcs.internal","tag":""},"1":{"uri":"sip:***@198.51.100.0/24","tag":""}}`,
		`"rr":{"0":{"uri":"sip:scscf.rcs.internal","tag":""}}`,
		`"path":{"0":{"uri":"sip:***@pcscf-1.rcs.internal","tag":""}}`,
		`"pai":{"0":{"uri":"tel:***","tag":""}}`,
		`"creds":{"0":{"scheme":"Digest","realm":"ims.example.net"`,
		`"challenges":{"0":{"scheme":"Digest","realm":"ims.example.net"`,
		`"parsed":{"0":{"uri":"sip:***@192.0.2.0/24","tag":""}}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %s:\n%s", want, out)
		}
	}
}

// A service may log a struct of its own, or a plain slice, holding these
// values. encoding/json, which slog's JSON handler uses for them, must get
// the redacted forms too (#95).
func TestStructFieldsAndPlainSlicesMarshalRedacted(t *testing.T) {
	m := mustParse(t, lines(
		"INVITE sip:+15550100001@ims.example.net SIP/2.0",
		"Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bK1;received=192.0.2.44",
		`From: "Alice Secret" <sip:+15550100001@ims.example.net>;tag=1`,
		"To: <sip:bob@ims.example.net>",
		"Call-ID: a@b",
		"CSeq: 1 INVITE",
		"Contact: <sip:001010000000001@10.20.30.40;transport=tcp>",
		`Authorization: Digest username="001010000000001@ims.example.net", realm="ims.example.net", nonce="n0nce-value", response="r3sponse-value"`,
		`WWW-Authenticate: Digest realm="ims.example.net", nonce="n0nce-value", opaque="0paque"`,
		"Content-Length: 11",
		"",
		"s3cret-body",
	))
	req := m.(*Request)
	from, _ := req.Header.From()
	cs, _ := req.Header.Contact()
	vias, _ := req.Header.Via()
	creds, _ := req.Header.Authorization()
	chs, _ := req.Header.WWWAuthenticate()
	type event struct {
		Req      *Request
		Resp     Response
		Hdr      Header
		From     Address
		Target   URI
		Contacts []Contact
		Vias     []Via
		Creds    []Credentials
		Chal     Challenge
	}
	e := event{Req: req, Resp: Response{StatusCode: 200, Reason: "OK", Body: []byte("s3cret-body")}, Hdr: req.Header, From: from,
		Target: req.URI, Contacts: []Contact(cs), Vias: []Via(vias), Creds: []Credentials(creds), Chal: chs[0]}
	direct, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	untimedJSONLogger(&buf).Info("x", "event", e, "contacts", []Contact(cs))
	if strings.Contains(buf.String(), `"time"`) {
		t.Fatalf("the line has a timestamp whose digits could match a secret:\n%s", buf.String())
	}
	for name, out := range map[string]string{"json.Marshal": string(direct), "slog": buf.String()} {
		for _, secret := range []string{"15550100001", "001010000000001", "Alice Secret", "198.51.100.7", "192.0.2.44", "10.20.30.40",
			":5060", "transport=", "received", "n0nce-value", "r3sponse-value", "0paque", "s3cret-body", "bob@",
			// The body as encoding/json writes a []byte, should Response
			// lose its MarshalJSON (QA of #101).
			"czNjcmV0LWJvZHk"} {
			if strings.Contains(out, secret) {
				t.Errorf("%s output contains %q:\n%s", name, secret, out)
			}
		}
	}
	// The JSON form is the log form.
	for _, c := range []struct {
		v    any
		want string
	}{
		{from, `{"uri":"sip:***@ims.example.net","tag":"1"}`},
		{req.URI, `"sip:***@ims.example.net"`},
		{vias[0], `{"transport":"UDP","host":"198.51.100.0/24","branch":"z9hG4bK1"}`},
		{cs[0], `{"uri":"sip:***@10.20.30.0/24","tag":""}`},
		{Contact{Star: true}, `"*"`},
		{req, `{"method":"INVITE","uri":"sip:***@ims.example.net","headers":9,"body_bytes":11}`},
		{Response{StatusCode: 200, Reason: "OK", Body: []byte("s3cret-body")}, `{"status":200,"reason":"OK","headers":0,"body_bytes":11}`},
	} {
		if got, err := json.Marshal(c.v); err != nil || string(got) != c.want {
			t.Errorf("json.Marshal(%T) = %s, %v, want %s", c.v, got, err, c.want)
		}
	}
}

// untimedJSONLogger writes JSON lines without the time attribute, so that a
// test searching a line for leaked digits cannot find them in the
// timestamp's nanoseconds (#99).
func untimedJSONLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}))
}

// untimedTextLogger is untimedJSONLogger for slog's text handler.
func untimedTextLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}))
}

// Accept-Contact values are the peer's text and +sip.instance can carry an
// IMEI; Reason text and a reason phrase are the peer's free text (#109). The
// log, in either handler and as JSON, keeps only what says what happened.
func TestAcceptContactReasonAndReasonPhrasesLogNoPeerText(t *testing.T) {
	m := mustParse(t, lines(
		"SIP/2.0 486 Busy 15550100001",
		"Via: SIP/2.0/TCP 198.51.100.7:5060;branch=z9hG4bK1",
		"From: <sip:alice@ims.example.net>;tag=1",
		"To: <sip:bob@ims.example.net>;tag=2",
		"Call-ID: a@b",
		"CSeq: 1 INVITE",
		`Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session";+sip.instance="<urn:gsma:imei:00101000-000003-1>";require`,
		`Reason: SIP;cause=486;text="Alice Secret 15550100001"`,
		"Content-Length: 0",
	))
	resp := m.(*Response)
	acs, err1 := resp.Header.AcceptContact()
	rs, err2 := resp.Header.Reason()
	if err := errors.Join(err1, err2); err != nil {
		t.Fatal(err)
	}
	type event struct {
		Accept  []AcceptContact
		Reasons []Reason
		Resp    Response
	}
	direct, err := json.Marshal(event{[]AcceptContact(acs), []Reason(rs), *resp})
	if err != nil {
		t.Fatal(err)
	}
	var js, text bytes.Buffer
	untimedJSONLogger(&js).Info("x", "accept", acs, "reasons", rs, "resp", resp)
	untimedTextLogger(&text).Info("x", "accept", acs, "reasons", rs, "resp", resp)
	for name, out := range map[string]string{"json.Marshal": string(direct), "JSON handler": js.String(), "text handler": text.String()} {
		if strings.Contains(out, "time=") || strings.Contains(out, `"time"`) {
			t.Fatalf("%s: the line has a timestamp whose digits could match a secret:\n%s", name, out)
		}
		for _, secret := range []string{"00101000-000003-1", "imei", "Alice Secret", "15550100001", "oma.cpm.session"} {
			if strings.Contains(out, secret) {
				t.Errorf("%s output contains %q:\n%s", name, secret, out)
			}
		}
	}
	for _, want := range []string{
		`"accept":{"0":{"params":"+g.3gpp.icsi-ref;+sip.instance;require"}}`,
		`"reasons":{"0":{"protocol":"SIP","cause":486}}`,
		`"resp":{"status":486,"reason":"(custom)"`,
	} {
		if !strings.Contains(js.String(), want) {
			t.Errorf("JSON log lacks %s:\n%s", want, js.String())
		}
	}
	if !strings.Contains(text.String(), "accept.0.params=+g.3gpp.icsi-ref;+sip.instance;require") ||
		!strings.Contains(text.String(), "reasons.0.cause=486") {
		t.Errorf("text log = %s", text.String())
	}
}

// The names of Accept-Contact parameters and the Reason protocol are the
// peer's tokens, masked like other text; a cause longer than a SIP or Q.850
// cause is marked, and a reason phrase other than the registered one is
// marked as custom (review of #132).
func TestPeerTokensInAcceptContactReasonAndPhrasesAreMasked(t *testing.T) {
	for _, tt := range []struct {
		name string
		v    slog.LogValuer
		want string
	}{
		{"Accept-Contact parameter name", mustAcceptContact(t, "*;+15550100001"), `{"params":"+***01"}`},
		{"Reason protocol", mustReason(t, "15550100001;cause=1"), `{"protocol":"***01","cause":1}`},
		{"eight-digit cause", mustReason(t, "SIP;cause=91234567"), `{"protocol":"SIP","cause":"***"}`},
		{"ten-digit cause with zeros", mustReason(t, "SIP;cause=0091234567"), `{"protocol":"SIP","cause":"***"}`},
		{"largest cause logged", mustReason(t, "Q.850;cause=999"), `{"protocol":"Q.850","cause":999}`},
		{"smallest cause marked", mustReason(t, "Q.850;cause=1000"), `{"protocol":"Q.850","cause":"***"}`},
		{"registered phrase", Response{StatusCode: 486, Reason: "Busy Here"}, `"reason":"Busy Here"`},
		{"registered phrase in another case", Response{StatusCode: 486, Reason: "busy here"}, `"reason":"busy here"`},
		{"class name of an unregistered code", Response{StatusCode: 499, Reason: "Client Error"}, `"reason":"Client Error"`},
		{"no phrase", Response{StatusCode: 200}, `"reason":""`},
		{"a name in the phrase", Response{StatusCode: 486, Reason: "Alice Secret is busy"}, `"reason":"(custom)"`},
		{"the registered phrase and more", Response{StatusCode: 486, Reason: "Busy Here 10.20.30.40"}, `"reason":"(custom)"`},
		{"another code's phrase", Response{StatusCode: 486, Reason: "Decline"}, `"reason":"(custom)"`},
	} {
		out, err := json.Marshal(tt.v)
		if err != nil {
			t.Fatal(err)
		}
		var js bytes.Buffer
		untimedJSONLogger(&js).Info("x", "v", tt.v)
		for name, got := range map[string]string{"json.Marshal": string(out), "JSON handler": js.String()} {
			if !strings.Contains(got, tt.want) {
				t.Errorf("%s: %s gives %s, want %s", tt.name, name, got, tt.want)
			}
		}
	}
}

func mustAcceptContact(t *testing.T, v string) AcceptContact {
	t.Helper()
	acs, err := headerWith(t, "Accept-Contact", v).AcceptContact()
	if err != nil || len(acs) != 1 {
		t.Fatalf("Accept-Contact %q = %v, %v", v, acs, err)
	}
	return acs[0]
}

func mustReason(t *testing.T, v string) Reason {
	t.Helper()
	rs, err := headerWith(t, "Reason", v).Reason()
	if err != nil || len(rs) != 1 {
		t.Fatalf("Reason %q = %v, %v", v, rs, err)
	}
	return rs[0]
}
