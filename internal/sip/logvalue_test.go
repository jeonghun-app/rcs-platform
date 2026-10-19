package sip

import (
	"bytes"
	"encoding/json"
	"errors"
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
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	log.Info("x", "req", req, "reqv", *req, "res", res, "resv", *res, "header", req.Header, "headerp", &req.Header, "uri", req.URI, "from", from, "to", to,
		"contact", cs[0], "apn", cs[1], "vias", vias, "star", Contact{Star: true}, "creds", creds[0], "challenge", chs[0], "zero", URI{},
		"urn", URI{Scheme: "urn", Opaque: "uuid:s3cret"})
	out := buf.String()
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

func TestViaLogsItsHostLikeAURIAndLeavesOutTheReceivedAddress(t *testing.T) {
	vias := mustParseVias(t, "SIP/2.0/TCP 198.51.100.23:40001;branch=z9hG4bK77;received=198.51.100.23;rport=40001")
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "via", vias[0], "all", vias)
	out := buf.String()
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
	slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}})).Info("x", "contacts", contacts, "route", route, "rr", rr, "path", path, "pai", pai,
		"creds", creds, "challenges", chs, "parsed", parsed)
	out := buf.String()
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
	untimed := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}))
	untimed.Info("x", "event", e, "contacts", []Contact(cs))
	for name, out := range map[string]string{"json.Marshal": string(direct), "slog": buf.String()} {
		for _, secret := range []string{"15550100001", "001010000000001", "Alice Secret", "198.51.100.7", "192.0.2.44", "10.20.30.40",
			":5060", "transport=", "received", "n0nce-value", "r3sponse-value", "0paque", "s3cret-body", "bob@"} {
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
	} {
		if got, err := json.Marshal(c.v); err != nil || string(got) != c.want {
			t.Errorf("json.Marshal(%T) = %s, %v, want %s", c.v, got, err, c.want)
		}
	}
}
