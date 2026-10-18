package sip

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestLoggedValuesLeaveOutIdentitiesAndCredentials(t *testing.T) {
	secrets := []string{"15550100001", "001010000000001", "Alice Secret", "n0nce-value", "r3sponse-value", "cn0nce", "0paque", "s3cret"}
	m := mustParse(t, lines(
		"REGISTER sip:+15550100001@ims.example.net;user=phone SIP/2.0",
		"Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK1",
		`From: "Alice Secret" <sip:+15550100001@ims.example.net>;tag=1`,
		"To: <tel:+15550100001>",
		"Call-ID: a@b",
		"CSeq: 1 REGISTER",
		`Contact: <sip:001010000000001:s3cret@192.0.2.1>;expires=600`,
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
	res := &Response{StatusCode: 200, Reason: "OK", Body: []byte("n0nce-value")}

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	log.Info("x", "req", req, "reqv", *req, "res", res, "resv", *res, "header", req.Header, "headerp", &req.Header, "uri", req.URI, "from", from, "to", to,
		"contact", cs[0], "star", Contact{Star: true}, "creds", creds[0], "challenge", chs[0], "zero", URI{},
		"urn", URI{Scheme: "urn", Opaque: "uuid:s3cret"})
	out := buf.String()
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("log contains %q:\n%s", s, out)
		}
	}
	for _, want := range []string{
		`"method":"REGISTER"`, `"uri":"sip:***@ims.example.net"`, `"status":200`, `"to":{"uri":"tel:***","tag":""}`,
		`"contact":{"uri":"sip:***@192.0.2.1","tag":""}`, `"star":"*"`, `"realm":"ims.example.net"`, `"algorithm":"AKAv1-MD5"`,
		`"zero":""`, `"urn":"urn:***"`, `"body_bytes":11`, `"reqv":{"method":"REGISTER"`, `"resv":{"status":200`,
		`"header":{"fields":9}`, `"headerp":{"fields":9}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %s:\n%s", want, out)
		}
	}
	if got := (URI{Scheme: "sip", Host: "example.com"}).LogValue().String(); got != "sip:example.com" {
		t.Errorf("URI without user logs %q", got)
	}
}
