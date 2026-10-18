package sip

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
)

// The messages in this file are our own, built to exercise what each RFC 4475
// §3.1.1 (valid) and §3.1.2 (invalid) torture test exercises. RFC 4475 tests that
// concern only the semantics of an element (SDP, Date, transaction handling) are
// left to the packages that implement them; see the end of the file.

// crlf turns a message written with LF line ends into one with CRLF line ends.
func crlf(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }

func parseValid(t *testing.T, msg string) Message {
	t.Helper()
	m, err := ParseMessage([]byte(msg))
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := mustBytes(t, m); !bytes.Equal(got, []byte(msg)) {
		t.Errorf("serialization differs:\n got %q\nwant %q", got, msg)
	}
	return m
}

// RFC 4475 §3.1.1.1: whitespace, folding and case everywhere the grammar allows.
func TestTortureRFC4475Section3_1_1_1ShortTortuousRequest(t *testing.T) {
	msg := crlf(`OPTIONS sip:carol@lab.example.com;oddparam SIP/2.0
TO :
 sip:carol@lab.example.com ;   tag    = 77aa21x
from   : "Q \"Tester\" \\"     <sip:tester@example.com>
  ;
  tag = t0rture
MaX-fOrWaRdS: 0042
Call-ID: tortuous.1x2y@192.0.2.7
Content-Length   : 4
cseq: 00017
  OPTIONS
Via  : SIP  /   2.0
 /UDP
    192.0.2.7;rport;branch=z9hG4bKw1
s :
Odd-Header:   first part
 second part
Weird-Separators: ,;;,,;
Content-Type: text/plain
Route:
 <sip:edge.example.com;lr;knob=value;flag-only>
v:  SIP  / 2.0  / TCP     relay.example.com   ;
  branch  =   z9hG4bKr2  ,
 SIP  /    2.0   / UDP  192.0.2.8   ; branch=
 z9hG4bKr3
m:"Quote \"\" inside" <sip:tester@example.com> ; p1 =
      v1 ;
  p2 ; q = 0.25

body`)
	req := parseValid(t, msg).(*Request)
	h := &req.Header
	if _, ok := req.URI.Param("oddparam"); !ok {
		t.Error("Request-URI parameter lost")
	}
	if to, _ := h.To(); to.Tag() != "77aa21x" || to.URI.User != "carol" {
		t.Errorf("To = %#v", to)
	}
	if from, _ := h.From(); from.DisplayName != `Q "Tester" \` || from.Tag() != "t0rture" {
		t.Errorf("From = %#v", from)
	}
	if mf, _ := h.MaxForwards(); mf != 42 {
		t.Errorf("Max-Forwards = %d", mf)
	}
	if cs, _ := h.CSeq(); cs != (CSeq{17, "OPTIONS"}) {
		t.Errorf("CSeq = %#v", cs)
	}
	vias, err := h.Via()
	if err != nil || len(vias) != 3 || vias[0].Host != "192.0.2.7" || vias[1].Branch() != "z9hG4bKr2" || vias[2].Branch() != "z9hG4bKr3" {
		t.Errorf("Via = %#v, %v", vias, err)
	}
	if h.Get("Subject") != "" || !h.Has("s") {
		t.Error("empty Subject")
	}
	if got := h.Get("odd-header"); got != "first part second part" {
		t.Errorf("Odd-Header = %q", got)
	}
	if got := h.Get("Weird-Separators"); got != ",;;,,;" {
		t.Errorf("unknown header value = %q", got)
	}
	cs, err := h.Contact()
	if err != nil || len(cs) != 1 || cs[0].DisplayName != `Quote "" inside` {
		t.Fatalf("Contact = %#v, %v", cs, err)
	}
	if q, _, _ := cs[0].Q(); q != 250 {
		t.Errorf("q = %d", q)
	}
	if v, _ := cs[0].Params.Get("p1"); v != "v1" || !cs[0].Params.Has("p2") {
		t.Errorf("contact params = %#v", cs[0].Params)
	}
	routes, err := h.Route()
	if _, lr := routes[0].URI.Param("lr"); err != nil || !lr {
		t.Errorf("Route = %#v, %v", routes, err)
	}
	if string(req.Body) != "body" {
		t.Errorf("body = %q", req.Body)
	}
}

// RFC 4475 §3.1.1.2: every character the grammar allows in each element.
func TestTortureRFC4475Section3_1_1_2WideRangeOfValidCharacters(t *testing.T) {
	const method = "!odd-Method0123456789_*+`.%indeed'~"
	const user = "1_odd.URI~(sure!)&isn't+it$/odd?,/;;*"
	msg := crlf(method + ` sip:` + user + `:&pw+has=1,odd!*pa$s~_.(doesn't-it)@example.com SIP/2.0
Via: SIP/2.0/TCP host1.example.com;branch=z9hG4bK-.!%66*_+` + "`'~" + `
To: "BEL:\` + "\x07" + ` NUL:\` + "\x00" + ` DEL:\` + "\x7f" + `" <sip:` + user + `@example.com>
From: token1~` + "`" + ` token2'+_ token3*%!.- <sip:mundane@example.com>;fromParam''~+*_!.-%="работа";tag=_token~1'+` + "`" + `*%!-.
Call-ID: oddcallid.word%ZK-!.*_+'@word` + "`" + `~)(><:\/"][?}{
CSeq: 139122385 ` + method + `
Max-Forwards: 255
extensionHeader-!.%*+_` + "`'~: \ufeff大停電" + `
Content-Length: 0

`)
	req := parseValid(t, msg).(*Request)
	if req.Method != method || req.URI.User != user || req.URI.Password != "&pw+has=1,odd!*pa$s~_.(doesn't-it)" {
		t.Errorf("start line = %q %#v", req.Method, req.URI)
	}
	to, err := req.Header.To()
	if err != nil || to.DisplayName != "BEL:\x07 NUL:\x00 DEL:\x7f" || to.URI.User != user {
		t.Errorf("To = %#v, %v", to, err)
	}
	from, err := req.Header.From()
	if err != nil || from.DisplayName != "token1~` token2'+_ token3*%!.-" || from.Tag() != "_token~1'+`*%!-." {
		t.Errorf("From = %#v, %v", from, err)
	}
	if v, _ := from.Params.Get("fromParam''~+*_!.-%"); v != "работа" {
		t.Errorf("fromParam = %q", v)
	}
	if got := req.Header.Get("extensionHeader-!.%*+_`'~"); got != "\ufeff大停電" {
		t.Errorf("extension header = %q", got)
	}
}

// RFC 4475 §3.1.1.3: escapes that decode to characters a component may also carry
// plainly, and escapes of reserved characters, which stay distinct.
func TestTortureRFC4475Section3_1_1_3ValidUseOfEscaping(t *testing.T) {
	msg := crlf(`INVITE sip:sips%3Afriend%40example.org@example.net SIP/2.0
To: sip:%66rien%64@example.com
From: <sip:I%20use%20spaces@example.net>;tag=e1
Max-Forwards: 87
i: esc.239409asdfakjkn23onasd0-3234
CSeq: 234234 INVITE
Via: SIP/2.0/UDP host5.example.net;branch=z9hG4bKkdjuw
C: application/sdp
Contact:
  <sip:ca%6Cler@host5.example.net;%6C%72;n%61me=v%61lue%25%34%31>
Content-Length: 0

`)
	req := parseValid(t, msg).(*Request)
	if got := unescape(req.URI.User); got != "sips:friend@example.org" {
		t.Errorf("Request-URI user = %q", got)
	}
	to, _ := req.Header.To()
	if !to.URI.Equal(mustURI(t, "sip:friend@example.com")) {
		t.Errorf("To URI %q is not sip:friend@example.com", to.URI.String())
	}
	cs, err := req.Header.Contact()
	if err != nil || !cs[0].URI.Equal(mustURI(t, "sip:caller@host5.example.net;lr;name=value%2541")) {
		t.Errorf("Contact = %#v, %v", cs, err)
	}
	if cs[0].URI.Equal(mustURI(t, "sip:caller@host5.example.net;lr;name=value%41")) {
		t.Error("%25 was decoded")
	}
}

// RFC 4475 §3.1.1.4: an escaped NUL in a user part is valid.
func TestTortureRFC4475Section3_1_1_4EscapedNullsInURIs(t *testing.T) {
	msg := crlf(`REGISTER sip:example.com SIP/2.0
To: sip:null-%00-null@example.com
From: sip:null-%00-null@example.com;tag=839923423
Max-Forwards: 70
Call-ID: escnull.39203ndfvkjdasfkq3w4otrq0adsfdfnavd
CSeq: 14398234 REGISTER
Via: SIP/2.0/UDP host5.example.com;branch=z9hG4bKkdjuw
Contact: <sip:%00@host5.example.com>
Contact: <sip:%00%00@host5.example.com>
L:0

`)
	req := parseValid(t, msg).(*Request)
	to, _ := req.Header.To()
	if unescape(to.URI.User) != "null-\x00-null" {
		t.Errorf("To user = %q", to.URI.User)
	}
	cs, err := req.Header.Contact()
	if err != nil || len(cs) != 2 || unescape(cs[1].URI.User) != "\x00\x00" {
		t.Errorf("Contact = %#v, %v", cs, err)
	}
}

// RFC 4475 §3.1.1.5: "%" is a token character, so a method or header name with
// escapes is just another token and is not decoded.
func TestTortureRFC4475Section3_1_1_5PercentThatIsNotAnEscape(t *testing.T) {
	msg := crlf(`RE%47IST%45R sip:registrar.example.com SIP/2.0
To: "%Z%45" <sip:resource@example.com>
From: "%Z%45" <sip:resource@example.com>;tag=f232jadfj23
Call-ID: esc02.asdfnqwo34rq23i34jrjasdcnl23nrlknsdf
Via: SIP/2.0/TCP host.example.com;branch=z9hG4bK209%fzsnel234
CSeq: 29344 RE%47IST%45R
Max-Forwards: 70
Contact: <sip:alias1@host1.example.com>
C%6Fntact: <sip:alias2@host2.example.com>
Contact: <sip:alias3@host3.example.com>
l: 0

`)
	req := parseValid(t, msg).(*Request)
	if req.Method == "REGISTER" {
		t.Error("method was decoded")
	}
	if to, _ := req.Header.To(); to.DisplayName != "%Z%45" {
		t.Errorf("To display name = %q", to.DisplayName)
	}
	cs, err := req.Header.Contact()
	if err != nil || len(cs) != 2 || cs[1].URI.User != "alias3" {
		t.Errorf("Contact = %#v, %v", cs, err)
	}
	if req.Header.Get("C%6Fntact") != "<sip:alias2@host2.example.com>" {
		t.Error("C%6Fntact is a header of its own")
	}
	if vs, _ := req.Header.Via(); vs[0].Branch() != "z9hG4bK209%fzsnel234" {
		t.Errorf("branch = %q", vs[0].Branch())
	}
}

// RFC 4475 §3.1.1.6: no whitespace between an unquoted display name and "<".
func TestTortureRFC4475Section3_1_1_6NoLWSBetweenDisplayNameAndAngle(t *testing.T) {
	msg := crlf(`OPTIONS sip:user@example.com SIP/2.0
To: sip:user@example.com
From: caller<sip:caller@example.com>;tag=323
Max-Forwards: 70
Call-ID: lwsdisp.1234abcd@funky.example.com
CSeq: 60 OPTIONS
Via: SIP/2.0/UDP funky.example.com;branch=z9hG4bKkdjuw
l: 0

`)
	req := parseValid(t, msg).(*Request)
	if from, _ := req.Header.From(); from.DisplayName != "caller" || from.URI.User != "caller" {
		t.Errorf("From = %#v", from)
	}
}

// RFC 4475 §3.1.1.7: long values everywhere, within the default limits.
func TestTortureRFC4475Section3_1_1_7LongValuesInHeaderFields(t *testing.T) {
	long := strings.Repeat("very", 75)
	var vias strings.Builder
	for i := 0; i < 30; i++ {
		vias.WriteString("Via: SIP/2.0/TCP sip" + strings.Repeat("x", i+1) + ".example.com;branch=z9hG4bK" + strings.Repeat("y", 40) + "\n")
	}
	msg := crlf(`INVITE sip:user@example.com SIP/2.0
To: "I have a user name of ` + long + ` long" <sip:` + long + `@example.com>
From: sip:caller@example.net;tag=` + strings.Repeat("t", 200) + `
Call-ID: longreq.` + strings.Repeat("c", 400) + `
CSeq: 1 INVITE
Max-Forwards: 70
Via: SIP/2.0/TCP sip33.example.com;branch=z9hG4bK` + long + `
` + vias.String() + `Contact: <sip:amazinglylongcallername@host5.example.net;` + strings.Repeat("p", 500) + `=1>
X-Unknown-Long-Header: ` + strings.Repeat("value ", 300) + `
Content-Length: 0

`)
	req := parseValid(t, msg).(*Request)
	vs, err := req.Header.Via()
	if err != nil || len(vs) != 31 {
		t.Errorf("Via count = %d, %v", len(vs), err)
	}
	if to, _ := req.Header.To(); to.URI.User != long {
		t.Error("long user part")
	}
}

// RFC 4475 §3.1.1.8: a datagram carrying a second message after the first. Bytes
// past Content-Length are discarded (RFC 3261 §18.3).
func TestTortureRFC4475Section3_1_1_8ExtraTrailingOctetsInADatagram(t *testing.T) {
	first := crlf(`REGISTER sip:example.com SIP/2.0
To: sip:j.user@example.com
From: sip:j.user@example.com;tag=43251j3j324
Max-Forwards: 8
I: dblreq.0ha0isndaksdj99sdfafnl3lk233412
Contact: sip:j.user@host.example.com
CSeq: 8 REGISTER
Via: SIP/2.0/UDP 192.0.2.125;branch=z9hG4bKkdjuw23492
Content-Length: 0

`)
	second := crlf(`INVITE sip:joe@example.com SIP/2.0
t: sip:joe@example.com
From: sip:caller@example.net;tag=141334
Max-Forwards: 8
Call-ID: dblreq.0ha0isnda977644900765@192.0.2.15
CSeq: 8 INVITE
Via: SIP/2.0/UDP 192.0.2.15;branch=z9hG4bKkdjuw380234
Content-Type: text/plain
Content-Length: 2

hi`)
	m, err := ParseMessage([]byte(first + second))
	if err != nil {
		t.Fatal(err)
	}
	req := m.(*Request)
	if req.Method != "REGISTER" || req.Body != nil {
		t.Errorf("got %q with body %q", req.Method, req.Body)
	}
	if got := mustBytes(t, m); string(got) != first {
		t.Errorf("serialization = %q", got)
	}
}

// RFC 4475 §3.1.1.9: parameters in the user part of a URI belong to the user.
func TestTortureRFC4475Section3_1_1_9SemicolonsInURIUserPart(t *testing.T) {
	msg := crlf(`OPTIONS sip:user;par=u%40example.net@example.com SIP/2.0
To: sip:j_user@example.com
From: sip:caller@example.org;tag=33242
Max-Forwards: 3
Call-ID: semiuri.0ha0isndaksdj
CSeq: 8 OPTIONS
Accept: application/sdp, application/pkcs7-mime,
        multipart/mixed, multipart/signed,
        message/sip, message/sipfrag
Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bKkdjuw
l: 0

`)
	req := parseValid(t, msg).(*Request)
	if req.URI.User != "user;par=u%40example.net" || req.URI.Host != "example.com" || req.URI.Params != nil {
		t.Errorf("Request-URI = %#v", req.URI)
	}
	if els, err := req.Header.Elements("Accept"); err != nil || len(els) != 6 {
		t.Errorf("Accept = %q, %v", els, err)
	}
}

// RFC 4475 §3.1.1.10: unknown transports are just tokens.
func TestTortureRFC4475Section3_1_1_10VariedAndUnknownTransports(t *testing.T) {
	msg := crlf(`OPTIONS sip:user@example.com SIP/2.0
To: sip:user@example.com
From: <sip:caller@example.com>;tag=323
Max-Forwards: 70
Call-ID: transports.kijh4akdnaqjkwendsasfdj
Accept: application/sdp
CSeq: 60 OPTIONS
Via: SIP/2.0/UDP t1.example.com;branch=z9hG4bKkdjuw
Via: SIP/2.0/SCTP t2.example.com;branch=z9hG4bKklasjdhf
Via: SIP/2.0/TLS t3.example.com;branch=z9hG4bK2980unddj
Via: SIP/2.0/UNKNOWN t4.example.com;branch=z9hG4bKasd0f3en
Via: SIP/2.0/TCP t5.example.com;branch=z9hG4bK0a9idfnee
l: 0

`)
	req := parseValid(t, msg).(*Request)
	vs, _ := req.Header.Via()
	var got []string
	for _, v := range vs {
		got = append(got, v.Transport)
	}
	if strings.Join(got, ",") != "UDP,SCTP,TLS,UNKNOWN,TCP" {
		t.Errorf("transports = %q", got)
	}
}

// RFC 4475 §3.1.1.11: a multipart body with binary content is framed by
// Content-Length alone.
func TestTortureRFC4475Section3_1_1_11MultipartMIMEMessage(t *testing.T) {
	binary := make([]byte, 256)
	for i := range binary {
		binary[i] = byte(i)
	}
	body := crlf("--boundary42\nContent-Type: text/plain\n\nhello\n--boundary42\nContent-Type: application/octet-stream\n\n") +
		string(binary) + crlf("\n--boundary42--\n")
	msg := crlf(`MESSAGE sip:kumiko@example.org SIP/2.0
Via: SIP/2.0/UDP 192.0.2.6:5060;branch=z9hG4bKky8u3
Max-Forwards: 70
To: <sip:kumiko@example.org>
From: <sip:hyakuya@example.com>;tag=4553
Call-ID: mpart01.75pm4vmn
CSeq: 1 MESSAGE
Content-Type: multipart/mixed;boundary=boundary42
Content-Length: `) + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	req := parseValid(t, msg).(*Request)
	if !bytes.Equal(req.Body, []byte(body)) {
		t.Error("binary body changed")
	}
	if ct, _ := req.Header.ContentType(); !ct.Is("multipart", "mixed") {
		t.Errorf("Content-Type = %#v", ct)
	}
}

// RFC 4475 §3.1.1.12 and §3.1.1.13: a UTF-8 reason phrase and an empty one.
func TestTortureRFC4475Section3_1_1_12And13UnusualAndEmptyReasonPhrases(t *testing.T) {
	head := crlf(`
Via: SIP/2.0/UDP 192.0.2.198;branch=z9hG4bK1324923
Call-ID: unreason.1234ksdfak3j2erwedfsASdf
CSeq: 35 INVITE
From: sip:user@example.com;tag=11141343
To: sip:user@example.edu;tag=2229
Content-Length: 0

`)
	for _, reason := range []string{"= 2**3 * 5**2 но всё ещё простое", ""} {
		res := parseValid(t, "SIP/2.0 200 "+reason+head).(*Response)
		if res.StatusCode != 200 || res.Reason != reason {
			t.Errorf("got %d %q", res.StatusCode, res.Reason)
		}
	}
}

// invalidBase is a well-formed request the §3.1.2 tests break one way each.
const invalidBase = "INVITE sip:user@example.com SIP/2.0\r\n" +
	"To: sip:j.user@example.com\r\n" +
	"From: sip:caller@example.net;tag=134161461246\r\n" +
	"Max-Forwards: 7\r\n" +
	"Call-ID: torture.0ha0isndaksdjasdf3234nas\r\n" +
	"CSeq: 8 INVITE\r\n" +
	"Via: SIP/2.0/UDP 192.0.2.15;branch=z9hG4bKkdjuw\r\n" +
	"Contact: \"Joe\" <sip:joe@example.org>\r\n" +
	"Expires: 60\r\n" +
	"Content-Length: 0\r\n\r\n"

func breakBase(t *testing.T, old, new string) string {
	t.Helper()
	if !strings.Contains(invalidBase, old) {
		t.Fatalf("%q not in the base message", old)
	}
	return strings.Replace(invalidBase, old, new, 1)
}

// RFC 4475 §3.1.2: messages a parser has to refuse. Some fail framing, so
// ParseMessage refuses them; the rest frame correctly and fail in Validate or in
// the accessor for the broken field, as RFC 3261 §16.3 lets a proxy that does not
// read a field forward it.
func TestTortureRFC4475Section3_1_2InvalidMessagesAreRefused(t *testing.T) {
	type check func(t *testing.T, m Message)
	failsValidate := func(header string) check {
		return func(t *testing.T, m Message) {
			err := m.Validate()
			var pe *ParseError
			if !errors.Is(err, ErrMalformed) || !errors.As(err, &pe) || pe.Header != header {
				t.Errorf("Validate() = %v, want a malformed %s", err, header)
			}
		}
	}
	accessorFailsWith := func(want error, get func(h *Header) error) check {
		return func(t *testing.T, m Message) {
			if err := get(m.Headers()); !errors.Is(err, want) {
				t.Errorf("accessor error = %v, want %v", err, want)
			}
		}
	}
	accessorFails := func(get func(h *Header) error) check { return accessorFailsWith(ErrMalformed, get) }
	tests := []struct {
		section string
		msg     string
		parse   error // non-nil: ParseMessage must fail with this
		checks  []check
	}{
		{section: "3.1.2.1 extraneous header field separators",
			msg:    breakBase(t, "From: sip:caller@example.net;tag=134161461246", "From: sip:caller@example.net;;;;tag=134161461246"),
			checks: []check{failsValidate("From")}},
		{section: "3.1.2.1 extraneous separators in Via",
			msg:    breakBase(t, "Via: SIP/2.0/UDP 192.0.2.15;branch=z9hG4bKkdjuw", "Via: SIP/2.0/UDP 192.0.2.15;;,;,,"),
			checks: []check{failsValidate("Via")}},
		{section: "3.1.2.1 extraneous separators in Contact",
			msg: breakBase(t, `Contact: "Joe" <sip:joe@example.org>`, `Contact: "Joe" <sip:joe@example.org>;;;;`),
			checks: []check{accessorFails(func(h *Header) error {
				_, err := h.Contact()
				return err
			})}},
		{section: "3.1.2.2 Content-Length larger than the message",
			msg: breakBase(t, "Content-Length: 0\r\n\r\n", "Content-Length: 9999\r\n\r\nv=0\r\n"), parse: ErrMalformed},
		{section: "3.1.2.3 negative Content-Length",
			msg: breakBase(t, "Content-Length: 0", "Content-Length: -999"), parse: ErrMalformed},
		{section: "3.1.2.4 overlarge Max-Forwards",
			msg: breakBase(t, "Max-Forwards: 7", "Max-Forwards: 300"), checks: []check{failsValidate("Max-Forwards")}},
		{section: "3.1.2.4 overlarge CSeq",
			msg: breakBase(t, "CSeq: 8 INVITE", "CSeq: 36893488147419103232 INVITE"), checks: []check{failsValidate("CSeq")}},
		// Overlarge expiry values are out of range rather than malformed, so a
		// registrar can clamp them (RFC 3261 §10.2).
		{section: "3.1.2.4 overlarge Expires",
			msg: breakBase(t, "Expires: 60", "Expires: 10000000000000000000"),
			checks: []check{accessorFailsWith(ErrOutOfRange, func(h *Header) error {
				_, err := h.Expires()
				return err
			})}},
		// The bad expires fails its own accessor only, so the rest of the Contact
		// stays readable.
		{section: "3.1.2.4 overlarge Contact expires",
			msg: breakBase(t, `Contact: "Joe" <sip:joe@example.org>`, `Contact: "Joe" <sip:joe@example.org>;expires=99999999999999999999`),
			checks: []check{accessorFailsWith(ErrOutOfRange, func(h *Header) error {
				cs, err := h.Contact()
				if err != nil {
					return err
				}
				_, _, err = cs[0].Expires()
				return err
			})}},
		{section: "3.1.2.5 response with an overlarge CSeq",
			msg: crlf("SIP/2.0 503 Service Unavailable\nVia: SIP/2.0/TCP host129.example.com;branch=z9hG4bKzzxdiwo34sw;received=192.0.2.129\n" +
				"To: <sip:user@example.com>\nFrom: <sip:other@example.net>;tag=2easdjfejw\nCSeq: 9292394834772304023312 OPTIONS\n" +
				"Call-ID: scalarlg.noase0of0234hn2qofoaf0232aewf2394r\nRetry-After: 949302838503028349304023988\nWarning: 1812 overture \"In Progress\"\nContent-Length: 0\n\n"),
			checks: []check{failsValidate("CSeq")}},
		{section: "3.1.2.6 unterminated quoted display name",
			msg: breakBase(t, "To: sip:j.user@example.com", `To: "Mr. J. User <sip:j.user@example.com>`), checks: []check{failsValidate("To")}},
		{section: "3.1.2.7 Request-URI enclosed in <>",
			msg: breakBase(t, "INVITE sip:user@example.com SIP/2.0", "INVITE <sip:user@example.com> SIP/2.0"), parse: ErrMalformed},
		{section: "3.1.2.8 LWS inside the Request-URI",
			msg: breakBase(t, "INVITE sip:user@example.com SIP/2.0", "INVITE sip:user@example.com; lr SIP/2.0"), parse: ErrMalformed},
		{section: "3.1.2.9 several SP between Request-Line elements",
			msg: breakBase(t, "INVITE sip:user@example.com SIP/2.0", "INVITE  sip:user@example.com  SIP/2.0"), parse: ErrMalformed},
		{section: "3.1.2.10 SP at the end of the Request-Line",
			msg: breakBase(t, "INVITE sip:user@example.com SIP/2.0", "INVITE sip:user@example.com SIP/2.0  "), parse: ErrMalformed},
		{section: "3.1.2.11 escaped headers in the Request-URI",
			msg: breakBase(t, "INVITE sip:user@example.com SIP/2.0", "INVITE sip:user@example.com?Route=%3Csip:example.com%3E SIP/2.0"), parse: ErrMalformed},
		{section: "3.1.2.13 addr-spec Contact with URI headers",
			msg: breakBase(t, `Contact: "Joe" <sip:joe@example.org>`, "Contact: sip:user@example.com?Route=%3Csip:sip.example.com%3E"),
			checks: []check{accessorFails(func(h *Header) error {
				_, err := h.Contact()
				return err
			})}},
		{section: "3.1.2.14 spaces inside the angle brackets",
			msg: breakBase(t, "To: sip:j.user@example.com", `To: "Watson, Thomas" < sip:t.watson@example.org >`), checks: []check{failsValidate("To")}},
		{section: "3.1.2.15 non-token characters in an unquoted display name",
			msg:    breakBase(t, "From: sip:caller@example.net;tag=134161461246", "From: Bell, Alexander <sip:a.g.bell@example.com>;tag=43"),
			checks: []check{failsValidate("From")}},
		{section: "3.1.2.16 unknown protocol version",
			msg: breakBase(t, "INVITE sip:user@example.com SIP/2.0", "INVITE sip:user@example.com SIP/7.0"), parse: ErrUnsupportedVersion},
		{section: "3.1.2.17 CSeq method differs from the request method",
			msg: breakBase(t, "INVITE sip:user@example.com SIP/2.0", "OPTIONS sip:user@example.com SIP/2.0"), checks: []check{failsValidate("CSeq")}},
		{section: "3.1.2.18 unknown method with a different CSeq method",
			msg: breakBase(t, "INVITE sip:user@example.com SIP/2.0", "NEWMETHOD sip:user@example.com SIP/2.0"), checks: []check{failsValidate("CSeq")}},
		{section: "3.1.2.19 overlarge response code",
			msg: crlf("SIP/2.0 4294967301 better not break the receiver\nVia: SIP/2.0/UDP 192.0.2.105;branch=z9hG4bK2398ndaoe\n" +
				"Call-ID: bigcode.asdof3uj203asdnf3429uasdhfas3ehjasdfas9i\nCSeq: 353494 INVITE\nFrom: <sip:user@example.com>;tag=39ansfi3\n" +
				"To: <sip:user@example.edu>;tag=902jndnke3\nContent-Length: 0\n\n"),
			parse: ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.section, func(t *testing.T) {
			m, err := ParseMessage([]byte(tt.msg))
			if tt.parse != nil {
				if !errors.Is(err, tt.parse) {
					t.Fatalf("ParseMessage() = %v, want %v", err, tt.parse)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseMessage() = %v; this message frames correctly", err)
			}
			if len(tt.checks) == 0 {
				t.Fatal("no check")
			}
			for _, c := range tt.checks {
				c(t, m)
			}
		})
	}
}

// RFC 4475 §3.1.2.2 on a stream: the body never arrives.
func TestTortureRFC4475Section3_1_2_2OnAStreamEndsUnexpectedly(t *testing.T) {
	msg := breakBase(t, "Content-Length: 0\r\n\r\n", "Content-Length: 9999\r\n\r\nv=0\r\n")
	_, err := NewReader(bufio.NewReader(strings.NewReader(msg)), Limits{}).ReadMessage()
	if err != io.ErrUnexpectedEOF {
		t.Errorf("ReadMessage() = %v, want io.ErrUnexpectedEOF", err)
	}
}

// RFC 4475 tests not exercised here, because they test something other than
// parsing: §3.1.2.12 (an invalid Date, which no service here interprets), §3.2
// (transaction layer), §3.3 (application layer: SDP, Require, unknown schemes),
// §3.4 (backward compatibility with RFC 2543 transactions).

func mustURI(t *testing.T, s string) URI {
	t.Helper()
	u, err := ParseURI(s)
	if err != nil {
		t.Fatalf("ParseURI(%q): %v", s, err)
	}
	return u
}
