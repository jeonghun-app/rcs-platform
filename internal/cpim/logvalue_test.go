package cpim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// untimedLoggers write JSON and text lines without the time attribute, so
// that a search for leaked digits cannot find them in the timestamp (#99).
func untimedLoggers(js, text io.Writer) (*slog.Logger, *slog.Logger) {
	opts := &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}
	return slog.New(slog.NewJSONHandler(js, opts)), slog.New(slog.NewTextHandler(text, opts))
}

// A CPIM address names a subscriber in its URI and a person in its formal
// name. Logged directly, in a plain slice or in a struct field, as JSON or
// text, it shows its URI's scheme and host only (#109).
func TestAddressesLogNeitherTheirUserNorTheirFormalName(t *testing.T) {
	from := Address{Name: "Alice Secret", URI: alice}
	to := []Address{{URI: "im:bob.secret@ims.mnc001.mcc001.3gppnetwork.org"}, {Name: "Carol", URI: "tel:+15550100003"}}
	direct, err := json.Marshal(struct {
		From Address
		To   []Address
	}{from, to})
	if err != nil {
		t.Fatal(err)
	}
	var js, text bytes.Buffer
	jsonLog, textLog := untimedLoggers(&js, &text)
	jsonLog.Info("x", "from", from, "to", to)
	textLog.Info("x", "from", from)
	for name, out := range map[string]string{"json.Marshal": string(direct), "JSON handler": js.String(), "text handler": text.String()} {
		if strings.Contains(out, "time=") || strings.Contains(out, `"time"`) {
			t.Fatalf("%s: the line has a timestamp whose digits could match a secret:\n%s", name, out)
		}
		for _, secret := range []string{"15550100001", "15550100003", "Alice Secret", "bob.secret", "Carol"} {
			if strings.Contains(out, secret) {
				t.Errorf("%s output contains %q:\n%s", name, secret, out)
			}
		}
	}
	for _, want := range []string{
		`"from":{"uri":"sip:***@ims.mnc001.mcc001.3gppnetwork.org"}`,
		`"to":[{"uri":"im:***@ims.mnc001.mcc001.3gppnetwork.org"},{"uri":"tel:***"}]`,
	} {
		if !strings.Contains(js.String(), want) {
			t.Errorf("JSON log lacks %s:\n%s", want, js.String())
		}
	}
	if !strings.Contains(text.String(), "from.uri=sip:***@ims.mnc001.mcc001.3gppnetwork.org") {
		t.Errorf("text log = %s", text.String())
	}
}

// An address logs as a SIP URI does whatever its scheme: the scheme and
// host only, an IP host as its network, no parameters or headers, and only
// the scheme of a URI whose user cannot be found (review of #132).
func TestAddressesLogTheirURIAsASIPURIIsLogged(t *testing.T) {
	for _, tt := range []struct{ uri, leak, want string }{
		{"sip:+15550100001@10.20.30.40", "10.20.30.40", "sip:***@10.20.30.0/24"},
		{"im:alice@[2001:db8:5:6::7]", "2001:db8:5:6::7", "im:***@2001:db8:5::/48"},
		{"sip:[fe80::0211:22ff:fe33:4455]", "22ff:fe33:4455", "sip:fe80::/48"},
		{"sip:alice@198.51.100.7:5061;transport=tls", "198.51.100.7", "sip:***@198.51.100.0/24"},
		{"mailto:alice.secret@example.com", "alice.secret", "mailto:***"},
		{"xmpp:alice.secret@example.com", "alice.secret", "xmpp:***"},
		{"http://alice.secret:pw@example.com/", "alice.secret", "http:***"},
		{"im:alice.secret", "alice.secret", "im:***"},
		{"sip:bob@ims.example.net?Subject=Alice%20Secret", "Alice%20Secret", "sip:***@ims.example.net"},
		{"sip:bob@ims.example.net;gr=urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6", "f81d4fae", "sip:***@ims.example.net"},
		{"tel:+15550100001;phone-context=ims.example.net", "0100001", "tel:***"},
		{"urn:gsma:imei:00101000-000003-1", "000003", "urn:***"},
	} {
		a, err := ParseAddress("<" + tt.uri + ">")
		if err != nil {
			t.Fatal(err)
		}
		out, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		var js, text bytes.Buffer
		jsonLog, textLog := untimedLoggers(&js, &text)
		jsonLog.Info("x", "from", a)
		textLog.Info("x", "from", a)
		for name, got := range map[string]string{"json.Marshal": string(out), "JSON handler": js.String(), "text handler": text.String()} {
			if strings.Contains(got, tt.leak) || !strings.Contains(got, tt.want) {
				t.Errorf("%s: <%s> logs %s, want %s", name, tt.uri, got, tt.want)
			}
		}
	}
}

// secretMessage has a formal name, a Subject, a header name and a body that
// name people or numbers, none of which may be logged or printed.
var secretMessage = crlf(`From: "Alice Secret" <` + alice + `>
To: Bob Secret <` + bob + `>
cc: Carol <` + carol + `>
DateTime: 2026-10-18T09:30:00Z
Subject: lunch with Dave Secret
NS: x <urn:example:x>
x.Note15550100004: 1

Content-Type: text/plain; name="Erin Secret.txt"

meet me at 15550100005`)

// secrets are the parts of secretMessage that no log line or printed form
// shows.
var secrets = []string{"Secret", "1555010000", "lunch", "urn:example", "meet me", "Bob", "Carol"}

// A message logs its header names, its addresses as above, its media type
// and its size; header values, which hold formal names and the sender's
// text, and the body never (review of #132). The To and cc lists log their
// addresses the same way through a text handler too.
func TestMessagesLogTheirAddressesAndSizesButNoValuesOrBody(t *testing.T) {
	m := mustParse(t, secretMessage)
	to, err1 := m.To()
	cc, err2 := m.Cc()
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	direct, err := json.Marshal(struct{ Msg Message }{*m})
	if err != nil {
		t.Fatal(err)
	}
	var js, text bytes.Buffer
	jsonLog, textLog := untimedLoggers(&js, &text)
	jsonLog.Info("x", "msg", m, "copy", *m)
	textLog.Info("x", "msg", m, "to", to, "cc", cc)
	for name, out := range map[string]string{"json.Marshal": string(direct), "JSON handler": js.String(), "text handler": text.String()} {
		if strings.Contains(out, "time=") || strings.Contains(out, `"time"`) {
			t.Fatalf("%s: the line has a timestamp whose digits could match a secret:\n%s", name, out)
		}
		for _, secret := range secrets {
			if strings.Contains(out, secret) {
				t.Errorf("%s output contains %q:\n%s", name, secret, out)
			}
		}
	}
	want := `{"headers":["From","To","cc","DateTime","Subject","NS","x.Note***04"],` +
		`"from":{"uri":"sip:***@ims.mnc001.mcc001.3gppnetwork.org"},` +
		`"to":%s,"cc":%s,"content_type":"text/plain","body_bytes":22}`
	for name, tt := range map[string]struct{ out, to, cc string }{
		"json.Marshal": {string(direct), `[{"uri":"sip:***@ims.mnc001.mcc001.3gppnetwork.org"}]`, `[{"uri":"tel:***"}]`},
		"JSON handler": {js.String(), `{"0":{"uri":"sip:***@ims.mnc001.mcc001.3gppnetwork.org"}}`, `{"0":{"uri":"tel:***"}}`},
	} {
		if w := fmt.Sprintf(want, tt.to, tt.cc); !strings.Contains(tt.out, w) {
			t.Errorf("%s lacks %s:\n%s", name, w, tt.out)
		}
	}
	for _, w := range []string{"msg.from.uri=sip:***@ims.mnc001.mcc001.3gppnetwork.org", "msg.body_bytes=22",
		"to.0.uri=sip:***@ims.mnc001.mcc001.3gppnetwork.org", "cc.0.uri=tel:***"} {
		if !strings.Contains(text.String(), w) {
			t.Errorf("text log lacks %s:\n%s", w, text.String())
		}
	}
}

// The media type is the sender's token too, masked like other text, and a
// nil *Message logs as an empty group rather than as LogValue's panic
// (review of #132).
func TestMessageLogValueMasksTheMediaTypeAndTakesANilMessage(t *testing.T) {
	m := mustParse(t, crlf("From: <"+alice+">\nTo: <"+bob+">\n\nContent-Type: text/x15550100004\n\nhi"))
	var nilMsg *Message
	var js bytes.Buffer
	jsonLog, _ := untimedLoggers(&js, io.Discard)
	jsonLog.Info("x", "msg", m, "none", nilMsg)
	out := js.String()
	if strings.Contains(out, "15550100004") || !strings.Contains(out, `"content_type":"text/x***04"`) {
		t.Errorf("media type logged as:\n%s", out)
	}
	if strings.Contains(out, "panic") || strings.Contains(out, `"none"`) {
		// slog drops an empty group.
		t.Errorf("nil message logged as:\n%s", out)
	}
}

// fmt, and slog's text handler, which formats a value that is not a
// LogValuer with %+v, print a Message value in the form MarshalJSON writes
// whatever the verb, also as a struct field or a slice element, rather
// than its formal names, Subject and body (#171). A nil *Message prints as
// fmt prints any nil pointer.
func TestAMessagePrintsAsItsLogFormWithEveryVerb(t *testing.T) {
	m := mustParse(t, secretMessage)
	want, err := m.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var text bytes.Buffer
	_, textLog := untimedLoggers(io.Discard, &text)
	textLog.Info("x", "value", *m)
	quoted := fmt.Sprintf("value=%q", want)
	if !strings.Contains(text.String(), quoted) {
		t.Errorf("text log lacks %s:\n%s", quoted, text.String())
	}
	printed := map[string]string{"text handler": text.String()}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		for name, arg := range map[string]any{"value": *m, "pointer": m} {
			got := fmt.Sprintf(verb, arg)
			printed[verb+" "+name] = got
			if got != string(want) {
				t.Errorf("%s of a %s = %s, want %s", verb, name, got, want)
			}
		}
	}
	for name, arg := range map[string]any{
		"field":   struct{ M Message }{*m},
		"element": []Message{*m},
	} {
		got := fmt.Sprintf("%+v", arg)
		printed[name] = got
		if !strings.Contains(got, string(want)) {
			t.Errorf("%s prints as %s, want it to hold %s", name, got, want)
		}
	}
	for name, out := range printed {
		for _, secret := range secrets {
			if strings.Contains(out, secret) {
				t.Errorf("%s output contains %q:\n%s", name, secret, out)
			}
		}
	}
	if got := fmt.Sprintf("%v", (*Message)(nil)); got != "<nil>" {
		t.Errorf("a nil *Message prints as %q", got)
	}
}
