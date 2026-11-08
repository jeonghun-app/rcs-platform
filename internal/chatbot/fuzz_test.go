package chatbot

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// FuzzNormalise checks that a normal form is a fixed point inside the bound,
// that an accepted URI writes back as received, that the strict parse never
// reads a URI as at the chatbot domain that the loose check misses, and,
// with the input as a user part, that Normalise and UserPartERE accept the
// same ones.
func FuzzNormalise(f *testing.F) {
	for _, s := range []string{
		"sip:mybot@" + botDomain, "sip:my-bot.pub@" + botDomain + ";tk=on", "sips:mybot@" + botDomain,
		"sip:mybot@" + botDomain + ":5060", "sip:a@b@" + botDomain, "tel:+15550100001", "mybot", "a.b.c", "my%62ot",
		"sip:sips:@" + botDomain, "sip:mybot@" + botDomain + ";x=@evil.example.net",
	} {
		f.Add(s)
	}
	d, ere := testDomain(f), userPartMatcher(f)
	f.Fuzz(func(t *testing.T, s string) {
		got, err := d.Normalise(s)
		switch {
		case err == nil:
			user, ok := strings.CutPrefix(strings.TrimSuffix(got, "@"+botDomain), "sip:")
			if !ok || !ere.MatchString(user) || len(got) > MaxURIBytes {
				t.Fatalf("Normalise(%q) = %q, not a normal form", s, got)
			}
			if again, err := d.Normalise(got); err != nil || again != got {
				t.Fatalf("Normalise(%q) = %q, %v; want it unchanged", got, again, err)
			}
			if u, _ := sip.ParseURI(s); u.String() != "sip"+s[len("sip"):] {
				t.Fatalf("Normalise accepted %q, which writes back as %q", s, u.String())
			}
		case errors.Is(err, ErrNotChatbot):
			if u, perr := sip.ParseURI(s); perr == nil && (u.Scheme == "sip" || u.Scheme == "sips") && strings.EqualFold(u.Host, botDomain) {
				t.Fatalf("Normalise(%q): ErrNotChatbot for a URI parsed at the chatbot domain", s)
			}
		case !errors.Is(err, ErrNotNormal):
			t.Fatalf("Normalise(%q): unexpected error %v", s, err)
		}
		_, err = d.Normalise("sip:" + s + "@" + botDomain)
		if (err == nil) != ere.MatchString(s) {
			t.Fatalf("user part %q: Normalise error %v, ERE match %v", s, err, ere.MatchString(s))
		}
	})
}

// FuzzValidateContent checks that accepted content is UTF-8 without the
// refused controls and, for a JSON type, that encoding/json reads it as one
// value whose re-encoding is accepted too.
func FuzzValidateContent(f *testing.F) {
	for _, s := range []string{"hi\r\n", `{"a":[1,2,{"b":null}]}`, `{"a":1,"a":2}`, "[[[[]]]]", "1e400", "\x00", "\xff", `"x" 1`} {
		f.Add(true, []byte(s))
		f.Add(false, []byte(s))
	}
	f.Fuzz(func(t *testing.T, isJSON bool, body []byte) {
		contentType := "text/plain"
		if isJSON {
			contentType = RichCardType
		}
		if ValidateContent(contentType, body) != nil {
			return
		}
		if !utf8.Valid(body) || bytes.ContainsFunc(body, func(r rune) bool { return r < 0x20 && r != '\t' && r != '\r' && r != '\n' }) {
			t.Fatalf("accepted %q", body)
		}
		if !isJSON {
			return
		}
		var v any
		if err := json.Unmarshal(body, &v); err != nil {
			t.Fatalf("accepted %q, which encoding/json refuses: %v", body, err)
		}
		again, _ := json.Marshal(v)
		if err := ValidateContent(contentType, again); err != nil {
			t.Fatalf("accepted %q but not its re-encoding %q: %v", body, again, err)
		}
	})
}

// FuzzDecodeEnvelope checks that an accepted envelope keeps every bound and
// that encoding it again decodes to the same value.
func FuzzDecodeEnvelope(f *testing.F) {
	for _, s := range []string{
		`{"body":"hi","count":1,"tags":["a"],"item":{"kind":"x"},"items":[{"kind":"y"}],"nest":{"next":{}}}`,
		`{"Body":"x"}`, `{"body":"a","body":"b"}`, `{"body":"😀"}`, `{"body":"\ud800"}`, `{"count":1e400}`, `{} {}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var e testEnvelope
		err := DecodeEnvelope(bytes.NewReader(data), 256, &e)
		if err != nil {
			if !errors.Is(err, ErrInvalidEnvelope) && !errors.Is(err, ErrBodyTooLarge) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		if len(e.Body) > 64 || len(e.Tags) > MaxEnvelopeArray || len(e.Items) > MaxEnvelopeArray {
			t.Fatalf("%q decoded past a bound: %+v", data, e)
		}
		for _, tag := range e.Tags {
			if len(tag) > 8 {
				t.Fatalf("%q decoded a tag past its bound", data)
			}
		}
		again, _ := json.Marshal(e)
		var e2 testEnvelope
		if err := DecodeEnvelope(bytes.NewReader(again), int64(len(again)), &e2); err != nil || !reflect.DeepEqual(e, e2) {
			t.Fatalf("%q decoded to %+v; its encoding %q decoded to %+v, %v", data, e, again, e2, err)
		}
	})
}

// FuzzBotMessage and FuzzBotNotification check rcs-as's chatbot API bodies
// (memo J6): DecodeEnvelope and Validate never panic, and a body they accept
// encodes again to one they accept, of the same value.
func FuzzBotMessage(f *testing.F) {
	addWireSeeds(f, "BotMessage")
	f.Fuzz(func(t *testing.T, data []byte) { checkWireBody[BotMessage](t, data, MaxBotMessageBytes) })
}

func FuzzBotNotification(f *testing.F) {
	addWireSeeds(f, "BotNotification")
	f.Fuzz(func(t *testing.T, data []byte) { checkWireBody[BotNotification](t, data, MaxBotNotificationBytes) })
}

func addWireSeeds(f *testing.F, name string) {
	for _, tc := range wireCases() {
		if tc.name == name {
			f.Add([]byte(tc.body))
			f.Add([]byte(strings.Replace(tc.body, `"tel:`, `"\r\ntel:`, 1)))
		}
	}
	f.Add([]byte(`{"dispositions":null}`))
}

func checkWireBody[T any, P interface {
	*T
	wireType
}](t *testing.T, data []byte, limit int64) {
	var v T
	err := DecodeEnvelope(bytes.NewReader(data), limit, P(&v))
	if err == nil {
		err = P(&v).Validate()
	}
	if err != nil {
		if !errors.Is(err, ErrInvalidEnvelope) && !errors.Is(err, ErrBodyTooLarge) {
			t.Fatalf("unexpected error %v", err)
		}
		return
	}
	again, _ := json.Marshal(v)
	var v2 T
	if err := DecodeEnvelope(bytes.NewReader(again), limit, P(&v2)); err != nil || P(&v2).Validate() != nil || !reflect.DeepEqual(v, v2) {
		t.Fatalf("%q was accepted as %+v; its encoding %q gave %+v, %v", data, v, again, v2, err)
	}
}
