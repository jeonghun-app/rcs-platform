package chatbot

import (
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/imdn"
)

type wireType interface{ Validate() error }

const (
	testBot            = "sip:mybot@" + botDomain
	testSub            = "tel:+15550100001"
	testMaxMessageSize = 256 << 10
)

// wireCase is a valid value of one wire type, the body the other side
// writes for it, and the limit its receiver decodes it under.
type wireCase struct {
	name  string
	limit int64
	body  string
	value wireType
}

func wireCases() []wireCase {
	rcsLimit := MaxRCSBodyBytes(testMaxMessageSize)
	return []wireCase{
		{"BotMessage", MaxBotMessageBytes, `{"sender":"` + testBot + `","display_name":"My Bot","recipient":"` + testSub +
			`","message_id":"0f1e2d3c","content_type":"text/plain;charset=utf-8","body":"hi\r\n","chip_list":"{\"suggestions\":[]}",
			"dispositions":{"positive_delivery":true,"negative_delivery":false,"display":true},"anonymous":true}`,
			BotMessage{testBot, "My Bot", testSub, "0f1e2d3c", "text/plain;charset=utf-8", "hi\r\n", `{"suggestions":[]}`,
				Dispositions{PositiveDelivery: true, Display: true}, true}},
		{"BotMessageAnswer", MaxAnswerBytes, `{}`, BotMessageAnswer{}},
		{"BotNotification", MaxBotNotificationBytes,
			`{"chatbot":"` + testBot + `","subscriber":"` + testSub + `","message_id":"Msg+1@x","kind":"display-notification"}`,
			BotNotification{testBot, testSub, "Msg+1@x", imdn.DisplayNotification}},
		{"BotNotificationAnswer", MaxAnswerBytes, `{}`, BotNotificationAnswer{}},
		{"Admission", rcsLimit, `{"chatbot":"` + testBot + `","subscriber":"` + testSub + `","anonymous":true}`,
			Admission{testBot, testSub, true}},
		{"AdmissionAnswer", MaxAnswerBytes, `{"state":"suspended","out_of_service_text":"Back soon"}`,
			AdmissionAnswer{StateSuspended, "Back soon"}},
		{"DeliveryCheck", rcsLimit, `{"chatbot":"` + testBot + `","subscriber":"` + testSub + `"}`, DeliveryCheck{testBot, testSub}},
		{"DeliveryCheckAnswer", MaxAnswerBytes, `{"deliver":false,"reason":"blocked"}`, DeliveryCheckAnswer{false, ReasonBlocked}},
		{"SubscriberMessage", rcsLimit, `{"chatbot":"` + testBot + `","subscriber":"` + testSub + `","anonymous":false,
			"message_id":"Msg+1@x","date_time_ms":1762646400123,"content_type":"text/plain","body":"hello",
			"dispositions":{"positive_delivery":true,"negative_delivery":true,"display":false},"accepted_at_ms":1762646400456}`,
			SubscriberMessage{testBot, testSub, false, "Msg+1@x", 1762646400123, "text/plain", "hello",
				Dispositions{PositiveDelivery: true, NegativeDelivery: true}, 1762646400456}},
		{"SubscriberMessageAnswer", MaxAnswerBytes, `{}`, SubscriberMessageAnswer{}},
		{"SubscriberNotification", rcsLimit, `{"chatbot":"` + testBot + `","subscriber":"` + testSub +
			`","anonymous":true,"message_id":"0f1e2d3c","kind":"delivery-notification","status":"failed"}`,
			SubscriberNotification{testBot, testSub, true, "0f1e2d3c", imdn.DeliveryNotification, imdn.Failed}},
		{"SubscriberNotificationAnswer", MaxAnswerBytes, `{}`, SubscriberNotificationAnswer{}},
	}
}

// decodeAs decodes body as a value of v's type.
func decodeAs(v wireType, body string, limit int64) (wireType, error) {
	p := reflect.New(reflect.TypeOf(v))
	err := DecodeEnvelope(strings.NewReader(body), limit, p.Interface())
	return p.Elem().Interface().(wireType), err
}

// stringFields lists the string fields of v's type, the content aside.
func stringFields(v wireType) []reflect.StructField {
	var fields []reflect.StructField
	for _, f := range reflect.VisibleFields(reflect.TypeOf(v)) {
		if f.Type.Kind() == reflect.String && f.Name != "Body" && f.Name != "ChipList" {
			fields = append(fields, f)
		}
	}
	return fields
}

// withField returns v with its string field f set to s.
func withField(v wireType, f reflect.StructField, s string) wireType {
	c := reflect.New(reflect.TypeOf(v)).Elem()
	c.Set(reflect.ValueOf(v))
	c.FieldByIndex(f.Index).SetString(s)
	return c.Interface().(wireType)
}

func jsonKey(f reflect.StructField) string { k, _, _ := strings.Cut(f.Tag.Get("json"), ","); return k }

func TestEveryWireTypeDecodesValidatesAndRoundTrips(t *testing.T) {
	snake := regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)
	for _, tc := range wireCases() {
		got, err := decodeAs(tc.value, tc.body, tc.limit)
		if err != nil || !reflect.DeepEqual(got, tc.value) {
			t.Errorf("%s: decoded %+v, %v; want %+v", tc.name, got, err, tc.value)
		}
		if err := tc.value.Validate(); err != nil {
			t.Errorf("%s: Validate: %v", tc.name, err)
		}
		data, _ := json.Marshal(tc.value)
		if again, err := decodeAs(tc.value, string(data), tc.limit); err != nil || !reflect.DeepEqual(again, tc.value) {
			t.Errorf("%s: %s decoded to %+v, %v", tc.name, data, again, err)
		}
		for _, typ := range []reflect.Type{reflect.TypeOf(tc.value), reflect.TypeFor[Dispositions]()} {
			for _, f := range reflect.VisibleFields(typ) {
				if !snake.MatchString(jsonKey(f)) {
					t.Errorf("%s.%s: JSON name %q is not snake_case", typ.Name(), f.Name, jsonKey(f))
				}
			}
		}
	}
}

// json.Marshal writes "<" as \u003c, so strings of "<" are the longest
// encoding of a value: what a limit must hold.
func TestTheBodyLimitsHoldTheLongestEncodingOfEveryValue(t *testing.T) {
	if MaxBotMessageBytes != 1496<<10 || MaxBotNotificationBytes != 8<<10 || MaxAnswerBytes != 8<<10 ||
		MaxRCSBodyBytes(testMaxMessageSize) != 6*testMaxMessageSize+8<<10 {
		t.Fatal("a body limit is not the one of ADR 0009 §9")
	}
	for _, tc := range wireCases() {
		v := tc.value
		for _, f := range stringFields(v) {
			n, _ := strconv.Atoi(f.Tag.Get("maxbytes"))
			v = withField(v, f, strings.Repeat("<", n))
		}
		switch m := v.(type) {
		case BotMessage:
			m.Body, m.ChipList = strings.Repeat("<", MaxContentBytes-1), "<"
			v = m
		case SubscriberMessage:
			m.Body = strings.Repeat("<", testMaxMessageSize)
			v = m
		}
		data, _ := json.Marshal(v)
		if _, err := decodeAs(tc.value, string(data), tc.limit); err != nil {
			t.Errorf("%s: the longest encoding, %d bytes: %v", tc.name, len(data), err)
		}
	}
}

func TestValidateRefusesAControlInEveryFieldButTheContent(t *testing.T) {
	for _, tc := range wireCases() {
		for _, f := range stringFields(tc.value) {
			for _, c := range []string{"\x00", "\r\n", "\x1f", "\x7f"} {
				v := withField(tc.value, f, reflect.ValueOf(tc.value).FieldByIndex(f.Index).String()+c)
				if err := v.Validate(); !errors.Is(err, ErrInvalidEnvelope) || reasonOf(err) != "invalid "+jsonKey(f) {
					t.Errorf("%s.%s with %q: %v", tc.name, f.Name, c, err)
				}
			}
		}
	}
	for _, v := range []wireType{
		BotMessage{testBot, "", testSub, "id", "text/plain", "a\x00\x7f", "\x1b", Dispositions{}, false},
		SubscriberMessage{testBot, testSub, false, "id", 0, "text/plain", "a\x00\x7f", Dispositions{}, 0},
	} {
		if err := v.Validate(); err != nil {
			t.Errorf("%T: content is ValidateContent's to check, but Validate says %v", v, err)
		}
	}
}

func TestEachFieldIsBoundedAtItsConstant(t *testing.T) {
	bounds := map[string]int{
		"sender": MaxURIBytes, "recipient": MaxURIBytes, "chatbot": MaxURIBytes, "subscriber": MaxURIBytes,
		"display_name": MaxDisplayNameBytes, "out_of_service_text": MaxOutOfServiceTextBytes,
		"message_id": MaxMessageIDBytes, "content_type": MaxContentTypeBytes,
	}
	for _, tc := range wireCases() {
		for _, f := range stringFields(tc.value) {
			bound, ok := bounds[jsonKey(f)]
			if !ok {
				continue // an enumeration
			}
			if f.Tag.Get("maxbytes") != strconv.Itoa(bound) {
				t.Errorf("%s.%s: maxbytes %s, want %d", tc.name, f.Name, f.Tag.Get("maxbytes"), bound)
			}
			for n, ok := range map[int]bool{bound: true, bound + 1: false} {
				if err := withField(tc.value, f, strings.Repeat("a", n)).Validate(); (err == nil) != ok {
					t.Errorf("%s.%s of %d bytes: %v", tc.name, f.Name, n, err)
				}
			}
		}
	}
	m := wireCases()[0].value.(BotMessage)
	m.Body, m.ChipList = strings.Repeat("a", MaxContentBytes-10), strings.Repeat("a", 10)
	if err := m.Validate(); err != nil {
		t.Errorf("content at its bound: %v", err)
	}
	if m.ChipList += "a"; reasonOf(m.Validate()) != "invalid body and chip_list together" {
		t.Errorf("content over its bound: %v", m.Validate())
	}
}

// maap generates a chatbot's Message-ID; a subscriber's client chose the
// others, as a CPIM token rcs-as checked.
func TestMessageIDsFollowTheRuleOfWhoChoseThem(t *testing.T) {
	tests := map[string]struct{ generated, client bool }{
		"":                       {false, false},
		"aZ09._~-":               {true, true},
		strings.Repeat("a", 128): {true, true},
		"a/b":                    {false, true},
		"Msg+1@x!%*'`":           {false, true},
		"é":                      {false, true},
		"a b":                    {false, true},
		"a\x7f":                  {false, false},
		strings.Repeat("a", 129): {false, false},
	}
	for id, want := range tests {
		bot := wireCases()[0].value.(BotMessage)
		bot.MessageID = id
		sub := SubscriberMessage{Chatbot: testBot, Subscriber: testSub, MessageID: id}
		note := BotNotification{testBot, testSub, id, imdn.DisplayNotification}
		status := SubscriberNotification{testBot, testSub, false, id, imdn.DisplayNotification, imdn.Displayed}
		if (bot.Validate() == nil) != want.generated {
			t.Errorf("BotMessage %q: %v", id, bot.Validate())
		}
		for _, v := range []wireType{sub, note, status} {
			if (v.Validate() == nil) != want.client {
				t.Errorf("%T %q: %v", v, id, v.Validate())
			}
		}
	}
}

func TestEnumeratedFieldsTakeOnlyTheirValues(t *testing.T) {
	note := func(k imdn.Kind) wireType { return BotNotification{testBot, testSub, "id", k} }
	status := func(k imdn.Kind, s imdn.Status) wireType {
		return SubscriberNotification{testBot, testSub, false, "id", k, s}
	}
	tests := map[string]struct {
		v    wireType
		want string // the refusal's reason, or "" for none
	}{
		"bot display":           {note(imdn.DisplayNotification), ""},
		"bot delivery":          {note(imdn.DeliveryNotification), "invalid kind"},
		"bot no kind":           {note(""), "invalid kind"},
		"active":                {AdmissionAnswer{StateActive, ""}, ""},
		"suspended":             {AdmissionAnswer{StateSuspended, "x"}, ""},
		"no state":              {AdmissionAnswer{"", ""}, "invalid state"},
		"blocked state":         {AdmissionAnswer{"blocked", ""}, "invalid state"},
		"deliver":               {DeliveryCheckAnswer{true, ""}, ""},
		"suspended reason":      {DeliveryCheckAnswer{false, ReasonSuspended}, ""},
		"unknown reason":        {DeliveryCheckAnswer{false, ReasonUnknown}, ""},
		"no reason":             {DeliveryCheckAnswer{false, ""}, "invalid reason"},
		"deliver with a reason": {DeliveryCheckAnswer{true, ReasonBlocked}, "invalid reason"},
		"other reason":          {DeliveryCheckAnswer{false, "busy"}, "invalid reason"},
		"delivered":             {status(imdn.DeliveryNotification, imdn.Delivered), ""},
		"delivery forbidden":    {status(imdn.DeliveryNotification, imdn.Forbidden), ""},
		"delivery error":        {status(imdn.DeliveryNotification, imdn.Error), ""},
		"displayed":             {status(imdn.DisplayNotification, imdn.Displayed), ""},
		"display error":         {status(imdn.DisplayNotification, imdn.Error), ""},
		"delivery displayed":    {status(imdn.DeliveryNotification, imdn.Displayed), "invalid status"},
		"display failed":        {status(imdn.DisplayNotification, imdn.Failed), "invalid status"},
		"display stored":        {status(imdn.DisplayNotification, imdn.Stored), "invalid status"},
		"processing":            {status(imdn.ProcessingNotification, imdn.Processed), "invalid kind"},
		"no status":             {status(imdn.DeliveryNotification, ""), "invalid status"},
	}
	for name, tc := range tests {
		if err := tc.v.Validate(); reasonOf(err) != tc.want || (err != nil && !errors.Is(err, ErrInvalidEnvelope)) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}
