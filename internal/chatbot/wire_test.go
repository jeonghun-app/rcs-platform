package chatbot

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/imdn"
)

type wireType interface{ Validate() error }

const (
	testBot = "sip:mybot@" + botDomain
	testSub = "tel:+15550100001"
)

func ptr[T any](v T) *T { return &v }

// wireCase is a valid value of one wire type, the body the other side
// writes for it, and the limit its receiver decodes it under.
type wireCase struct {
	name  string
	limit int64
	body  string
	value wireType
}

func wireCases() []wireCase {
	cases := []wireCase{
		{"BotMessage", MaxBotMessageBytes, `{"sender":"` + testBot + `","display_name":"My Bot","recipient":"` + testSub +
			`","message_id":"0f1e2d3c","content_type":"text/plain;charset=utf-8","body":"hi\r\n","chip_list":"{\"suggestions\":[]}",
			"dispositions":{"positive_delivery":true,"negative_delivery":false,"display":true},"anonymous":true}`,
			BotMessage{testBot, ptr("My Bot"), testSub, "0f1e2d3c", "text/plain;charset=utf-8", ptr("hi\r\n"), `{"suggestions":[]}`,
				&Dispositions{PositiveDelivery: true, Display: true}, ptr(true)}},
		{"BotMessageAnswer", MaxAnswerBytes, `{}`, BotMessageAnswer{}},
		{"BotNotification", MaxBotNotificationBytes,
			`{"chatbot":"` + testBot + `","subscriber":"` + testSub + `","message_id":"Msg+1!x","kind":"display-notification"}`,
			BotNotification{testBot, testSub, "Msg+1!x", imdn.DisplayNotification}},
		{"BotNotificationAnswer", MaxAnswerBytes, `{}`, BotNotificationAnswer{}},
	}
	return append(cases, rcsWireCases()...)
}

// wireEnums lists the values of every enumerated field, for
// TestWireContractIsPinned.
func wireEnums() [][]string {
	kinds := []string{"bot notification kind"}
	for _, k := range botNotificationKinds {
		kinds = append(kinds, string(k))
	}
	return append([][]string{kinds}, rcsWireEnums()...)
}

// fieldBounds are the bounded string fields and their bounds; the other
// string fields are enumerations.
var fieldBounds = map[string]int{
	"sender": MaxURIBytes, "recipient": MaxURIBytes, "chatbot": MaxURIBytes, "subscriber": MaxURIBytes,
	"display_name": MaxDisplayNameBytes, "message_id": MaxMessageIDBytes, "content_type": MaxContentTypeBytes,
	"out_of_service_text": MaxOutOfServiceTextBytes,
}

// decodeAs decodes body as a value of v's type; DecodeEnvelope validates it.
func decodeAs(v wireType, body string, limit int64) (wireType, error) {
	p := reflect.New(reflect.TypeOf(v))
	err := DecodeEnvelope(strings.NewReader(body), limit, p.Interface())
	return p.Elem().Interface().(wireType), err
}

// stringFields lists the string fields of v's type, pointers included, the
// content aside.
func stringFields(v wireType) []reflect.StructField {
	var fields []reflect.StructField
	for _, f := range reflect.VisibleFields(reflect.TypeOf(v)) {
		t := f.Type
		if t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if t.Kind() == reflect.String && f.Name != "Body" && f.Name != "ChipList" {
			fields = append(fields, f)
		}
	}
	return fields
}

// withField returns v with its string field f set to s.
func withField(v wireType, f reflect.StructField, s string) wireType {
	c := reflect.New(reflect.TypeOf(v)).Elem()
	c.Set(reflect.ValueOf(v))
	if fv := c.FieldByIndex(f.Index); fv.Kind() == reflect.Pointer {
		fv.Set(reflect.ValueOf(&s))
	} else {
		fv.SetString(s)
	}
	return c.Interface().(wireType)
}

func fieldString(v wireType, f reflect.StructField) string {
	return reflect.Indirect(reflect.ValueOf(v).FieldByIndex(f.Index)).String()
}

func jsonKey(f reflect.StructField) string { k, _, _ := strings.Cut(f.Tag.Get("json"), ","); return k }

func TestEveryWireTypeDecodesValidatesAndRoundTrips(t *testing.T) {
	snake := regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)
	for _, tc := range wireCases() {
		if got, err := decodeAs(tc.value, tc.body, tc.limit); err != nil || !reflect.DeepEqual(got, tc.value) {
			t.Errorf("%s: decoded %+v, %v; want %+v", tc.name, got, err, tc.value)
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

// wireContract is the first contract. If this test fails, the change must
// follow the rolling-update rule of the package documentation: a new field
// is omitempty, means the old behaviour when absent and is never required;
// a new enum value ships in the receiver first.
const wireContract = `BotMessage: sender display_name recipient message_id content_type body chip_list,omitempty dispositions anonymous
BotMessageAnswer:
BotNotification: chatbot subscriber message_id kind
BotNotificationAnswer:
Admission: chatbot subscriber anonymous
AdmissionAnswer: state,omitempty out_of_service_text,omitempty reason,omitempty
DeliveryCheck: chatbot subscriber
DeliveryCheckAnswer: deliver reason,omitempty
SubscriberMessage: chatbot subscriber anonymous message_id date_time_ms,omitempty content_type body dispositions accepted_at_ms
SubscriberMessageAnswer:
SubscriberNotification: chatbot subscriber anonymous message_id kind status
SubscriberNotificationAnswer:
Dispositions: positive_delivery negative_delivery display
bot notification kind: display-notification
state: active suspended
admission reason: blocked over_limit unknown
delivery reason: suspended blocked unknown
delivery-notification: delivered failed forbidden error
display-notification: displayed forbidden error
`

func TestWireContractIsPinned(t *testing.T) {
	var b strings.Builder
	line := func(name string, values []string) {
		fmt.Fprintln(&b, strings.TrimSpace(name+": "+strings.Join(values, " ")))
	}
	keys := func(typ reflect.Type) (tags []string) {
		for _, f := range reflect.VisibleFields(typ) {
			tags = append(tags, f.Tag.Get("json"))
		}
		return tags
	}
	for _, tc := range wireCases() {
		line(tc.name, keys(reflect.TypeOf(tc.value)))
	}
	line("Dispositions", keys(reflect.TypeFor[Dispositions]()))
	for _, e := range wireEnums() {
		line(e[0], e[1:])
	}
	if b.String() != wireContract {
		t.Errorf("the wire contract changed; see wireContract. Got:\n%s", b.String())
	}
}

// A sender that leaves out a field of the first contract, or writes null,
// is refused, not read as false, zero or empty (ADR 0009 §10: anonymous).
func TestARequiredFieldLeftOutIsRefused(t *testing.T) {
	for _, tc := range wireCases() {
		for _, f := range reflect.VisibleFields(reflect.TypeOf(tc.value)) {
			if strings.HasSuffix(f.Tag.Get("json"), ",omitempty") {
				continue
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal([]byte(tc.body), &body); err != nil {
				t.Fatal(err)
			}
			for _, absent := range []bool{true, false} {
				if delete(body, jsonKey(f)); !absent {
					body[jsonKey(f)] = json.RawMessage("null")
				}
				data, _ := json.Marshal(body)
				// DecodeEnvelope refuses a null that has no pointer to set.
				if _, err := decodeAs(tc.value, string(data), tc.limit); !errors.Is(err, ErrInvalidEnvelope) ||
					reasonOf(err) != "invalid "+jsonKey(f) && (absent || f.Type.Kind() == reflect.Pointer) {
					t.Errorf("%s without %s (null %v): %v", tc.name, jsonKey(f), !absent, err)
				}
			}
		}
	}
}

// longest returns v with every bounded string at its bound in its longest
// valid encoding. json.Marshal writes "<" and "&" as \u003c and \u0026;
// maap's Message-IDs hold neither.
func longest(v wireType) wireType {
	for _, f := range stringFields(v) {
		if n, ok := fieldBounds[jsonKey(f)]; ok {
			c := "<"
			if jsonKey(f) == "message_id" {
				c = map[bool]string{true: "a", false: "&"}[reflect.TypeOf(v) == reflect.TypeFor[BotMessage]()]
			}
			v = withField(v, f, strings.Repeat(c, n))
		}
	}
	switch m := v.(type) {
	case BotMessage:
		m.Body, m.ChipList = ptr(strings.Repeat("<", MaxContentBytes-1)), "<"
		v = m
	case SubscriberMessage:
		m.Body = ptr(strings.Repeat("<", testMaxMessageSize))
		v = m
	}
	return v
}

func TestTheBodyLimitsHoldTheLongestEncodingOfEveryValue(t *testing.T) {
	if MaxBotMessageBytes != 1496<<10 || MaxBotNotificationBytes != 8<<10 || MaxAnswerBytes != 8<<10 {
		t.Fatal("a body limit is not the one of ADR 0009 §9")
	}
	for _, tc := range wireCases() {
		data, _ := json.Marshal(longest(tc.value))
		if _, err := decodeAs(tc.value, string(data), tc.limit); err != nil {
			t.Errorf("%s: the longest encoding, %d bytes: %v", tc.name, len(data), err)
		}
	}
}

func TestValidateRefusesAControlInEveryFieldButTheContent(t *testing.T) {
	for _, tc := range wireCases() {
		for _, f := range stringFields(tc.value) {
			for _, c := range []string{"\x00", "\r\n", "\x1f", "\x7f"} {
				v := withField(tc.value, f, fieldString(tc.value, f)+c)
				if err := v.Validate(); !errors.Is(err, ErrInvalidEnvelope) || reasonOf(err) != "invalid "+jsonKey(f) {
					t.Errorf("%s.%s with %q: %v", tc.name, f.Name, c, err)
				}
			}
		}
	}
	bot := wireCases()[0].value.(BotMessage)
	bot.Body, bot.ChipList = ptr("a\x00\x7f"), "\x1b"
	if err := bot.Validate(); err != nil {
		t.Errorf("content is ValidateContent's to check, but Validate says %v", err)
	}
}

func TestEachFieldIsBoundedAtItsConstant(t *testing.T) {
	for _, tc := range wireCases() {
		for _, f := range stringFields(tc.value) {
			bound, ok := fieldBounds[jsonKey(f)]
			if !ok {
				continue
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
	m.Body, m.ChipList = ptr(strings.Repeat("a", MaxContentBytes-10)), strings.Repeat("a", 10)
	if err := m.Validate(); err != nil {
		t.Errorf("content at its bound: %v", err)
	}
	if m.ChipList += "a"; reasonOf(m.Validate()) != "invalid body" {
		t.Errorf("content over its bound: %v", m.Validate())
	}
}

// messageIDs says which Message-IDs the rule of maap's (generated) and of a
// client's accept. A client's must be one rcs-as can write into an IMDN.
var messageIDs = map[string]struct{ generated, client bool }{
	"":                       {false, false},
	"aZ09._~-":               {true, true},
	strings.Repeat("a", 128): {true, true},
	"Msg+1!#$%&'*^`|":        {false, true},
	"é":                      {false, true},
	"a/b":                    {false, false},
	"a@b":                    {false, false},
	"a b":                    {false, false},
	`a<"b";,`:                {false, false},
	"a\uFFFE":                {false, false},
	"a\x7f":                  {false, false},
	strings.Repeat("a", 129): {false, false},
}

func TestBotMessageIDsFollowTheRuleOfWhoChoseThem(t *testing.T) {
	for id, want := range messageIDs {
		bot := wireCases()[0].value.(BotMessage)
		bot.MessageID = id
		note := BotNotification{testBot, testSub, id, imdn.DisplayNotification}
		if (bot.Validate() == nil) != want.generated || (note.Validate() == nil) != want.client {
			t.Errorf("%q: BotMessage %v, BotNotification %v", id, bot.Validate(), note.Validate())
		}
	}
	note := BotNotification{testBot, testSub, "id", imdn.DeliveryNotification}
	if reasonOf(note.Validate()) != "invalid kind" {
		t.Errorf("a chatbot's delivery notification: %v", note.Validate())
	}
}
