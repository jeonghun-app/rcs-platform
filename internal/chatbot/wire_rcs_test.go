package chatbot

import (
	"errors"
	"math"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/imdn"
)

const testMaxMessageSize = 256 << 10

func rcsWireCases() []wireCase {
	rcsLimit := MaxRCSBodyBytes(testMaxMessageSize)
	return []wireCase{
		{"Admission", rcsLimit, `{"chatbot":"` + testBot + `","subscriber":"` + testSub + `","anonymous":false}`,
			Admission{testBot, testSub, ptr(false)}},
		{"AdmissionAnswer", MaxAnswerBytes, `{"state":"suspended","out_of_service_text":"Back soon"}`,
			AdmissionAnswer{StateSuspended, "Back soon", ""}},
		{"DeliveryCheck", rcsLimit, `{"chatbot":"` + testBot + `","subscriber":"` + testSub + `"}`, DeliveryCheck{testBot, testSub}},
		{"DeliveryCheckAnswer", MaxAnswerBytes, `{"deliver":false,"reason":"blocked"}`, DeliveryCheckAnswer{ptr(false), ReasonBlocked}},
		{"SubscriberMessage", rcsLimit, `{"chatbot":"` + testBot + `","subscriber":"` + testSub + `","anonymous":false,
			"message_id":"Msg+1!x","date_time_ms":1762646400123,"content_type":"text/plain","body":"",
			"dispositions":{"positive_delivery":true,"negative_delivery":true,"display":false},"accepted_at_ms":1762646400456}`,
			testSubscriberMessage()},
		{"SubscriberMessageAnswer", MaxAnswerBytes, `{}`, SubscriberMessageAnswer{}},
		{"SubscriberNotification", rcsLimit, `{"chatbot":"` + testBot + `","subscriber":"` + testSub +
			`","anonymous":true,"message_id":"0f1e2d3c","kind":"delivery-notification","status":"failed"}`,
			SubscriberNotification{testBot, testSub, ptr(true), "0f1e2d3c", imdn.DeliveryNotification, imdn.Failed}},
		{"SubscriberNotificationAnswer", MaxAnswerBytes, `{}`, SubscriberNotificationAnswer{}},
	}
}

func testSubscriberMessage() SubscriberMessage {
	return SubscriberMessage{testBot, testSub, ptr(false), "Msg+1!x", 1762646400123, "text/plain", ptr(""),
		&Dispositions{PositiveDelivery: true, NegativeDelivery: true}, 1762646400456}
}

func rcsWireEnums() [][]string {
	enums := [][]string{
		append([]string{"state"}, chatbotStates...),
		append([]string{"admission reason"}, admissionReasons...),
		append([]string{"delivery reason"}, deliveryReasons...),
	}
	for _, k := range []imdn.Kind{imdn.DeliveryNotification, imdn.DisplayNotification} {
		values := []string{string(k)}
		for _, s := range notificationStatuses[k] {
			values = append(values, string(s))
		}
		enums = append(enums, values)
	}
	if len(notificationStatuses) != 2 {
		enums = append(enums, []string{"another notification kind"})
	}
	return enums
}

func TestTheRCSBodyLimitIsSixTimesTheMessageSizeAndNeverOverflows(t *testing.T) {
	if MaxRCSBodyBytes(testMaxMessageSize) != 6*testMaxMessageSize+8<<10 || MaxRCSBodyBytes(math.MaxInt64/6) != math.MaxInt64 {
		t.Errorf("MaxRCSBodyBytes(256 KiB) = %d, MaxRCSBodyBytes(MaxInt64/6) = %d",
			MaxRCSBodyBytes(testMaxMessageSize), MaxRCSBodyBytes(math.MaxInt64/6))
	}
	m := testSubscriberMessage()
	m.Body = ptr("a\x00\x7f")
	if err := m.Validate(); err != nil {
		t.Errorf("content is ValidateContent's to check, but Validate says %v", err)
	}
}

func TestSubscriberMessageIDsAreClientIDs(t *testing.T) {
	for id, want := range messageIDs {
		m := testSubscriberMessage()
		m.MessageID = id
		n := SubscriberNotification{testBot, testSub, ptr(false), id, imdn.DisplayNotification, imdn.Displayed}
		if (m.Validate() == nil) != want.client || (n.Validate() == nil) != want.client {
			t.Errorf("%q: SubscriberMessage %v, SubscriberNotification %v", id, m.Validate(), n.Validate())
		}
	}
}

func TestRCSEnumeratedAndNumericFieldsTakeOnlyTheirValues(t *testing.T) {
	status := func(k imdn.Kind, s imdn.Status) wireType {
		return SubscriberNotification{testBot, testSub, ptr(false), "id", k, s}
	}
	admit := func(state, text, reason string) wireType { return AdmissionAnswer{state, text, reason} }
	check := func(deliver bool, reason string) wireType { return DeliveryCheckAnswer{&deliver, reason} }
	msg := func(dateTime, acceptedAt int64) wireType {
		m := testSubscriberMessage()
		m.DateTimeMS, m.AcceptedAtMS = dateTime, acceptedAt
		return m
	}
	tests := map[string]struct {
		v    wireType
		want string // the refusal's reason, or "" for none
	}{
		"active":                  {admit(StateActive, "", ""), ""},
		"suspended":               {admit(StateSuspended, "x", ""), ""},
		"blocked":                 {admit("", "", ReasonBlocked), ""},
		"over limit":              {admit("", "", ReasonOverLimit), ""},
		"unknown chatbot":         {admit("", "", ReasonUnknown), ""},
		"no state, no reason":     {admit("", "", ""), "invalid state"},
		"blocked as a state":      {admit("blocked", "", ""), "invalid state"},
		"state and reason":        {admit(StateActive, "", ReasonBlocked), "invalid state"},
		"text with a reason":      {admit("", "x", ReasonBlocked), "invalid out_of_service_text"},
		"suspended as a reason":   {admit("", "", ReasonSuspended), "invalid reason"},
		"deliver":                 {check(true, ""), ""},
		"suspended reason":        {check(false, ReasonSuspended), ""},
		"unknown reason":          {check(false, ReasonUnknown), ""},
		"no reason":               {check(false, ""), "invalid reason"},
		"deliver with a reason":   {check(true, ReasonBlocked), "invalid reason"},
		"over limit, no delivery": {check(false, ReasonOverLimit), "invalid reason"},
		"delivered":               {status(imdn.DeliveryNotification, imdn.Delivered), ""},
		"delivery forbidden":      {status(imdn.DeliveryNotification, imdn.Forbidden), ""},
		"delivery error":          {status(imdn.DeliveryNotification, imdn.Error), ""},
		"displayed":               {status(imdn.DisplayNotification, imdn.Displayed), ""},
		"display error":           {status(imdn.DisplayNotification, imdn.Error), ""},
		"delivery displayed":      {status(imdn.DeliveryNotification, imdn.Displayed), "invalid status"},
		"display failed":          {status(imdn.DisplayNotification, imdn.Failed), "invalid status"},
		"display stored":          {status(imdn.DisplayNotification, imdn.Stored), "invalid status"},
		"processing":              {status(imdn.ProcessingNotification, imdn.Processed), "invalid kind"},
		"no DateTime":             {msg(0, 1), ""},
		"negative DateTime":       {msg(-1, 1), "invalid date_time_ms"},
		"negative accepted at":    {msg(1, -1), "invalid accepted_at_ms"},
	}
	for name, tc := range tests {
		if err := tc.v.Validate(); reasonOf(err) != tc.want || (err != nil && !errors.Is(err, ErrInvalidEnvelope)) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}
