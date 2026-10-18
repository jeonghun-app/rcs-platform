package imdn

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
)

const (
	alice = "sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org"
	bob   = "sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org"
	focus = "sip:focus@ims.mnc001.mcc001.3gppnetwork.org"
	relay = "sip:rcs-as@ims.mnc001.mcc001.3gppnetwork.org"
)

func crlf(s string) []byte {
	return []byte(strings.ReplaceAll(s, "\n", "\r\n"))
}

func mustCPIM(t *testing.T, s string) *cpim.Message {
	t.Helper()
	m, err := cpim.Parse(crlf(s))
	if err != nil {
		t.Fatalf("cpim.Parse: %v", err)
	}
	return m
}

func TestParseDispositionsReadsEveryDefinedValue(t *testing.T) {
	tests := map[string]Disposition{
		"positive-delivery, negative-delivery": PositiveDelivery | NegativeDelivery,
		"display":                              Display,
		"processing":                           Processing,
		"positive-delivery,display ,  processing": PositiveDelivery | Display | Processing,
		"display;x=1 ; y=2":                       Display,
		"future-value, display":                   Display,
		"Display":                                 0,
		"":                                        0,
		"   ":                                     0,
		"negative-delivery, negative-delivery":    NegativeDelivery,
		"positive-delivery, negative-delivery, display, processing": PositiveDelivery | NegativeDelivery | Display | Processing,
	}
	for in, want := range tests {
		got, err := ParseDispositions(in)
		if err != nil || got != want {
			t.Errorf("ParseDispositions(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
}

func TestMalformedDispositionsAreRejected(t *testing.T) {
	for _, in := range []string{"display,,", ",display", "dis play", "display;", "display;x", "display;=1", "dis/play"} {
		if _, err := ParseDispositions(in); !errors.Is(err, ErrMalformed) {
			t.Errorf("ParseDispositions(%q) error = %v, want ErrMalformed", in, err)
		}
	}
}

func TestDispositionStringRoundTripsEveryCombination(t *testing.T) {
	if got := (PositiveDelivery | Display | NegativeDelivery).String(); got != "positive-delivery, negative-delivery, display" {
		t.Errorf("String() = %q", got)
	}
	for d := Disposition(0); d < 16; d++ {
		back, err := ParseDispositions(d.String())
		if err != nil || back != d {
			t.Errorf("ParseDispositions(%q) = %v, %v; want %v", d.String(), back, err, d)
		}
	}
}

func TestWantsMatchesEachStatusToTheRequestItAnswers(t *testing.T) {
	all := PositiveDelivery | NegativeDelivery | Display | Processing
	tests := []struct {
		d    Disposition
		k    Kind
		s    Status
		want bool
	}{
		{PositiveDelivery, DeliveryNotification, Delivered, true},
		{NegativeDelivery, DeliveryNotification, Delivered, false},
		{NegativeDelivery, DeliveryNotification, Failed, true},
		{NegativeDelivery, DeliveryNotification, Forbidden, true},
		{PositiveDelivery, DeliveryNotification, Forbidden, true},
		{Display | Processing, DeliveryNotification, Forbidden, false},
		{NegativeDelivery, DeliveryNotification, Error, true},
		{PositiveDelivery, DeliveryNotification, Failed, false},
		{Display, DisplayNotification, Displayed, true},
		{Display, DisplayNotification, Forbidden, true},
		{Display, DisplayNotification, Error, true},
		{all &^ Display, DisplayNotification, Displayed, false},
		{Processing, ProcessingNotification, Processed, true},
		{Processing, ProcessingNotification, Stored, true},
		{all &^ Processing, ProcessingNotification, Stored, false},
		{all, DeliveryNotification, Displayed, false},
		{all, DisplayNotification, Delivered, false},
		{all, ProcessingNotification, Failed, false},
		{all, Kind("other-notification"), Error, false},
	}
	for _, tt := range tests {
		if got := tt.d.Wants(tt.k, tt.s); got != tt.want {
			t.Errorf("%v.Wants(%s, %s) = %v, want %v", tt.d, tt.k, tt.s, got, tt.want)
		}
	}
}

func TestParseRequestReadsEverythingANotificationNeeds(t *testing.T) {
	m := mustCPIM(t, `From: <`+alice+`>
To: <`+bob+`>
NS: imdn <urn:ietf:params:imdn>
imdn.Message-ID: Kd3Pq8sXw2
DateTime: 2026-10-18T09:30:00+09:00
imdn.Disposition-Notification: positive-delivery, display
imdn.Original-To: Group <`+focus+`>
imdn.IMDN-Record-Route: <`+relay+`>
imdn.IMDN-Record-Route: <`+focus+`>

Content-Type: text/plain

Hello`)
	r, err := ParseRequest(m)
	if err != nil {
		t.Fatal(err)
	}
	want := Request{
		MessageID:    "Kd3Pq8sXw2",
		DateTime:     "2026-10-18T09:30:00+09:00",
		Dispositions: PositiveDelivery | Display,
		OriginalTo:   cpim.Address{Name: "Group", URI: focus},
		RecordRoute:  []cpim.Address{{URI: relay}, {URI: focus}},
	}
	if !reflect.DeepEqual(r, want) {
		t.Errorf("ParseRequest() = %+v\nwant %+v", r, want)
	}
	if got, err := r.Time(); err != nil || !got.Equal(time.Date(2026, 10, 18, 0, 30, 0, 0, time.UTC)) {
		t.Errorf("Time() = %v, %v", got, err)
	}
}

func TestParseRequestAcceptsWhateverPrefixTheSenderChose(t *testing.T) {
	m := mustCPIM(t, `NS: n <urn:ietf:params:imdn>
n.Message-ID: abc
DateTime: 2026-10-18T00:30:00Z
n.Disposition-Notification: display
n.Disposition-Notification: negative-delivery

Content-Type: text/plain

`)
	r, err := ParseRequest(m)
	if err != nil || r.MessageID != "abc" || r.Dispositions != Display|NegativeDelivery {
		t.Errorf("ParseRequest() = %+v, %v", r, err)
	}
}

func TestMessageWithoutARequestAsksForNothing(t *testing.T) {
	m := mustCPIM(t, "From: <"+alice+">\nNS: imdn <urn:ietf:params:imdn>\nimdn.Message-ID: abc\n\nContent-Type: text/plain\n\n")
	r, err := ParseRequest(m)
	if err != nil || r.Dispositions != 0 || r.MessageID != "abc" {
		t.Errorf("ParseRequest() = %+v, %v", r, err)
	}
}

func TestRequestWithoutMessageIDOrDateTimeIsIncomplete(t *testing.T) {
	for name, msg := range map[string]string{
		"no Message-ID": "NS: imdn <urn:ietf:params:imdn>\nDateTime: 2026-10-18T00:30:00Z\nimdn.Disposition-Notification: display\n",
		"no DateTime":   "NS: imdn <urn:ietf:params:imdn>\nimdn.Message-ID: abc\nimdn.Disposition-Notification: display\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseRequest(mustCPIM(t, msg+"\nContent-Type: text/plain\n\n"))
			if !errors.Is(err, ErrIncompleteRequest) {
				t.Errorf("ParseRequest() error = %v, want ErrIncompleteRequest", err)
			}
		})
	}
}

func TestANotificationCannotRequestNotifications(t *testing.T) {
	m := mustCPIM(t, `NS: imdn <urn:ietf:params:imdn>
imdn.Message-ID: abc
DateTime: 2026-10-18T00:30:00Z
imdn.Disposition-Notification: positive-delivery

Content-Type: message/imdn+xml
Content-Disposition: notification

`)
	r, err := ParseRequest(m)
	if err != nil || r.Dispositions != 0 {
		t.Errorf("ParseRequest() = %+v, %v; a request inside an IMDN must be ignored", r, err)
	}
}

func TestParseRequestRejectsMalformedHeaders(t *testing.T) {
	ns := cpim.Header{Name: "NS", Value: "imdn <urn:ietf:params:imdn>"}
	dt := cpim.Header{Name: "DateTime", Value: "2026-10-18T00:30:00Z"}
	id := cpim.Header{Name: "imdn.Message-ID", Value: "abc"}
	tests := map[string][]cpim.Header{
		"two Message-IDs":        {ns, id, id},
		"Message-ID not a token": {ns, {Name: "imdn.Message-ID", Value: "a b"}},
		"bad dispositions":       {ns, id, dt, {Name: "imdn.Disposition-Notification", Value: "display,,"}},
		"two Original-To":        {ns, id, {Name: "imdn.Original-To", Value: "<" + focus + ">"}, {Name: "imdn.Original-To", Value: "<" + focus + ">"}},
		"bad Original-To":        {ns, id, {Name: "imdn.Original-To", Value: focus}},
		"bad IMDN-Record-Route":  {ns, id, {Name: "imdn.IMDN-Record-Route", Value: relay}},
	}
	for name, headers := range tests {
		t.Run(name, func(t *testing.T) {
			m := &cpim.Message{Headers: headers}
			if _, err := ParseRequest(m); !errors.Is(err, ErrMalformed) && !errors.Is(err, cpim.ErrMalformed) {
				t.Errorf("ParseRequest() error = %v, want a malformed error", err)
			}
		})
	}
}

func chatToBob(t *testing.T) *cpim.Message {
	t.Helper()
	m := &cpim.Message{}
	for _, h := range [][2]string{
		{cpim.HeaderFrom, "<" + alice + ">"},
		{cpim.HeaderTo, "<" + bob + ">"},
		{cpim.HeaderDateTime, "2026-10-18T00:30:00Z"},
	} {
		if err := m.Add(cpim.CoreNamespace, h[0], h[1]); err != nil {
			t.Fatal(err)
		}
	}
	m.ContentHeaders = []cpim.Field{{Name: "Content-Type", Value: "text/plain"}}
	m.Body = []byte("Hi")
	return m
}

func TestAddRequestWritesTheHeadersARecipientReads(t *testing.T) {
	m := chatToBob(t)
	if err := AddRequest(m, "Kd3Pq8sXw2", PositiveDelivery|Display); err != nil {
		t.Fatal(err)
	}
	out, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := crlf(`From: <` + alice + `>
To: <` + bob + `>
DateTime: 2026-10-18T00:30:00Z
NS: imdn <urn:ietf:params:imdn>
imdn.Message-ID: Kd3Pq8sXw2
imdn.Disposition-Notification: positive-delivery, display

Content-Type: text/plain

Hi`)
	if !bytes.Equal(out, want) {
		t.Errorf("Marshal() =\n%s\nwant\n%s", out, want)
	}
	parsed, err := cpim.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseRequest(parsed)
	if err != nil || r.MessageID != "Kd3Pq8sXw2" || r.Dispositions != PositiveDelivery|Display {
		t.Errorf("ParseRequest() = %+v, %v", r, err)
	}
}

func TestAddRequestReusesAnExistingPrefix(t *testing.T) {
	m := chatToBob(t)
	if err := m.Declare("x", Namespace); err != nil {
		t.Fatal(err)
	}
	if err := AddRequest(m, "abc", Display); err != nil {
		t.Fatal(err)
	}
	if got := m.Headers[len(m.Headers)-1].Name; got != "x.Disposition-Notification" {
		t.Errorf("last header = %q", got)
	}
}

func TestAddRequestRefusesWhatARecipientCouldNotAnswer(t *testing.T) {
	tests := map[string]struct {
		prepare func(m *cpim.Message)
		id      string
		d       Disposition
	}{
		"nothing requested":    {func(*cpim.Message) {}, "abc", 0},
		"undefined bits only":  {func(*cpim.Message) {}, "abc", 1 << 6},
		"Message-ID not token": {func(*cpim.Message) {}, "a b", Display},
		"no DateTime":          {func(m *cpim.Message) { m.Headers = m.Headers[:2] }, "abc", Display},
		"Message-ID present": {func(m *cpim.Message) {
			_ = m.Declare(Prefix, Namespace)
			_ = m.Add(Namespace, HeaderMessageID, "old")
		}, "abc", Display},
		"request present": {func(m *cpim.Message) {
			_ = m.Declare(Prefix, Namespace)
			_ = m.Add(Namespace, HeaderDispositionNotification, "display")
		}, "abc", Display},
		"NS header unwritable": {func(m *cpim.Message) {
			_ = m.Declare("", "urn:example:other")
		}, "abc", Display},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := chatToBob(t)
			tt.prepare(m)
			if err := AddRequest(m, tt.id, tt.d); err == nil {
				t.Error("AddRequest succeeded")
			}
		})
	}
}

func TestNewMessageIDCarries128BitsFromTheGivenSource(t *testing.T) {
	src := bytes.NewReader(bytes.Repeat([]byte{0xab}, 16))
	id, err := NewMessageID(src)
	if err != nil || id != strings.Repeat("ab", 16) {
		t.Errorf("NewMessageID() = %q, %v", id, err)
	}
	if _, err := NewMessageID(iotest.ErrReader(errors.New("no entropy"))); err == nil {
		t.Error("NewMessageID ignored a failing source")
	}
	if _, err := NewMessageID(bytes.NewReader(make([]byte, 8))); err == nil {
		t.Error("NewMessageID accepted 64 bits when it promises 128")
	}
	a, errA := NewMessageID(nil)
	b, errB := NewMessageID(nil)
	if errA != nil || errB != nil || a == b || !cpim.IsToken(a) || len(a) != 32 {
		t.Errorf("NewMessageID(nil) = %q, %q, %v, %v", a, b, errA, errB)
	}
}

func TestIsNotificationReadsContentDisposition(t *testing.T) {
	for v, want := range map[string]bool{
		"notification":                    true,
		"Notification; handling=required": true,
		"render":                          false,
		"notification; =broken":           false,
	} {
		m := &cpim.Message{ContentHeaders: []cpim.Field{{Name: "Content-Disposition", Value: v}}}
		if got := IsNotification(m); got != want {
			t.Errorf("IsNotification(%q) = %v, want %v", v, got, want)
		}
	}
	if IsNotification(&cpim.Message{}) {
		t.Error("a message without Content-Disposition is not a notification")
	}
}

func TestAddRecordRoutePutsTheLatestIntermediaryOnTop(t *testing.T) {
	m := chatToBob(t)
	for _, a := range []string{relay, focus} {
		if err := AddRecordRoute(m, cpim.Address{URI: a}); err != nil {
			t.Fatal(err)
		}
	}
	if err := AddRequest(m, "abc", Display); err != nil {
		t.Fatal(err)
	}
	out, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := cpim.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseRequest(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if want := []cpim.Address{{URI: focus}, {URI: relay}}; !reflect.DeepEqual(r.RecordRoute, want) {
		t.Errorf("RecordRoute = %+v, want the last intermediary first", r.RecordRoute)
	}
	if err := AddRecordRoute(m, cpim.Address{URI: "relay"}); err == nil {
		t.Error("AddRecordRoute accepted an address that is not a URI")
	}
	stuck := &cpim.Message{}
	_ = stuck.Declare("", "urn:example:other")
	if err := AddRecordRoute(stuck, cpim.Address{URI: relay}); err == nil {
		t.Error("AddRecordRoute succeeded where no NS header can be written")
	}
}
