package messaging

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
)

func TestConversationHeadersAreTrimmedTokens(t *testing.T) {
	c, err := ParseConversationHeaders(" f81d4fae-7dec-11d0-a765-00a0c91e6bf6\t", "c0ffee01", "")
	if err != nil {
		t.Fatal(err)
	}
	if c != (Conversation{ID: "f81d4fae-7dec-11d0-a765-00a0c91e6bf6", Contribution: "c0ffee01"}) {
		t.Fatalf("got %+v", c)
	}
	c, err = ParseConversationHeaders("a", "b", " Cc.!%*_+`'~ ")
	if err != nil || c.InReplyTo != "Cc.!%*_+`'~" {
		t.Fatalf("got %+v, %v", c, err)
	}
}

// rcsjta sends a Contribution-ID without a Conversation-ID (#298): the
// request is in the contribution, with no Conversation-ID made up for it.
func TestAContributionIDAloneIsTaken(t *testing.T) {
	for _, h := range [][3]string{{"", "b", ""}, {" ", "b", "c"}} {
		c, err := ParseConversationHeaders(h[0], h[1], h[2])
		if err != nil || c != (Conversation{Contribution: "b", InReplyTo: h[2]}) {
			t.Errorf("ParseConversationHeaders(%q) = %+v, %v", h, c, err)
		}
	}
}

func TestARequestWithoutConversationHeadersHasNoConversation(t *testing.T) {
	// As rcsjta sends pager-mode notifications.
	if c, err := ParseConversationHeaders("", " ", ""); err != nil || c != (Conversation{}) {
		t.Fatalf("got %+v, %v", c, err)
	}
}

func TestQueueIDsKeepTheirOrderWithinATask(t *testing.T) {
	r := newRig(t, Config{})
	now := r.clock.Now()
	prev := ""
	for i := range 100 {
		at := now
		if i == 50 {
			at = now.Add(-time.Hour) // the clock stepped back
		}
		id, err := r.e.newID(at)
		if err != nil {
			t.Fatal(err)
		}
		if id <= prev {
			t.Fatalf("ID %d %q not after %q", i, id, prev)
		}
		prev = id
	}
}

func TestConversationHeadersOutsideTheGrammarAreRefused(t *testing.T) {
	long := strings.Repeat("a", MaxIDLength+1)
	for _, h := range [][3]string{
		{"a", "", ""},
		{"", "", "c"},
		{"a b", "c", ""},
		{"a", "b;c", ""},
		{"a", "b", "c\r\nVia: x"},
		{"\"a\"", "b", ""},
		{long, "b", ""},
		{"a", "b", long},
		{"\xff", "b", ""},
	} {
		if c, err := ParseConversationHeaders(h[0], h[1], h[2]); !errors.Is(err, ErrInvalidConversation) {
			t.Errorf("ParseConversationHeaders(%q) = %+v, %v", h, c, err)
		}
	}
	if _, err := ParseConversationHeaders(strings.Repeat("a", MaxIDLength), "b", ""); err != nil {
		t.Errorf("an identifier of MaxIDLength: %v", err)
	}
}

func TestDisplayNamesAreEscapedBeforeLeavingCPIM(t *testing.T) {
	for in, want := range map[string]string{
		"Alice":                           "Alice",
		"Zo\u00eb \uc815\ud6c8":           "Zo\u00eb \uc815\ud6c8",
		"a\r\nb":                          `a\u000d\u000ab`,
		"tab\tnul\x00del\x7f":             `tab\u0009nul\u0000del\u007f`,
		`say "hi" \o/`:                    `say \u0022hi\u0022 \u005co/`,
		"c1\u0085ls\u2028ps\u2029":        `c1\u0085ls\u2028ps\u2029`,
		"\u202eevil\u202c":                `\u202eevil\u202c`,
		"\u2066x\u2069\u200f\u200b\u061c": `\u2066x\u2069\u200f\u200b\u061c`,
		"bad\xffutf8":                     "bad\ufffdutf8",
	} {
		if got := EscapeDisplayName(in); got != want {
			t.Errorf("EscapeDisplayName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseMessageReadsWhatTheEngineNeeds(t *testing.T) {
	m, err := ParseMessage(chat(t, "m1", "hi", imdn.PositiveDelivery|imdn.Display), 4096)
	if err != nil {
		t.Fatal(err)
	}
	if m.From.URI != AnonymousURI || m.Request.MessageID != "m1" || m.Request.Dispositions != imdn.PositiveDelivery|imdn.Display ||
		m.Notification != nil || m.IncompleteRequest {
		t.Fatalf("message %+v", m)
	}
	m, err = ParseMessage(receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed), 4096)
	if err != nil {
		t.Fatal(err)
	}
	if m.Notification == nil || m.Notification.MessageID != "m1" || m.Request.Dispositions != 0 {
		t.Fatalf("notification %+v", m)
	}
}

func TestARequestWithoutItsMessageIDIsDeliveredWithoutNotifications(t *testing.T) {
	body := "From: <tel:+15550100001>\r\nTo: <tel:+15550100002>\r\nNS: imdn <urn:ietf:params:imdn>\r\n" +
		"imdn.Disposition-Notification: positive-delivery\r\n\r\nContent-Type: text/plain\r\n\r\nhi"
	m, err := ParseMessage([]byte(body), 4096)
	if err != nil {
		t.Fatal(err)
	}
	if !m.IncompleteRequest || m.Request.Dispositions != 0 {
		t.Fatalf("message %+v", m)
	}
	r := newRig(t, Config{})
	if err := r.e.Submit(t.Context(), standalone(alice, bob, []byte(body))); err != nil {
		t.Fatal(err)
	}
	if r.m.get("imdn.incomplete_request") != 1 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestParseMessageRefusesWhatItCannotRead(t *testing.T) {
	badIMDN := "From: <tel:+15550100002>\r\nTo: <tel:+15550100001>\r\nNS: imdn <urn:ietf:params:imdn>\r\nimdn.Message-ID: n1\r\n" +
		"DateTime: 2026-03-04T05:06:07Z\r\n\r\nContent-Type: message/imdn+xml\r\nContent-Disposition: notification\r\n\r\n<imdn/>"
	badRequest := "From: <tel:+15550100001>\r\nTo: <tel:+15550100002>\r\nNS: imdn <urn:ietf:params:imdn>\r\nimdn.Message-ID: m 1\r\n" +
		"DateTime: 2026-03-04T05:06:07Z\r\nimdn.Disposition-Notification: display\r\n\r\nContent-Type: text/plain\r\n\r\nhi"
	for body, want := range map[string]Reason{
		"x": ReasonMalformed,
		"To: <tel:+15550100002>\r\n\r\nContent-Type: text/plain\r\n\r\nhi": ReasonMalformed, // no From
		badIMDN:                   ReasonIMDNMalformed,
		badRequest:                ReasonMalformed,
		strings.Repeat("x", 4097): ReasonTooLarge,
	} {
		_, err := ParseMessage([]byte(body), 4096)
		if got := rejected(err); got != want {
			t.Errorf("ParseMessage(%.30q) = %v, want %s", body, err, want)
		}
	}
}

func TestRejectionsMapToMSRPCodesAndKeepTheirCause(t *testing.T) {
	for r, want := range map[Reason]int{
		ReasonTooLarge: 413, ReasonContentType: 415, ReasonMalformed: 400, ReasonIMDNMalformed: 400,
		ReasonRateLimited: 403, ReasonIMDNForged: 403, ReasonFromMismatch: 403,
	} {
		if got := reject(r, nil).MSRPStatus(); got != want {
			t.Errorf("%s: %d, want %d", r, got, want)
		}
	}
	err := reject(ReasonMalformed, cpim.ErrMalformed)
	if !errors.Is(err, cpim.ErrMalformed) || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("err = %v", err)
	}
	if reject(ReasonIMDNForged, nil).Error() != "messaging: rejected (imdn_forged)" {
		t.Fatal(reject(ReasonIMDNForged, nil).Error())
	}
}

func TestTheRateRefillsAndIsKeptPerSender(t *testing.T) {
	t0 := newFakeClock().Now()
	l := newLimiter(Rate{PerMinute: 6, Burst: 2}, 100)
	if !l.allow("a", t0) || !l.allow("a", t0) || l.allow("a", t0) {
		t.Fatal("the burst is not 2")
	}
	if !l.allow("b", t0) {
		t.Fatal("one sender's use limited another")
	}
	if l.allow("a", t0.Add(9*time.Second)) || !l.allow("a", t0.Add(10*time.Second)) || l.allow("a", t0.Add(10*time.Second)) {
		t.Fatal("a token did not take 10 s to refill")
	}
	off := newLimiter(Rate{PerMinute: -1}, 1)
	for range 100 {
		if !off.allow("a", t0) {
			t.Fatal("a disabled limit limited")
		}
	}
}

func TestTheLimiterForgetsSendersRatherThanGrow(t *testing.T) {
	t0 := newFakeClock().Now()
	l := newLimiter(Rate{PerMinute: 1, Burst: 1}, 4)
	for i := range 100 {
		l.allow(string(rune('A'+i)), t0)
		if len(l.full) > 4 {
			t.Fatalf("%d buckets", len(l.full))
		}
	}
	// Once full again, a bucket is forgotten in preference to the others.
	l = newLimiter(Rate{PerMinute: 1, Burst: 1}, 2)
	l.allow("used", t0)
	l.allow("idle", t0.Add(-time.Hour))
	l.allow("new", t0)
	if _, ok := l.full["used"]; !ok || len(l.full) != 2 {
		t.Fatalf("buckets %v", l.full)
	}
}
