package messaging

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

const (
	testBot  = "sip:mybot@botplatform.mnc001.mcc001.3gppnetwork.org"
	otherBot = "sip:otherbot@botplatform.mnc001.mcc001.3gppnetwork.org"
)

// botMessage is a message as the chatbot API hands it on, with edit
// applied.
func botMessage(edit func(*chatbot.BotMessage)) chatbot.BotMessage {
	name, body, anonymous := "My Bot", "hi there", false
	m := chatbot.BotMessage{
		Sender: testBot, DisplayName: &name, Recipient: alice, MessageID: "m-1",
		ContentType: "text/plain;charset=utf-8", Body: &body, Anonymous: &anonymous,
		Dispositions: &chatbot.Dispositions{PositiveDelivery: true, Display: true},
	}
	if edit != nil {
		edit(&m)
	}
	return m
}

// stored submits m and returns the queue item it became, claimed.
func (r *rig) stored(t *testing.T, m chatbot.BotMessage, chipListType string) store.Message {
	t.Helper()
	if err := r.e.SubmitChatbot(t.Context(), m, chipListType); err != nil {
		t.Fatal(err)
	}
	ms, err := r.store.Pending(t.Context(), m.Recipient, "", r.clock.Now(), 10)
	if err != nil || len(ms) != 1 {
		t.Fatalf("queued %+v, %v", ms, err)
	}
	return ms[0]
}

// headers are the CPIM message headers of q as name: value lines, in order.
func headers(t *testing.T, q store.Message) []string {
	t.Helper()
	c, err := cpim.Parse(q.CPIM.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, h := range c.Headers {
		out = append(out, h.Name+": "+h.Value)
	}
	return out
}

func TestAChatbotsCPIMIsBuiltByRCSAs(t *testing.T) {
	r := newRig(t, Config{})
	q := r.stored(t, botMessage(nil), "")
	want := []string{
		`From: My Bot <` + testBot + `?Contact=+g.gsma.rcs.isbot%3B+g.gsma.rcs.botversion%3D%22%23%3D1%2C%23%3D2%22>`,
		"To: <" + alice + ">",
		"DateTime: 2026-03-04T05:06:07Z",
		"NS: imdn <urn:ietf:params:imdn>",
		"imdn.Message-ID: m-1",
		"imdn.Disposition-Notification: positive-delivery, display",
	}
	if got := headers(t, q); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("headers\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	c, _ := cpim.Parse(q.CPIM.Bytes())
	if c.ContentType() != "text/plain;charset=utf-8" || string(c.Body.Bytes()) != "hi there" {
		t.Fatalf("content %q %q", c.ContentType(), c.Body.Bytes())
	}
	if !q.Chatbot || q.Anonymous || q.Sender != testBot || q.Mode != store.Standalone || q.MessageID != "m-1" ||
		!q.Enqueued.Equal(r.clock.Now()) || !q.Expires.Equal(r.clock.Now().Add(DefaultStoreTTL)) {
		t.Fatalf("item %+v", q)
	}
	s, err := r.store.Sent(t.Context(), testBot, "m-1", r.clock.Now())
	if err != nil || len(s.Recipients) != 1 || s.Recipients[0] != alice || s.Dispositions != imdn.PositiveDelivery|imdn.Display {
		t.Fatalf("sent record %+v, %v", s, err)
	}
}

func TestAChatbotMessageWithoutNotificationsStillCarriesItsMessageID(t *testing.T) {
	r := newRig(t, Config{})
	q := r.stored(t, botMessage(func(m *chatbot.BotMessage) {
		m.Dispositions, *m.DisplayName, *m.Anonymous = &chatbot.Dispositions{}, "", true
	}), "")
	got := strings.Join(headers(t, q), "\n")
	if !strings.HasPrefix(got, "From: <"+testBot+"?Contact=") || !strings.HasSuffix(got, "imdn.Message-ID: m-1") ||
		strings.Contains(got, "Disposition-Notification") || !q.Anonymous {
		t.Fatalf("headers\n%s\nanonymous %v", got, q.Anonymous)
	}
	if _, err := r.store.Sent(t.Context(), testBot, "m-1", r.clock.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a sent record without notifications asked for: %v", err)
	}
}

func TestAChipListIsTheSecondPartOfAMultipartCPIM(t *testing.T) {
	r := newRig(t, Config{})
	card, chips := `{"message":{}}`, `{"suggestions":[]}`
	q := r.stored(t, botMessage(func(m *chatbot.BotMessage) {
		m.ContentType, m.Body, m.ChipList = chatbot.RichCardType, &card, chips
	}), chatbot.ChipListType)
	c, err := cpim.Parse(q.CPIM.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	typ, params, err := mime.ParseMediaType(c.ContentType())
	if err != nil || typ != "multipart/mixed" || len(params["boundary"]) != 32 {
		t.Fatalf("Content-Type %q", c.ContentType())
	}
	mr := multipart.NewReader(bytes.NewReader(c.Body.Bytes()), params["boundary"])
	var names []string
	for i, want := range [][2]string{{chatbot.RichCardType, card}, {chatbot.ChipListType, chips}} {
		p, err := mr.NextPart()
		if err != nil {
			t.Fatalf("part %d: %v", i+1, err)
		}
		b, _ := io.ReadAll(p)
		_, dp, _ := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
		names = append(names, dp["filename"])
		if p.Header.Get("Content-Type") != want[0] || string(b) != want[1] || !strings.HasPrefix(p.Header.Get("Content-Disposition"), "inline;") {
			t.Fatalf("part %d: %v %q", i+1, p.Header, b)
		}
	}
	if _, err := mr.NextPart(); err != io.EOF || names[0] == "" || names[0] == names[1] {
		t.Fatalf("a third part (%v), or filenames %q", err, names)
	}
}

// A boundary is never split by content that holds it: with a reader of
// zeros the boundary is known, and content holding it is refused.
func TestContentHoldingTheBoundaryIsRefused(t *testing.T) {
	r := newRig(t, Config{Rand: bytes.NewReader(make([]byte, 1<<10))})
	chips := "--" + strings.Repeat("0", 32) + "\r\nContent-Type: text/plain\r\n\r\nforged"
	err := r.e.SubmitChatbot(t.Context(), botMessage(func(m *chatbot.BotMessage) { m.ChipList = chips }), chatbot.ChipListType)
	if !errors.Is(err, errBoundaryInContent) || r.queued(t, alice) != 0 {
		t.Fatalf("SubmitChatbot = %v, %d queued", err, r.queued(t, alice))
	}
}

// A display name holding CR, LF and NUL cannot add a header to the CPIM or
// to the SIP From the SIP layer makes of it (viaPager, sipas).
func TestADisplayNameWithControlsKeepsOneLinePerHeader(t *testing.T) {
	r := newRig(t, Config{})
	q := r.stored(t, botMessage(func(m *chatbot.BotMessage) {
		*m.DisplayName = "Bot\r\nTo: <" + bob + ">\x00\"\\\u202e"
	}), "")
	got := headers(t, q)
	if len(got) != 6 || !strings.HasPrefix(got[1], "To: <"+alice+">") {
		t.Fatalf("headers %q", got)
	}
	m, err := ParseMessage(q.CPIM.Bytes(), DefaultMaxMessageSize)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := sip.ParseURI(testBot)
	if err != nil {
		t.Fatal(err)
	}
	from := sip.Address{DisplayName: EscapeDisplayName(m.From.Name), URI: uri}.String()
	for _, line := range []string{got[0], from} {
		if strings.ContainsAny(line, "\r\n\x00\u202e") {
			t.Fatalf("a control in %q", line)
		}
	}
}

// Each chatbot holds a sender's share of a subscriber's queue and all of
// them a quarter together; a full share is refused as for a person, with
// no negative notification queued for the chatbot (that is #705's).
func TestChatbotsHoldAShareEachAndAQuarterOfAQueue(t *testing.T) {
	r := newRig(t, Config{MaxQueueMessages: 8})
	submit := func(bot, id string) error {
		return r.e.SubmitChatbot(t.Context(), botMessage(func(m *chatbot.BotMessage) {
			m.Sender, m.MessageID, m.Dispositions = bot, id, &chatbot.Dispositions{NegativeDelivery: true}
		}), "")
	}
	if err := submit(testBot, "m-1"); err != nil {
		t.Fatal(err)
	}
	if s, err := r.store.Sent(t.Context(), testBot, "m-1", r.clock.Now()); err != nil || s.Dispositions != imdn.NegativeDelivery {
		t.Fatalf("sent record %+v, %v", s, err)
	}
	if err := submit(testBot, "m-2"); rejected(err) != ReasonQueueShareFull {
		t.Fatalf("beyond the chatbot's share: %v", err)
	}
	if err := submit(otherBot, "m-3"); err != nil {
		t.Fatal(err)
	}
	if err := submit("sip:third@botplatform.mnc001.mcc001.3gppnetwork.org", "m-4"); rejected(err) != ReasonQueueShareFull {
		t.Fatalf("beyond the chatbots' quarter: %v", err)
	}
	if err := r.e.Submit(t.Context(), standalone(bob, alice, chat(t, "p-1", "hi", 0))); err != nil {
		t.Fatalf("a person beside the full quarter: %v", err)
	}
	if r.queued(t, testBot)+r.queued(t, "sip:third@botplatform.mnc001.mcc001.3gppnetwork.org") != 0 ||
		r.m.get("message.rejected.queue_share_full") != 2 {
		t.Fatalf("notifications queued for chatbots, or metrics %v", r.m)
	}
}

// Until #702 brings the delivery check, a stored chatbot message is never
// delivered: the person's message behind it is, and the chatbot's expires
// under the store TTL as undeliverable, without a notification queued for
// the chatbot.
func TestStoredChatbotMessagesAreHeldUntilTheyExpire(t *testing.T) {
	r := newRig(t, Config{})
	if err := r.e.SubmitChatbot(t.Context(), botMessage(func(m *chatbot.BotMessage) {
		m.Dispositions = &chatbot.Dispositions{NegativeDelivery: true}
	}), ""); err != nil {
		t.Fatal(err)
	}
	if err := r.e.Submit(t.Context(), standalone(bob, alice, chat(t, "p-1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	r.e.UserRegistered(alice, true)
	if d := r.d.nextPager(t); d.Sender != bob {
		t.Fatalf("delivered %+v", d)
	}
	waitFor(t, "the person's message removed", func() bool { return r.queued(t, alice) == 1 })
	if n, err := r.e.Sweep(context.Background()); n != 0 || err != nil {
		t.Fatalf("Sweep before the TTL = %d, %v", n, err)
	}
	r.clock.Advance(DefaultStoreTTL)
	r.e.UserRegistered(alice, true)
	if n, err := r.e.Sweep(context.Background()); n != 1 || err != nil {
		t.Fatalf("Sweep at the TTL = %d, %v", n, err)
	}
	if len(r.d.pagers) != 0 || r.queued(t, alice) != 0 || r.queued(t, testBot) != 0 || r.m.get("message.expired") != 1 {
		t.Fatalf("pagers %d, queued %d and %d, metrics %v", len(r.d.pagers), r.queued(t, alice), r.queued(t, testBot), r.m)
	}
}

// maap sends the same Message-ID again after a lost answer, which is taken
// again as a person's resend is; the same ID to someone else is refused.
func TestAChatbotsResentMessageIsTakenAndAReusedIDRefused(t *testing.T) {
	r := newRig(t, Config{})
	for range 2 {
		if err := r.e.SubmitChatbot(t.Context(), botMessage(nil), ""); err != nil {
			t.Fatal(err)
		}
	}
	err := r.e.SubmitChatbot(t.Context(), botMessage(func(m *chatbot.BotMessage) { m.Recipient = bob }), "")
	if rejected(err) != ReasonMessageIDReused || r.m.get("message.resent") != 1 || r.queued(t, alice) != 2 {
		t.Fatalf("SubmitChatbot = %v, metrics %v", err, r.m)
	}
}
