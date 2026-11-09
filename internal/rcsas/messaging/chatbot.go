package messaging

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"net/textproto"
	"strconv"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
	"github.com/jeonghun-app/rcs-platform/internal/content"
	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// ChatbotsShare: all chatbots' messages in a queue hold at most a quarter
// of it together, beside each chatbot's sender share, as group
// notifications do (ADR 0009 §9, threat model T10, memo D3).
const ChatbotsShare = 4

// botTags are the feature tags of a chatbot's CPIM From (RCC.07 v13.0
// §3.6.8.1.2 item 1): isbot and the Chatbot application versions 1 and 2
// (§3.6.2.2), in the Contact header of the From URI with the escapes of
// §3.2.2.6, as that clause's example writes them.
const botTags = "?Contact=+g.gsma.rcs.isbot%3B+g.gsma.rcs.botversion%3D%22%23%3D1%2C%23%3D2%22"

var errBoundaryInContent = errors.New("messaging: chatbot content holds the multipart boundary")

// SubmitChatbot stores a chatbot's message that rcs-as's chatbot API let
// through (ADR 0009 §4, chatbot → subscriber step 4), with its sent record
// when it asks for notifications. The API has checked it: m.Sender is the
// chatbot's URI in normal form, m.ContentType the configured entry its type
// matched, its content valid, and its backstops taken. chipListType is the
// configured chip-list type. Its errors are Submit's.
//
// The CPIM is rcs-as's own, built from these fields: nothing maap writes
// reaches a header but through them. The stored item is marked as a
// chatbot's, which every delivery holds until #702's delivery check exists,
// and counts against the chatbot's share of the queue and the chatbots'
// total.
func (e *Engine) SubmitChatbot(ctx context.Context, m chatbot.BotMessage, chipListType string) error {
	err := e.submitChatbot(ctx, m, chipListType)
	e.counted(err, m.Recipient)
	return err
}

func (e *Engine) submitChatbot(ctx context.Context, m chatbot.BotMessage, chipListType string) error {
	now := e.clock.Now()
	raw, err := e.chatbotCPIM(m, chipListType, now)
	if err != nil {
		return err
	}
	// Read back as every delivery reads it, so that only what the engine
	// can deliver is stored.
	msg, err := ParseMessage(raw, e.cfg.MaxMessageSize)
	if err != nil {
		return err
	}
	o := Origin{Sender: m.Sender, Recipient: m.Recipient, Mode: store.Standalone, CPIM: content.BodyOf(raw), chatbot: true, anonymous: *m.Anonymous}
	ctx, cancel := e.withTimeout(ctx, e.cfg.StoreTimeout)
	defer cancel()
	return e.submitMessage(ctx, o, msg, now)
}

// chatbotCPIM writes the CPIM of a chatbot's message (RCC.07 v13.0
// §3.6.8.1.2, §3.6.10.1): From the chatbot's URI with the bot tags and the
// registry name through EscapeDisplayName, so that no control character of
// it ends a line here or in a SIP display name made from it; To the
// subscriber; DateTime rcs-as's clock; the Message-ID maap generated, with
// the notifications asked for; the configured content type. A chip list
// makes it a multipart CPIM, the message first.
func (e *Engine) chatbotCPIM(m chatbot.BotMessage, chipListType string, now time.Time) ([]byte, error) {
	c := &cpim.Message{}
	err := errors.Join(
		c.Add(cpim.CoreNamespace, cpim.HeaderFrom, cpim.Address{Name: EscapeDisplayName(*m.DisplayName), URI: m.Sender + botTags}.String()),
		c.Add(cpim.CoreNamespace, cpim.HeaderTo, cpim.Address{URI: m.Recipient}.String()),
		c.Add(cpim.CoreNamespace, cpim.HeaderDateTime, cpim.FormatDateTime(now)),
	)
	if err != nil {
		return nil, err
	}
	if d := dispositionsOf(*m.Dispositions); d != 0 {
		err = imdn.AddRequest(c, m.MessageID, d)
	} else if err = c.Declare(imdn.Prefix, imdn.Namespace); err == nil {
		// Without a request too: a client drops a copy maap sent again
		// after a lost answer by it (ADR 0009 §4).
		err = c.Add(imdn.Namespace, imdn.HeaderMessageID, m.MessageID)
	}
	if err != nil {
		return nil, err
	}
	contentType, body := m.ContentType, []byte(*m.Body)
	if m.ChipList != "" {
		boundary, err := e.randomHex(16)
		if err != nil {
			return nil, err
		}
		contentType = `multipart/mixed; boundary="` + boundary + `"`
		if body, err = chatbotParts(boundary, [2]string{m.ContentType, *m.Body}, [2]string{chipListType, m.ChipList}); err != nil {
			return nil, err
		}
	}
	c.ContentHeaders = []cpim.Field{{Name: "Content-Type", Value: contentType}}
	c.Body = content.BodyOf(body)
	return c.Marshal()
}

// chatbotParts writes the parts of a multipart CPIM, each a content type
// and its content, inline with a filename of its own (§3.6.10.1). The
// boundary is random, so content made to end a part early would have to
// guess it; content that holds it all the same is refused, never split.
func chatbotParts(boundary string, parts ...[2]string) ([]byte, error) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	if err := w.SetBoundary(boundary); err != nil {
		return nil, err
	}
	for i, p := range parts {
		if bytes.Contains([]byte(p[1]), []byte("--"+boundary)) {
			return nil, errBoundaryInContent
		}
		pw, err := w.CreatePart(textproto.MIMEHeader{
			"Content-Type":        {p[0]},
			"Content-Disposition": {`inline; filename="part` + strconv.Itoa(i+1) + `"`},
			"Content-Length":      {strconv.Itoa(len(p[1]))},
		})
		if err != nil {
			return nil, err
		}
		_, _ = pw.Write([]byte(p[1]))
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func dispositionsOf(d chatbot.Dispositions) imdn.Disposition {
	var out imdn.Disposition
	for _, f := range []struct {
		asked bool
		d     imdn.Disposition
	}{{d.PositiveDelivery, imdn.PositiveDelivery}, {d.NegativeDelivery, imdn.NegativeDelivery}, {d.Display, imdn.Display}} {
		if f.asked {
			out |= f.d
		}
	}
	return out
}
