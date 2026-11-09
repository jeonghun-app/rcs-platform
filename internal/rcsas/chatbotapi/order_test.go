package chatbotapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
)

// Each request below breaks two checks at once, and the earlier one of
// docs/rcs-as.md's order must answer: token → path → method → switch → API
// backstop → decode cap → body → field rules → scope → content type →
// content → sender and subscriber backstops.
func TestTheFirstCheckInTheDocumentedOrderAnswers(t *testing.T) {
	off := func(c *Config) { c.On = false }
	holdSlot := func(t *testing.T, e *env) { e.rawRequest(t, messagesPath, currentToken, "{"); e.waitSlots(t, 1) }
	send := func(method, path, contentType, body string) func(*testing.T, *env) (int, string) {
		return func(t *testing.T, e *env) (int, string) {
			status, _, answer := e.do(t, method, path, "Bearer "+currentToken, contentType, body)
			return status, answer
		}
	}
	post := func(path, body string) func(*testing.T, *env) (int, string) {
		return send(http.MethodPost, path, "application/json", body)
	}
	for _, c := range []struct {
		name  string
		edit  func(*Config)
		setup func(*testing.T, *env)
		run   func(*testing.T, *env) (int, string)
		want  int
		says  string
	}{
		{name: "path before method and switch", edit: off, run: send(http.MethodGet, "/v1/elsewhere", "", ""), want: 404, says: "no such resource"},
		{name: "method before switch", edit: off, run: send(http.MethodGet, messagesPath, "", ""), want: 405, says: "only POST"},
		{
			name: "switch before API backstop", edit: func(c *Config) { c.APIRate.Burst = 1 },
			setup: func(t *testing.T, e *env) {
				if status := e.post(t, messagesPath, message(nil)); status != 202 {
					t.Fatalf("the first message: %d", status)
				}
				e.api.cfg.On = false
			},
			run: post(messagesPath, message(nil)), want: 503, says: "off",
		},
		{
			name: "API backstop before decode cap", edit: func(c *Config) { c.APIRate.Burst, c.Decodes = 1, 1 }, setup: holdSlot,
			run: post(notesPath, notification(nil)), want: 429, says: "backstop",
		},
		{
			name: "decode cap before content type", edit: func(c *Config) { c.Decodes = 1 }, setup: holdSlot,
			run: send(http.MethodPost, notesPath, "text/plain", notification(nil)), want: 503, says: "too many bodies",
		},
		{name: "body before field rules", run: post(messagesPath, message(map[string]any{"anonymous": nil, "recipient": "tel:+1-555-0100001"})), want: 400, says: "anonymous"},
		{name: "field rules before scope 404", run: post(messagesPath, message(map[string]any{"recipient": "tel:+1-555-0100001", "sender": "sip:MyBot@" + botDomain})), want: 400, says: "canonical"},
		{name: "chatbot 404 before subscriber in range", run: post(messagesPath, message(map[string]any{"sender": "sip:MyBot@" + botDomain, "recipient": "sip:other@" + botDomain})), want: 404, says: "normal form"},
		{name: "notification chatbot 404 before subscriber in range", run: post(notesPath, notification(map[string]any{"chatbot": "sip:MyBot@" + botDomain, "subscriber": "sip:other@" + botDomain})), want: 404, says: "normal form"},
		{name: "scope before content type", run: post(messagesPath, message(map[string]any{"sender": testSub, "content_type": "image/png"})), want: 403, says: "outside"},
		{name: "scope before content", run: post(messagesPath, message(map[string]any{"sender": testSub, "body": "a\x00b"})), want: 403, says: "outside"},
		{name: "content type before content", run: post(messagesPath, message(map[string]any{"content_type": "image/png", "body": "a\x00b"})), want: 415, says: "content_type"},
		{
			name: "chip list type before content", edit: func(c *Config) { c.ContentTypes.ChipList = "" },
			run: post(messagesPath, message(map[string]any{"content_type": chatbot.RichCardType, "body": "{", "chip_list": "{"})), want: 415, says: "chip list",
		},
		{
			name: "content before sender backstop", edit: func(c *Config) { c.SenderRate.Burst = 1 },
			setup: func(t *testing.T, e *env) { e.post(t, messagesPath, message(nil)) },
			run:   post(messagesPath, message(map[string]any{"body": "a\x00b", "recipient": "tel:+15550100002"})), want: 400, says: "control",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, c.edit)
			if c.setup != nil {
				c.setup(t, e)
			}
			if status, answer := c.run(t, e); status != c.want || !strings.Contains(answer, c.says) {
				t.Fatalf("%d %s, want %d naming %q", status, answer, c.want, c.says)
			}
		})
	}
}

// The sender's bucket is keyed by the chatbot URI in normal form, so that
// maap cannot get a fresh bucket by writing the same chatbot another way
// (tk=on, the host's or the scheme's case), for messages and notifications.
func TestTheSendersBucketIsKeyedByTheNormalForm(t *testing.T) {
	for _, c := range []struct{ name, path, body string }{
		{"message with tk=on", messagesPath, message(map[string]any{"sender": testBot + ";tk=on", "recipient": "tel:+15550100002"})},
		{"message with the host in upper case", messagesPath, message(map[string]any{"sender": "sip:mybot@" + strings.ToUpper(botDomain), "recipient": "tel:+15550100003"})},
		{"notification with the scheme in upper case", notesPath, notification(map[string]any{"chatbot": "SIP:mybot@" + botDomain})},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, func(c *Config) { c.SenderRate.Burst = 1 })
			if status := e.post(t, messagesPath, message(nil)); status != 202 {
				t.Fatalf("the first message: %d", status)
			}
			if status := e.post(t, c.path, c.body); status != 429 {
				t.Fatalf("the same chatbot written another way: %d, want 429", status)
			}
		})
	}
}
