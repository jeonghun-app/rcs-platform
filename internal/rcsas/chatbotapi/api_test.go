package chatbotapi

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

const (
	imsDomain    = "ims.mnc001.mcc001.3gppnetwork.org"
	botDomain    = "botplatform.mnc001.mcc001.3gppnetwork.org"
	testBot      = "sip:mybot@" + botDomain
	testSub      = "tel:+15550100001"
	currentToken = "maap-current-token"
	nextToken    = "maap-next-token"
	messagesPath = "/v1/chatbot/messages"
	notesPath    = "/v1/chatbot/notifications"
	auditMsg     = "audit: chatbot API request"
)

// recorder is an Acceptor that keeps what it is handed.
type recorder struct {
	mu            sync.Mutex
	messages      []chatbot.BotMessage
	notifications []chatbot.BotNotification
	panics        bool
	// entered, when set, hears each message, which then waits for release.
	entered, release chan struct{}
}

func (r *recorder) AcceptMessage(_ context.Context, m chatbot.BotMessage) error {
	if r.entered != nil {
		r.entered <- struct{}{}
		<-r.release
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.panics {
		panic("acceptor")
	}
	r.messages = append(r.messages, m)
	return nil
}

func (r *recorder) AcceptNotification(_ context.Context, n chatbot.BotNotification) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notifications = append(r.notifications, n)
	return nil
}

type env struct {
	api  *API
	addr string
	h    *runtimetest.Harness
	acc  *recorder
}

// newEnv serves the API with the switch on, the defaults of docs/rcs-as.md
// and a clock that stands still, on a real listener.
func newEnv(t *testing.T, edit func(*Config)) *env {
	t.Helper()
	domain, err := chatbot.NewDomain(botDomain, imsDomain)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		On: true, Domain: domain, ContentTypes: chatbot.DefaultContentTypes(), Decodes: 8,
		Tokens:     TokenPair{secret.NewString(currentToken), secret.NewString(nextToken)},
		SenderRate: messaging.Rate{PerMinute: 1500, Burst: 250}, SubscriberRate: messaging.Rate{PerMinute: 120, Burst: 20},
		APIRate: messaging.Rate{PerMinute: 3000, Burst: 500},
		Now:     func() time.Time { return runtimetest.Start },
	}
	if edit != nil {
		edit(&cfg)
	}
	e := &env{h: runtimetest.New(t, "rcs-as"), acc: &recorder{}}
	e.api = New(cfg, e.acc, e.h.Runtime.Logger, e.h.Runtime.Metrics)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := e.api.Server()
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	e.addr = ln.Addr().String()
	return e
}

// do sends one request on a connection of its own and returns the status,
// the answer's headers and its body.
func (e *env) do(t *testing.T, method, path, auth, contentType, body string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+e.addr+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	req.Header.Set("Content-Type", contentType)
	res, err := (&http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, string(b)
}

func (e *env) post(t *testing.T, path, body string) int {
	t.Helper()
	status, _, _ := e.do(t, http.MethodPost, path, "Bearer "+currentToken, "application/json", body)
	return status
}

// message is a valid message body with edit applied (a nil value drops the
// field).
func message(edit map[string]any) string {
	m := map[string]any{
		"sender": testBot, "display_name": "My Bot", "recipient": testSub, "message_id": "m-1",
		"content_type": "text/plain;charset=utf-8", "body": "hi there", "anonymous": false,
		"dispositions": map[string]bool{"positive_delivery": true, "negative_delivery": false, "display": true},
	}
	return encode(m, edit)
}

func notification(edit map[string]any) string {
	return encode(map[string]any{"chatbot": testBot, "subscriber": testSub, "message_id": "Msg+1", "kind": "display-notification"}, edit)
}

func encode(m, edit map[string]any) string {
	for k, v := range edit {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// rawRequest opens a connection and sends the headers of a POST with
// Content-Length 1000 and then the start of its body, nothing more.
func (e *env) rawRequest(t *testing.T, path, token, bodyStart string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_, err = io.WriteString(conn, "POST "+path+" HTTP/1.1\r\nHost: rcs-as\r\nAuthorization: Bearer "+token+
		"\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n"+bodyStart)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func readAnswer(t *testing.T, conn net.Conn) *http.Response {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer while the body is unsent: %v", err)
	}
	return res
}

func (e *env) waitSlots(t *testing.T, n int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); len(e.api.slots) != n; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d decode slots held, want %d", len(e.api.slots), n)
		}
	}
}

func TestOnlyMaapsTwoTokensAreAccepted(t *testing.T) {
	e := newEnv(t, nil)
	for _, c := range []struct {
		method, path, auth string
		want               int
	}{
		{"POST", messagesPath, "", 401},
		{"POST", messagesPath, "Bearer wrong", 401},
		{"POST", messagesPath, "Basic " + currentToken, 401},
		{"POST", messagesPath, "Bearer " + currentToken + "x", 401},
		{"POST", "/v1/elsewhere", "Bearer wrong", 401},
		{"GET", messagesPath, "", 401},
		{"POST", messagesPath, "Bearer " + currentToken, 202},
		{"POST", notesPath, "bearer " + nextToken, 202},
		{"POST", "/v1/elsewhere", "Bearer " + currentToken, 404},
		{"POST", "/v1/chatbot/messages/", "Bearer " + currentToken, 404},
		{"GET", messagesPath, "Bearer " + currentToken, 405},
	} {
		body := message(nil)
		if c.path == notesPath {
			body = notification(nil)
		}
		status, h, _ := e.do(t, c.method, c.path, c.auth, "application/json", body)
		if status != c.want || (status == 401) != (h.Get("WWW-Authenticate") != "") || h.Get("Cache-Control") != "no-store" {
			t.Errorf("%s %s with %q: %d, headers %v; want %d", c.method, c.path, c.auth, status, h, c.want)
		}
	}
	audits := e.h.Logs(auditMsg)
	if len(audits) != 11 || audits[0]["token"] != "none" || audits[6]["token"] != "current" || audits[7]["token"] != "next" ||
		audits[7]["operation"] != "notifications" || audits[8]["operation"] != "other" || audits[8]["status"] != 404.0 {
		t.Fatalf("audit lines %v", audits)
	}
	if n, _ := e.h.Metric("chatbot.api.messages.401"); n != 5 {
		t.Fatalf("chatbot.api.messages.401 = %v", n)
	}
	if out := e.h.Output(); strings.Contains(out, "mybot") || strings.Contains(out, "0100001") || strings.Contains(out, currentToken) {
		t.Fatalf("the log holds part of a request:\n%s", out)
	}
}

func TestTheSwitchOffAnswersOnlyAuthenticatedRequests503(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.On = false })
	if status, h, body := e.do(t, "POST", messagesPath, "Bearer "+currentToken, "application/json", message(nil)); status != 503 ||
		h.Get("Retry-After") == "" || !strings.Contains(body, "off") {
		t.Fatalf("authenticated: %d %q, Retry-After %q", status, body, h.Get("Retry-After"))
	}
	if status := e.post(t, "/v1/elsewhere", ""); status != 404 {
		t.Fatalf("another path: %d", status)
	}
	if status, _, _ := e.do(t, "POST", notesPath, "Bearer wrong", "application/json", notification(nil)); status != 401 {
		t.Fatalf("unauthenticated: %d", status)
	}
}

// An answer given before the body is read comes at once and closes the
// connection, the body never sent (#723 review).
func TestAnEarlyAnswerDoesNotWaitForTheBody(t *testing.T) {
	e := newEnv(t, nil)
	for _, c := range []struct {
		path, token string
		want        int
	}{{messagesPath, "wrong", 401}, {"/v1/elsewhere", currentToken, 404}} {
		if res := readAnswer(t, e.rawRequest(t, c.path, c.token, "")); res.StatusCode != c.want || !res.Close {
			t.Errorf("%s with %q: %d, close %v", c.path, c.token, res.StatusCode, res.Close)
		}
	}
}

// pad makes body exactly n bytes with leading white space, which JSON allows.
func pad(body string, n int) string { return strings.Repeat(" ", n-len(body)) + body }

func TestBodiesAreDecodedStrictlyUnderTheirLimits(t *testing.T) {
	e := newEnv(t, nil)
	for _, c := range []struct {
		name, path, contentType, body string
		want                          int
	}{
		{"message at 1,496 KiB", messagesPath, "application/json", pad(message(nil), 1531904), 202},
		{"message over it", messagesPath, "application/json", pad(message(nil), 1531905), 413},
		{"notification at 8 KiB", notesPath, "application/json", pad(notification(nil), 8192), 202},
		{"notification over it", notesPath, "application/json", pad(notification(nil), 8193), 413},
		{"unknown field", messagesPath, "application/json", message(map[string]any{"priority": 1}), 400},
		{"missing anonymous", messagesPath, "application/json", message(map[string]any{"anonymous": nil}), 400},
		{"control in display name", messagesPath, "application/json", message(map[string]any{"display_name": "a\r\nb"}), 400},
		{"bad kind", notesPath, "application/json", notification(map[string]any{"kind": "delivery-notification"}), 400},
		{"not JSON", messagesPath, "text/plain", message(nil), 415},
		{"no content type", notesPath, "", notification(nil), 415},
		{"charset is fine", notesPath, "application/json; charset=utf-8", notification(nil), 202},
	} {
		if status, _, _ := e.do(t, "POST", c.path, "Bearer "+currentToken, c.contentType, c.body); status != c.want {
			t.Errorf("%s: %d, want %d", c.name, status, c.want)
		}
	}
}

// The decode cap answers at once: the second request's body is never sent,
// and its 503 still comes, closing the connection.
func TestARequestOverTheDecodeCapIs503BeforeItsBodyIsRead(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Decodes = 1 })
	holder := e.rawRequest(t, messagesPath, currentToken, "{")
	e.waitSlots(t, 1)
	res := readAnswer(t, e.rawRequest(t, notesPath, currentToken, ""))
	if res.StatusCode != 503 || res.Header.Get("Retry-After") != "1" || !res.Close {
		t.Fatalf("over the cap: %d, Retry-After %q, close %v", res.StatusCode, res.Header.Get("Retry-After"), res.Close)
	}
	if n, _ := e.h.Metric("chatbot.api.decode_busy"); n != 1 {
		t.Fatalf("chatbot.api.decode_busy = %v", n)
	}
	_ = holder.Close()
	e.waitSlots(t, 0)
}

// A notification's body has bodyTime(8 KiB), 1.03 s, to arrive.
func TestASlowBodyLosesItsDecodeSlotAtItsDeadline(t *testing.T) {
	e := newEnv(t, nil)
	e.rawRequest(t, notesPath, currentToken, "{")
	e.waitSlots(t, 1)
	held := time.Now()
	e.waitSlots(t, 0)
	if d := time.Since(held); d > 2500*time.Millisecond {
		t.Fatalf("the slot was held %v", d)
	}
}

func TestWhatPassesReachesTheAcceptor(t *testing.T) {
	e := newEnv(t, nil)
	status, h, body := e.do(t, "POST", messagesPath, "Bearer "+currentToken, "application/json", message(nil))
	if status != 202 || strings.TrimSpace(body) != "{}" || h.Get("Content-Type") != "application/json" || h.Get("Connection") == "close" {
		t.Fatalf("message: %d %q, headers %v", status, body, h)
	}
	if status := e.post(t, notesPath, notification(nil)); status != 202 {
		t.Fatalf("notification: %d", status)
	}
	if m := e.acc.messages; len(m) != 1 || m[0].MessageID != "m-1" || *m[0].Body != "hi there" {
		t.Fatalf("messages %+v", m)
	}
	if n := e.acc.notifications; len(n) != 1 || n[0].MessageID != "Msg+1" {
		t.Fatalf("notifications %+v", n)
	}
	if out := e.h.Output(); strings.Contains(out, "hi there") || strings.Contains(out, "0100001") {
		t.Fatalf("the log holds part of a request:\n%s", out)
	}
}

// A panic in the handler still frees the slot and leaves its audit line,
// with 500 since nothing was answered.
func TestAPanicIsAuditedAndFreesItsSlot(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Decodes = 1 })
	e.acc.panics = true
	req, _ := http.NewRequest("POST", "http://"+e.addr+messagesPath, strings.NewReader(message(nil)))
	req.Header.Set("Authorization", "Bearer "+currentToken)
	req.Header.Set("Content-Type", "application/json")
	if res, err := http.DefaultClient.Do(req); err == nil {
		t.Fatalf("a panic was answered %d", res.StatusCode)
	}
	if a := e.h.Logs(auditMsg); len(a) != 1 || a[0]["status"] != 500.0 {
		t.Fatalf("audit lines %v", a)
	}
	e.waitSlots(t, 0)
}

func TestTheDefaultAcceptorAnswers503(t *testing.T) {
	a := New(Config{}, nil, nil, nil)
	if err := a.acceptor.AcceptMessage(context.Background(), chatbot.BotMessage{}); err != ErrUnavailable {
		t.Fatalf("messages: %v", err)
	}
	if err := a.acceptor.AcceptNotification(context.Background(), chatbot.BotNotification{}); err != ErrUnavailable {
		t.Fatalf("notifications: %v", err)
	}
	if ans := accepted(ErrUnavailable); ans.status != 503 || ans.retryAfter == "" {
		t.Fatalf("answer %+v", ans)
	}
}

// A sender holding a slot must keep up 256 KiB/s (docs/rcs-as.md).
func TestTheBodyDeadlinesAreTheDocumentedOnes(t *testing.T) {
	if d := bodyTime(chatbot.MaxBotMessageBytes); d.Round(100*time.Millisecond) != 6800*time.Millisecond {
		t.Errorf("message: %v", d)
	}
	if d := bodyTime(chatbot.MaxBotNotificationBytes); d.Round(10*time.Millisecond) != 1030*time.Millisecond {
		t.Errorf("notification: %v", d)
	}
}

// The slot is freed once the body is checked, before the acceptor's store
// calls: a message the acceptor holds leaves the only slot to another.
func TestTheAcceptorRunsWithoutTheDecodeSlot(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Decodes = 1 })
	e.acc.entered, e.acc.release = make(chan struct{}), make(chan struct{})
	done := make(chan int, 1)
	go func() { done <- e.post(t, messagesPath, message(nil)) }()
	<-e.acc.entered
	if status := e.post(t, notesPath, notification(nil)); status != 202 {
		t.Errorf("while the acceptor holds a message: %d", status)
	}
	close(e.acc.release)
	if status := <-done; status != 202 {
		t.Fatalf("the held message: %d", status)
	}
}

// net/http sends the first status written; the audit line must say the same.
func TestTheRecorderKeepsTheFirstStatus(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	rec.WriteHeader(http.StatusServiceUnavailable)
	rec.WriteHeader(http.StatusOK)
	if _, _ = rec.Write([]byte("x")); rec.status != http.StatusServiceUnavailable {
		t.Fatalf("status %d", rec.status)
	}
}

func TestRequestsOutsideMaapsScopeAreRefused(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.ContentTypes.ChipList = "" })
	for _, c := range []struct {
		name, path, body string
		want             int
	}{
		{"sender a tel URI", messagesPath, message(map[string]any{"sender": testSub}), 403},
		{"sender at the IMS domain", messagesPath, message(map[string]any{"sender": "sip:mybot@" + imsDomain}), 403},
		{"sender not in normal form", messagesPath, message(map[string]any{"sender": "sip:MyBot@" + botDomain}), 404},
		{"recipient a chatbot", messagesPath, message(map[string]any{"recipient": "sip:other@" + botDomain}), 403},
		{"recipient a SIP URI", messagesPath, message(map[string]any{"recipient": "sip:+15550100001@" + imsDomain}), 400},
		{"recipient not canonical", messagesPath, message(map[string]any{"recipient": "tel:+1-555-0100001"}), 400},
		{"recipient a local number", messagesPath, message(map[string]any{"recipient": "tel:0100001"}), 400},
		{"bad recipient before bad sender", messagesPath, message(map[string]any{"sender": testSub, "recipient": "x"}), 400},
		{"content type off the list", messagesPath, message(map[string]any{"content_type": "image/png"}), 415},
		{"content type with another charset", messagesPath, message(map[string]any{"content_type": "text/plain;charset=latin1"}), 415},
		{"chip list with none accepted", messagesPath, message(map[string]any{"chip_list": "{}"}), 415},
		{"rich card that is not JSON", messagesPath, message(map[string]any{"content_type": chatbot.RichCardType, "body": "{"}), 400},
		{"text with a NUL", messagesPath, message(map[string]any{"body": "a\x00b"}), 400},
		{"notifying chatbot a tel URI", notesPath, notification(map[string]any{"chatbot": testSub}), 403},
		{"notified subscriber a chatbot", notesPath, notification(map[string]any{"subscriber": testBot}), 403},
		{"notified subscriber not a tel URI", notesPath, notification(map[string]any{"subscriber": "sip:x@" + imsDomain}), 400},
	} {
		if status := e.post(t, c.path, c.body); status != c.want {
			t.Errorf("%s: %d, want %d", c.name, status, c.want)
		}
	}
	if len(e.acc.messages)+len(e.acc.notifications) != 0 {
		t.Fatal("a refused request reached the acceptor")
	}
}

func TestEachBackstopRefusesOverItsBurst(t *testing.T) {
	sub := func(tel string) map[string]any { return map[string]any{"recipient": tel} }
	for _, c := range []struct {
		name   string
		edit   func(*Config)
		bodies []string
	}{
		{"sender, messages and notifications together", func(c *Config) { c.SenderRate.Burst = 2 },
			[]string{message(sub(testSub)), notification(nil), message(sub("tel:+15550100002"))}},
		{"subscriber, from every chatbot", func(c *Config) { c.SubscriberRate.Burst = 2 },
			[]string{message(nil), message(map[string]any{"sender": "sip:other@" + botDomain}), message(map[string]any{"sender": "sip:third@" + botDomain})}},
		{"the whole API", func(c *Config) { c.APIRate.Burst = 2 },
			[]string{message(sub(testSub)), notification(map[string]any{"chatbot": "sip:other@" + botDomain}), message(map[string]any{"sender": "sip:third@" + botDomain})}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, c.edit)
			for i, body := range c.bodies {
				path := messagesPath
				if strings.Contains(body, `"kind"`) {
					path = notesPath
				}
				want := 202
				if i == 2 {
					want = 429
				}
				if status, h, _ := e.do(t, "POST", path, "Bearer "+currentToken, "application/json", body); status != want || (status == 429) != (h.Get("Retry-After") == "1") {
					t.Fatalf("request %d: %d, Retry-After %q", i, status, h.Get("Retry-After"))
				}
			}
			if n, _ := e.h.Metric("chatbot.backstop_refused"); n != 1 {
				t.Fatalf("chatbot.backstop_refused = %v", n)
			}
		})
	}
}

// A message the subscriber's bucket refuses takes no token from the
// sender's: the sender's three still carry three messages.
func TestASubscriberRefusalLeavesTheSendersBucketAlone(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.SenderRate.Burst, c.SubscriberRate.Burst = 3, 1 })
	for i, c := range []struct {
		recipient string
		want      int
	}{{testSub, 202}, {testSub, 429}, {"tel:+15550100002", 202}, {"tel:+15550100003", 202}} {
		if status := e.post(t, messagesPath, message(map[string]any{"recipient": c.recipient})); status != c.want {
			t.Fatalf("message %d: %d, want %d", i, status, c.want)
		}
	}
}

func TestWhatPassesReachesTheAcceptorInNormalForm(t *testing.T) {
	e := newEnv(t, nil)
	status, h, body := e.do(t, "POST", messagesPath, "Bearer "+currentToken, "application/json", message(map[string]any{
		"sender": testBot + ";tk=on", "content_type": "Text/Plain; Charset=UTF-8", "chip_list": `{"suggestions":[]}`}))
	if status != 202 || strings.TrimSpace(body) != "{}" || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("message: %d %q, Cache-Control %q", status, body, h.Get("Cache-Control"))
	}
	if status := e.post(t, notesPath, notification(map[string]any{"chatbot": "SIP:mybot@" + botDomain})); status != 202 {
		t.Fatalf("notification: %d", status)
	}
	if m := e.acc.messages; len(m) != 1 || m[0].Sender != testBot || m[0].ContentType != "text/plain;charset=utf-8" || m[0].ChipList == "" {
		t.Fatalf("messages %+v", m)
	}
	if n := e.acc.notifications; len(n) != 1 || n[0].Chatbot != testBot || n[0].Subscriber != testSub {
		t.Fatalf("notifications %+v", n)
	}
	if out := e.h.Output(); strings.Contains(out, "mybot") || strings.Contains(out, "0100001") || strings.Contains(out, "hi there") ||
		strings.Contains(out, currentToken) {
		t.Fatalf("the log holds part of a request:\n%s", out)
	}
}

// The subscriber's bucket counts messages only: notifications are bounded
// by T10's once per kind (ADR 0009 §9), and a message refused for its chip
// list, which is content too, takes no token.
func TestTheSubscribersBucketCountsAcceptedMessagesOnly(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.SubscriberRate.Burst = 1 })
	for i, c := range []struct {
		path, body string
		want       int
	}{
		{notesPath, notification(nil), 202},
		{notesPath, notification(nil), 202},
		{messagesPath, message(map[string]any{"chip_list": "{"}), 400},
		{messagesPath, message(nil), 202},
		{messagesPath, message(nil), 429},
	} {
		if status := e.post(t, c.path, c.body); status != c.want {
			t.Fatalf("request %d: %d, want %d", i, status, c.want)
		}
	}
}
