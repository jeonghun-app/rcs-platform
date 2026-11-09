package chatbotapi

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
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

type env struct {
	api  *API
	addr string
	h    *runtimetest.Harness
}

// newEnv serves the API with the switch on, on a real listener.
func newEnv(t *testing.T, edit func(*Config)) *env {
	t.Helper()
	domain, err := chatbot.NewDomain(botDomain, imsDomain)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{On: true, Domain: domain, Tokens: TokenPair{secret.NewString(currentToken), secret.NewString(nextToken)}}
	if edit != nil {
		edit(&cfg)
	}
	e := &env{h: runtimetest.New(t, "rcs-as")}
	e.api = New(cfg, e.h.Runtime.Logger, e.h.Runtime.Metrics)
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
		{"POST", messagesPath, "Bearer " + currentToken, 503},
		{"POST", notesPath, "bearer " + nextToken, 503},
		{"POST", "/v1/elsewhere", "Bearer " + currentToken, 404},
		{"POST", "/v1/chatbot/messages/", "Bearer " + currentToken, 404},
		{"GET", messagesPath, "Bearer " + currentToken, 405},
	} {
		status, h, _ := e.do(t, c.method, c.path, c.auth, "application/json", message(nil))
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
	for token, want := range map[string]int{"wrong": 401, currentToken: 503} {
		if res := readAnswer(t, e.rawRequest(t, messagesPath, token, "")); res.StatusCode != want || !res.Close {
			t.Errorf("token %q: %d, close %v", token, res.StatusCode, res.Close)
		}
	}
}
