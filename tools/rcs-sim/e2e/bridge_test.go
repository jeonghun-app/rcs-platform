//go:build e2ecompose

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/simtest"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/websocket/wstest"
)

// bridgeURLVar, when set, is a running rcs-bridge for the test to use, such
// as the compose service make bridge-up starts (http://rcs-bridge:8720 on
// the stack's network), with RCS_BRIDGE_TOKEN from deploy/compose.env.
// Unset, the test builds the bridge and runs it on this container.
const bridgeURLVar = "RCS_BRIDGE_E2E_URL"

// The bridge's endpoints in this test. The names are fixed, so that a rerun
// finds the subscriptions an earlier run made in hss (by name) instead of
// taking two slots more each time; what an earlier run left in rcs-as's
// queues is told apart by its Message-ID.
const (
	bridgeCar   = "e2e-car"
	bridgePhone = "e2e-phone"
)

// TestE2EBridgeOnTheComposeStack (#658): two endpoints the bridge creates
// register with IMS AKA through pcscf, icscf and scscf; a message sent
// while no event stream is open is kept by rcs-as and comes once one is
// open and the receiver registers again; a message from one
// to the other goes through rcs-as and arrives as an event with its body
// and content type, and the sender hears it was delivered; a display
// notification sent through the API reaches the sender; and a message to
// the receiver offline is kept by rcs-as (202) and arrives once it is
// online again.
func TestE2EBridgeOnTheComposeStack(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, svc := range []string{"hss", "icscf", "scscf", "pcscf", "rcs-as-a"} {
		waitReady(ctx, t, "http://"+svc+":8080/readyz")
	}
	br := startBridge(ctx, t)

	// Without the token: 401, and no event stream.
	if status, _ := br.call(ctx, t, http.MethodPut, "/v1/endpoints/"+bridgeCar, "", map[string]bool{"online": true}); status != http.StatusUnauthorized {
		t.Fatalf("a PUT without the token answered %d, want 401", status)
	}
	if c, res, err := wstest.Dial(br.url+"/v1/events", nil); err == nil || res == nil || res.StatusCode != http.StatusUnauthorized {
		if c != nil {
			c.Close(1000)
		}
		t.Fatalf("the event stream without the token: %v %v, want 401", res, err)
	}

	for _, name := range []string{bridgeCar, bridgePhone} {
		status, out := br.call(ctx, t, http.MethodPut, "/v1/endpoints/"+name, br.token, map[string]bool{"online": true})
		if status/100 != 2 || out["registered"] != true {
			t.Fatalf("PUT %s online answered %d %v", name, status, out)
		}
		if !strings.HasPrefix(str(out["tel"]), "tel:+15550108") || !strings.HasPrefix(str(out["impu"]), "sip:+15550108") {
			t.Fatalf("%s has identities %v, outside the bridge's range", name, out)
		}
	}

	run := randomHex(t)
	text := "rcs-bridge e2e " + run + " 한글 ✓"
	id := "e2e-" + run

	// No event stream is open yet, so nobody can take a message: the
	// phone's bridge answers rcs-as 480, rcs-as keeps the message, and the
	// car hears nothing. Once a stream is open and the phone registers
	// again, rcs-as delivers it, and only then is it delivered (code
	// review on #661). This assumes no other client holds a stream to the
	// bridge, which is so for the one the test starts.
	early := id + "-early"
	if out := br.send(ctx, t, bridgeCar, map[string]any{"to": bridgePhone, "body": text + " early", "message_id": early, "imdn": []string{"delivery"}}); out["sip_status"] != float64(202) {
		t.Fatalf("the send with no stream open answered %v, want rcs-as's 202", out)
	}
	br.awaitLog(ctx, t, `"msg":"message refused: no event stream is open"`)
	ev := br.events(t)
	for _, online := range []bool{false, true} {
		if status, out := br.call(ctx, t, http.MethodPut, "/v1/endpoints/"+bridgePhone, br.token, map[string]bool{"online": online}); status != http.StatusOK || out["registered"] != online {
			t.Fatalf("PUT %s online=%v answered %d %v", bridgePhone, online, status, out)
		}
	}
	if m := ev.await(t, "message", bridgePhone, early, ""); m["body"] != text+" early" || m["from_endpoint"] != bridgeCar {
		t.Fatalf("message event %v", m)
	}
	if d := ev.await(t, "imdn", bridgeCar, early, "delivered"); d["from_endpoint"] != bridgePhone {
		t.Fatalf("delivery notification event %v", d)
	}

	// rcs-as answers 202 to what it stores (docs/rcs-as.md, Answers); the
	// phone's own 200 would mean the MESSAGE went past it.
	if out := br.send(ctx, t, bridgeCar, map[string]any{"to": bridgePhone, "content_type": "text/plain;charset=utf-8", "body": text, "message_id": id, "imdn": []string{"delivery", "display"}}); out["sip_status"] != float64(202) || out["message_id"] != id {
		t.Fatalf("the send answered %v, want rcs-as's 202", out)
	}
	m := ev.await(t, "message", bridgePhone, id, "")
	if m["body"] != text || m["content_type"] != "text/plain;charset=utf-8" || m["from_endpoint"] != bridgeCar || !strings.HasPrefix(str(m["from"]), "tel:+15550108") {
		t.Fatalf("message event %v", m)
	}
	if d := ev.await(t, "imdn", bridgeCar, id, "delivered"); d["from_endpoint"] != bridgePhone {
		t.Fatalf("delivery notification event %v", d)
	}

	status, out := br.call(ctx, t, http.MethodPost, "/v1/endpoints/"+bridgePhone+"/imdn", br.token, map[string]any{"to": bridgeCar, "message_id": id, "status": "displayed"})
	if status != http.StatusOK || out["sip_status"] != float64(202) {
		t.Fatalf("the display notification answered %d %v, want rcs-as's 202", status, out)
	}
	if d := ev.await(t, "imdn", bridgeCar, id, "displayed"); d["from_endpoint"] != bridgePhone {
		t.Fatalf("display notification event %v", d)
	}

	// The phone goes offline: rcs-as keeps the message until it registers
	// again.
	if status, out := br.call(ctx, t, http.MethodPut, "/v1/endpoints/"+bridgePhone, br.token, map[string]bool{"online": false}); status != http.StatusOK || out["registered"] != false {
		t.Fatalf("PUT offline answered %d %v", status, out)
	}
	ev.awaitState(t, bridgePhone, "unregistered")
	stored := id + "-stored"
	if out := br.send(ctx, t, bridgeCar, map[string]any{"to": bridgePhone, "body": text + " stored", "message_id": stored, "imdn": []string{"delivery"}}); out["sip_status"] != float64(202) {
		t.Fatalf("the send to the offline phone answered %v, want rcs-as's 202", out)
	}
	if status, out := br.call(ctx, t, http.MethodPut, "/v1/endpoints/"+bridgePhone, br.token, map[string]bool{"online": true}); status != http.StatusOK || out["registered"] != true {
		t.Fatalf("PUT online again answered %d %v", status, out)
	}
	if m := ev.await(t, "message", bridgePhone, stored, ""); m["body"] != text+" stored" || m["from_endpoint"] != bridgeCar {
		t.Fatalf("stored message event %v", m)
	}
	ev.await(t, "imdn", bridgeCar, stored, "delivered")

	for _, name := range []string{bridgeCar, bridgePhone} {
		br.call(ctx, t, http.MethodPut, "/v1/endpoints/"+name, br.token, map[string]bool{"online": false})
	}
	br.checkLogs(t, br.token, env(t, "HSS_ADMIN_TOKEN"), run)
}

// bridgeUnderTest is the bridge the test talks to.
type bridgeUnderTest struct {
	url, token string
	// logs is the bridge's output when the test started it.
	logs *lockedBuffer
}

// startBridge returns the bridge of bridgeURLVar, or builds rcs-bridge and
// runs it on this container, on the stack's network, with a token of its
// own and hss's operator token, as the compose service has them.
func startBridge(ctx context.Context, t *testing.T) *bridgeUnderTest {
	t.Helper()
	if u := os.Getenv(bridgeURLVar); u != "" {
		return &bridgeUnderTest{url: strings.TrimSuffix(u, "/"), token: env(t, "RCS_BRIDGE_TOKEN")}
	}
	bin := build(t, "./tools/rcs-sim/cmd/rcs-bridge")
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(simtest.FreePort(t)))
	br := &bridgeUnderTest{url: "http://" + addr, token: randomHex(t) + randomHex(t), logs: &lockedBuffer{}}
	cmd := exec.Command(filepath.Join(bin, "rcs-bridge"))
	cmd.Env = []string{
		"RCS_BRIDGE_TOKEN=" + br.token,
		"RCS_BRIDGE_ADDR=" + addr,
		"RCS_BRIDGE_HSS_URL=" + hssAPI,
		"RCS_BRIDGE_HSS_TOKEN=" + env(t, "HSS_ADMIN_TOKEN"),
		// The compose service's key, so that both find the same
		// subscriptions by name.
		"RCS_BRIDGE_IMPI_KEY=" + env(t, "RCS_BRIDGE_IMPI_KEY"),
		"RCS_BRIDGE_PCSCF=" + net.JoinHostPort(env(t, "PCSCF_PUBLIC_HOST"), "5060"),
		"RCS_IMS_DOMAIN=" + composeDomain,
		"RCS_PII_HMAC_KEY=" + env(t, "RCS_PII_HMAC_KEY"),
		"RCS_LOG_LEVEL=debug",
	}
	cmd.Stdout, cmd.Stderr = br.logs, br.logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-exited:
		case <-time.After(30 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
		if t.Failed() {
			t.Logf("rcs-bridge log:\n%s", br.logs.String())
		}
	})
	for {
		if status, _ := br.call(ctx, t, http.MethodGet, "/healthz", br.token, nil); status == http.StatusOK {
			return br
		}
		select {
		case <-exited:
			t.Fatalf("rcs-bridge exited:\n%s", br.logs.String())
		case <-ctx.Done():
			t.Fatalf("rcs-bridge did not start:\n%s", br.logs.String())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// call sends a request with token ("" for none) and decodes the JSON answer.
func (b *bridgeUnderTest) call(ctx context.Context, t *testing.T, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(data)
	}
	var req *http.Request
	var err error
	if rd != nil {
		req, err = http.NewRequestWithContext(ctx, method, b.url+path, rd)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, b.url+path, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// send posts a message from endpoint and returns the answer, which must
// be 200.
func (b *bridgeUnderTest) send(ctx context.Context, t *testing.T, endpoint string, msg map[string]any) map[string]any {
	t.Helper()
	status, out := b.call(ctx, t, http.MethodPost, "/v1/endpoints/"+endpoint+"/messages", b.token, msg)
	if status != http.StatusOK {
		t.Fatalf("the send from %s answered %d %v", endpoint, status, out)
	}
	return out
}

// awaitLog waits until the bridge's log has line, when the test started
// the bridge; for one it did not start, it waits a few seconds instead.
func (b *bridgeUnderTest) awaitLog(ctx context.Context, t *testing.T, line string) {
	t.Helper()
	if b.logs == nil {
		time.Sleep(3 * time.Second)
		return
	}
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(b.logs.String(), line) {
		if time.Now().After(deadline) || ctx.Err() != nil {
			t.Fatalf("the bridge never logged %s:\n%s", line, b.logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// checkLogs fails if the bridge's log shows any of secrets, the message
// text's run token among them, or a run of eight digits or more, which an
// identity would be without internal/pii.
func (b *bridgeUnderTest) checkLogs(t *testing.T, secrets ...string) {
	t.Helper()
	if b.logs == nil {
		return
	}
	logs := b.logs.String()
	for _, s := range secrets {
		if strings.Contains(logs, s) {
			t.Error("the bridge's log shows a secret or a message body")
		}
	}
	// Each line's own time has nanoseconds, nine digits.
	untimed := regexp.MustCompile(`"time":"[^"]*"`).ReplaceAllString(logs, "")
	if regexp.MustCompile(`[0-9]{8,}`).MatchString(untimed) {
		t.Error("the bridge's log shows a run of eight digits, an identity not through internal/pii")
	}
	if !strings.Contains(logs, `"msg":"registered"`) {
		t.Errorf("the bridge's log has no registration:\n%s", logs)
	}
}

// eventStream reads the bridge's events.
type eventStream struct{ c *wstest.Client }

func (b *bridgeUnderTest) events(t *testing.T) *eventStream {
	t.Helper()
	c, _, err := wstest.Dial(b.url+"/v1/events", http.Header{"Authorization": {"Bearer " + b.token}})
	if err != nil {
		t.Fatalf("opening the event stream: %v", err)
	}
	t.Cleanup(func() { c.Close(1000) })
	return &eventStream{c: c}
}

// await returns the event of type typ for endpoint about messageID (and
// with status, when given), skipping the others: an earlier run's
// messages that rcs-as kept, and the registration events.
func (s *eventStream) await(t *testing.T, typ, endpoint, messageID, status string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		ev := s.next(t, time.Until(deadline))
		if ev["type"] == typ && ev["endpoint"] == endpoint && ev["message_id"] == messageID && (status == "" || ev["status"] == status) {
			return ev
		}
	}
	t.Fatalf("no %s event for %s about %s", typ, endpoint, messageID)
	return nil
}

func (s *eventStream) awaitState(t *testing.T, endpoint, state string) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		ev := s.next(t, time.Until(deadline))
		if ev["type"] == "registration" && ev["endpoint"] == endpoint && ev["state"] == state {
			return
		}
	}
	t.Fatalf("%s never became %s", endpoint, state)
}

func (s *eventStream) next(t *testing.T, timeout time.Duration) map[string]any {
	t.Helper()
	p, err := s.c.Next(timeout)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return nil
	}
	if err != nil {
		t.Fatalf("the event stream: %v", err)
	}
	var ev map[string]any
	if err := json.Unmarshal(p, &ev); err != nil {
		t.Fatalf("an event that is not JSON: %q", p)
	}
	return ev
}

func str(v any) string { s, _ := v.(string); return s }

func randomHex(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}

// lockedBuffer is the bridge's output, written by the process's pipes and
// read by the test.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
