package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/simtest"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/websocket/wstest"
)

const testToken = "bridge-token-0123456789abcdef0123456789abcdef"

func lookupOf(env map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := env[k]; return v, ok }
}

func goodEnv() map[string]string {
	return map[string]string{
		"RCS_BRIDGE_TOKEN":     testToken,
		"RCS_BRIDGE_HSS_TOKEN": "hss-admin-token",
		"RCS_BRIDGE_IMPI_KEY":  "impi-key-0123456789abcdef0123456789abcdef",
		"RCS_IMS_DOMAIN":       "ims.mnc001.mcc001.3gppnetwork.org",
	}
}

func TestTheDefaultsAreTheComposeStacks(t *testing.T) {
	c, err := readConfig(lookupOf(goodEnv()))
	if err != nil {
		t.Fatal(err)
	}
	// Loopback outside compose: plain HTTP, and the bridge holds hss's
	// operator token.
	if c.addr != "127.0.0.1:8720" || c.hssURL != "http://hss:8081" || c.pcscf != "pcscf:5060" || c.maxEndpoints != 64 {
		t.Fatalf("defaults %+v", c)
	}
}

func TestSettingsThatCannotWorkAreRefusedTogetherWithoutTheirValues(t *testing.T) {
	env := map[string]string{
		"RCS_BRIDGE_TOKEN":         "short-secret-value",
		"RCS_BRIDGE_ADDR":          "8720",
		"RCS_BRIDGE_MAX_ENDPOINTS": "0",
		"RCS_PII_HMAC_KEY":         "short-pii-key",
		"RCS_BRIDGE_IMPI_KEY":      "short-impi-key",
		"RCS_LOG_LEVEL":            "loud",
	}
	_, err := readConfig(lookupOf(env))
	if err == nil {
		t.Fatal("readConfig took them")
	}
	for _, want := range []string{"RCS_BRIDGE_TOKEN is shorter", "RCS_BRIDGE_HSS_TOKEN is required", "RCS_IMS_DOMAIN is required",
		"RCS_BRIDGE_IMPI_KEY is shorter", "RCS_BRIDGE_ADDR", "RCS_BRIDGE_MAX_ENDPOINTS", "RCS_PII_HMAC_KEY", "RCS_LOG_LEVEL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not say %q: %v", want, err)
		}
	}
	for _, secret := range []string{"short-secret-value", "short-pii-key", "short-impi-key"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error shows a secret: %v", err)
		}
	}
	var stderr bytes.Buffer
	if code := run(context.Background(), nil, lookupOf(env), &bytes.Buffer{}, &stderr); code != exitUsage {
		t.Fatalf("run = %d, want %d", code, exitUsage)
	}
}

// syncBuffer is a Buffer the server's goroutine and the test share.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestTheHealthcheckAsksTheRunningBridgeWithTheToken(t *testing.T) {
	env := goodEnv()
	env["RCS_BRIDGE_ADDR"] = "127.0.0.1:" + strconv.Itoa(simtest.FreePort(t))
	ctx, cancel := context.WithCancel(context.Background())
	var out syncBuffer
	exited := make(chan int, 1)
	go func() { exited <- run(ctx, nil, lookupOf(env), &out, &out) }()
	deadline := time.Now().Add(10 * time.Second)
	for run(context.Background(), []string{"-healthcheck"}, lookupOf(env), &bytes.Buffer{}, &bytes.Buffer{}) != exitOK {
		select {
		case code := <-exited:
			t.Fatalf("the bridge exited with %d:\n%s", code, out.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the healthcheck never passed:\n%s", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Another token is not let in.
	wrong := goodEnv()
	wrong["RCS_BRIDGE_ADDR"], wrong["RCS_BRIDGE_TOKEN"] = env["RCS_BRIDGE_ADDR"], testToken+"-not-it"
	var stderr bytes.Buffer
	if code := run(context.Background(), []string{"-healthcheck"}, lookupOf(wrong), &bytes.Buffer{}, &stderr); code != exitFailed || !strings.Contains(stderr.String(), "401") {
		t.Fatalf("the healthcheck with another token = %d %s", code, stderr.String())
	}
	cancel()
	if code := <-exited; code != exitOK {
		t.Fatalf("the bridge exited with %d", code)
	}
	for _, secret := range []string{testToken, "hss-admin-token"} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("the log shows a token:\n%s", out.String())
		}
	}
	if !strings.Contains(out.String(), `"msg":"listening"`) {
		t.Fatalf("no listening line:\n%s", out.String())
	}
}

func TestAnIMPIKeyIsRequired(t *testing.T) {
	env := goodEnv()
	delete(env, "RCS_BRIDGE_IMPI_KEY")
	if _, err := readConfig(lookupOf(env)); err == nil || !strings.Contains(err.Error(), "RCS_BRIDGE_IMPI_KEY is required") {
		t.Fatalf("readConfig = %v", err)
	}
}

// A connection that got its 401 and stays idle, or that never finishes
// its request, is closed by the server; an event stream, whose deadlines
// websocket.Upgrade clears, outlives the same timeouts (security review on
// #661). The timeouts are cut to fractions of a second for the test.
func TestConnectionsWithoutTheTokenDoNotStayButAnEventStreamDoes(t *testing.T) {
	saved := httpTimeouts
	httpTimeouts.read, httpTimeouts.write, httpTimeouts.idle = 300*time.Millisecond, 300*time.Millisecond, 300*time.Millisecond
	defer func() { httpTimeouts = saved }()
	env := goodEnv()
	addr := "127.0.0.1:" + strconv.Itoa(simtest.FreePort(t))
	env["RCS_BRIDGE_ADDR"] = addr
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out syncBuffer
	exited := make(chan int, 1)
	go func() { exited <- run(ctx, nil, lookupOf(env), &out, &out) }()
	defer func() { cancel(); <-exited }()
	deadline := time.Now().Add(10 * time.Second)
	for run(context.Background(), []string{"-healthcheck"}, lookupOf(env), &bytes.Buffer{}, &bytes.Buffer{}) != exitOK {
		if time.Now().After(deadline) {
			t.Fatalf("the bridge did not start:\n%s", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	stream, _, err := wstest.Dial("http://"+addr+"/v1/events", http.Header{"Authorization": {"Bearer " + testToken}})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close(1000)

	// One that got its 401 and keeps the connection, one that sends half
	// a request, and one that sends a body slower than the read timeout.
	idle := dial(t, addr)
	if _, err := idle.Write([]byte("GET /healthz HTTP/1.1\r\nHost: b\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if res, err := http.ReadResponse(bufio.NewReader(idle), nil); err != nil || res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("answered %v %v, want 401", res, err)
	}
	half := dial(t, addr)
	if _, err := half.Write([]byte("PUT /v1/endpoints/car HTTP/1.1\r\nHost: b\r\nAuthorization: Bearer " + testToken + "\r\nContent-Length: 100\r\n\r\n{")); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]net.Conn{"idle after a 401": idle, "body never finished": half} {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		b := make([]byte, 4096)
		for {
			_, err := c.Read(b)
			if err == nil {
				continue
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Errorf("%s: the server kept the connection", name)
			}
			break
		}
	}
	// The stream is still there, well past every timeout.
	if err := stream.Ping(); err != nil {
		t.Fatalf("the event stream: %v", err)
	}
	if _, err := stream.Next(500 * time.Millisecond); err != nil {
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("the event stream ended: %v", err)
		}
	}
	if stream.Pongs() != 1 {
		t.Fatalf("the event stream answered %d pings, want 1", stream.Pongs())
	}
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
