package main

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/simtest"
)

const testToken = "bridge-token-0123456789abcdef0123456789abcdef"

func lookupOf(env map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := env[k]; return v, ok }
}

func goodEnv() map[string]string {
	return map[string]string{
		"RCS_BRIDGE_TOKEN":     testToken,
		"RCS_BRIDGE_HSS_TOKEN": "hss-admin-token",
		"RCS_IMS_DOMAIN":       "ims.mnc001.mcc001.3gppnetwork.org",
	}
}

func TestTheDefaultsAreTheComposeStacks(t *testing.T) {
	c, err := readConfig(lookupOf(goodEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if c.addr != ":8720" || c.hssURL != "http://hss:8081" || c.pcscf != "pcscf:5060" || c.maxEndpoints != 64 {
		t.Fatalf("defaults %+v", c)
	}
}

func TestSettingsThatCannotWorkAreRefusedTogetherWithoutTheirValues(t *testing.T) {
	env := map[string]string{
		"RCS_BRIDGE_TOKEN":         "short-secret-value",
		"RCS_BRIDGE_ADDR":          "8720",
		"RCS_BRIDGE_MAX_ENDPOINTS": "0",
		"RCS_PII_HMAC_KEY":         "short-pii-key",
		"RCS_LOG_LEVEL":            "loud",
	}
	_, err := readConfig(lookupOf(env))
	if err == nil {
		t.Fatal("readConfig took them")
	}
	for _, want := range []string{"RCS_BRIDGE_TOKEN is shorter", "RCS_BRIDGE_HSS_TOKEN is required", "RCS_IMS_DOMAIN is required",
		"RCS_BRIDGE_ADDR", "RCS_BRIDGE_MAX_ENDPOINTS", "RCS_PII_HMAC_KEY", "RCS_LOG_LEVEL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not say %q: %v", want, err)
		}
	}
	for _, secret := range []string{"short-secret-value", "short-pii-key"} {
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
