package simtest

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A relay that stops before it is ready, because its port is taken, ends
// the test that started it at once (#107). The cleanup used to wait for
// the relay's result a second time, after the readiness wait had taken it,
// and the test hung until go test's 10-minute timeout. The child test runs
// in a process of its own, so a hang shows here as a timeout and not as
// this test hanging too.
func TestARelayThatCannotListenEndsTheTestAtOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestChildRelayOnATakenPort$", "-test.count=1")
	cmd.Env = append(os.Environ(), "SIMTEST_CHILD=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("the child test hung:\n%s", out)
	}
	if err == nil || !strings.Contains(string(out), "address already in use") || strings.Contains(string(out), "want EADDRINUSE") {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

// TestChildRelayOnATakenPort is the child of the test above: it starts a
// relay on a port that is taken and fails the way StartRelay does.
func TestChildRelayOnATakenPort(t *testing.T) {
	if os.Getenv("SIMTEST_CHILD") != "1" {
		t.Skip("run by TestARelayThatCannotListenEndsTheTestAtOnce")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, err = startRelay(t, ln.Addr().(*net.TCPAddr).Port, FreePort(t), nil, nil)
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Errorf("startRelay = %v, want EADDRINUSE, which StartRelay retries", err)
	}
	t.Fatalf("msrp-relay stopped: %v", err)
}

// StartRelay tries again with fresh ports when the first ones are taken,
// and only then (QA on #127): a relay whose first public port is taken still
// starts and answers.
func TestStartRelayTriesAgainWhenItsPortIsTaken(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	taken, calls := ln.Addr().(*net.TCPAddr).Port, 0
	freePorts = func(t testing.TB, n int) []int {
		if calls++; calls == 1 {
			return append([]int{taken}, FreePorts(t, n-1)...)
		}
		return FreePorts(t, n)
	}
	defer func() { freePorts = FreePorts }()
	r := StartRelay(t)
	resp, err := http.Post(r.Control.JoinPath("/v1/bindings").String(), "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || calls != 2 {
		t.Fatalf("control = %d after %d port picks, want 401 after 2", resp.StatusCode, calls)
	}
}

func TestFreePortsAreDifferent(t *testing.T) {
	for range 200 {
		ps := FreePorts(t, 6)
		seen := map[int]bool{}
		for _, p := range ps {
			if seen[p] {
				t.Fatalf("FreePorts gave %d twice: %v", p, ps)
			}
			seen[p] = true
		}
	}
}
