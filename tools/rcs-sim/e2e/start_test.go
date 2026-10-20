//go:build e2e

package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/simtest"
)

// A service that exits before it is ready ends the test that started it at
// once (#139). The cleanup used to wait for the exit a second time, after
// the readiness wait had taken it, and make e2e hung until go test's
// timeout. The child runs in a process of its own, so a hang shows here as
// a timeout, or as the runtime's deadlock report when nothing else runs in
// the child, instead of hanging this test too.
func TestAServiceThatExitsBeforeItIsReadyEndsTheTestAtOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestChildServiceThatExitsAtOnce$", "-test.count=1")
	cmd.Env = append(os.Environ(), "E2E_CHILD=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("the child test hung:\n%s", out)
	}
	if err == nil || !strings.Contains(string(out), "svc exited: exit status 3") {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

// TestChildServiceThatExitsAtOnce is the child of the test above: it starts
// a "service" that exits at once.
func TestChildServiceThatExitsAtOnce(t *testing.T) {
	if os.Getenv("E2E_CHILD") != "1" {
		t.Skip("run by TestAServiceThatExitsBeforeItIsReadyEndsTheTestAtOnce")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "svc"), []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	start(t, dir, "svc", strconv.Itoa(simtest.FreePort(t)), nil)
	t.Fatal("start returned for a service that exited")
}
