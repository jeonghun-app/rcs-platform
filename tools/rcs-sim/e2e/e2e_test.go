//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The stack's test identities: an IMPI of the MCC 001 test network (on the
// allow-list) and secrets made up for this run.
const (
	ftUser     = "001010000000001@ims.mnc001.mcc001.3gppnetwork.org"
	ftPassword = "e2e-ft-password"
	relayToken = "e2e-relay-token-0123456789-0123456789-abcdef"
	// partSize is ft-server's smallest (the memory store keeps S3's 5 MiB
	// rule), so the resume file is a little over one part.
	partSize   = 5 << 20
	resumeSize = partSize + 1<<20
	// maxInfoWait bounds how long ft-resume's get_upload_info step waits
	// for ft-server to notice the break and keep the parts, its 300 ms quiet
	// time included: a server that is slow to keep a broken upload fails
	// here instead of passing on retries. A bound on elapsed time rather
	// than on the number of answers keeps its margin when a loaded host
	// answers slowly.
	maxInfoWait = 2000 // ms
)

// result is one line of rcs-sim's output.
type result struct {
	Scenario string           `json:"scenario"`
	Step     string           `json:"step"`
	OK       bool             `json:"ok"`
	Millis   int64            `json:"ms"`
	Error    string           `json:"error"`
	Detail   map[string]int64 `json:"detail"`
}

func TestE2ESimulatorAgainstTheServiceBinaries(t *testing.T) {
	bin := build(t)

	ftPort, ftAdmin := freePort(t), freePort(t)
	start(t, bin, "ft-server", ftAdmin, map[string]string{
		"FT_LISTEN_ADDR":    "127.0.0.1:" + ftPort,
		"FT_UPLOAD_URI":     "http://127.0.0.1:" + ftPort + "/ft",
		"FT_DOWNLOAD_URI":   "http://127.0.0.1:" + ftPort + "/dl",
		"FT_REALM":          "ft.ims.mnc001.mcc001.3gppnetwork.org",
		"FT_STORE":          "memory",
		"FT_CREDENTIALS":    "static",
		"FT_STATIC_USERS":   ftUser + "=" + ftPassword,
		"FT_PART_SIZE":      strconv.Itoa(partSize),
		"FT_SWEEP_INTERVAL": "1h",
	})

	public, control, relayAdmin, core := freePort(t), freePort(t), freePort(t), freePort(t)
	start(t, bin, "msrp-relay", relayAdmin, map[string]string{
		"RELAY_LISTEN_ADDR":   "127.0.0.1:" + public,
		"RELAY_CONTROL_ADDR":  "127.0.0.1:" + control,
		"RELAY_PUBLIC_HOST":   "127.0.0.1",
		"RELAY_PUBLIC_PORT":   public,
		"RELAY_PUBLIC_TLS":    "false",
		"RELAY_CORE_HOST":     "127.0.0.1",
		"RELAY_CORE_NETWORKS": "127.0.0.0/8",
		"RELAY_CORE_PORTS":    core,
		"RELAY_STORE":         "memory",
		"RELAY_PCSCF_TOKEN":   relayToken,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(bin, "rcs-sim"),
		"-ft-upload-url", "http://127.0.0.1:"+ftPort+"/ft",
		"-resume-size", strconv.Itoa(resumeSize),
		"-relay-control", "http://127.0.0.1:"+control,
		"-core-listen", "127.0.0.1:"+core,
		// Quiet for five keep-alive intervals.
		"-msrp-keepalive", "300ms", "-idle-wait", "1500ms",
		"all")
	cmd.Env = append(os.Environ(),
		"RCS_SIM_FT_USER="+ftUser, "RCS_SIM_FT_PASSWORD="+ftPassword, "RCS_SIM_RELAY_TOKEN="+relayToken)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	t.Logf("rcs-sim output:\n%s%s", stdout.String(), stderr.String())
	if err != nil {
		t.Fatalf("rcs-sim: %v", err)
	}

	out := stdout.String() + stderr.String()
	seen := map[string]result{}
	sc := bufio.NewScanner(&stdout)
	for sc.Scan() {
		var r result
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("not a result line: %q", sc.Text())
		}
		if !r.OK {
			t.Errorf("%s/%s: %s", r.Scenario, r.Step, r.Error)
		}
		seen[r.Scenario+"/"+r.Step] = r
	}
	for _, want := range []string{
		"ft/upload", "ft/download", "ft/download-range", "ft/download-resume", "ft/download-thumbnail",
		"ft-resume/interrupted-upload", "ft-resume/get_upload_info", "ft-resume/resume", "ft-resume/download",
		"chat-client-originated/client-to-core", "chat-client-originated/core-to-client", "chat-client-originated/keep-alive",
		"chat-client-originated/release",
		"chat-core-originated/connect-then-answer", "chat-core-originated/core-sends-first", "chat-core-originated/client-to-core",
		"chat-core-originated/release",
	} {
		if _, ok := seen[want]; !ok {
			t.Errorf("step %s did not run", want)
		}
	}
	// The parts of the broken upload were kept: rcsjta would have uploaded
	// the whole file again.
	if _, ok := seen["ft-resume/upload-again"]; ok {
		t.Error("ft-resume uploaded again: ft-server kept nothing of the broken upload")
	}
	if info := seen["ft-resume/get_upload_info"]; info.Millis > maxInfoWait {
		t.Errorf("get_upload_info took %d ms (%d answers asked again, %d of them 404), more than %d ms: ft-server is slow to keep a broken upload",
			info.Millis, info.Detail["retries"], info.Detail["not_held"], maxInfoWait)
	}
	// Nothing on an idle stack is busy: a retry rcsjta would make here
	// would hide an overloaded or misconfigured ft-server.
	for name, r := range seen {
		if n := r.Detail["busy_retries"]; n != 0 {
			t.Errorf("%s: %d upload POSTs sent again after 503", name, n)
		}
	}
	// The same rule as the unit tests' (scenario_test.go): no secret, test
	// number, URL or address, on either stream.
	for _, leak := range []string{ftPassword, relayToken, ftUser, "15550100001", "15550100002", "http://", "msrp://", "127.0.0.1"} {
		if strings.Contains(out, leak) {
			t.Errorf("rcs-sim printed %q", leak)
		}
	}
}

// build compiles the three binaries into a temporary directory.
func build(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command("go", "build", "-o", dir, "./cmd/ft-server", "./cmd/msrp-relay", "./tools/rcs-sim")
	cmd.Dir = filepath.Join("..", "..", "..")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return dir
}

// start runs one service binary with env and the shared settings of a test
// stack, and waits until its /readyz answers 200. Its log goes to the test
// log when the test fails.
func start(t *testing.T, bin, name, admin string, env map[string]string) {
	t.Helper()
	cmd := exec.Command(filepath.Join(bin, name))
	cmd.Env = []string{"RCS_ENV=test", "RCS_ADMIN_ADDR=127.0.0.1:" + admin, "RCS_SHUTDOWN_TIMEOUT=20s", "HOME=" + t.TempDir()}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-exited:
		case <-time.After(30 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
		if t.Failed() {
			t.Logf("%s log:\n%s", name, logs.String())
		}
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := http.Get("http://127.0.0.1:" + admin + "/readyz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		select {
		case err := <-exited:
			t.Fatalf("%s exited: %v\n%s", name, err, logs.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not become ready\n%s", name, logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// freePort returns a loopback port nothing listens on now; the services
// must be told their ports before they start.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return fmt.Sprint(ln.Addr().(*net.TCPAddr).Port)
}
