//go:build e2ecompose

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/awsstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
)

// The group scenario's bounds. handshakeWait is how long the host may take
// to stop a task or write the logs (scripts/e2e-compose.sh bounds each
// docker call to 60 s); restartWait how long it may take to restart both
// rcs-as tasks, each stopped cleanly (25 s at most) and then healthy (120 s
// at most).
const (
	handshakeWait = 90 * time.Second
	restartWait   = 6 * time.Minute
	handshakePoll = 100 * time.Millisecond
	// groupRejoins is how many times the client rejoins before the owner
	// stops. The core gives each request to either task at random, so
	// each rejoin's INVITE, ACK and BYE have a half chance each of reaching
	// the task that does not own the group, which forwards them: none of
	// the 3 × 5 doing so is a chance of 2^-15.
	groupRejoins = 5
)

// handshake is the test's side of scripts/e2e-compose.sh: files in a
// directory the host watches, which make e2e-compose names in
// RCS_E2E_HANDSHAKE. rcs-sim writes `conference` there when it wants the
// group's owner stopped and waits for `stopped`; the test finds the owner
// and asks the host to stop it.
type handshake struct{ dir string }

func newHandshake(t *testing.T) handshake {
	t.Helper()
	dir := os.Getenv("RCS_E2E_HANDSHAKE")
	if dir == "" {
		t.Fatal("RCS_E2E_HANDSHAKE is not set: run the test through make e2e-compose, whose host side stops the group's owner")
	}
	return handshake{dir: dir}
}

// wait returns the content of the first of names to appear, and which one.
func (h handshake) wait(ctx context.Context, names ...string) (string, []byte, error) {
	for {
		for _, n := range names {
			if b, err := os.ReadFile(filepath.Join(h.dir, n)); err == nil {
				return n, b, nil
			}
		}
		select {
		case <-ctx.Done():
			return "", nil, ctx.Err()
		case <-time.After(handshakePoll):
		}
	}
}

// write writes a request file atomically, so that the host never reads it
// half written.
func (h handshake) write(name string, data []byte) error {
	tmp := filepath.Join(h.dir, name+".tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(h.dir, name))
}

// stop has the host stop the rcs-as task at addr and returns its service.
func (h handshake) stop(ctx context.Context, addr netip.Addr) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeWait)
	defer cancel()
	if err := h.write("stop", []byte(addr.String())); err != nil {
		return "", err
	}
	name, b, err := h.wait(ctx, "stopped", "failed")
	switch {
	case err != nil:
		return "", errors.New("the host did not stop the owner in time")
	case name == "failed":
		return "", errors.New("the host could not stop the owner: " + strings.TrimSpace(string(b)))
	}
	return strings.TrimSpace(string(b)), nil
}

// restart has the host restart both rcs-as tasks and returns the host's
// time after, in Unix seconds. A task writes its counters as it stops and
// starts with none, so the logs from then on hold what happens after alone
// (runtime.Metrics writes them only once a minute otherwise).
func (h handshake) restart(ctx context.Context) (string, error) {
	for _, n := range []string{"restarted", "failed"} {
		_ = os.Remove(filepath.Join(h.dir, n))
	}
	ctx, cancel := context.WithTimeout(ctx, restartWait)
	defer cancel()
	if err := h.write("restart", nil); err != nil {
		return "", err
	}
	name, b, err := h.wait(ctx, "restarted", "failed")
	switch {
	case err != nil:
		return "", errors.New("the host did not restart the rcs-as tasks in time")
	case name == "failed":
		return "", errors.New("the host could not restart the rcs-as tasks: " + strings.TrimSpace(string(b)))
	}
	return strings.TrimSpace(string(b)), nil
}

// logs has the host write the rcs-as tasks' logs since since, a time in
// Unix seconds that restart returned, and returns them.
func (h handshake) logs(ctx context.Context, since string) ([]byte, error) {
	_ = os.Remove(filepath.Join(h.dir, "logs"))
	if err := h.write("logs-request", []byte(since)); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, handshakeWait)
	defer cancel()
	_, b, err := h.wait(ctx, "logs")
	return b, err
}

// emfSum is the sum of the metric name over the EMF lines in logs (runtime.
// Metrics): one line per metric and interval, the value under its name.
func emfSum(logs []byte, name string) float64 {
	var sum float64
	sc := bufio.NewScanner(bytes.NewReader(logs))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if !bytes.Contains(line, []byte(`"_aws"`)) {
			continue
		}
		var m map[string]any
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		if v, ok := m[name].(float64); ok {
			sum += v
		}
	}
	return sum
}

// ownerStop is what the test learned stopping the group's owner.
type ownerStop struct {
	before  groupstore.Owner
	service string
	err     error
}

// serveOwnerStop waits for rcs-sim to ask for the group's owner to be
// stopped, reads the owner from the groups table, and has the host stop it.
func serveOwnerStop(ctx context.Context, h handshake, groups *awsstore.Groups) <-chan ownerStop {
	out := make(chan ownerStop, 1)
	go func() {
		var s ownerStop
		defer func() { out <- s }()
		_, conf, err := h.wait(ctx, "conference")
		if err != nil {
			s.err = errors.New("rcs-sim never asked for the owner to stop")
			return
		}
		octx, cancel := context.WithTimeout(ctx, handshakeWait)
		s.before, err = groups.Owner(octx, strings.TrimSpace(string(conf)))
		cancel()
		if err != nil {
			s.err = errors.New("reading the group's owner: " + err.Error())
			return
		}
		ap, err := netip.ParseAddrPort(s.before.SIP)
		if err != nil {
			s.err = errors.New("the owner's SIP address does not parse")
			return
		}
		s.service, s.err = h.stop(ctx, ap.Addr())
	}()
	return out
}

func TestE2EComposeGroupChat(t *testing.T) {
	domain := composeDomain
	impi := composeIMSI + "@" + domain
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	for _, svc := range []string{"hss", "msrp-relay", "icscf", "scscf", "pcscf", "rcs-as-a", "rcs-as-b"} {
		waitReady(ctx, t, "http://"+svc+":8080/readyz")
	}
	h := newHandshake(t)
	// Both tasks start afresh: their counters from now on are this run's.
	since, err := h.restart(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, svc := range []string{"rcs-as-a", "rcs-as-b"} {
		waitReady(ctx, t, "http://"+svc+":8080/readyz")
	}
	// DynamoDB Local takes any credentials, and the SDK needs some: without
	// them it would look for a task role that is not there.
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "local")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "local")
	groups, err := awsstore.NewGroups(ctx, awsstore.Config{Table: "groupchats", Endpoint: "http://dynamodb:8000"})
	if err != nil {
		t.Fatal(err)
	}
	putProfile(ctx, t, impi, "")
	doc := acsConfiguration(ctx, t, env(t, "ACS_ADMIN_TOKEN"))
	pcscf := doc.value("LBO_P-CSCF_Address", "Address")
	stopCtx, stopWaiting := context.WithCancel(ctx)
	defer stopWaiting()
	stopped := serveOwnerStop(stopCtx, h, groups)

	bin := build(t, "./tools/rcs-sim")
	cmd := exec.CommandContext(ctx, filepath.Join(bin, "rcs-sim"),
		"-sip-proxy", net.JoinHostPort(pcscf, "5060"), "-sip-transport", "tcp",
		"-sip-impi", impi, "-sip-peer-impi", composePeerIMSI+"@"+domain,
		"-sip-conference-factory", doc.value("CHAT", "ConfFctyURI"),
		"-group-rejoins", "5", "-group-owner-stop-dir", h.dir, "-require-all",
		"group-chat")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	t.Logf("rcs-sim group output:\n%s%s", stdout.String(), stderr.String())
	if err != nil {
		t.Errorf("rcs-sim group-chat: %v", err)
	}
	// rcs-sim has ended: an owner stop it never asked for will not come.
	if _, err := os.Stat(filepath.Join(h.dir, "conference")); err != nil {
		stopWaiting()
	}
	checkResults(t, stdout.String(), stderr.String(), []string{
		"group-chat/register", "group-chat/create", "group-chat/invited", "group-chat/message", "group-chat/roster",
		"group-chat/rejoin", "group-chat/owner-stop", "group-chat/owner-lost", "group-chat/rejoin-after-loss",
		"group-chat/roster-after-loss", "group-chat/message-after-loss", "group-chat/clean",
	}, env(t, "RCS_SIM_AKA_K"), env(t, "RCS_SIM_AKA_OPC"), env(t, "RCS_SIM_PEER_AKA_K"), env(t, "RCS_SIM_PEER_AKA_OPC"),
		composeIMSI, composePeerIMSI)

	var stop ownerStop
	select {
	case stop = <-stopped:
	case <-ctx.Done():
		t.Fatal("the owner stop never finished")
	}
	if stop.err != nil {
		t.Fatalf("stopping the owner: %v", stop.err)
	}
	if stop.service != "rcs-as-a" && stop.service != "rcs-as-b" {
		t.Fatalf("the host stopped %q, not an rcs-as task", stop.service)
	}
	// The other task took the group over: its owner item names another
	// task, one epoch up (docs/rcs-as.md, groupchats table).
	conf, err := os.ReadFile(filepath.Join(h.dir, "conference"))
	if err != nil {
		t.Fatal(err)
	}
	after, err := groups.Owner(ctx, strings.TrimSpace(string(conf)))
	if err != nil {
		t.Fatalf("reading the group's owner after the stop: %v", err)
	}
	if after.Task == stop.before.Task || after.SIP == stop.before.SIP || after.Epoch != stop.before.Epoch+1 {
		t.Errorf("after the stop the owner is task %t, address %t, epoch %d (before %d): want the other task, one epoch up",
			after.Task == stop.before.Task, after.SIP == stop.before.SIP, after.Epoch, stop.before.Epoch)
	}
	// And the tasks counted it in this run: a request forwarded to the
	// owner before it stopped, the rejoins' through the other task, and the
	// takeover. Restarted again, each task writes its counters as it stops.
	if _, err := h.restart(ctx); err != nil {
		t.Fatal(err)
	}
	logs, err := h.logs(ctx, since)
	if err != nil {
		t.Fatalf("the rcs-as logs: %v", err)
	}
	if fwd, takeover := emfSum(logs, "group.forwarded"), emfSum(logs, "group.owner_takeover"); fwd == 0 || takeover == 0 {
		t.Errorf("this run's group.forwarded %v, group.owner_takeover %v: want both above 0", fwd, takeover)
	}
}
