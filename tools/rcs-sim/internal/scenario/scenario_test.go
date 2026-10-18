package scenario_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/anchor"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/ft"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/scenario"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/simtest"
)

const part = 64 << 10

var (
	self = cpim.Address{URI: "sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org"}
	peer = cpim.Address{URI: "sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org"}
)

// stack starts ft-server and msrp-relay in the test process and returns a
// Config for them.
func stack(t *testing.T) scenario.Config {
	t.Helper()
	f := simtest.StartFT(t, part)
	corePort := simtest.FreePort(t)
	r := simtest.StartRelay(t, corePort)
	return scenario.Config{
		FT:         &ft.Client{HTTP: f.Server.Client(), UploadURL: f.UploadURL, User: simtest.FTUser, Password: ft.NewSecret(simtest.FTPassword)},
		FileSize:   100 << 10,
		ResumeSize: 5*part + 123,
		Control:    &anchor.Control{HTTP: http.DefaultClient, URL: r.Control, Token: anchor.NewToken(simtest.RelayToken)},
		CoreListen: "127.0.0.1:" + strconv.Itoa(corePort),
		MSRP:       msrp.Config{KeepAliveInterval: 100 * time.Millisecond},
		IdleWait:   400 * time.Millisecond,
		Self:       self, Peer: peer,
		StepTimeout: 20 * time.Second,
	}
}

func runAll(t *testing.T, cfg scenario.Config, names ...string) (bool, []scenario.Result) {
	t.Helper()
	var results []scenario.Result
	ok, err := scenario.Run(context.Background(), cfg, names, func(r scenario.Result) { results = append(results, r) })
	if err != nil {
		t.Fatal(err)
	}
	return ok, results
}

func TestEveryScenarioPassesAgainstTheRealServices(t *testing.T) {
	cfg := stack(t)
	ok, results := runAll(t, cfg, "all")
	for _, r := range results {
		if !r.OK {
			t.Errorf("%s/%s failed: %s", r.Scenario, r.Step, r.Error)
		}
	}
	if !ok {
		t.Fatal("the run failed")
	}
	steps := map[string]bool{}
	for _, r := range results {
		steps[r.Scenario+"/"+r.Step] = true
	}
	for _, want := range []string{
		"ft/upload", "ft/download", "ft/download-range", "ft/download-thumbnail", "ft/get_download_info",
		"ft-resume/interrupted-upload", "ft-resume/get_upload_info", "ft-resume/resume", "ft-resume/download",
		"chat-client-originated/connect", "chat-client-originated/client-to-core", "chat-client-originated/core-to-client",
		"chat-client-originated/chunked-message", "chat-client-originated/keep-alive", "chat-client-originated/release",
		"chat-core-originated/core-sends-first", "chat-core-originated/client-to-core", "chat-core-originated/release",
	} {
		if !steps[want] {
			t.Errorf("step %s did not run", want)
		}
	}
}

func TestResultsCarryNoSecretsOrIdentifiers(t *testing.T) {
	cfg := stack(t)
	_, results := runAll(t, cfg, "all")
	out, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{simtest.FTPassword, simtest.RelayToken, simtest.FTUser, "15550100001", "15550100002", "msrp://", "http://"} {
		if strings.Contains(string(out), secret) {
			t.Fatalf("results contain %q:\n%s", secret, out)
		}
	}
}

func TestAMissingClientFailsTheScenarioAtItsFirstStep(t *testing.T) {
	ok, results := runAll(t, scenario.Config{Self: self, Peer: peer}, "ft", "ft-resume", "chat-client-originated", "chat-core-originated")
	if ok || len(results) != 4 {
		t.Fatalf("ok %v, %d results", ok, len(results))
	}
	for _, r := range results {
		if r.OK || r.Error == "" {
			t.Fatalf("result %+v", r)
		}
	}
}

func TestUnknownScenariosAreRefusedBeforeAnythingRuns(t *testing.T) {
	ran := false
	_, err := scenario.Run(context.Background(), scenario.Config{}, []string{"ft", "nope"}, func(scenario.Result) { ran = true })
	if !errors.Is(err, scenario.ErrUnknown) || ran {
		t.Fatalf("Run = %v, ran %v", err, ran)
	}
	if names := scenario.Names(); len(names) != 4 || names[0] != "chat-client-originated" {
		t.Fatalf("Names = %v", names)
	}
}

func TestAResumeFileNoLargerThanAPartIsReportedAsSuch(t *testing.T) {
	cfg := stack(t)
	cfg.ResumeSize = part / 2
	ok, results := runAll(t, cfg, "ft-resume")
	last := results[len(results)-1]
	if ok || last.Step != "get_upload_info" || !strings.Contains(last.Error, "FT_PART_SIZE") {
		t.Fatalf("last result %+v", last)
	}
}

func TestAWrongRelayTokenFailsTheChatAtAllocation(t *testing.T) {
	cfg := stack(t)
	cfg.Control.Token = anchor.NewToken("wrong-wrong-wrong-wrong-wrong-wrong-wrong-xx")
	ok, results := runAll(t, cfg, "chat-client-originated")
	last := results[len(results)-1]
	if ok || last.Step != "allocate" || !strings.Contains(last.Error, "401") {
		t.Fatalf("last result %+v", last)
	}
}

func TestAStandInThatCannotListenFailsTheChat(t *testing.T) {
	cfg := stack(t)
	cfg.CoreListen = "256.0.0.1:1"
	ok, results := runAll(t, cfg, "chat-core-originated")
	if ok || results[0].Step != "listen-core" || results[0].OK {
		t.Fatalf("results %+v", results)
	}
}
