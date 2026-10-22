//go:build e2e || e2ecompose

package e2e

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// maxInfoWait bounds how long ft-server takes to notice the break and show
// the parts it keeps in get_upload_info: a server that is slow to keep a
// broken upload fails here instead of passing on retries. It bounds the
// step's showed_ms, the time until the last request was sent that did not
// get the bytes held the step settled on (ft.Settled.Showed), rather than the
// step's whole time: on a loaded host the answers themselves, and so the
// 300 ms quiet time's confirmation, take seconds (#286). A bound on time
// rather than on the number of answers keeps its margin when the answers
// come slowly.
const maxInfoWait = 2000 // ms

// result is one line of rcs-sim's output.
type result struct {
	Scenario string           `json:"scenario"`
	Step     string           `json:"step"`
	OK       bool             `json:"ok"`
	Millis   int64            `json:"ms"`
	Error    string           `json:"error"`
	Detail   map[string]int64 `json:"detail"`
}

// build compiles the packages pkgs (relative to the module root) into a
// temporary directory.
func build(t *testing.T, pkgs ...string) string {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command("go", append([]string{"build", "-o", dir}, pkgs...)...)
	cmd.Dir = filepath.Join("..", "..", "..")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return dir
}

// checkResults checks rcs-sim's output: every line a successful result, the
// steps in want among them, the resume and busy rules below, and none of
// leaks, test numbers, URLs or MSRP URIs on either stream. It returns the
// results by scenario/step.
func checkResults(t *testing.T, stdout, stderr string, want []string, leaks ...string) map[string]result {
	t.Helper()
	seen := map[string]result{}
	sc := bufio.NewScanner(strings.NewReader(stdout))
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
	for _, w := range want {
		if _, ok := seen[w]; !ok {
			t.Errorf("step %s did not run", w)
		}
	}
	// The parts of the broken upload were kept: rcsjta would have uploaded
	// the whole file again.
	if _, ok := seen["ft-resume/upload-again"]; ok {
		t.Error("ft-resume uploaded again: ft-server kept nothing of the broken upload")
	}
	if info, ok := seen["ft-resume/get_upload_info"]; ok {
		// A missing key would read as 0 and pass any server.
		if showed, ok := info.Detail["showed_ms"]; !ok {
			t.Errorf("get_upload_info reported no showed_ms: %v", info.Detail)
		} else if showed > maxInfoWait {
			t.Errorf("get_upload_info showed the parts held %d ms after it began (%d answers asked again, %d of them 404; %d ms in all), more than %d ms: ft-server is slow to keep a broken upload",
				showed, info.Detail["retries"], info.Detail["not_held"], info.Millis, maxInfoWait)
		}
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
	for _, leak := range append(leaks, "15550100001", "15550100002", "http://", "msrp://") {
		if strings.Contains(stdout+stderr, leak) {
			t.Errorf("rcs-sim printed %q", leak)
		}
	}
	return seen
}
