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

// maxInfoRetries bounds how often ft-resume asks get_upload_info again while
// ft-server notices the break (100 ms apart): a server that is slow to keep a
// broken upload fails here instead of passing on retries.
const maxInfoRetries = 10

// result is one line of rcs-sim's output.
type result struct {
	Scenario string           `json:"scenario"`
	Step     string           `json:"step"`
	OK       bool             `json:"ok"`
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
// leaks, test numbers, URLs or MSRP URIs on either stream.
func checkResults(t *testing.T, stdout, stderr string, want []string, leaks ...string) {
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
	if info := seen["ft-resume/get_upload_info"]; info.Detail["retries"] > maxInfoRetries {
		t.Errorf("get_upload_info asked again %d times (%d of them 404), more than %d: ft-server is slow to keep a broken upload",
			info.Detail["retries"], info.Detail["not_held"], maxInfoRetries)
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
}
