package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/scenario"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/simtest"
)

func env(kv ...string) func(string) (string, bool) {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func call(lookup func(string) (string, bool), args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, lookup, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestUsageErrorsExitWithTwo(t *testing.T) {
	for _, tt := range []struct {
		name string
		env  []string
		args []string
		want string
	}{
		{"no scenario", nil, nil, "name at least one scenario"},
		{"unknown flag", nil, []string{"-nope"}, "flag provided but not defined"},
		{"unknown scenario", nil, []string{"nope"}, "unknown scenario"},
		{"ft without a password", []string{"RCS_SIM_FT_USER", "u"}, []string{"-ft-upload-url", "http://127.0.0.1:1/ft", "ft"}, "RCS_SIM_FT_PASSWORD"},
		{"ft URL not http", nil, []string{"-ft-upload-url", "ftp://x/ft", "ft"}, "-ft-upload-url"},
		{"control without a token", nil, []string{"-relay-control", "http://127.0.0.1:1", "chat-core-originated"}, "RCS_SIM_RELAY_TOKEN"},
		{"control URL with user info", nil, []string{"-relay-control", "http://u:p@x", "all"}, "-relay-control"},
		{"self not a URI", nil, []string{"-self", "nobody", "all"}, "-self"},
		{"peer not a URI", nil, []string{"-peer", "nobody", "all"}, "-peer"},
		{"no file size", nil, []string{"-file-size", "0", "all"}, "-file-size"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			code, _, errOut := call(env(tt.env...), tt.args...)
			if code != exitUsage || !strings.Contains(errOut, tt.want) {
				t.Fatalf("exit %d, stderr %q; want 2 and %q", code, errOut, tt.want)
			}
			if strings.Contains(errOut, "u:p") {
				t.Fatal("the usage error repeats the URL")
			}
		})
	}
}

func TestListAndVersionAndHelp(t *testing.T) {
	code, out, _ := call(env(), "-list")
	if code != exitOK || strings.Fields(out)[0] != scenario.Names()[0] || len(strings.Fields(out)) != len(scenario.Names()) {
		t.Fatalf("-list: %d %q", code, out)
	}
	if code, out, _ := call(env(), "-version"); code != exitOK || !strings.HasPrefix(out, "rcs-sim") {
		t.Fatalf("-version: %d %q", code, out)
	}
	if code, _, _ := call(env(), "-h"); code != exitOK {
		t.Fatalf("-h: %d", code)
	}
}

func TestARunPrintsOneJSONLinePerStepAndExitsWithItsOutcome(t *testing.T) {
	f := simtest.StartFT(t, 64<<10)
	corePort := simtest.FreePort(t)
	r := simtest.StartRelay(t, corePort)
	lookup := env("RCS_SIM_FT_USER", simtest.FTUser, "RCS_SIM_FT_PASSWORD", simtest.FTPassword, "RCS_SIM_RELAY_TOKEN", simtest.RelayToken)
	args := []string{
		"-ft-upload-url", f.UploadURL.String(), "-resume-size", strconv.Itoa(5*64<<10 + 1),
		"-relay-control", r.Control.String(), "-core-listen", "127.0.0.1:" + strconv.Itoa(corePort),
		// Quiet for six keep-alive intervals, so a slow scheduler still
		// sees one go out.
		"-msrp-keepalive", "100ms", "-idle-wait", "600ms",
		"all",
	}
	code, out, errOut := call(lookup, args...)
	if code != exitOK {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	lines := 0
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		var res scenario.Result
		if err := json.Unmarshal(sc.Bytes(), &res); err != nil || res.Scenario == "" || res.Step == "" || !res.OK {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		lines++
	}
	if lines < 20 {
		t.Fatalf("%d result lines", lines)
	}
	for _, secret := range []string{simtest.FTPassword, simtest.RelayToken, simtest.FTUser} {
		if strings.Contains(out+errOut, secret) {
			t.Fatalf("output contains %q", secret)
		}
	}

	// A failing step makes the exit status 1.
	bad := env("RCS_SIM_FT_USER", simtest.FTUser, "RCS_SIM_FT_PASSWORD", "wrong", "RCS_SIM_RELAY_TOKEN", simtest.RelayToken)
	if code, out, _ := call(bad, "-ft-upload-url", f.UploadURL.String(), "ft"); code != exitFailed || !strings.Contains(out, `"ok":false`) {
		t.Fatalf("exit %d, output %q", code, out)
	}
}

// Failed results name a fixed reason, never the address or host name that
// failed, nor the resolver asked, nor what a server that is not HTTP sent
// (QA's regression test on #68).
func TestFailureResultsCarryNoAddress(t *testing.T) {
	port := strconv.Itoa(simtest.FreePort(t))
	// Something else listening where ft-server was expected.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Read the request first: Go treats bytes that arrive before
			// it asks as a stray answer on an idle connection.
			_, _ = http.ReadRequest(bufio.NewReader(c))
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH secret-host.example\r\n"))
			_ = c.Close()
		}
	}()
	banner := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	lookup := env("RCS_SIM_FT_USER", "u", "RCS_SIM_FT_PASSWORD", "p", "RCS_SIM_RELAY_TOKEN", simtest.RelayToken)
	for _, host := range []string{"127.0.0.1:" + port, "ft.operator-host.invalid", "127.0.0.1:" + banner} {
		code, out, errOut := call(lookup, "-ft-upload-url", "http://"+host+"/ft",
			"-relay-control", "http://"+host, "-step-timeout", "2s", "ft", "chat-client-originated")
		if code != exitFailed || strings.Count(out, `"ok":false`) != 2 {
			t.Fatalf("%s: exit %d, output %q", host, code, out)
		}
		text := stringsIn(t, out) + errOut
		for _, leak := range []string{port, banner, "127.0.0.1", "operator-host", ":53", "secret-host"} {
			if strings.Contains(text, leak) {
				t.Errorf("%s: output names %q:\n%s", host, leak, out)
			}
		}
	}
}

// stringsIn returns every string value of the result lines in out, one per
// line. Only strings can name an address: searching the raw lines would
// also find ":53" in a step that took 53 ms ("ms":53, #84), and a port
// number among the sizes and times.
func stringsIn(t *testing.T, out string) string {
	t.Helper()
	var b strings.Builder
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case string:
			b.WriteString(v)
			b.WriteByte('\n')
		case map[string]any:
			for k, e := range v {
				walk(k)
				walk(e)
			}
		case []any:
			for _, e := range v {
				walk(e)
			}
		}
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		var line any
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatalf("not a result line: %q", sc.Text())
		}
		walk(line)
	}
	return b.String()
}

func TestTheLeakCheckReadsStringsNotTimes(t *testing.T) {
	// A step that took 53 ms names no resolver; an error that quotes one
	// does.
	clean := `{"scenario":"ft","step":"pre-check","ok":false,"ms":53,"error":"ft: pre-check: host name not resolved"}` + "\n" +
		`{"scenario":"ft","step":"upload","ok":true,"ms":5301,"detail":{"bytes":40123}}`
	if text := stringsIn(t, clean); strings.Contains(text, ":53") || strings.Contains(text, "40123") {
		t.Fatalf("times and sizes taken for text:\n%s", text)
	}
	for _, leaked := range []string{
		`{"error":"dial tcp: lookup ft.operator-host.invalid on 127.0.0.1:53: no such host"}`,
		`{"error":"dial tcp [::1]:53: connect: connection refused"}`,
		`{"detail":{"127.0.0.1:53":1}}`,
	} {
		if !strings.Contains(stringsIn(t, leaked), ":53") {
			t.Errorf("an address in %s is not seen", leaked)
		}
	}
}
