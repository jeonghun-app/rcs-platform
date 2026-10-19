package scenario_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
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
	// IdleWait is six keep-alive intervals, so a slow scheduler still sees
	// one go out.
	return scenario.Config{
		FT:         &ft.Client{HTTP: f.Server.Client(), UploadURL: f.UploadURL, User: simtest.FTUser, Password: ft.NewSecret(simtest.FTPassword)},
		FileSize:   100 << 10,
		ResumeSize: 5*part + 123,
		Control:    &anchor.Control{HTTP: http.DefaultClient, URL: r.Control, Token: anchor.NewToken(simtest.RelayToken)},
		CoreListen: "127.0.0.1:" + strconv.Itoa(corePort),
		MSRP:       msrp.Config{KeepAliveInterval: 100 * time.Millisecond},
		IdleWait:   600 * time.Millisecond,
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
		"ft/upload", "ft/download", "ft/download-range", "ft/download-resume", "ft/download-thumbnail", "ft/get_download_info",
		"ft-resume/interrupted-upload", "ft-resume/get_upload_info", "ft-resume/resume", "ft-resume/download",
		"chat-client-originated/connect", "chat-client-originated/client-to-core", "chat-client-originated/core-to-client",
		"chat-client-originated/chunked-message", "chat-client-originated/keep-alive", "chat-client-originated/release",
		"chat-core-originated/connect-then-answer", "chat-core-originated/core-sends-first", "chat-core-originated/client-to-core", "chat-core-originated/release",
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

// byStep indexes results by step.
func byStep(results []scenario.Result) map[string]scenario.Result {
	m := map[string]scenario.Result{}
	for _, r := range results {
		m[r.Step] = r
	}
	return m
}

func TestAResumeFileNoLargerThanAPartIsUploadedAgainAsRCSJTADoes(t *testing.T) {
	cfg := stack(t)
	cfg.ResumeSize = part / 2
	ok, results := runAll(t, cfg, "ft-resume")
	steps := byStep(results)
	info := steps["get_upload_info"]
	if !ok || !info.OK || info.Detail["held"] != 0 || info.Detail["not_held"] == 0 {
		t.Fatalf("results %+v", results)
	}
	if _, resumed := steps["resume"]; resumed || !steps["upload-again"].OK || !steps["download"].OK {
		t.Fatalf("results %+v", results)
	}
}

// answering answers the requests match picks with status instead of
// sending them on, and counts them; others go to next.
type answering struct {
	next   http.RoundTripper
	match  func(*http.Request) bool
	status int
	// body, when set, is sent as an ft document.
	body string
	// header is added to the answer.
	header http.Header
	n      atomic.Int32
}

func (a *answering) RoundTrip(r *http.Request) (*http.Response, error) {
	if !a.match(r) {
		return a.next.RoundTrip(r)
	}
	a.n.Add(1)
	if r.Body != nil {
		_ = r.Body.Close()
	}
	resp := &http.Response{StatusCode: a.status, Header: a.header.Clone(), Body: http.NoBody, Request: r}
	if resp.Header == nil {
		resp.Header = http.Header{}
	}
	if a.body != "" {
		resp.Header.Set("Content-Type", ft.ContentType)
		resp.Body = io.NopCloser(strings.NewReader(a.body))
	}
	return resp, nil
}

// intercept puts a in front of c's transport.
func intercept(c *http.Client, a *answering) *http.Client {
	a.next = c.Transport
	if a.next == nil {
		a.next = http.DefaultTransport
	}
	wrapped := *c
	wrapped.Transport = a
	return &wrapped
}

func TestAResumeAnsweredOtherThan200FailsWithoutARetry(t *testing.T) {
	for _, status := range []int{http.StatusConflict, http.StatusServiceUnavailable} {
		cfg := stack(t)
		a := &answering{match: func(r *http.Request) bool { return r.Method == http.MethodPut }, status: status}
		cfg.FT.HTTP = intercept(cfg.FT.HTTP, a)
		ok, results := runAll(t, cfg, "ft-resume")
		last := results[len(results)-1]
		if ok || last.Step != "resume" || last.OK || !strings.Contains(last.Error, "rcsjta fails the transfer") {
			t.Fatalf("%d: last result %+v", status, last)
		}
		if n := a.n.Load(); n != 1 {
			t.Fatalf("%d: %d PUTs sent, want 1", status, n)
		}
	}
}

func TestABusyUploadIsSentAgainAndCounted(t *testing.T) {
	cfg := stack(t)
	// The first signed upload POST is answered 503 with Retry-After: 1, as
	// ft-server answers a user over its upload rate.
	var posts atomic.Int32
	a := &answering{match: func(r *http.Request) bool {
		return r.Method == http.MethodPost && r.Header.Get("Authorization") != "" && posts.Add(1) == 1
	}, status: http.StatusServiceUnavailable, header: http.Header{"Retry-After": {"1"}}}
	cfg.FT.HTTP = intercept(cfg.FT.HTTP, a)
	ok, results := runAll(t, cfg, "ft")
	upload := byStep(results)["upload"]
	if !ok || !upload.OK || upload.Detail["busy_retries"] != 1 || posts.Load() != 2 {
		t.Fatalf("ok %v, upload %+v, %d POSTs", ok, upload, posts.Load())
	}
}

func TestUploadInfoAskedAgainIsCounted(t *testing.T) {
	cfg := stack(t)
	// The first three signed get_upload_info answer 404, as when the server
	// has not yet noticed the break.
	var signed atomic.Int32
	a := &answering{match: func(r *http.Request) bool {
		return strings.Contains(r.URL.RawQuery, "get_upload_info") && r.Header.Get("Authorization") != "" && signed.Add(1) <= 3
	}, status: http.StatusNotFound}
	cfg.FT.HTTP = intercept(cfg.FT.HTTP, a)
	ok, results := runAll(t, cfg, "ft-resume")
	info := byStep(results)["get_upload_info"]
	if !ok || info.Detail["not_held"] != 3 || info.Detail["retries"] < 4 || info.Detail["held"] == 0 {
		t.Fatalf("ok %v, get_upload_info %+v", ok, info)
	}
	if !byStep(results)["resume"].OK {
		t.Fatalf("results %+v", results)
	}
}

func TestTheResumeWaitsOutTheQuietTime(t *testing.T) {
	// get_upload_info resumes only once the bytes held have stayed the same
	// for 300 ms (docs/rcs-sim.md), so the step cannot be shorter than that.
	// The value is written out here, not taken from the package, so that a
	// change to it fails until the documents agree.
	const quiet = 300 * time.Millisecond
	ok, results := runAll(t, stack(t), "ft-resume")
	info := byStep(results)["get_upload_info"]
	if !ok || time.Duration(info.Millis)*time.Millisecond < quiet {
		t.Fatalf("ok %v, get_upload_info took %d ms, want at least %v", ok, info.Millis, quiet)
	}
}

func TestAnUploadInfoThatWouldOverflowFailsTheStep(t *testing.T) {
	cfg := stack(t)
	a := &answering{match: func(r *http.Request) bool {
		return strings.Contains(r.URL.RawQuery, "get_upload_info") && r.Header.Get("Authorization") != ""
	}, status: http.StatusOK, body: `<?xml version="1.0"?><file-resume-info xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp">` +
		`<file-range start="0" end="9223372036854775807"/><data url="/ft/x"/></file-resume-info>`}
	cfg.FT.HTTP = intercept(cfg.FT.HTTP, a)
	ok, results := runAll(t, cfg, "ft-resume")
	last := results[len(results)-1]
	if ok || last.Step != "get_upload_info" || last.OK {
		t.Fatalf("last result %+v", last)
	}
}

func TestFilesOfOneAndTwoBytesTakeEveryDownloadPath(t *testing.T) {
	for _, size := range []int{1, 2} {
		cfg := stack(t)
		cfg.FileSize = size
		if ok, results := runAll(t, cfg, "ft"); !ok {
			t.Fatalf("%d bytes: %+v", size, results)
		}
	}
}

func TestAReleaseThatLeavesTheBindingFails(t *testing.T) {
	cfg := stack(t)
	// The relay answers 204 but the binding stays (and is still claimed,
	// so the probe is refused with 403, not 481).
	a := &answering{match: func(r *http.Request) bool { return r.Method == http.MethodDelete }, status: http.StatusNoContent}
	cfg.Control.HTTP = intercept(cfg.Control.HTTP, a)
	ok, results := runAll(t, cfg, "chat-client-originated")
	release := byStep(results)["release"]
	if ok || release.OK || !strings.Contains(release.Error, "released session") {
		t.Fatalf("release %+v", release)
	}
}

func TestAClientThatSendsNoKeepAliveFailsTheStep(t *testing.T) {
	// The keep-alive step waits for the keep-alive past IdleWait (#97). A
	// client that sends none must still fail with the stack's own step
	// timeout (20 s), which outlasts the test relay's 10 s keep-alive: the
	// client's 200 to that is not a keep-alive of its own (QA on #102).
	cfg := stack(t)
	cfg.MSRP.KeepAliveInterval = -1
	ok, results := runAll(t, cfg, "chat-client-originated")
	ka, ran := byStep(results)["keep-alive"]
	if !ran {
		t.Fatalf("the keep-alive step did not run: %+v", results)
	}
	if ok || ka.OK || !strings.Contains(ka.Error, "no keep-alive went out") {
		t.Fatalf("keep-alive %+v\nall results: %+v", ka, results)
	}
}

func TestAClientThatSendsNoKeepAliveFailsAtTheStepTimeout(t *testing.T) {
	// The same with a step timeout shorter than the relay's keep-alive.
	cfg := stack(t)
	cfg.MSRP.KeepAliveInterval = -1
	cfg.StepTimeout = 2 * time.Second
	ok, results := runAll(t, cfg, "chat-client-originated")
	ka, ran := byStep(results)["keep-alive"]
	if !ran {
		t.Fatalf("the keep-alive step did not run: %+v", results)
	}
	if ok || ka.OK || !strings.Contains(ka.Error, "no keep-alive went out") {
		t.Fatalf("keep-alive %+v\nall results: %+v", ka, results)
	}
}

// tlsStack is stack(t) with the client's side of the relay behind a TLS
// terminator, as behind the NLB (ADR 0003): client_path is msrps: and the
// client speaks TLS, while the relay listens plain (QA's probe on #102).
func tlsStack(t *testing.T) scenario.Config {
	t.Helper()
	ts := httptest.NewTLSServer(http.NotFoundHandler()) // only for its certificate
	t.Cleanup(ts.Close)
	roots := ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", ts.TLS.Clone())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tlsLn.Close() })
	tlsPort := tlsLn.Addr().(*net.TCPAddr).Port

	f := simtest.StartFT(t, part)
	corePort, plain, control := simtest.FreePort(t), simtest.FreePort(t), simtest.FreePort(t)
	env := map[string]string{
		"RCS_ENV": "test", "RELAY_LISTEN_ADDR": "127.0.0.1:" + strconv.Itoa(plain),
		"RELAY_CONTROL_ADDR": "127.0.0.1:" + strconv.Itoa(control),
		"RELAY_PUBLIC_HOST":  "127.0.0.1", "RELAY_PUBLIC_PORT": strconv.Itoa(tlsPort), "RELAY_PUBLIC_TLS": "true",
		"RELAY_CORE_HOST": "127.0.0.1", "RELAY_CORE_NETWORKS": "127.0.0.0/8", "RELAY_CORE_PORTS": strconv.Itoa(corePort),
		"RELAY_STORE": "memory", "RELAY_PCSCF_TOKEN": simtest.RelayToken,
		"RELAY_KEEPALIVE_INTERVAL": "10s", "RELAY_IDLE_TIMEOUT": "60s",
	}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	shared := runtime.NewEnv("RCS_", lookup)
	rcfg := msrprelay.Configure(&runtime.Settings{Env: shared.WithPrefix("RELAY_"), Shared: shared, Environment: runtime.Test})
	if err := shared.Err(); err != nil {
		t.Fatal(err)
	}
	h := runtimetest.New(t, "msrp-relay")
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { _ = msrprelay.Run(ctx, h.Runtime, rcfg); close(stopped) }()
	t.Cleanup(func() { cancel(); <-stopped })
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if code, _ := h.Get("/readyz"); code == http.StatusOK {
			break
		}
		select {
		case <-stopped:
			t.Fatal("the relay stopped before it was ready")
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the relay did not become ready")
		}
	}
	// The terminator: TLS in, plain to the relay's public listener.
	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(plain))
				if err != nil {
					return
				}
				defer b.Close()
				go func() { _, _ = io.Copy(b, c); _ = b.(*net.TCPConn).CloseWrite() }()
				_, _ = io.Copy(c, b)
			}()
		}
	}()
	u, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(control))
	cfg := stack(t)
	cfg.FT = &ft.Client{HTTP: f.Server.Client(), UploadURL: f.UploadURL, User: simtest.FTUser, Password: ft.NewSecret(simtest.FTPassword)}
	cfg.Control = &anchor.Control{HTTP: http.DefaultClient, URL: u, Token: anchor.NewToken(simtest.RelayToken)}
	cfg.CoreListen = "127.0.0.1:" + strconv.Itoa(corePort)
	cfg.TLS = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	return cfg
}

// The keep-alive step watches the MSRP inside TLS: over msrps:, the
// deployed path (ADR 0003), a client's keep-alives count (QA on #102: the
// wrapper once saw only ciphertext, and the step always failed there).
func TestTheKeepAliveStepWorksOverTLS(t *testing.T) {
	cfg := tlsStack(t)
	ok, results := runAll(t, cfg, "chat-client-originated")
	if !ok {
		t.Fatalf("chat-client-originated over msrps: %+v", results)
	}
}

func TestAClientWithoutKeepAlivesFailsOverTLSToo(t *testing.T) {
	cfg := tlsStack(t)
	cfg.MSRP.KeepAliveInterval = -1
	cfg.StepTimeout = 2 * time.Second
	ok, results := runAll(t, cfg, "chat-client-originated")
	ka, ran := byStep(results)["keep-alive"]
	if !ran || ok || ka.OK || !strings.Contains(ka.Error, "no keep-alive went out") {
		t.Fatalf("keep-alive %+v\nall results: %+v", ka, results)
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
