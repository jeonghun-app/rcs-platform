package scenario_test

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
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
	corePort := simtest.StandInPort(t)
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
func intercept(c *http.Client, a interface {
	http.RoundTripper
	setNext(http.RoundTripper)
}) *http.Client {
	next := c.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	a.setNext(next)
	wrapped := *c
	wrapped.Transport = a
	return &wrapped
}

func (a *answering) setNext(next http.RoundTripper) { a.next = next }

// delaying holds the first request that matches for delay, then passes
// every request on.
type delaying struct {
	next  http.RoundTripper
	match func(*http.Request) bool
	delay time.Duration
	done  atomic.Bool
}

func (d *delaying) setNext(next http.RoundTripper) { d.next = next }

func (d *delaying) RoundTrip(r *http.Request) (*http.Response, error) {
	if d.match(r) && d.done.CompareAndSwap(false, true) {
		time.Sleep(d.delay)
	}
	return d.next.RoundTrip(r)
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
	// The answers below decide how often get_upload_info is asked, so the
	// step's own timeout is the only bound. Under load one request took the
	// whole of the default settle time, which ended the step after a single
	// 404 (#159); the first one here, the unsigned GET that draws the
	// challenge, is made that slow on purpose.
	slow := scenario.UploadSettle() + 100*time.Millisecond
	defer scenario.SetUploadSettle(time.Hour)()
	cfg := stack(t)
	// The first three signed get_upload_info answer 404, as when the server
	// has not yet noticed the break.
	var signed atomic.Int32
	a := &answering{match: func(r *http.Request) bool {
		return strings.Contains(r.URL.RawQuery, "get_upload_info") && r.Header.Get("Authorization") != "" && signed.Add(1) <= 3
	}, status: http.StatusNotFound}
	cfg.FT.HTTP = intercept(cfg.FT.HTTP, a)
	cfg.FT.HTTP = intercept(cfg.FT.HTTP, &delaying{match: func(r *http.Request) bool {
		return strings.Contains(r.URL.RawQuery, "get_upload_info")
	}, delay: slow})
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

func TestTheResumeQuietTimeIsCountedOnTheClock(t *testing.T) {
	// The same 300 ms as above, without depending on how fast a loaded host
	// asks (#197). The clock moves 50 ms each time it is read, twice per
	// request, and the server always holds the same bytes, so the step
	// sends exactly 300 ms / 100 ms + 1 = 4 requests; with no quiet time
	// it would send 2.
	const quiet = 300 * time.Millisecond
	cfg := stack(t)
	var reads atomic.Int64
	start := time.Unix(0, 0)
	cfg.FT.Now = func() time.Time { return start.Add(time.Duration(reads.Add(1)) * 50 * time.Millisecond) }
	var signed atomic.Int32
	a := &answering{match: func(r *http.Request) bool {
		if strings.Contains(r.URL.RawQuery, "get_upload_info") && r.Header.Get("Authorization") != "" {
			signed.Add(1)
			return true
		}
		return false
	}, status: http.StatusOK, body: `<?xml version="1.0"?><file-resume-info xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp">` +
		`<file-range start="0" end="65535"/><data url="/ft/x"/></file-resume-info>`}
	cfg.FT.HTTP = intercept(cfg.FT.HTTP, a)
	_, results := runAll(t, cfg, "ft-resume")
	if info := byStep(results)["get_upload_info"]; !info.OK || info.Detail["held"] != 65536 {
		t.Fatalf("get_upload_info %+v", info)
	}
	if want := int32(quiet/(2*50*time.Millisecond)) + 1; signed.Load() != want {
		t.Fatalf("%d signed get_upload_info, want %d for a %v quiet time", signed.Load(), want, quiet)
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
	// The client did write while quiet, its answer to the relay's
	// keep-alive, so this is the case the step must not count.
	if ka.Detail["bytes_while_quiet"] == 0 {
		t.Fatalf("no bytes written while quiet: the relay's keep-alive never came, so the test proves less than it says: %+v", ka)
	}
}

func TestAClientThatSendsNoKeepAliveFailsAtTheStepTimeout(t *testing.T) {
	// The same with a step timeout shorter than the relay's keep-alive. It
	// is the keep-alive step's alone: a loaded host can take longer than
	// that over the steps before it (#178).
	cfg := stack(t)
	cfg.MSRP.KeepAliveInterval = -1
	cfg.KeepAliveTimeout = 2 * time.Second
	ok, results := runAll(t, cfg, "chat-client-originated")
	ka, ran := byStep(results)["keep-alive"]
	if !ran {
		t.Fatalf("the keep-alive step did not run: %+v", results)
	}
	if ok || ka.OK || !strings.Contains(ka.Error, "no keep-alive went out") {
		t.Fatalf("keep-alive %+v\nall results: %+v", ka, results)
	}
	// Ended by its own 2 s, before the relay's 10 s keep-alive, not by the
	// stack's 20 s step timeout.
	if ka.Millis >= 10000 {
		t.Fatalf("the keep-alive step took %d ms: KeepAliveTimeout did not bound it", ka.Millis)
	}
}

// slowRand stalls the first large read, the chunked message's content, as
// a loaded host would stall the chunked-message step (QA on #181).
type slowRand struct {
	stall time.Duration
	done  atomic.Bool
}

func (s *slowRand) Read(p []byte) (int, error) {
	if len(p) >= 100<<10 && s.done.CompareAndSwap(false, true) {
		time.Sleep(s.stall)
	}
	return cryptorand.Read(p)
}

func TestASlowStepBeforeTheKeepAliveStepIsNotHeldToItsBound(t *testing.T) {
	// KeepAliveTimeout bounds the keep-alive step alone: a chunked message
	// that takes 3 s, longer than it, still passes (#178).
	cfg := stack(t)
	cfg.MSRP.KeepAliveInterval = -1
	cfg.KeepAliveTimeout = 2 * time.Second
	cfg.Rand = &slowRand{stall: 3 * time.Second}
	ok, results := runAll(t, cfg, "chat-client-originated")
	ka, ran := byStep(results)["keep-alive"]
	if !ran {
		t.Fatalf("the keep-alive step did not run: %+v", results)
	}
	if ok || ka.OK || !strings.Contains(ka.Error, "no keep-alive went out") || ka.Millis >= 10000 {
		t.Fatalf("keep-alive %+v\nall results: %+v", ka, results)
	}
	if c := byStep(results)["chunked-message"]; !c.OK || c.Millis < 3000 {
		t.Fatalf("chunked-message %+v: the stall did not happen", c)
	}
}

// tlsStack is stack(t) with the client's side of the relay behind a TLS
// terminator, as behind the NLB (ADR 0003): client_path is msrps: and the
// client speaks TLS, while the relay listens plain (QA's probe on #102).
func tlsStack(t *testing.T) scenario.Config {
	t.Helper()
	cfg := stack(t)
	corePort := simtest.FreePort(t)
	r := simtest.StartRelayBehindTLS(t, corePort)
	cfg.Control = &anchor.Control{HTTP: http.DefaultClient, URL: r.Control, Token: anchor.NewToken(simtest.RelayToken)}
	cfg.CoreListen = "127.0.0.1:" + strconv.Itoa(corePort)
	cfg.TLS = &tls.Config{RootCAs: r.TLSRoots, MinVersion: tls.VersionTLS12}
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
	// Only the keep-alive step is short; the TLS connect and the chunked
	// message before it got 2 s too once, and a loaded host took longer
	// (#178).
	cfg.KeepAliveTimeout = 2 * time.Second
	ok, results := runAll(t, cfg, "chat-client-originated")
	ka, ran := byStep(results)["keep-alive"]
	if !ran {
		t.Fatalf("the keep-alive step did not run: %+v", results)
	}
	if ok || ka.OK || !strings.Contains(ka.Error, "no keep-alive went out") {
		t.Fatalf("keep-alive %+v\nall results: %+v", ka, results)
	}
	// Ended by its own 2 s, before the relay's 10 s keep-alive, not by the
	// stack's 20 s step timeout.
	if ka.Millis >= 10000 {
		t.Fatalf("the keep-alive step took %d ms: KeepAliveTimeout did not bound it", ka.Millis)
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
