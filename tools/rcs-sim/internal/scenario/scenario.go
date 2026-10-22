// Package scenario runs the simulator's scenarios: named sequences of steps
// against a stack, each step reported as one result. A scenario stops at its
// first failed step, and the run fails if any step did.
//
// Results carry the scenario, the step, the outcome, the time taken and a
// few numbers (sizes, counts). They never carry a URL, a session id, a user
// name, a password or a token: the run's output goes to CI logs, and the
// only addresses in it would be the MCC 001 test numbers anyway, which the
// results leave out too.
package scenario

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/anchor"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/ft"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/sipua"
)

// Config is what the scenarios run against.
type Config struct {
	// FT is the file transfer client; nil skips nothing but fails the FT
	// scenarios at their first step.
	FT *ft.Client
	// FileSize is the size of the file the ft scenario sends, and
	// ResumeSize that of ft-resume, which must exceed ft-server's part size
	// (FT_PART_SIZE): only whole parts survive a broken upload, and with
	// nothing held the scenario uploads again rather than resuming.
	FileSize, ResumeSize int

	// Control plays pcscf toward msrp-relay; nil fails the chat scenarios.
	Control *anchor.Control
	// CoreListen is where the rcs-as stand-in listens, and CoreAdvertise
	// the host the relay is told to connect to (empty: the listener's).
	CoreListen, CoreAdvertise string
	// CoreListener, when set, gives each chat scenario's stand-in its
	// listener instead of CoreListen: a test that listens on port 0 before
	// it starts the relay holds the port the relay is told about from the
	// first, where listening anew on it for each scenario could find it
	// taken (#186).
	CoreListener func() (net.Listener, error)
	// MSRP configures both ends' connections, the keep-alive interval
	// among them.
	MSRP msrp.Config
	// TLS configures the client's connection to an msrps relay path.
	TLS *tls.Config
	// UploadSettle is how long ft-resume asks get_upload_info again for a
	// broken upload to show (ft.Client.SettledUploadInfo); zero is 3 s.
	UploadSettle time.Duration

	// IdleWait is how long the chat scenarios stay quiet to see keep-alives
	// go out (it should exceed MSRP.KeepAliveInterval); zero skips the step.
	IdleWait time.Duration

	// Self is the simulated client and Peer the far end of its chats.
	Self, Peer cpim.Address

	// SIP configures the SIP client the scenarios of #135 register with,
	// as Self, and SIPPeer the far end's, as Peer. Without them "all"
	// leaves the SIP scenarios out, and naming one fails it at its first
	// step.
	SIP, SIPPeer *sipua.Config
	// Deregister has the network end the registration of impu, as an
	// operator's DELETE through the HSS API does (an RTR to the S-CSCF, TS
	// 24.229 §5.4.1.5), for reg-event's network-deregister step. Nil skips
	// that step, which RequireAll (-require-all) makes a failure.
	Deregister func(ctx context.Context, impu sip.URI) error
	// ConferenceFactory is the URI group-chat creates its group at, the
	// ConfFctyURI the client is provisioned with.
	ConferenceFactory sip.URI
	// GroupRejoins is how many times group-chat's client rejoins its group
	// before the owner stops (at least once).
	GroupRejoins int
	// StopOwner stops the rcs-as task that owns the group at conf and
	// returns once it has stopped, for group-chat's owner steps (#121).
	// Nil skips them, which RequireAll makes a failure.
	StopOwner func(ctx context.Context, conf sip.URI) error
	// OwnerCrash says StopOwner kills the owner rather than stopping it
	// cleanly: group-chat then expects no BYE and no end of its roster
	// subscription, and its client gives up its own session (#121).
	OwnerCrash bool
	// RelayPublic is msrp-relay's public host:port, the authority of every
	// client_path (RELAY_PUBLIC_HOST, RELAY_PUBLIC_PORT). chat-invite
	// requires each a=path the network gives a client to name it, so a
	// chat that went past the relay fails (ADR 0004, code review on #553).
	RelayPublic string

	// StepTimeout bounds each step.
	StepTimeout time.Duration

	// RequireAll makes a step that would be skipped, for want of
	// something the stack does not offer yet, a failure instead, so CI can
	// require it once the stack does.
	RequireAll bool
	// KeepAliveTimeout bounds the keep-alive step alone, the IdleWait
	// included, so it must be longer than IdleWait; zero is StepTimeout. A
	// short one makes a client that sends no keep-alive fail soon without
	// holding every other step, a 100 KiB chunked message say, to the same
	// bound (#178).
	KeepAliveTimeout time.Duration
	// Rand supplies ids and content; crypto/rand when nil.
	Rand io.Reader
}

// Result is one step's outcome, written as one JSON line.
type Result struct {
	Scenario string `json:"scenario"`
	Step     string `json:"step"`
	OK       bool   `json:"ok"`
	Millis   int64  `json:"ms"`
	// Error says what failed, without identifiers.
	Error string `json:"error,omitempty"`
	// Skipped, on a step that did not run but did not fail either, says
	// why, in a fixed text. Config.RequireAll makes it a failure.
	Skipped string `json:"skipped,omitempty"`
	// Detail holds sizes and counts.
	Detail map[string]int64 `json:"detail,omitempty"`
}

// Report receives each Result as it happens.
type Report func(Result)

// scenarios are the built-in scenarios by name.
var scenarios = map[string]func(*run) error{
	"ft":                     fileTransfer,
	"ft-resume":              fileTransferResumed,
	"chat-client-originated": chatClientOriginated,
	"chat-core-originated":   chatCoreOriginated,
	"chat-invite":            chatInvite,
	"group-chat":             groupChat,
	"pager-message":          pagerMessage,
	"reg-event":              regEvent,
	"options":                options,
}

// sipScenarios need the SIP clients; "all" leaves them out of a run with no
// SIP configuration at all, as a stack without pcscf cannot run them
// (#135). With SIP configured they run, and one that lacks a setting it
// needs, such as the peer, fails at its first step rather than vanish.
var sipScenarios = map[string]bool{"pager-message": true, "reg-event": true, "options": true, "chat-invite": true, "group-chat": true}

// Names lists the built-in scenarios, sorted.
func Names() []string {
	names := make([]string, 0, len(scenarios))
	for n := range scenarios {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ErrUnknown is returned for a scenario name that does not exist.
var ErrUnknown = errors.New("scenario: unknown scenario")

// Run runs the named scenarios in order and reports every step; "all" runs
// every built-in one, the SIP ones only with SIP set. It returns whether
// every step succeeded, or ErrUnknown before running anything.
func Run(ctx context.Context, cfg Config, names []string, report Report) (bool, error) {
	if slices.Contains(names, "all") {
		names = slices.DeleteFunc(Names(), func(n string) bool { return sipScenarios[n] && cfg.SIP == nil })
	}
	for _, n := range names {
		if scenarios[n] == nil {
			return false, fmt.Errorf("%w %q (known: %s)", ErrUnknown, n, strings.Join(Names(), ", "))
		}
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.StepTimeout <= 0 {
		cfg.StepTimeout = 30 * time.Second
	}
	ok := true
	for _, n := range names {
		r := &run{ctx: ctx, cfg: cfg, name: n, report: report}
		err := scenarios[n](r)
		r.cleanup()
		if err != nil && !errors.Is(err, errStepFailed) || r.failed {
			ok = false
		}
	}
	return ok, nil
}

// run is one scenario's state.
type run struct {
	ctx      context.Context
	cfg      Config
	name     string
	report   Report
	failed   bool
	cleanups []func()

	// refusal is why the peer last refused an offer the network sent it
	// (answerCalls), which a step that then waits in vain reports.
	refusalMu sync.Mutex
	refusal   string
}

// errStepFailed stops a scenario after a failed or skipped step has been
// reported.
var errStepFailed = errors.New("step failed")

// step runs f as the step called name and reports it. A failure ends the
// scenario: the error returned is errStepFailed.
func (r *run) step(name string, f func(ctx context.Context) (map[string]int64, error)) error {
	return r.stepWithin(name, r.cfg.StepTimeout, f)
}

// stepWithin is step with its own timeout.
func (r *run) stepWithin(name string, timeout time.Duration, f func(ctx context.Context) (map[string]int64, error)) error {
	ctx, cancel := context.WithTimeout(r.ctx, timeout)
	defer cancel()
	start := time.Now()
	detail, err := f(ctx)
	res := Result{Scenario: r.name, Step: name, OK: err == nil, Millis: time.Since(start).Milliseconds(), Detail: detail}
	if err != nil {
		res.Error = err.Error()
		r.failed = true
	}
	r.report(res)
	if err != nil {
		return errStepFailed
	}
	return nil
}

// skip reports the step called name as not run, for reason, a fixed text,
// and ends the scenario. With Config.RequireAll it is a failure.
func (r *run) skip(name, reason string) error {
	res := Result{Scenario: r.name, Step: name, OK: true, Skipped: reason}
	if r.cfg.RequireAll {
		res = Result{Scenario: r.name, Step: name, Error: reason}
		r.failed = true
	}
	r.report(res)
	return errStepFailed
}

// onEnd registers f to run when the scenario ends, last first.
func (r *run) onEnd(f func()) { r.cleanups = append(r.cleanups, f) }

func (r *run) cleanup() {
	for _, f := range slices.Backward(r.cleanups) {
		f()
	}
}

// content returns n bytes of random content.
func (r *run) content(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r.cfg.Rand, b); err != nil {
		return nil, err
	}
	return b, nil
}
