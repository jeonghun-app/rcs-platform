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
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
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
	// MSRP configures both ends' connections, the keep-alive interval
	// among them.
	MSRP msrp.Config
	// TLS configures the client's connection to an msrps relay path.
	TLS *tls.Config
	// IdleWait is how long the chat scenarios stay quiet to see keep-alives
	// go out (it should exceed MSRP.KeepAliveInterval); zero skips the step.
	IdleWait time.Duration

	// Self is the simulated client and Peer the far end of its chats.
	Self, Peer cpim.Address

	// SIP configures the SIP client the scenarios of #135 register with;
	// none uses it yet, as they need pcscf and scscf.
	SIP *sipua.Config

	// StepTimeout bounds each step.
	StepTimeout time.Duration
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
}

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
// every built-in one. It returns whether every step succeeded, or ErrUnknown
// before running anything.
func Run(ctx context.Context, cfg Config, names []string, report Report) (bool, error) {
	if slices.Contains(names, "all") {
		names = Names()
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
		if err != nil || r.failed {
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
}

// errStepFailed stops a scenario after a failed step has been reported.
var errStepFailed = errors.New("step failed")

// step runs f as the step called name and reports it. A failure ends the
// scenario: the error returned is errStepFailed.
func (r *run) step(name string, f func(ctx context.Context) (map[string]int64, error)) error {
	ctx, cancel := context.WithTimeout(r.ctx, r.cfg.StepTimeout)
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
