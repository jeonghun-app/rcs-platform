package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// readinessTimeout bounds one readiness evaluation. It stays below the 5 s
// timeout ECS and load balancer health checks commonly use, so a hanging
// dependency is reported as not ready rather than as a timed-out probe.
const readinessTimeout = 2 * time.Second

// readinessCacheTTL is how long a finished evaluation answers /readyz. The
// admin port has no authentication, so without it every request inside the VPC
// would turn into one call per check to the dependencies, which hurts most when
// they are already slow.
const readinessCacheTTL = time.Second

// Admin is the admin HTTP handler: /healthz, /readyz and whatever a service
// mounts with [Admin.Handle], nothing else. It has its own mux rather than
// http.DefaultServeMux so that a package registering debug handlers there
// (net/http/pprof, expvar) cannot expose them by accident.
//
// /healthz answers 200 while the process runs, from the moment the admin
// server listens to the end of shutdown, or, with Service.LiveAfterReady, 503
// "starting" until the service calls [Runtime.Ready] and 200 from then on.
// /readyz answers 503 with status "starting" until the service calls
// [Runtime.Ready], 503 "stopping" once shutdown has begun, and otherwise 200
// only if every readiness check passes.
type Admin struct {
	mux   *http.ServeMux
	log   *slog.Logger
	now   func() time.Time
	after func(time.Duration) <-chan time.Time

	mu     sync.Mutex
	checks []readinessCheck
	// failing is each check's result in the last evaluation, so that a check
	// is logged when it starts or stops failing rather than on every request.
	failing map[string]bool
	cached  *evaluation
	running *evaluation
	// generation counts changes to checks. An evaluation that started before
	// the latest change answers the requests already waiting for it but is not
	// cached or joined, since it did not run every check.
	generation uint64

	ready    atomic.Bool
	stopping atomic.Bool
	// liveAfterReady is Service.LiveAfterReady; it is set before the admin
	// server starts and never changes.
	liveAfterReady bool
}

type readinessCheck struct {
	name  string
	check func(context.Context) error
}

// evaluation is one run of every readiness check, shared by all /readyz
// requests that arrive while it runs or within readinessCacheTTL after.
type evaluation struct {
	done     chan struct{}
	finished time.Time
	failing  []string
}

func newAdmin(log *slog.Logger, now func() time.Time, after func(time.Duration) <-chan time.Time) *Admin {
	a := &Admin{mux: http.NewServeMux(), log: log, now: now, after: after, failing: map[string]bool{}}
	a.mux.HandleFunc("GET /healthz", a.healthz)
	a.mux.HandleFunc("GET /readyz", a.readyz)
	return a
}

// AddReadinessCheck registers a check that /readyz runs. check must return
// promptly once its context is done; a check that panics counts as failing.
// Errors and panics are logged, redacted, when a check starts failing, but never
// sent to the caller, since they may name internal hosts or tables.
// AddReadinessCheck panics on an empty or duplicate name, which is a wiring
// mistake.
func (a *Admin) AddReadinessCheck(name string, check func(context.Context) error) {
	if name == "" || check == nil {
		panic("runtime: readiness check needs a name and a function")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if slices.ContainsFunc(a.checks, func(c readinessCheck) bool { return c.name == name }) {
		panic("runtime: duplicate readiness check " + name)
	}
	a.checks = append(a.checks, readinessCheck{name: name, check: check})
	// A cached "ready" must not hide a check that has never run.
	a.generation++
	a.cached, a.running = nil, nil
}

// Handle mounts h on the admin server, with http.ServeMux pattern rules. The
// admin port has no authentication and is reachable from inside the VPC, so a
// handler that changes state or reveals data must authenticate its callers
// itself.
func (a *Admin) Handle(pattern string, h http.Handler) {
	a.mux.Handle(pattern, h)
}

func (a *Admin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

// markReady ends the "starting" state; it reports whether this call did.
func (a *Admin) markReady() bool {
	return a.ready.CompareAndSwap(false, true)
}

// stop makes /readyz fail from now on, so that whatever routes traffic by
// readiness stops sending new work while the process drains.
func (a *Admin) stop() {
	a.stopping.Store(true)
}

func (a *Admin) healthz(w http.ResponseWriter, _ *http.Request) {
	if a.liveAfterReady && !a.ready.Load() {
		writeStatus(w, http.StatusServiceUnavailable, map[string]any{"status": "starting"})
		return
	}
	// Shutdown leaves /healthz passing: a draining task is alive, and a
	// failing container health check would make ECS kill it mid-drain.
	writeStatus(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (a *Admin) readyz(w http.ResponseWriter, r *http.Request) {
	switch {
	case a.stopping.Load():
		writeStatus(w, http.StatusServiceUnavailable, map[string]any{"status": "stopping"})
		return
	case !a.ready.Load():
		writeStatus(w, http.StatusServiceUnavailable, map[string]any{"status": "starting"})
		return
	}
	failing, ok := a.evaluate(r.Context())
	switch {
	case !ok:
		// The caller went away while waiting; nobody reads this answer.
		writeStatus(w, http.StatusServiceUnavailable, map[string]any{"status": "not ready"})
	case len(failing) > 0:
		writeStatus(w, http.StatusServiceUnavailable, map[string]any{"status": "not ready", "failing": failing})
	default:
		writeStatus(w, http.StatusOK, map[string]any{"status": "ready"})
	}
}

// evaluate returns the names of the failing checks from a recent evaluation,
// joins the one in progress, or starts one. ok is false if ctx ended first.
func (a *Admin) evaluate(ctx context.Context) (failing []string, ok bool) {
	a.mu.Lock()
	if c := a.cached; c != nil && a.now().Sub(c.finished) < readinessCacheTTL {
		a.mu.Unlock()
		return c.failing, true
	}
	e := a.running
	if e == nil {
		e = &evaluation{done: make(chan struct{})}
		a.running = e
		// The evaluation is shared, so it must not end with the request that
		// happened to start it.
		go a.runChecks(e, slices.Clone(a.checks), a.generation)
	}
	a.mu.Unlock()

	select {
	case <-e.done:
		return e.failing, true
	case <-ctx.Done():
		return nil, false
	}
}

// runChecks runs every check concurrently, so one slow dependency cannot use up
// the time the others need, and records the names of those that failed,
// panicked or did not answer within readinessTimeout, in registration order.
func (a *Admin) runChecks(e *evaluation, checks []readinessCheck, generation uint64) {
	ctx, cancel := withTimer(context.Background(), a.after, readinessTimeout)
	defer cancel()

	results := make([]chan error, len(checks))
	for i, c := range checks {
		results[i] = make(chan error, 1)
		go func() {
			defer recoverInto(results[i])
			results[i] <- c.check(ctx)
		}()
	}
	errs := make([]error, len(checks))
	for i := range checks {
		// A check that answered in time passes even if a sibling then used up
		// the deadline.
		errs[i], _ = await(ctx, results[i])
	}

	type change struct {
		name string
		err  error
	}
	var changes []change
	a.mu.Lock()
	for i, c := range checks {
		failed := errs[i] != nil
		if failed {
			e.failing = append(e.failing, c.name)
		}
		if was, seen := a.failing[c.name]; failed != was && (seen || failed) {
			changes = append(changes, change{c.name, errs[i]})
		}
		a.failing[c.name] = failed
	}
	e.finished = a.now()
	if a.generation == generation {
		a.cached = e
	}
	if a.running == e {
		a.running = nil
	}
	a.mu.Unlock()

	// Logged before the answer is released, so a caller that has its answer
	// can rely on the log line being there.
	for _, ch := range changes {
		if ch.err != nil {
			a.log.Warn("readiness check failing", slog.String("check", ch.name), slog.String("error", pii.Redact(ch.err.Error())))
		} else {
			a.log.Info("readiness check passing again", slog.String("check", ch.name))
		}
	}
	close(e.done)
}

// panicError is what a readiness check or shutdown hook that panicked
// returns. The stack goes to the log so the bug can be found; the panic value
// and stack are redacted there like any other error text.
type panicError struct {
	value any
	stack []byte
}

func (p *panicError) Error() string {
	return fmt.Sprintf("panic: %v\n%s", p.value, p.stack)
}

// recoverInto turns a panic in the calling goroutine into a *panicError sent
// on result. Checks and hooks run in their own goroutines, where net/http's
// handler recovery does not reach: without this, one bad check would let an
// unauthenticated GET /readyz end the process.
func recoverInto(result chan<- error) {
	if v := recover(); v != nil {
		result <- &panicError{value: v, stack: debug.Stack()}
	}
}

func writeStatus(w http.ResponseWriter, code int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// withTimer is context.WithTimeout on an injected clock, so tests decide when a
// deadline passes instead of sleeping.
func withTimer(parent context.Context, after func(time.Duration) <-chan time.Time, d time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancelCause(parent)
	timer := after(d)
	go func() {
		select {
		case <-timer:
			cancel(context.DeadlineExceeded)
		case <-ctx.Done():
		}
	}()
	return ctx, func() { cancel(context.Canceled) }
}
