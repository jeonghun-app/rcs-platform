package runtime

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// readinessTimeout bounds one /readyz evaluation. It stays below the 5 s
// timeout ECS and load balancer health checks commonly use, so a hanging
// dependency is reported as not ready rather than as a timed-out probe.
const readinessTimeout = 2 * time.Second

// Admin is the admin HTTP handler: /healthz, /readyz and whatever a service
// mounts with [Admin.Handle], nothing else. It has its own mux rather than
// http.DefaultServeMux so that a package registering debug handlers there
// (net/http/pprof, expvar) cannot expose them by accident.
type Admin struct {
	mux   *http.ServeMux
	log   *slog.Logger
	after func(time.Duration) <-chan time.Time

	mu     sync.Mutex
	checks []readinessCheck

	stopping atomic.Bool
}

type readinessCheck struct {
	name  string
	check func(context.Context) error
}

func newAdmin(log *slog.Logger, after func(time.Duration) <-chan time.Time) *Admin {
	a := &Admin{mux: http.NewServeMux(), log: log, after: after}
	a.mux.HandleFunc("GET /healthz", a.healthz)
	a.mux.HandleFunc("GET /readyz", a.readyz)
	return a
}

// AddReadinessCheck registers a check /readyz runs on every request. check must
// return promptly once its context is done; its error is logged but never sent
// to the caller, since it may name internal hosts or tables. AddReadinessCheck
// panics on an empty or duplicate name, which is a wiring mistake.
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
}

// Handle mounts h on the admin server, with http.ServeMux pattern rules. Only
// what is mounted here is served, so mount nothing that should not be reachable
// from inside the VPC.
func (a *Admin) Handle(pattern string, h http.Handler) {
	a.mux.Handle(pattern, h)
}

func (a *Admin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

// stop makes /readyz fail from now on, so that whatever routes traffic by
// readiness stops sending new work while the process drains.
func (a *Admin) stop() {
	a.stopping.Store(true)
}

func (a *Admin) healthz(w http.ResponseWriter, _ *http.Request) {
	writeStatus(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (a *Admin) readyz(w http.ResponseWriter, r *http.Request) {
	if a.stopping.Load() {
		writeStatus(w, http.StatusServiceUnavailable, map[string]any{"status": "stopping"})
		return
	}
	if failing := a.failingChecks(r.Context()); len(failing) > 0 {
		writeStatus(w, http.StatusServiceUnavailable, map[string]any{"status": "not ready", "failing": failing})
		return
	}
	writeStatus(w, http.StatusOK, map[string]any{"status": "ready"})
}

// failingChecks runs every check concurrently, so one slow dependency cannot use
// up the time the others need, and returns the names of those that failed or
// did not answer within readinessTimeout, in registration order.
func (a *Admin) failingChecks(parent context.Context) []string {
	a.mu.Lock()
	checks := slices.Clone(a.checks)
	a.mu.Unlock()

	ctx, cancel := withTimer(parent, a.after, readinessTimeout)
	defer cancel()

	results := make([]chan error, len(checks))
	for i, c := range checks {
		results[i] = make(chan error, 1)
		go func() { results[i] <- c.check(ctx) }()
	}
	var failing []string
	for i, c := range checks {
		// A check that answered in time passes even if a sibling then used up
		// the deadline.
		if err, _ := await(ctx, results[i]); err != nil {
			failing = append(failing, c.name)
			a.log.Warn("readiness check failed", slog.String("check", c.name), slog.String("error", pii.Redact(err.Error())))
		}
	}
	return failing
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
