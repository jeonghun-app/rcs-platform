package runtime

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/buildinfo"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// healthcheckTimeout bounds -healthcheck end to end, well inside the 5 s
// minimum timeout of an ECS container health check, so a wedged admin server
// shows up as unhealthy rather than as a hung check.
const healthcheckTimeout = 3 * time.Second

// Exit codes returned by Run.
const (
	ExitOK      = 0
	ExitFailure = 1
	ExitUsage   = 2
)

// Service describes one service binary. C is the service's own configuration,
// produced by Configure and handed to Run.
type Service[C any] struct {
	// Name is the binary name ("pcscf"). It is the service field of every log
	// line and the Service dimension of every metric.
	Name string
	// EnvPrefix prefixes the service's own variables ("PCSCF_"). It must not
	// start with RCS_, which is reserved for the shared settings: rcs-as uses
	// RCSAS_, since RCS_AS_ would mix its settings into the shared namespace.
	EnvPrefix string
	// Configure reads the service's settings and declares the ones unsafe in
	// production. It must not start anything: when it returns, every problem it
	// and the runtime recorded is reported at once and the process exits if
	// there is any.
	Configure func(s *Settings) C
	// Run starts the service, calls rt.Ready once it can take work, and blocks
	// until ctx is cancelled, which happens on SIGTERM or SIGINT, or until the
	// service fails. /readyz answers 503 "starting" until Ready is called. When
	// Run returns the process shuts down: a non-nil error, other than ctx's
	// own, makes the exit status non-zero.
	Run func(ctx context.Context, rt *Runtime, cfg C) error
}

var envPrefixPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*_$`)

func (svc Service[C]) validate() {
	switch {
	case svc.Name == "":
		panic("runtime: Service.Name is empty")
	case !envPrefixPattern.MatchString(svc.EnvPrefix) || strings.HasPrefix(svc.EnvPrefix, "RCS_"):
		panic("runtime: Service.EnvPrefix must look like PCSCF_ and must not start with RCS_")
	case svc.Configure == nil || svc.Run == nil:
		panic("runtime: Service.Configure and Service.Run are required")
	}
}

// Settings is what a service's Configure reads its configuration through.
type Settings struct {
	// Env reads the service's own variables (EnvPrefix).
	Env *Env
	// Shared reads RCS_ variables shared by every service, such as the IMS
	// domain. Its problems are reported with the others.
	Shared *Env
	// Environment is RCS_ENV, or empty when RCS_ENV is missing or invalid (the
	// process will refuse to start in that case).
	Environment Environment

	unsafe []string
}

// ForbidInProduction refuses to start in staging and prod when unsafe is true,
// giving reason (say what is unsafe and why, e.g. "PCSCF_STORE=memory keeps
// registrations in one task"). Every refused reason is listed together. In dev
// and test the reasons are logged as a warning instead.
func (s *Settings) ForbidInProduction(unsafe bool, reason string) {
	if unsafe {
		s.unsafe = append(s.unsafe, reason)
	}
}

// Runtime is what a running service gets from the runtime. Run builds it; tests
// of service packages get one from internal/runtime/runtimetest.
type Runtime struct {
	Environment Environment
	Logger      *slog.Logger
	Metrics     *Metrics
	Admin       *Admin

	mu    sync.Mutex
	hooks []shutdownHook
}

// RuntimeOptions configures [NewRuntime].
type RuntimeOptions struct {
	// Service names the service in logs and metrics.
	Service string
	// Environment is reported by Runtime.Environment.
	Environment Environment
	// Out receives log and metric lines; nil discards them.
	Out io.Writer
	// Level is the log level; nil means info.
	Level slog.Leveler
	// MetricsNamespace defaults to DefaultMetricsNamespace.
	MetricsNamespace string
	// Now and After are the clock; nil means time.Now and time.After.
	Now   func() time.Time
	After func(time.Duration) <-chan time.Time
}

// NewRuntime returns a Runtime that is not attached to a process: Run uses it,
// and runtimetest uses it so that service packages can test their Run function
// without signals or a listener.
func NewRuntime(o RuntimeOptions) *Runtime {
	if o.Out == nil {
		o.Out = io.Discard
	}
	if o.Level == nil {
		o.Level = slog.LevelInfo
	}
	if o.MetricsNamespace == "" {
		o.MetricsNamespace = DefaultMetricsNamespace
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.After == nil {
		o.After = time.After
	}
	out := &syncWriter{w: o.Out}
	log := NewLogger(out, o.Service, buildinfo.Version, o.Level)
	return &Runtime{
		Environment: o.Environment,
		Logger:      log,
		Metrics:     NewMetrics(out, o.MetricsNamespace, o.Service, o.Now, log),
		Admin:       newAdmin(log, o.Now, o.After),
	}
}

// Ready tells the runtime the service can take work: /readyz stops answering
// "starting" and from then on reflects the readiness checks. Register the
// checks before calling it. Calling it again has no effect.
func (r *Runtime) Ready() {
	if r.Admin.markReady() {
		r.Logger.Info("ready")
	}
}

type shutdownHook struct {
	name string
	fn   func(context.Context) error
}

// OnShutdown registers fn to run after Service.Run has returned. Hooks run one
// at a time, last registered first (like defer), so something registered after
// its dependencies is stopped before them. They share the RCS_SHUTDOWN_TIMEOUT
// deadline through ctx; a hook still running at the deadline is abandoned and
// the remaining hooks are skipped.
func (r *Runtime) OnShutdown(name string, fn func(ctx context.Context) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hooks = append(r.hooks, shutdownHook{name: name, fn: fn})
}

// Shutdown makes /readyz answer "stopping" and runs the shutdown hooks as
// described at [Runtime.OnShutdown], returning every failure. A hook that
// panics fails without stopping the others. Run calls Shutdown after
// Service.Run returns; a service never calls it itself, and tests call it
// through runtimetest.
func (r *Runtime) Shutdown(ctx context.Context) error {
	r.Admin.stop()
	r.mu.Lock()
	hooks := slices.Clone(r.hooks)
	r.mu.Unlock()

	var errs []error
	for _, h := range slices.Backward(hooks) {
		if ctx.Err() != nil {
			r.Logger.Error("shutdown hook skipped: deadline passed", slog.String("hook", h.name))
			errs = append(errs, fmt.Errorf("shutdown hook %s: skipped", h.name))
			continue
		}
		done := make(chan error, 1)
		go func() {
			defer recoverInto(done)
			done <- h.fn(ctx)
		}()
		err, finished := await(ctx, done)
		switch {
		case !finished:
			r.Logger.Error("shutdown hook did not finish before the deadline", slog.String("hook", h.name))
			errs = append(errs, fmt.Errorf("shutdown hook %s: %w", h.name, err))
		case err != nil:
			r.Logger.Error("shutdown hook failed", slog.String("hook", h.name), slog.String("error", pii.Redact(err.Error())))
			errs = append(errs, fmt.Errorf("shutdown hook %s failed", h.name))
		}
	}
	return errors.Join(errs...)
}

// Process is what Run takes from the operating system. [Main] fills it from
// the real process; tests fill it with fakes.
type Process struct {
	// Args are the command-line arguments without the program name.
	Args []string
	// LookupEnv reads the environment; nil means an empty environment.
	LookupEnv func(string) (string, bool)
	// Stdout receives log and metric lines and -version; Stderr receives flag
	// and -healthcheck errors. nil discards.
	Stdout, Stderr io.Writer
	// Listen opens the admin listener; nil means net.Listen.
	Listen func(network, address string) (net.Listener, error)
	// Now and After are the clock; nil means time.Now and time.After.
	Now   func() time.Time
	After func(time.Duration) <-chan time.Time
}

func (p Process) withDefaults() Process {
	if p.LookupEnv == nil {
		p.LookupEnv = func(string) (string, bool) { return "", false }
	}
	if p.Stdout == nil {
		p.Stdout = io.Discard
	}
	if p.Stderr == nil {
		p.Stderr = io.Discard
	}
	if p.Listen == nil {
		p.Listen = net.Listen
	}
	if p.Now == nil {
		p.Now = time.Now
	}
	if p.After == nil {
		p.After = time.After
	}
	return p
}

// Main runs svc as the process and exits with Run's status. It is the whole of
// a service's main function.
func Main[C any](svc Service[C]) {
	os.Exit(Run(context.Background(), svc, Process{
		Args:      os.Args[1:],
		LookupEnv: os.LookupEnv,
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
	}))
}

// Run runs svc and returns the exit status.
//
// With -version it prints buildinfo.String and returns. With -healthcheck it
// GETs /healthz on the admin port of the copy of the service running in the
// same container and returns 0 only on 200, within 3 s; distroless images have
// no curl, so the ECS container health check runs the binary itself.
//
// Otherwise it reads the configuration, refusing to start on any problem, serves
// the admin endpoints, calls svc.Run, and on SIGTERM, SIGINT or cancellation of
// ctx shuts down within RCS_SHUTDOWN_TIMEOUT: /readyz turns 503, Run's context
// is cancelled, Run is awaited, shutdown hooks run, and the admin server closes
// last so /healthz answers throughout. A second signal during shutdown kills
// the process at once.
func Run[C any](ctx context.Context, svc Service[C], p Process) int {
	svc.validate()
	p = p.withDefaults()

	fs := flag.NewFlagSet(svc.Name, flag.ContinueOnError)
	fs.SetOutput(p.Stderr)
	version := fs.Bool("version", false, "print the version and exit")
	healthcheck := fs.Bool("healthcheck", false, "exit 0 if the service in this container answers /healthz")
	if err := fs.Parse(p.Args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if fs.NArg() > 0 || *version && *healthcheck {
		fmt.Fprintf(p.Stderr, "usage: %s [-version | -healthcheck]\n", svc.Name)
		return ExitUsage
	}
	switch {
	case *version:
		fmt.Fprintln(p.Stdout, buildinfo.String(svc.Name))
		return ExitOK
	case *healthcheck:
		if err := probe(ctx, p); err != nil {
			fmt.Fprintf(p.Stderr, "%s: healthcheck: %v\n", svc.Name, err)
			return ExitFailure
		}
		return ExitOK
	}
	return serve(ctx, svc, p)
}

func serve[C any](ctx context.Context, svc Service[C], p Process) int {
	out := &syncWriter{w: p.Stdout}

	sharedEnv := NewEnv("RCS_", p.LookupEnv)
	sh := loadShared(sharedEnv)
	settings := &Settings{
		Env:         sharedEnv.WithPrefix(svc.EnvPrefix),
		Shared:      sharedEnv,
		Environment: sh.environment,
	}
	// Unkeyed hints show the last two characters of every identifier, which
	// together with a time and an address narrows a subscriber down, and they
	// correlate poorly; production logs leave the platform, so they are keyed.
	settings.ForbidInProduction(!sh.piiKeySet,
		"RCS_PII_HMAC_KEY is unset: log hints would show the last two characters of each identifier")
	cfg := svc.Configure(settings)

	log := NewLogger(out, svc.Name, buildinfo.Version, sh.logLevel)
	if sh.environment.Production() {
		for _, reason := range settings.unsafe {
			sharedEnv.report.problems = append(sharedEnv.report.problems,
				"refused in "+string(sh.environment)+": "+reason)
		}
	}
	if err := sharedEnv.Err(); err != nil {
		var ce *ConfigError
		errors.As(err, &ce)
		log.Error("configuration rejected", slog.Any("problems", ce.Problems))
		return ExitFailure
	}
	if len(settings.unsafe) > 0 {
		log.Warn("production-unsafe settings in use", slog.Any("reasons", settings.unsafe))
	}

	pii.SetDefault(sh.redactor)
	rt := NewRuntime(RuntimeOptions{
		Service:          svc.Name,
		Environment:      sh.environment,
		Out:              out,
		Level:            sh.logLevel,
		MetricsNamespace: sh.metricsNamespace,
		Now:              p.Now,
		After:            p.After,
	})
	log = rt.Logger
	// Libraries that log through slog's or log's default logger end up in the
	// same JSON stream instead of as plain text on stderr.
	slog.SetDefault(log)

	ln, err := p.Listen("tcp", sh.admin.listen)
	if err != nil {
		log.Error("admin listener failed", slog.String("error", pii.Redact(err.Error())))
		return ExitFailure
	}
	srv := &http.Server{
		Handler:           rt.Admin,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	adminDone := make(chan error, 1)
	go func() { adminDone <- srv.Serve(ln) }()

	sigCtx, stopSignals := signal.NotifyContext(ctx, syscall.SIGTERM, os.Interrupt)
	defer stopSignals()
	runCtx, cancelRun := context.WithCancel(sigCtx)
	defer cancelRun()

	log.Info("started", slog.String("environment", string(sh.environment)), slog.String("admin_addr", ln.Addr().String()))
	runDone := make(chan error, 1)
	go func() { runDone <- svc.Run(runCtx, rt, cfg) }()

	failed, runReturned := false, false
	select {
	case <-runCtx.Done():
		log.Info("stopping: shutdown requested")
	case err := <-runDone:
		runReturned = true
		if runCtx.Err() != nil {
			// Stop was requested and Run returned at once; select may pick
			// either ready case, so this is the case above.
			log.Info("stopping: shutdown requested")
			failed = stopFailed(log, err)
			break
		}
		if err != nil {
			log.Error("stopping: service failed", slog.String("error", pii.Redact(err.Error())))
			failed = true
		} else {
			log.Info("stopping: service returned")
		}
	case err := <-adminDone:
		log.Error("stopping: admin server failed", slog.String("error", pii.Redact(err.Error())))
		failed = true
	}
	// From here a second signal gets the default action and ends the process,
	// for an operator who does not want to wait for the drain.
	stopSignals()
	rt.Admin.stop()
	cancelRun()

	deadline, cancelDeadline := withTimer(context.Background(), p.After, sh.shutdownTimeout)
	defer cancelDeadline()
	if !runReturned {
		err, finished := await(deadline, runDone)
		if !finished {
			log.Error("service did not stop before the shutdown deadline", slog.Duration("timeout", sh.shutdownTimeout))
			failed = true
		} else if stopFailed(log, err) {
			failed = true
		}
	}
	if rt.Shutdown(deadline) != nil {
		failed = true
	}
	if err := srv.Shutdown(deadline); err != nil {
		_ = srv.Close()
	}

	if failed {
		log.Error("stopped with errors")
		return ExitFailure
	}
	log.Info("stopped")
	return ExitOK
}

// stopFailed logs and reports an error Service.Run returned after it was asked
// to stop; its own context's cancellation is a clean stop.
func stopFailed(log *slog.Logger, err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	log.Error("service failed while stopping", slog.String("error", pii.Redact(err.Error())))
	return true
}

// probe performs -healthcheck. Proxies and redirects are ignored: the target is
// always this container's own admin port, and HTTP_PROXY in the task
// environment must not send the probe elsewhere.
func probe(ctx context.Context, p Process) error {
	env := NewEnv("RCS_", p.LookupEnv)
	addr := loadAdminAddr(env)
	if err := env.Err(); err != nil {
		return err
	}
	ctx, cancel := withTimer(ctx, p.After, healthcheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr.probeURL, nil)
	if err != nil {
		return err
	}
	resp, err := probeClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", addr.probeURL, resp.Status)
	}
	return nil
}

// probeClient is the -healthcheck client: no proxy and no redirects.
func probeClient() *http.Client {
	return &http.Client{
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// await returns the value sent on done, or reports finished=false if ctx ends
// first. A value already sent wins over an ended ctx; a bare select would pick
// between the two at random.
func await(ctx context.Context, done <-chan error) (err error, finished bool) {
	select {
	case err = <-done:
		return err, true
	default:
	}
	select {
	case err = <-done:
		return err, true
	case <-ctx.Done():
		return context.Cause(ctx), false
	}
}
