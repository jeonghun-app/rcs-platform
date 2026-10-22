// Package panics contains a panic in code that one part of the platform runs
// for another, such as a service's hook, handler or callback, to the work it
// was for (#428, #445). A Guard recovers the panic on the goroutine it
// happened on, counts it, and logs it without its value, which may hold
// message content, at most once a minute for each name; the caller then
// ends that work as it would after the code's error, and everything else
// goes on.
package panics

import (
	"fmt"
	"log/slog"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Counter receives a Guard's counts; *runtime.Metrics is one.
type Counter interface {
	Count(name string, n int64)
}

// Config configures a Guard.
type Config struct {
	// Metric is the name every panic is counted under, such as
	// "proxy.hook_panics".
	Metric string
	// Message is the log message, such as "proxy: a service hook panicked".
	Message string
	// Log receives the log lines; nil discards them.
	Log *slog.Logger
	// Metrics, if set, counts every panic as Metric, at once.
	Metrics Counter
	// Now and Start are the clock of the log limit, which measures
	// Now().Sub(Start): nil is time.Now, and zero Start is Now() at New.
	// Two time.Now readings are compared on the monotonic clock, so a step
	// of the wall clock neither silences nor floods the log.
	Now   func() time.Time
	Start time.Time
}

// A Guard recovers and reports panics. Its methods are safe for concurrent
// use. A nil *Guard recovers too, and only that, so that code given none
// still contains a panic.
type Guard struct {
	cfg    Config
	panics atomic.Uint64
	// logs holds an *everyMinute for each name, made on its first panic.
	logs sync.Map
}

// New returns a Guard for cfg.
func New(cfg Config) *Guard {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Start.IsZero() {
		cfg.Start = cfg.Now()
	}
	return &Guard{cfg: cfg}
}

// Run runs f, which calls the code named name, and reports whether it
// returned. A panic in it is recovered here, counted and logged. A lock the
// panicking code held stays held: Run cannot know of it, so a caller runs
// such code with no lock of its own held.
func (g *Guard) Run(name string, f func()) (ok bool) {
	defer func() {
		if v := recover(); v != nil {
			g.panicked(name, v)
			ok = false
		}
	}()
	f()
	return true
}

// Panics returns how many panics g has recovered.
func (g *Guard) Panics() uint64 {
	if g == nil {
		return 0
	}
	return g.panics.Load()
}

func (g *Guard) panicked(name string, v any) {
	if g == nil {
		return
	}
	g.panics.Add(1)
	if g.cfg.Metrics != nil {
		g.cfg.Metrics.Count(g.cfg.Metric, 1)
	}
	if !g.limiter(name).allow(g.cfg.Now().Sub(g.cfg.Start)) {
		return
	}
	g.cfg.Log.Error(g.cfg.Message,
		slog.String("hook", name),
		slog.String("panic", Kind(v)),
		slog.String("at", frames()))
}

// limiter returns the log limit of name, made on its first panic, so that
// every name has one.
func (g *Guard) limiter(name string) *everyMinute {
	if l, ok := g.logs.Load(name); ok {
		return l.(*everyMinute)
	}
	l, _ := g.logs.LoadOrStore(name, &everyMinute{})
	return l.(*everyMinute)
}

// everyMinute allows one event a minute: code that panics on every request
// logs one line a minute, as the counts give how many there were (code
// review of #436). A time earlier than the last allowed, as a clock set back
// gives, is allowed.
type everyMinute struct {
	// last is the time of the last event allowed plus one nanosecond, or 0
	// before the first.
	last atomic.Int64
}

func (e *everyMinute) allow(at time.Duration) bool {
	last := e.last.Load()
	if since := at - time.Duration(last-1); last != 0 && since >= 0 && since < time.Minute {
		return false
	}
	return e.last.CompareAndSwap(last, int64(at)+1)
}

// Kind describes a panic value without its contents: the message of a
// runtime error, which names only types, indices and lengths, or else the
// value's type, since a value of the code's own may quote the message it was
// handling.
func Kind(v any) string {
	if err, ok := v.(runtime.Error); ok {
		return err.Error()
	}
	return fmt.Sprintf("%T", v)
}

// maxFrames bounds the frames logged for a panic: enough to find the code,
// few enough for one line.
const maxFrames = 8

// frames returns where the panic happened, innermost first: the frames
// between the runtime's panic and Guard.Run, as "function file:line", with
// no arguments, which may be message content.
func frames() string {
	pcs := make([]uintptr, 64)
	fs := runtime.CallersFrames(pcs[:runtime.Callers(1, pcs)])
	var out []string
	inPanic := false
	for {
		f, more := fs.Next()
		switch {
		case strings.HasPrefix(f.Function, "runtime."):
			// gopanic, and the runtime's own frames for a fault.
			inPanic = true
		case strings.HasSuffix(f.Function, "panics.(*Guard).Run"):
			return strings.Join(out, " < ")
		case inPanic && len(out) < maxFrames:
			out = append(out, path.Base(f.Function)+" "+path.Base(f.File)+":"+strconv.Itoa(f.Line))
		}
		if !more {
			return strings.Join(out, " < ")
		}
	}
}
