package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// MetricHookPanics counts the panics recovered from the hooks a service gives
// the proxy (#428).
const MetricHookPanics = "proxy.hook_panics"

// Metrics receives the proxy's counts; *runtime.Metrics is one.
type Metrics interface {
	Count(name string, n int64)
}

// errHookPanic fails a branch whose Prepare panicked, as Prepare's error
// does (500), or whose Resolver did, as the Resolver's error does (a 503 from
// the next hop, which goes upstream as 500).
var errHookPanic = errors.New("proxy: a service hook panicked")

// route asks the Router for its Decision. A panic in it is answered 500, and
// an ACK it was for is dropped.
func (p *Proxy) route(ctx context.Context, in *Request) Decision {
	dec := Decision{Status: 500}
	p.hook("Route", func() { dec = p.router.Route(ctx, in) })
	return dec
}

// everyMinute allows one event a minute: a hook that panics on every request
// logs one line a minute, as the counters give how many there were (code
// review of #436; icscf's unknownLog does the same). Times are how long the
// proxy has run, which a time.Now reading measures on the monotonic clock,
// so a step of the wall clock neither silences nor floods the log; one that
// is earlier than the last allowed, as a clock set back gives, is allowed.
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

// panicLog returns the limiter of hook name's log lines, made on its first
// panic, so that every name Proxy.hook is given has one.
func (p *Proxy) panicLog(name string) *everyMinute {
	if l, ok := p.panicLogs.Load(name); ok {
		return l.(*everyMinute)
	}
	l, _ := p.panicLogs.LoadOrStore(name, &everyMinute{})
	return l.(*everyMinute)
}

// maxPanicFrames bounds the frames logged for a hook's panic: enough to find
// the hook, few enough for one line.
const maxPanicFrames = 8

// hook runs f, which calls a hook the service gave the proxy (the Router,
// a Decision's hooks, the Resolver, DrainAnswer), and reports whether it
// returned. A panic in it is recovered here, on the hook's goroutine, so that
// it ends only the request, branch or response the hook was for: the caller
// answers or drops that as it would after the hook's error. The panic is
// counted, and logged without its value, which may hold message content, at
// most once a minute for each hook.
//
// The proxy calls no hook with a lock of its own held, so none is left held.
// A hook that panics while it holds a lock of the service's still leaves that
// one held.
func (p *Proxy) hook(name string, f func()) (ok bool) {
	defer func() {
		if v := recover(); v != nil {
			p.hookPanicked(name, v)
			ok = false
		}
	}()
	f()
	return true
}

func (p *Proxy) hookPanicked(name string, v any) {
	p.stats.hookPanics.Add(1)
	if p.metrics != nil {
		p.metrics.Count(MetricHookPanics, 1)
	}
	if !p.panicLog(name).allow(p.now().Sub(p.started)) {
		return
	}
	p.log.Error("proxy: a service hook panicked",
		slog.String("hook", name),
		slog.String("panic", panicKind(v)),
		slog.String("at", panicFrames()))
}

// panicKind describes a panic value without its contents: the message of a
// runtime error, which names only types, indices and lengths, or else the
// value's type, since a service's own panic value may quote the message it
// was handling.
func panicKind(v any) string {
	if err, ok := v.(runtime.Error); ok {
		return err.Error()
	}
	return fmt.Sprintf("%T", v)
}

// panicFrames returns where the panic happened, innermost first: the frames
// between the runtime's panic and Proxy.hook, as "function file:line", with
// no arguments, which may be message content.
func panicFrames() string {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(1, pcs)])
	var out []string
	inPanic := false
	for {
		f, more := frames.Next()
		switch {
		case strings.HasPrefix(f.Function, "runtime."):
			// gopanic, and the runtime's own frames for a fault.
			inPanic = true
		case strings.HasSuffix(f.Function, "proxy.(*Proxy).hook"):
			return strings.Join(out, " < ")
		case inPanic && len(out) < maxPanicFrames:
			out = append(out, path.Base(f.Function)+" "+path.Base(f.File)+":"+strconv.Itoa(f.Line))
		}
		if !more {
			return strings.Join(out, " < ")
		}
	}
}
