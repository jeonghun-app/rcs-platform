package bridge

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/safeerr"
)

// Retry waits after a registration fails or a flow is lost: doubling from
// minRetry up to maxRetry, so that a network that refuses the endpoint is
// not asked more than about once a minute. scscf allows ten challenges a
// minute per IMPI (docs/local-stack.md, Troubleshooting).
const (
	minRetry = 2 * time.Second
	maxRetry = 60 * time.Second
)

// inboxLength bounds the delivery notifications an endpoint has yet to
// send; a MESSAGE that asks for one beyond it is answered 486, and the
// network tries again.
const inboxLength = 64

// Registration states, as events carry them.
const (
	stateRegistered   = "registered"
	stateUnregistered = "unregistered"
	stateFailed       = "failed"
)

// reasonFlowLost is the reason of a registration lost with its flow.
const reasonFlowLost = "the flow to the P-CSCF failed"

// endpoint is one named test subscriber and its registration.
type endpoint struct {
	b      *Bridge
	name   string
	sub    Subscriber
	number string
	// self is the endpoint in CPIM From and in its notifications.
	self  cpim.Address
	inbox chan inbound
	// received remembers the messages the endpoint received, for a
	// display notification the application sends later.
	received *recent

	// opMu is held by whatever changes the registration, one at a time:
	// a PUT, a refresh, a retry, a lost flow, the shutdown. mu guards the
	// fields below, which Send and the events read without opMu.
	opMu sync.Mutex
	mu   sync.Mutex
	// online is what the application asked for; line is the registered
	// flow, nil while there is none.
	online bool
	line   Line
	// timer is the one pending refresh or retry; timerGen names it, so a
	// timer that fires as it is replaced does nothing.
	timer    transaction.Timer
	timerGen uint64
	backoff  time.Duration
	stopped  bool
	done     chan struct{}
}

func newEndpoint(b *Bridge, name string, sub Subscriber, number string) *endpoint {
	return &endpoint{
		b: b, name: name, sub: sub, number: number,
		self:     cpim.Address{URI: sub.IMPU.String()},
		inbox:    make(chan inbound, inboxLength),
		received: newRecent(recentLength),
		done:     make(chan struct{}),
	}
}

// view is the endpoint as the API answers with it.
type view struct {
	Name       string `json:"name"`
	IMPU       string `json:"impu"`
	Tel        string `json:"tel"`
	Registered bool   `json:"registered"`
}

func (e *endpoint) view() view {
	return view{Name: e.name, IMPU: e.sub.IMPU.String(), Tel: e.sub.Tel.String(), Registered: e.currentLine() != nil}
}

// currentLine is the registered flow, nil when there is none.
func (e *endpoint) currentLine() Line {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.line
}

// setOnline registers the endpoint (online) or removes its registration,
// and returns once that is done or has failed. A failure is in the
// registration event; online, the endpoint keeps trying. It returns
// errFull, and changes nothing, when the endpoint would be one more online
// than the bridge allows.
func (e *endpoint) setOnline(ctx context.Context, online bool) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	e.mu.Lock()
	if e.stopped {
		e.mu.Unlock()
		return ErrClosed
	}
	if online != e.online && !e.b.countOnline(online) {
		e.mu.Unlock()
		return errFull
	}
	e.online = online
	line := e.line
	e.mu.Unlock()
	switch {
	case online && line == nil:
		// A retry pending is replaced by this attempt.
		e.backoff = 0
		e.connectLocked(ctx)
	case !online && line != nil:
		e.disconnectLocked(ctx)
	case !online:
		e.stopTimer()
	}
	return nil
}

// connectLocked registers on a new flow; opMu is held.
func (e *endpoint) connectLocked(ctx context.Context) {
	e.stopTimer()
	line, expires, err := e.b.cfg.SIP.Register(ctx, e.sub, e.receive)
	if err != nil {
		reason := safeerr.Reason(err).Error()
		e.b.log.Warn("registration failed", pii.Identity("endpoint", e.name), slog.String("reason", reason))
		e.publishState(stateFailed, reason)
		e.retryLater()
		return
	}
	e.mu.Lock()
	e.line = line
	e.backoff = 0
	e.mu.Unlock()
	e.b.log.Info("registered", pii.Identity("endpoint", e.name), slog.String("expires", expires.String()))
	e.publishState(stateRegistered, "")
	e.schedule(refreshIn(expires), e.refreshLocked)
	e.b.wg.Go(func() { e.watch(line) })
}

// disconnectLocked removes the registration and closes the flow; opMu is
// held. The line is forgotten first, so its Done is not taken for a lost
// flow.
func (e *endpoint) disconnectLocked(ctx context.Context) {
	e.stopTimer()
	e.mu.Lock()
	line := e.line
	e.line = nil
	e.mu.Unlock()
	if line == nil {
		return
	}
	if err := line.Unregister(ctx); err != nil {
		// The line is closed anyway; the registration expires in the
		// network.
		e.b.log.Warn("unregistration failed", pii.Identity("endpoint", e.name), slog.String("reason", safeerr.Reason(err).Error()))
	}
	e.b.log.Info("unregistered", pii.Identity("endpoint", e.name))
	e.publishState(stateUnregistered, "")
}

// refreshLocked registers again on the flow before the registration
// expires; opMu is held. A refresh that fails loses the flow, and a new
// one is tried.
func (e *endpoint) refreshLocked() {
	line := e.currentLine()
	if line == nil {
		return
	}
	ctx, cancel := e.b.opContext()
	defer cancel()
	expires, err := line.Refresh(ctx)
	if err == nil {
		e.schedule(refreshIn(expires), e.refreshLocked)
		return
	}
	reason := safeerr.Reason(err).Error()
	e.b.log.Warn("refresh failed", pii.Identity("endpoint", e.name), slog.String("reason", reason))
	e.lose(line, reason)
}

// watch waits for line to fail while it is the endpoint's flow.
func (e *endpoint) watch(line Line) {
	select {
	case <-line.Done():
	case <-e.done:
		return
	}
	e.opMu.Lock()
	defer e.opMu.Unlock()
	if e.currentLine() == line {
		e.b.log.Warn("flow lost", pii.Identity("endpoint", e.name))
		e.lose(line, reasonFlowLost)
	}
}

// lose drops line, reports the registration failed and tries again; opMu
// is held.
func (e *endpoint) lose(line Line, reason string) {
	e.mu.Lock()
	if e.line == line {
		e.line = nil
	}
	e.mu.Unlock()
	line.Close()
	e.publishState(stateFailed, reason)
	e.retryLater()
}

// retryLater schedules the next registration attempt while the endpoint
// is wanted online; opMu is held.
func (e *endpoint) retryLater() {
	e.mu.Lock()
	online := e.online && !e.stopped
	e.mu.Unlock()
	if !online {
		return
	}
	switch {
	case e.backoff == 0:
		e.backoff = minRetry
	case e.backoff < maxRetry:
		e.backoff = min(2*e.backoff, maxRetry)
	}
	e.schedule(e.backoff, func() {
		e.mu.Lock()
		again := e.online && e.line == nil && !e.stopped
		e.mu.Unlock()
		if again {
			ctx, cancel := e.b.opContext()
			defer cancel()
			e.connectLocked(ctx)
		}
	})
}

// schedule replaces the pending timer with one that runs fn, holding
// opMu, after d.
func (e *endpoint) schedule(d time.Duration, fn func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	if e.timer != nil {
		e.timer.Stop()
	}
	e.timerGen++
	gen := e.timerGen
	e.timer = e.b.cfg.Clock.AfterFunc(d, func() {
		e.opMu.Lock()
		defer e.opMu.Unlock()
		e.mu.Lock()
		current := gen == e.timerGen && !e.stopped
		if current {
			e.timer = nil
		}
		e.mu.Unlock()
		if current {
			fn()
		}
	})
}

func (e *endpoint) stopTimer() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.timer != nil {
		e.timer.Stop()
		e.timer = nil
	}
	e.timerGen++
}

// shutdown unregisters the endpoint within ctx and stops its work.
func (e *endpoint) shutdown(ctx context.Context) {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	e.disconnectLocked(ctx)
	e.mu.Lock()
	e.stopped = true
	e.mu.Unlock()
	close(e.done)
}

func (e *endpoint) publishState(state, reason string) {
	e.b.hub.publish(registrationEvent{Type: "registration", Endpoint: e.name, State: state, Reason: reason})
}

// refreshIn is when a registration of expires is refreshed (TS 24.229
// §5.1.1.4.1): 600 s before it expires when it was granted for more than
// 1200 s, half way through otherwise.
func refreshIn(expires time.Duration) time.Duration {
	if expires > 1200*time.Second {
		return expires - 600*time.Second
	}
	return max(expires/2, time.Second)
}
