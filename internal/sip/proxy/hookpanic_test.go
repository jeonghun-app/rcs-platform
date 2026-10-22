package proxy

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// lockedBuffer collects log output written from the proxy's goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// countingMetrics records the counts the proxy reports.
type countingMetrics struct {
	mu     sync.Mutex
	counts map[string]int64
}

func (m *countingMetrics) Count(name string, n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.counts == nil {
		m.counts = map[string]int64{}
	}
	m.counts[name] += n
}

func (m *countingMetrics) count(name string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counts[name]
}

// hookSecret stands for message content a panicking hook puts in its panic
// value, which must not reach the log.
const hookSecret = "hook-secret-value"

// panicWith panics as a service hook might, with the message's From in the
// value.
func panicWith(m *sip.Header) { panic(hookSecret + " " + m.Get("From")) }

// panickingResolver panics for the host "panic.example.net" only.
type panickingResolver struct{}

func (panickingResolver) Resolve(ctx context.Context, u sip.URI) (transport.Destination, error) {
	if u.Host == "panic.example.net" {
		panic(hookSecret)
	}
	return fakeResolver{}.Resolve(ctx, u)
}

// A panic in a hook a service gives the proxy is recovered on the hook's
// goroutine (#428): the request it was for is answered 500, or the branch
// or response it was for is ended, the panic is logged without the
// message's contents and counted, and the proxy goes on serving.
func TestAPanicInAHookEndsOnlyItsOwnRequest(t *testing.T) {
	tests := []struct {
		name string
		hook string // the hook the log names
		cfg  Config
		// run drives the request and returns the status codes sent upstream.
		run  func(t *testing.T, h *harness) []int
		want []int
		// draining: the proxy is stopping afterwards and serves nothing more.
		draining bool
	}{
		{
			name: "Router", hook: "Route", want: codes(500),
			run: func(t *testing.T, h *harness) []int {
				h.route(func(_ contextT, r *Request) Decision { panicWith(&r.Message.Header); return Decision{} })
				h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
				return h.upstream()
			},
		},
		{
			name: "Serve", hook: "Serve", want: codes(500),
			run: func(t *testing.T, h *harness) []int {
				h.route(func(_ contextT, r *Request) Decision {
					return Decision{Serve: func(context.Context, *UAS) { panicWith(&r.Message.Header) }}
				})
				h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
				return h.upstream()
			},
		},
		{
			name: "Prepare", hook: "Prepare", want: codes(500),
			run: func(t *testing.T, h *harness) []int {
				h.decide(Decision{
					Targets: []Target{target("sip:a@192.0.2.1")},
					Prepare: func(_ contextT, _ Target, req *sip.Request) error { panicWith(&req.Header); return nil },
				})
				h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
				check(t, "sent", h.sentMethods(), nil)
				return h.upstream()
			},
		},
		{
			name: "Resolver", hook: "Resolver", cfg: Config{Resolver: panickingResolver{}}, want: codes(500),
			run: func(t *testing.T, h *harness) []int {
				h.decide(Decision{Targets: []Target{target("sip:a@panic.example.net")}})
				h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
				check(t, "sent", h.sentMethods(), nil)
				return h.upstream()
			},
		},
		{
			// The failed branch's own final response is the answer; the
			// hook's targets, had it returned any, are not tried.
			name: "OnBranchFailure", hook: "OnBranchFailure", want: codes(404),
			run: func(t *testing.T, h *harness) []int {
				h.decide(Decision{
					Targets: []Target{target("sip:a@192.0.2.1")},
					OnBranchFailure: func(_ contextT, f BranchFailure) []Target {
						panicWith(&f.Response.Header)
						return []Target{target("sip:b@192.0.2.2")}
					},
				})
				h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
				h.reply(h.one(), 404)
				check(t, "sent", h.sentMethods(), nil)
				return h.upstream()
			},
		},
		{
			// The response the hook may have half changed is not sent.
			name: "OnFinal", hook: "OnFinal", want: codes(500),
			run: func(t *testing.T, h *harness) []int {
				h.decide(Decision{
					Targets: []Target{target("sip:a@192.0.2.1")},
					OnFinal: func(_ contextT, res *sip.Response) {
						res.StatusCode = 486
						panicWith(&res.Header)
					},
				})
				h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
				h.reply(h.one(), 404)
				return h.upstream()
			},
		},
		{
			name: "OnResponse on a final response", hook: "OnResponse", want: codes(500),
			run: func(t *testing.T, h *harness) []int {
				h.decide(Decision{
					Targets: []Target{target("sip:a@192.0.2.1")},
					OnResponse: func(_ contextT, res *sip.Response) {
						if err := res.Header.Set("X-Half", "1"); err != nil {
							t.Error(err)
						}
						panicWith(&res.Header)
					},
				})
				h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
				h.reply(h.one(), 200)
				res := h.upstreamResponses()
				var out []int
				for _, r := range res {
					if r.Header.Has("X-Half") {
						t.Error("the response the hook half changed was sent")
					}
					out = append(out, r.StatusCode)
				}
				return out
			},
		},
		{
			// A provisional response is dropped; the final one still goes.
			name: "OnResponse on a provisional response", hook: "OnResponse", want: codes(200),
			run: func(t *testing.T, h *harness) []int {
				h.decide(Decision{
					Targets: []Target{target("sip:a@192.0.2.1")},
					OnResponse: func(_ contextT, res *sip.Response) {
						if res.StatusCode < 200 {
							panicWith(&res.Header)
						}
					},
				})
				h.receive(invite(t))
				fwd := h.one()
				h.reply(fwd, 180)
				h.reply(fwd, 200)
				return h.upstream()
			},
		},
		{
			// A 2xx retransmission is dropped; the UAS sends it again
			// until the ACK (RFC 6026 §8.1).
			name: "OnResponse on a 2xx retransmission", hook: "OnResponse", want: codes(200),
			run: func(t *testing.T, h *harness) []int {
				calls := 0
				h.decide(Decision{
					Targets: []Target{target("sip:a@192.0.2.1")},
					OnResponse: func(_ contextT, res *sip.Response) {
						if calls++; calls == 2 {
							panicWith(&res.Header)
						}
					},
				})
				h.receive(invite(t))
				fwd := h.one()
				h.reply(fwd, 200)
				h.reply(fwd, 200)
				return h.upstream()
			},
		},
		{
			// Drain falls back to its default answer.
			name: "DrainAnswer", hook: "DrainAnswer", draining: true, want: codes(500),
			cfg: Config{DrainAnswer: func(req *sip.Request) (int, time.Duration) {
				panicWith(&req.Header)
				return 503, time.Second
			}},
			run: func(t *testing.T, h *harness) []int {
				h.decide(Decision{Targets: []Target{target("sip:bob@192.0.2.2")}})
				h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
				h.one()
				<-drainFor(h, 100*time.Millisecond)
				res := h.upstreamResponses()
				var out []int
				for _, r := range res {
					if r.Header.Get("Retry-After") != overloadRetryAfter {
						t.Errorf("Retry-After = %q, want the default", r.Header.Get("Retry-After"))
					}
					out = append(out, r.StatusCode)
				}
				return out
			},
		},
		{
			// Drain's own answer goes through OnResponse as well; the 500
			// keeps its Retry-After, which sends the client elsewhere.
			name: "OnResponse on Drain's answer", hook: "OnResponse", draining: true, want: codes(500),
			cfg: Config{DrainAnswer: func(*sip.Request) (int, time.Duration) { return 503, 7 * time.Second }},
			run: func(t *testing.T, h *harness) []int {
				h.decide(Decision{
					Targets: []Target{target("sip:bob@192.0.2.2")},
					OnResponse: func(_ contextT, res *sip.Response) {
						if err := res.Header.Set("X-Half", "1"); err != nil {
							t.Error(err)
						}
						panicWith(&res.Header)
					},
				})
				h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
				h.one()
				<-drainFor(h, 100*time.Millisecond)
				var out []int
				for _, r := range h.upstreamResponses() {
					if r.Header.Has("X-Half") {
						t.Error("the response the hook half changed was sent")
					}
					if ra := r.Header.Get("Retry-After"); ra != "7" {
						t.Errorf("Retry-After = %q, want DrainAnswer's 7", ra)
					}
					out = append(out, r.StatusCode)
				}
				return out
			},
		},
		{
			// A panic value that is an error is logged by its type only:
			// its text may quote the message.
			name: "Router with an error value", hook: "Route", want: codes(500),
			run: func(t *testing.T, h *harness) []int {
				h.route(func(_ contextT, r *Request) Decision {
					panic(fmt.Errorf("%s %s", hookSecret, r.Message.Header.Get("From")))
				})
				h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
				return h.upstream()
			},
		},
		{
			// OnFinal's panic leaves OnResponse out, as pcscf sets both:
			// the response OnFinal half changed is not passed on.
			name: "OnFinal with OnResponse", hook: "OnFinal", want: codes(500),
			run: func(t *testing.T, h *harness) []int {
				var calls atomic.Int32
				h.decide(Decision{
					Targets: []Target{target("sip:a@192.0.2.1")},
					OnFinal: func(_ contextT, res *sip.Response) {
						res.StatusCode = 486
						panicWith(&res.Header)
					},
					OnResponse: func(contextT, *sip.Response) { calls.Add(1) },
				})
				h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
				h.reply(h.one(), 404)
				if n := calls.Load(); n != 0 {
					t.Errorf("OnResponse called %d times after OnFinal panicked", n)
				}
				return h.upstream()
			},
		},
		{
			// The 2xx the 500 replaced comes again: dropped, and no
			// upstream error (QA of #436).
			name: "OnResponse on an INVITE's first 2xx", hook: "OnResponse", want: codes(500),
			run: func(t *testing.T, h *harness) []int {
				var calls atomic.Int32
				h.decide(Decision{
					Targets: []Target{target("sip:a@192.0.2.1")},
					OnResponse: func(_ contextT, res *sip.Response) {
						if calls.Add(1) == 1 {
							panicWith(&res.Header)
						}
					},
				})
				h.receive(invite(t))
				fwd := h.one()
				h.reply(fwd, 200)
				h.reply(fwd, 200)
				h.reply(fwd, 200)
				if n := h.p.Stats().UpstreamErrors; n != 0 {
					t.Errorf("UpstreamErrors = %d for the replaced 2xx's retransmissions", n)
				}
				return h.upstream()
			},
		},
		{
			// An ACK for a 2xx has nothing to answer: it is dropped.
			name: "Router for an ACK", hook: "Route", want: nil,
			run: func(t *testing.T, h *harness) []int {
				h.route(func(_ contextT, r *Request) Decision { panicWith(&r.Message.Header); return Decision{} })
				h.receive(ackFor2xx(t))
				check(t, "sent", h.sentMethods(), nil)
				if n := h.p.Stats().ACKsDropped; n != 1 {
					t.Errorf("ACKsDropped = %d, want 1", n)
				}
				return h.upstream()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs lockedBuffer
			metrics := &countingMetrics{}
			cfg := tt.cfg
			cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
			cfg.Metrics = metrics
			h := newHarness(t, cfg)
			check(t, "upstream", tt.run(t, h), tt.want)
			// One panic, Drain's included: it asks DrainAnswer once a
			// request (QA of #436).
			n := h.p.Stats().HookPanics
			if n != 1 {
				t.Errorf("HookPanics = %d, want 1", n)
			}
			if m := metrics.count(MetricHookPanics); m != int64(n) {
				t.Errorf("%s counted %d, Stats %d", MetricHookPanics, m, n)
			}
			out := logs.String()
			if !strings.Contains(out, "hook="+tt.hook) {
				t.Errorf("the log does not name the hook %s:\n%s", tt.hook, out)
			}
			for _, secret := range []string{hookSecret, "alice@example.com", "bob@"} {
				if strings.Contains(out, secret) {
					t.Errorf("the log holds %q:\n%s", secret, out)
				}
			}
			if !strings.Contains(out, "hookpanic_test.go:") {
				t.Errorf("the log does not say where the hook panicked:\n%s", out)
			}
			if tt.draining {
				return
			}
			// The proxy goes on serving.
			h.decide(Decision{Status: 404})
			h.receive(request(t, "OPTIONS", "sip:example.com",
				"Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKup-next", "Call-ID: next@192.0.2.10"))
			check(t, "upstream after the panic", h.upstream(), codes(404))
			if n := h.p.Stats().Contexts; n != 0 {
				t.Errorf("Contexts = %d, want 0", n)
			}
		})
	}
}

// A hook that panics on every request logs one line a minute, and counts
// every panic (code review of #436): none more at 59 s, the next at 60 s,
// and one at once when the clock goes back, rather than none until it has
// caught up (QA of #436).
func TestAHookPanicIsLoggedOnceAMinute(t *testing.T) {
	var logs lockedBuffer
	h := newHarness(t, Config{Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	now := h.p.started
	h.p.now = func() time.Time { return now }
	h.route(func(_ contextT, r *Request) Decision { panicWith(&r.Message.Header); return Decision{} })
	n := 0
	send := func() {
		n++
		h.receive(request(t, "MESSAGE", "sip:bob@example.com",
			"Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKup-"+itoa(n), "Call-ID: call-"+itoa(n)+"@192.0.2.10"))
	}
	lines := func() int { return strings.Count(logs.String(), "hook=Route") }
	for _, step := range []struct {
		advance time.Duration
		want    int
	}{
		{0, 1}, {0, 1}, {0, 1},
		{59 * time.Second, 1},
		{time.Second, 2},
		{-time.Hour, 3},
		{59 * time.Second, 3},
		{time.Second, 4},
	} {
		now = now.Add(step.advance)
		send()
		if got := lines(); got != step.want {
			t.Fatalf("after panic %d (clock %v): %d lines, want %d", n, now.Sub(h.p.started), got, step.want)
		}
	}
	if got := h.p.Stats().HookPanics; got != uint64(n) {
		t.Errorf("HookPanics = %d, want %d", got, n)
	}
	check(t, "upstream", h.upstream(), codes(500, 500, 500, 500, 500, 500, 500, 500))
}

// A Serve handler that panics after a CANCEL is answered 487, as one that
// returns without an answer then is (§9.2).
func TestAServePanicAfterACancelIsAnswered487(t *testing.T) {
	h := newHarness(t, Config{})
	entered := make(chan struct{})
	h.decide(Decision{Serve: func(ctx context.Context, u *UAS) {
		close(entered)
		<-ctx.Done()
		panicWith(&u.Request().Message.Header)
	}})
	req := invite(t)
	h.p.Receive(inboundFrom(req, "up"))
	<-entered
	h.receive(uacCancel(t, req))
	check(t, "upstream", h.upstream(), codes(200, 487))
	if n := h.p.Stats().HookPanics; n != 1 {
		t.Errorf("HookPanics = %d, want 1", n)
	}
}

// The proxy's transaction layer counts a service's response handler's
// panics where the proxy counts its hooks' (#445): pcscf's SUBSCRIBE goes
// through Layer().Request.
func TestTheProxysLayerCountsAResponseHandlersPanics(t *testing.T) {
	metrics := &countingMetrics{}
	h := newHarness(t, Config{Metrics: metrics})
	req := request(t, "SUBSCRIBE", "sip:bob@192.0.2.30", "Via: SIP/2.0/TCP proxy.example.net;branch=z9hG4bKsub1")
	if _, err := h.p.Layer().Request(req, transport.Destination{Network: transport.TCP, ServerName: "s"}, func(res *sip.Response, err error) {
		if res != nil {
			panic("handler")
		}
	}); err != nil {
		t.Fatal(err)
	}
	h.reply(h.one(), 200)
	if n := metrics.count(transaction.MetricHandlerPanics); n != 1 {
		t.Errorf("%s = %d, want 1", transaction.MetricHandlerPanics, n)
	}
}
