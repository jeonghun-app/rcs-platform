package transaction

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// fakeClock runs timers only when advanced, in deadline order, on the calling
// goroutine.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Duration
	seq    int
	timers []*fakeTimer
}

type fakeTimer struct {
	c    *fakeClock
	at   time.Duration
	seq  int
	f    func()
	done bool
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	t := &fakeTimer{c: c, at: c.now + d, seq: c.seq, f: f}
	c.timers = append(c.timers, t)
	return t
}

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := !t.done
	t.done = true
	return was
}

// advance moves the clock forward by d, firing every timer that falls due,
// including timers those firings start.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	end := c.now + d
	for {
		var next *fakeTimer
		for _, t := range c.timers {
			if !t.done && t.at <= end && (next == nil || t.at < next.at || t.at == next.at && t.seq < next.seq) {
				next = t
			}
		}
		if next == nil {
			break
		}
		next.done = true
		c.now = next.at
		c.mu.Unlock()
		next.f()
		c.mu.Lock()
	}
	c.now = end
	c.timers = slices.DeleteFunc(c.timers, func(t *fakeTimer) bool { return t.done })
	c.mu.Unlock()
}

func (c *fakeClock) elapsed() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// fakeSender records what the layer sends, with the fake time it was sent.
type fakeSender struct {
	clock   *fakeClock
	network transport.Network

	mu   sync.Mutex
	sent []sent
	// fail, when set, is returned by every send.
	fail error
}

type sent struct {
	at     time.Duration
	msg    sip.Message
	dst    transport.Destination
	noWait bool
}

// label names a message the way the tables write it: the method of a request,
// the status code of a response.
func label(m sip.Message) string {
	switch m := m.(type) {
	case *sip.Request:
		return m.Method
	case *sip.Response:
		return strconv.Itoa(m.StatusCode)
	}
	return "?"
}

func (s *fakeSender) SendRequest(req *sip.Request, dst transport.Destination, opts ...transport.SendOption) (transport.Network, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return "", s.fail
	}
	s.sent = append(s.sent, sent{s.clock.elapsed(), req, dst, slices.Contains(opts, transport.NoWait)})
	return s.network, nil
}

func (s *fakeSender) SendResponse(res *sip.Response, src transport.Source, opts ...transport.SendOption) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	s.sent = append(s.sent, sent{s.clock.elapsed(), res, transport.Destination{}, slices.Contains(opts, transport.NoWait)})
	return nil
}

func (s *fakeSender) failWith(err error) {
	s.mu.Lock()
	s.fail = err
	s.mu.Unlock()
}

// labels returns the labels of everything sent so far and forgets it.
func (s *fakeSender) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, x := range s.sent {
		out = append(out, label(x.msg))
	}
	s.sent = nil
	return out
}

// modes returns each message sent as "label wait" or "label nowait".
func (s *fakeSender) modes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, x := range s.sent {
		m := " wait"
		if x.noWait {
			m = " nowait"
		}
		out = append(out, label(x.msg)+m)
	}
	return out
}

// times returns when each message was sent, as "label@time".
func (s *fakeSender) times() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, x := range s.sent {
		out = append(out, label(x.msg)+"@"+x.at.String())
	}
	return out
}

func (s *fakeSender) last() sip.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sent) == 0 {
		return nil
	}
	return s.sent[len(s.sent)-1].msg
}

func (s *fakeSender) lastDestination() transport.Destination {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent[len(s.sent)-1].dst
}

// tuRecorder is a TU that records every call as a label.
type tuRecorder struct {
	mu     sync.Mutex
	events []string
	txs    []*ServerTransaction
	// onRequest, if set, runs inside Request.
	onRequest func(*ServerTransaction)
}

func (r *tuRecorder) record(e string) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

func (r *tuRecorder) Request(tx *ServerTransaction) {
	r.mu.Lock()
	r.txs = append(r.txs, tx)
	r.mu.Unlock()
	r.record("request " + tx.Request().Method)
	if r.onRequest != nil {
		r.onRequest(tx)
	}
}

func (r *tuRecorder) Stray(in transport.Inbound) { r.record("stray " + label(in.Message)) }

func (r *tuRecorder) ServerFailed(tx *ServerTransaction, err error) {
	r.record("failed: " + err.Error())
}

func (r *tuRecorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.events
	r.events = nil
	return e
}

func (r *tuRecorder) lastTx() *ServerTransaction {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.txs[len(r.txs)-1]
}

// harness is a Layer wired to fakes.
type harness struct {
	t      *testing.T
	clock  *fakeClock
	sender *fakeSender
	tu     *tuRecorder
	layer  *Layer
	// responses records what client transactions pass to their handler.
	mu        sync.Mutex
	responses []string
}

func newHarness(t *testing.T, network transport.Network, cfg Config) *harness {
	clock := &fakeClock{}
	h := &harness{t: t, clock: clock, sender: &fakeSender{clock: clock, network: network}, tu: &tuRecorder{}}
	cfg.Clock = clock
	h.layer = New(h.sender, h.tu, cfg)
	return h
}

func (h *harness) handler(res *sip.Response, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err != nil {
		h.responses = append(h.responses, "error: "+err.Error())
		return
	}
	h.responses = append(h.responses, label(res))
}

func (h *harness) takeResponses() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.responses
	h.responses = nil
	return r
}

// request builds a request in wire form and parses it, as the transport would
// deliver it.
func request(t *testing.T, method, branch string, extra ...string) *sip.Request {
	t.Helper()
	lines := []string{
		method + " sip:bob@example.com SIP/2.0",
		"Via: SIP/2.0/UDP client.example.com:5060;branch=" + branch,
		"Max-Forwards: 70",
		"To: <sip:bob@example.com>",
		"From: <sip:alice@example.com>;tag=a1",
		"Call-ID: call-1@example.com",
		"CSeq: 1 " + method,
	}
	lines = append(lines, extra...)
	lines = append(lines, "Content-Length: 0")
	m, err := sip.ParseMessage([]byte(strings.Join(lines, "\r\n") + "\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	return m.(*sip.Request)
}

func response(t *testing.T, req *sip.Request, code int) *sip.Response {
	t.Helper()
	res, err := sip.NewResponse(req, code, "", "b1")
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func inbound(m sip.Message, network transport.Network) transport.Inbound {
	return transport.Inbound{Message: m, Source: transport.Source{Flow: "flow-1", Network: network}}
}

func (h *harness) startClient(req *sip.Request) *ClientTransaction {
	h.t.Helper()
	tx, err := h.layer.Request(req, transport.Destination{Network: h.sender.network}, h.handler)
	if err != nil {
		h.t.Fatal(err)
	}
	return tx
}

func (h *harness) receive(m sip.Message) { h.layer.Receive(inbound(m, h.sender.network)) }

func equal(a, b []string) bool { return slices.Equal(a, b) }

func check(t *testing.T, what string, got, want []string) {
	t.Helper()
	if !equal(got, want) {
		t.Errorf("%s = %q, want %q", what, got, want)
	}
}

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

func at(l string, d time.Duration) string { return fmt.Sprintf("%s@%s", l, d) }
