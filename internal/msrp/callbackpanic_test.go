package msrp

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/panics"
)

type panicCounts struct {
	mu sync.Mutex
	n  map[string]int64
}

func (c *panicCounts) Count(name string, n int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == nil {
		c.n = map[string]int64{}
	}
	c.n[name] += n
}

func (c *panicCounts) get(name string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[name]
}

func newGuard() (*panics.Guard, *panicCounts) {
	c := &panicCounts{}
	return panics.New(panics.Config{Metric: MetricCallbackPanics, Metrics: c}), c
}

// panickingHandler panics on its first message, report and request, and
// records the later ones.
type panickingHandler struct {
	*recorder
	messages, reports, requests atomic.Int32
}

func (h *panickingHandler) HandleMessage(s *Session, m *Message) error {
	if h.messages.Add(1) == 1 {
		panic("message-secret " + string(m.Body.Bytes()))
	}
	return h.recorder.HandleMessage(s, m)
}

func (h *panickingHandler) HandleReport(s *Session, r Report) {
	if h.reports.Add(1) == 1 {
		panic("report")
	}
	h.recorder.HandleReport(s, r)
}

func (h *panickingHandler) HandleRequest(*Session, *Message) int {
	if h.requests.Add(1) == 1 {
		panic("request")
	}
	return StatusOK
}

// A HandleMessage that panics is answered as an error is, with a failure
// REPORT of 403, and the session's next message is delivered (#445).
func TestAPanicInHandleMessageIsAnsweredAsAnError(t *testing.T) {
	guard, counts := newGuard()
	h := &panickingHandler{recorder: newRecorder()}
	_, p := boundPassive(t, h, Config{Panics: guard})
	p.send(t, sendLines("m3ss1", "Message-ID: msg1", "Content-Type: text/plain", "", "hi", "-------m3ss1$")...)
	expectResponse(t, p, "m3ss1", StatusOK)
	if rep := p.next(t); rep.Method != MethodReport || rep.Status.Code != StatusForbidden || rep.MessageID != "msg1" {
		t.Fatalf("got %s %s %d, want the failure REPORT 403", rep.Method, rep.MessageID, rep.Status.Code)
	}
	p.send(t, sendLines("m3ss2", "Message-ID: msg2", "Content-Type: text/plain", "", "again", "-------m3ss2$")...)
	expectResponse(t, p, "m3ss2", StatusOK)
	if m := h.message(t); string(m.Body.Bytes()) != "again" {
		t.Fatalf("delivered %q", m.Body)
	}
	if n := counts.get(MetricCallbackPanics); n != 1 {
		t.Errorf("%s = %d, want 1", MetricCallbackPanics, n)
	}
}

// A HandleReport that panics drops that report; the next is delivered.
func TestAPanicInHandleReportDropsThatReport(t *testing.T) {
	guard, counts := newGuard()
	h := &panickingHandler{recorder: newRecorder()}
	_, p := boundPassive(t, h, Config{Panics: guard})
	report := func(tid, id string) []string {
		return []string{"MSRP " + tid + " REPORT", "To-Path: " + asURI, "From-Path: " + clientURI,
			"Message-ID: " + id, "Byte-Range: 1-10/10", "Status: 000 200 OK", "-------" + tid + "$"}
	}
	p.send(t, report("r3p1", "msg1")...)
	p.send(t, report("r3p2", "msg2")...)
	if r := h.report(t); r.MessageID != "msg2" {
		t.Fatalf("delivered the report of %q, want msg2's", r.MessageID)
	}
	if n := counts.get(MetricCallbackPanics); n != 1 {
		t.Errorf("%s = %d, want 1", MetricCallbackPanics, n)
	}
}

// A HandleRequest that panics is answered 403; the next request is served.
func TestAPanicInHandleRequestIsAnswered403(t *testing.T) {
	guard, counts := newGuard()
	h := &panickingHandler{recorder: newRecorder()}
	_, p := boundPassive(t, h, Config{Panics: guard})
	nick := func(tid string) []string {
		return []string{"MSRP " + tid + " NICKNAME", "To-Path: " + asURI, "From-Path: " + clientURI, `Use-Nickname: "Alice"`, "-------" + tid + "$"}
	}
	p.send(t, nick("n1ck1")...)
	expectResponse(t, p, "n1ck1", StatusForbidden)
	p.send(t, nick("n1ck2")...)
	expectResponse(t, p, "n1ck2", StatusOK)
	if n := counts.get(MetricCallbackPanics); n != 1 {
		t.Errorf("%s = %d, want 1", MetricCallbackPanics, n)
	}
}

// An OnEvent that panics ends that call; the connection goes on.
func TestAPanicInOnEventLeavesTheConnection(t *testing.T) {
	guard, counts := newGuard()
	_, p := boundPassive(t, newRecorder(), Config{Panics: guard, OnEvent: func(Event) { panic("event") }}, "text/plain")
	p.send(t, sendLines("unsup1", "Message-ID: msg1", "Content-Type: image/x-nope", "", "hi", "-------unsup1$")...)
	expectResponse(t, p, "unsup1", StatusUnsupportedMediaType)
	sentinel(t, p)
	if n := counts.get(MetricCallbackPanics); n == 0 {
		t.Errorf("%s = 0 after OnEvent panicked", MetricCallbackPanics)
	}
}

// readPanics panics in Read, as a parsing bug on the peer's input would on
// the reading goroutine.
type readPanics struct{ net.Conn }

func (readPanics) Read([]byte) (int, error) { panic("read") }

// A panic while a connection reads ends that connection only, as
// EventClosed with ErrPanicked, and is counted.
func TestAPanicWhileReadingEndsThatConnection(t *testing.T) {
	guard, counts := newGuard()
	ours, theirs := net.Pipe()
	t.Cleanup(func() { _ = theirs.Close() })
	events := make(chan Event, 8)
	c, err := NewPassiveConn(readPanics{ours}, &Registry{}, Config{Panics: guard, OnEvent: func(e Event) { events <- e }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	// EventClosed comes before Done (Conn.fail).
	select {
	case <-c.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the connection did not end")
	}
	for {
		select {
		case e := <-events:
			if e.Kind != EventClosed {
				continue
			}
			if !errors.Is(e.Err, ErrPanicked) {
				t.Errorf("EventClosed with %v, want ErrPanicked", e.Err)
			}
			if n := counts.get(MetricCallbackPanics); n != 1 {
				t.Errorf("%s = %d, want 1", MetricCallbackPanics, n)
			}
			return
		default:
			t.Fatal("no EventClosed")
		}
	}
}
