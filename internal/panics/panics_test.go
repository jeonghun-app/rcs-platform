package panics

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

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

type counts struct {
	mu sync.Mutex
	m  map[string]int64
}

func (c *counts) Count(name string, n int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]int64{}
	}
	c.m[name] += n
}

func (c *counts) get(name string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[name]
}

const secret = "panic-secret <sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org>"

func failing() { panic(secret) }

// A panic is recovered, Run reports it, and it is counted and logged with
// the name, its kind and where it happened, never its value; a runtime
// error is logged by its message, any other error by its type only.
func TestARecoveredPanicIsCountedAndLoggedWithoutItsValue(t *testing.T) {
	var logs lockedBuffer
	c := &counts{}
	g := New(Config{Metric: "x.panics", Message: "x: a callback panicked", Log: slog.New(slog.NewTextHandler(&logs, nil)), Metrics: c})
	if g.Run("Callback", failing) {
		t.Fatal("Run reported a panicking call as returned")
	}
	if !g.Run("Callback", func() {}) {
		t.Fatal("Run reported a call that returned as panicked")
	}
	var m map[string]int
	g.Run("NilMap", func() { m["k"] = 1 })
	g.Run("Error", func() { panic(fmt.Errorf("%s", secret)) })
	if n := g.Panics(); n != 3 {
		t.Errorf("Panics = %d, want 3", n)
	}
	if n := c.get("x.panics"); n != 3 {
		t.Errorf("x.panics = %d, want 3", n)
	}
	out := logs.String()
	for _, want := range []string{
		`msg="x: a callback panicked" hook=Callback panic=string at="panics.failing panics_test.go:`,
		`hook=NilMap panic="assignment to entry in nil map"`,
		`hook=Error panic=*errors.errorString`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the log lacks %s:\n%s", want, out)
		}
	}
	for _, leak := range []string{"panic-secret", "15550100001", "3gppnetwork"} {
		if strings.Contains(out, leak) {
			t.Errorf("the log holds %q:\n%s", leak, out)
		}
	}
	if strings.Contains(out, "Guard).Run") || strings.Contains(out, "gopanic") {
		t.Errorf("the frames run past the panic or Run:\n%s", out)
	}
}

// A nil Guard still recovers, so code given none never ends the process.
func TestANilGuardRecovers(t *testing.T) {
	var g *Guard
	if g.Run("x", failing) {
		t.Fatal("Run reported a panicking call as returned")
	}
	if g.Panics() != 0 {
		t.Fatal("a nil Guard counts")
	}
}

// Each name logs one line a minute, measured from Start: none more at
// 59 s, the next at 60 s, and one at once when the clock goes back. Every
// panic is counted.
func TestEachNameLogsOneLineAMinute(t *testing.T) {
	var logs lockedBuffer
	start := time.Unix(1_800_000_000, 0)
	now := start
	g := New(Config{Metric: "x.panics", Message: "x", Log: slog.New(slog.NewTextHandler(&logs, nil)), Now: func() time.Time { return now }, Start: start})
	lines := func(name string) int { return strings.Count(logs.String(), "hook="+name+" ") }
	for i, step := range []struct {
		advance time.Duration
		want    int
	}{
		{0, 1}, {0, 1}, {59 * time.Second, 1}, {time.Second, 2}, {-time.Hour, 3}, {59 * time.Second, 3}, {time.Second, 4},
	} {
		now = now.Add(step.advance)
		g.Run("A", failing)
		if got := lines("A"); got != step.want {
			t.Fatalf("step %d: %d lines, want %d", i, got, step.want)
		}
	}
	// Another name has a limit of its own.
	g.Run("B", failing)
	if lines("B") != 1 {
		t.Errorf("B's first panic was not logged")
	}
	if n := g.Panics(); n != 8 {
		t.Errorf("Panics = %d, want 8", n)
	}
}

// Kind names a runtime error by its message and anything else by its type.
func TestKindNamesAValueWithoutItsContents(t *testing.T) {
	for v, want := range map[any]string{
		"text":               "string",
		errors.New("x"):      "*errors.errorString",
		42:                   "int",
		struct{ S string }{}: "struct { S string }",
	} {
		if got := Kind(v); got != want {
			t.Errorf("Kind(%T) = %q, want %q", v, got, want)
		}
	}
}
