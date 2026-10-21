package pcscf

import (
	"context"
	"sync"
	"testing"
)

// Waiting for the work under way while other goroutines start more is
// safe, and wait returns once none runs, what started meanwhile included
// (#248 code review: a WaitGroup's Add raced its Wait).
func TestWaitingWhileWorkStartsIsSafe(t *testing.T) {
	var b background
	b.ctx = context.Background()
	var starters sync.WaitGroup
	for range 4 {
		starters.Add(1)
		go func() {
			defer starters.Done()
			for range 200 {
				b.goRun(func(context.Context) {})
			}
		}()
	}
	for range 200 {
		b.wait()
	}
	starters.Wait()
	b.wait()
	b.mu.Lock()
	running := b.running
	b.mu.Unlock()
	if running != 0 {
		t.Errorf("%d still running after wait", running)
	}
	b.close()
	ran := false
	b.goRun(func(context.Context) { ran = true })
	b.wait()
	if ran {
		t.Error("work started after close")
	}
}
