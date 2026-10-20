package pcscf

import (
	"context"
	"sync"
)

// background runs work that must not hold up the request or response that
// starts it, a SUBSCRIBE or a call to msrp-relay, on goroutines it can wait
// for when the service stops.
type background struct {
	// ctx ends the work; once closed no other starts.
	ctx    context.Context
	mu     sync.Mutex
	wg     sync.WaitGroup
	closed bool
}

// goRun runs f on a goroutine of its own, unless close has been called:
// the sweep may still be running when the service stops.
func (b *background) goRun(f func(ctx context.Context)) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.wg.Add(1)
	b.mu.Unlock()
	go func() {
		defer b.wg.Done()
		f(b.ctx)
	}()
}

// wait waits for the work under way.
func (b *background) wait() { b.wg.Wait() }

// close starts no more work and waits for what is under way.
func (b *background) close() {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.wg.Wait()
}
