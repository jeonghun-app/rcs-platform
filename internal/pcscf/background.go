package pcscf

import (
	"context"
	"sync"
)

// background runs work that must not hold up the request or response that
// starts it, a SUBSCRIBE or a call to msrp-relay, on goroutines it can wait
// for when the service stops.
//
// The work under way is counted under mu, not in a sync.WaitGroup: a test
// waits for it while a transport goroutine may start more, and a
// WaitGroup's Add must not race its Wait from zero (#248 code review).
type background struct {
	// ctx ends the work; once closed no other starts.
	ctx     context.Context
	mu      sync.Mutex
	idle    *sync.Cond
	running int
	closed  bool
}

// goRun runs f on a goroutine of its own, unless close has been called:
// the sweep may still be running when the service stops.
func (b *background) goRun(f func(ctx context.Context)) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.running++
	b.mu.Unlock()
	go func() {
		defer b.done()
		f(b.ctx)
	}()
}

func (b *background) done() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.running--; b.running == 0 && b.idle != nil {
		b.idle.Broadcast()
	}
}

// wait waits until no work is under way, the work started meanwhile
// included.
func (b *background) wait() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.waitLocked()
}

func (b *background) waitLocked() {
	if b.idle == nil {
		b.idle = sync.NewCond(&b.mu)
	}
	for b.running > 0 {
		b.idle.Wait()
	}
}

// close starts no more work and waits for what is under way.
func (b *background) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.waitLocked()
}
