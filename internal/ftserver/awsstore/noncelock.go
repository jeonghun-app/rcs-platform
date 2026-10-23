package awsstore

import (
	"context"
	"sync"
)

// maxNonceLocks bounds the (user, nonce) keys nonceLocks holds at once. Only
// keys with an Advance in progress are held, so this is far above what a
// task's request limits let through; past it, an Advance goes unserialised,
// which the conditional write still keeps correct.
const maxNonceLocks = 4096

// nonceLocks lets one Advance at a time work on each (user, nonce) in this
// task. Requests in flight on one nonce would otherwise race each other's
// conditional writes, and every lost race costs another read and write
// (security review on #610). A key's entry goes when its last user leaves.
// The zero value is ready to use.
type nonceLocks struct {
	mu   sync.Mutex
	held map[string]*nonceLock
}

type nonceLock struct {
	token chan struct{} // holds one value while the key is locked
	users int           // holding or waiting
}

// lock waits until the caller holds key, or ctx ends. waited reports that
// another Advance held it first. unlock must be called once lock returns
// without an error.
func (l *nonceLocks) lock(ctx context.Context, key string) (unlock func(), waited bool, err error) {
	l.mu.Lock()
	e := l.held[key]
	if e == nil {
		if len(l.held) >= maxNonceLocks {
			l.mu.Unlock()
			return func() {}, false, nil
		}
		if l.held == nil {
			l.held = map[string]*nonceLock{}
		}
		e = &nonceLock{token: make(chan struct{}, 1)}
		l.held[key] = e
	}
	e.users++
	l.mu.Unlock()
	leave := func() {
		l.mu.Lock()
		if e.users--; e.users == 0 {
			delete(l.held, key)
		}
		l.mu.Unlock()
	}
	select {
	case e.token <- struct{}{}:
	default:
		waited = true
		select {
		case e.token <- struct{}{}:
		case <-ctx.Done():
			leave()
			return nil, true, ctx.Err()
		}
	}
	return func() { <-e.token; leave() }, waited, nil
}

// len is the number of keys held, for tests.
func (l *nonceLocks) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.held)
}
