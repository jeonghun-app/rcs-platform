package maap

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
)

// Bounds of the authenticator's caches (ADR 0009 §7).
const (
	// cacheTTL is how long a task keeps what it read of the registry, a
	// credential, a chatbot or that there is none, or that a key ID is
	// unknown: a revocation, suspension or permission change reaches every
	// task within it.
	cacheTTL = 30 * time.Second
	// maxUnknownKeys bounds the unknown key IDs a task remembers, which a
	// caller may draw at will; past it the oldest is forgotten.
	maxUnknownKeys = 10_000
	// useInterval is how often a task records a credential's last use, and
	// how long it waits after a write that failed.
	useInterval = time.Hour
	// sweepAt is the size of a cache of known items past which the caches
	// drop what has expired, at most once per cacheTTL (#746 review: not on
	// every insert, under the lock every lookup takes).
	sweepAt = 10_000
	// readTimeout bounds a credential read that several lookups share, and
	// writeTimeout a last-use write; neither ends with the request that
	// started it.
	readTimeout  = 5 * time.Second
	writeTimeout = 5 * time.Second
	// warnEvery bounds the warnings of failed last-use writes.
	warnEvery = time.Minute
)

// errUnauthenticated is the one answer to a credential that does not
// authenticate a chatbot: an unknown, revoked or malformed key ID, a wrong
// secret, a deleted chatbot. #683 answers it 401, the same for each.
var errUnauthenticated = errors.New("maap: the credential is not accepted")

// authenticator finds the chatbot a credential belongs to, for #683's
// public listener. It reads the registry through caches of at most
// cacheTTL, so every request does not cost a read and every change still
// takes effect within it.
type authenticator struct {
	registry store.Registry
	creds    store.Credentials
	now      func() time.Time
	log      *slog.Logger

	mu   sync.Mutex
	keys map[string]cached[store.Credential]
	// chatbots holds a nil value for a chatbot that is gone, so that a
	// credential a deletion left behind its tombstone costs one read per
	// cacheTTL too.
	chatbots map[string]cached[*store.Chatbot]
	unknown  map[string]time.Time // key ID → expiry
	// unknownOrder holds the unknown key IDs oldest first; as each has the
	// same lifetime, the expired ones are at its front.
	unknownOrder []unknownKey
	// reads are the credential reads in progress, by key ID: concurrent
	// misses of one key ID share one read and one place among the unknown.
	reads map[string]*read
	// used is when this task last wrote, or tried to write, each
	// credential's use.
	used  map[string]time.Time
	swept time.Time
	// warned is when a failed write was last logged; quiet counts the
	// failures since that were not.
	warned time.Time
	quiet  int
	// writes are the last-use writes in progress, which #683 waits for at
	// shutdown.
	writes sync.WaitGroup
}

type cached[T any] struct {
	value   T
	expires time.Time
}

type unknownKey struct {
	id      string
	expires time.Time
}

type read struct {
	done    chan struct{}
	cred    store.Credential
	known   bool
	err     error
	waiters int // for tests
}

func newAuthenticator(r store.Registry, c store.Credentials, now func() time.Time, log *slog.Logger) *authenticator {
	return &authenticator{
		registry: r, creds: c, now: now, log: log,
		keys: map[string]cached[store.Credential]{}, chatbots: map[string]cached[*store.Chatbot]{},
		unknown: map[string]time.Time{}, reads: map[string]*read{}, used: map[string]time.Time{},
	}
}

// authenticate returns the chatbot whose credential keyID and secret are,
// as of at most cacheTTL ago, whatever its state: the caller answers a
// suspended one. errUnauthenticated if they are not one; any other error
// is the store failing.
func (a *authenticator) authenticate(ctx context.Context, keyID, secret string) (store.Chatbot, error) {
	if !store.ValidKeyID(keyID) {
		return store.Chatbot{}, errUnauthenticated
	}
	now := a.now()
	cred, known, err := a.credential(ctx, keyID, now)
	if err != nil {
		return store.Chatbot{}, err
	}
	// An unknown key ID is compared too, with a digest no secret has, so
	// that it takes the time a wrong secret does.
	presented := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(presented[:], cred.Digest[:]) != 1 || !known {
		return store.Chatbot{}, errUnauthenticated
	}
	c, err := a.chatbot(ctx, cred.Chatbot, now)
	switch {
	case err != nil:
		return store.Chatbot{}, err
	case c == nil, c.Registration != cred.Registration:
		// Deleted, and the credential left behind its tombstone by a
		// deletion that stopped part way (#742 security review), or of
		// another registration.
		return store.Chatbot{}, errUnauthenticated
	}
	a.recordUse(ctx, keyID, now)
	return *c, nil
}

// credential returns the credential with keyID, known false if there is
// none, from the cache or from a read it may share with other lookups.
func (a *authenticator) credential(ctx context.Context, keyID string, now time.Time) (store.Credential, bool, error) {
	a.mu.Lock()
	if e, ok := a.keys[keyID]; ok && now.Before(e.expires) {
		a.mu.Unlock()
		return e.value, true, nil
	}
	if exp, ok := a.unknown[keyID]; ok && now.Before(exp) {
		a.mu.Unlock()
		return store.Credential{}, false, nil
	}
	if r, ok := a.reads[keyID]; ok {
		r.waiters++
		a.mu.Unlock()
		select {
		case <-r.done:
			return r.cred, r.known, r.err
		case <-ctx.Done():
			return store.Credential{}, false, ctx.Err()
		}
	}
	r := &read{done: make(chan struct{})}
	a.reads[keyID] = r
	a.mu.Unlock()
	defer close(r.done)
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), readTimeout)
	defer cancel()
	cred, err := a.creds.Credential(rctx, keyID)
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.reads, keyID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		delete(a.keys, keyID)
		a.addUnknown(keyID, now)
	case err != nil:
		r.err = err
	default:
		delete(a.unknown, keyID)
		a.sweep(now)
		a.keys[keyID] = cached[store.Credential]{cred, now.Add(cacheTTL)}
		r.cred, r.known = cred, true
	}
	return r.cred, r.known, r.err
}

// chatbot returns the chatbot with id, nil if it is gone, from the cache
// or the registry.
func (a *authenticator) chatbot(ctx context.Context, id string, now time.Time) (*store.Chatbot, error) {
	a.mu.Lock()
	e, ok := a.chatbots[id]
	a.mu.Unlock()
	if ok && now.Before(e.expires) {
		return e.value, nil
	}
	c, err := a.registry.Chatbot(ctx, id)
	var found *store.Chatbot
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return nil, err
	default:
		found = &c
	}
	a.mu.Lock()
	a.sweep(now)
	a.chatbots[id] = cached[*store.Chatbot]{found, now.Add(cacheTTL)}
	a.mu.Unlock()
	return found, nil
}

// sweep drops what has expired from the caches of known items once one
// is large, at most once per cacheTTL; the caller holds the lock.
func (a *authenticator) sweep(now time.Time) {
	if now.Sub(a.swept) < cacheTTL || max(len(a.keys), len(a.chatbots), len(a.used)) < sweepAt {
		return
	}
	a.swept = now
	for k, e := range a.keys {
		if !now.Before(e.expires) {
			delete(a.keys, k)
		}
	}
	for k, e := range a.chatbots {
		if !now.Before(e.expires) {
			delete(a.chatbots, k)
		}
	}
	for k, t := range a.used {
		if now.Sub(t) >= useInterval {
			delete(a.used, k)
		}
	}
}

// addUnknown remembers keyID as unknown, dropping the expired and, at
// maxUnknownKeys, the oldest; the caller holds the lock.
func (a *authenticator) addUnknown(keyID string, now time.Time) {
	drop := func() {
		k := a.unknownOrder[0]
		a.unknownOrder = a.unknownOrder[1:]
		if a.unknown[k.id].Equal(k.expires) {
			delete(a.unknown, k.id)
		}
	}
	for len(a.unknownOrder) > 0 && !now.Before(a.unknownOrder[0].expires) {
		drop()
	}
	for len(a.unknownOrder) >= maxUnknownKeys {
		drop()
	}
	exp := now.Add(cacheTTL)
	a.unknown[keyID] = exp
	a.unknownOrder = append(a.unknownOrder, unknownKey{keyID, exp})
}

// recordUse writes the credential's last use, off the request's path, if
// this task has not written or tried to in the last useInterval: a write
// that failed waits for the next hour, so a table that throttles gets no
// more writes for it.
func (a *authenticator) recordUse(ctx context.Context, keyID string, now time.Time) {
	a.mu.Lock()
	if last, ok := a.used[keyID]; ok && now.Sub(last) < useInterval {
		a.mu.Unlock()
		return
	}
	a.sweep(now)
	a.used[keyID] = now
	a.mu.Unlock()
	a.writes.Add(1)
	go func() {
		defer a.writes.Done()
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
		defer cancel()
		if err := a.creds.Used(wctx, keyID, now); err != nil {
			a.warn(now, keyID, err)
		}
	}()
}

// warn logs a failed last-use write, at most once per warnEvery, with how
// many it left out since the last line.
func (a *authenticator) warn(now time.Time, keyID string, err error) {
	a.mu.Lock()
	if !a.warned.IsZero() && now.Sub(a.warned) < warnEvery {
		a.quiet++
		a.mu.Unlock()
		return
	}
	quiet := a.quiet
	a.warned, a.quiet = now, 0
	a.mu.Unlock()
	a.log.Warn("recording a credential's use failed",
		slog.String("key_id", keyID), slog.String("error", err.Error()), slog.Int("not_logged_since", quiet))
}
