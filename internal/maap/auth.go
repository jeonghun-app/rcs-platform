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
	// credential, a chatbot, or that a key ID is unknown: a revocation,
	// suspension or permission change reaches every task within it.
	cacheTTL = 30 * time.Second
	// maxUnknownKeys bounds the unknown key IDs a task remembers, which a
	// caller may draw at will; past it the oldest is forgotten.
	maxUnknownKeys = 10_000
	// useInterval is how often a task records a credential's last use.
	useInterval = time.Hour
	// sweepAt is the size of a cache of known items past which an insert
	// first drops what has expired.
	sweepAt = 10_000
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

	mu       sync.Mutex
	keys     map[string]cached[store.Credential]
	chatbots map[string]cached[store.Chatbot]
	unknown  map[string]time.Time // key ID → expiry
	// unknownOrder holds the unknown key IDs oldest first; as each has the
	// same lifetime, the expired ones are at its front.
	unknownOrder []unknownKey
	// used is when this task last recorded each credential's use.
	used map[string]time.Time
}

type cached[T any] struct {
	value   T
	expires time.Time
}

type unknownKey struct {
	id      string
	expires time.Time
}

func newAuthenticator(r store.Registry, c store.Credentials, now func() time.Time, log *slog.Logger) *authenticator {
	return &authenticator{
		registry: r, creds: c, now: now, log: log,
		keys: map[string]cached[store.Credential]{}, chatbots: map[string]cached[store.Chatbot]{},
		unknown: map[string]time.Time{}, used: map[string]time.Time{},
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
	case errors.Is(err, store.ErrNotFound):
		// Deleted, and the credential left behind its tombstone by a
		// deletion that stopped part way (#742 security review).
		return store.Chatbot{}, errUnauthenticated
	case err != nil:
		return store.Chatbot{}, err
	case c.Registration != cred.Registration:
		return store.Chatbot{}, errUnauthenticated
	}
	a.recordUse(ctx, keyID, now)
	return c, nil
}

// credential returns the credential with keyID, known false if there is
// none, from the cache or the store.
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
	a.mu.Unlock()
	cred, err := a.creds.Credential(ctx, keyID)
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case errors.Is(err, store.ErrNotFound):
		delete(a.keys, keyID)
		a.addUnknown(keyID, now)
		return store.Credential{}, false, nil
	case err != nil:
		return store.Credential{}, false, err
	}
	delete(a.unknown, keyID)
	put(a.keys, keyID, cred, now)
	return cred, true, nil
}

// chatbot returns the chatbot with id from the cache or the registry.
func (a *authenticator) chatbot(ctx context.Context, id string, now time.Time) (store.Chatbot, error) {
	a.mu.Lock()
	e, ok := a.chatbots[id]
	a.mu.Unlock()
	if ok && now.Before(e.expires) {
		return e.value, nil
	}
	c, err := a.registry.Chatbot(ctx, id)
	if err != nil {
		return store.Chatbot{}, err
	}
	a.mu.Lock()
	put(a.chatbots, id, c, now)
	a.mu.Unlock()
	return c, nil
}

// put caches v under k until cacheTTL from now, first dropping what has
// expired once the cache is large; the caller holds the lock.
func put[T any](m map[string]cached[T], k string, v T, now time.Time) {
	if len(m) >= sweepAt {
		for k, e := range m {
			if !now.Before(e.expires) {
				delete(m, k)
			}
		}
	}
	m[k] = cached[T]{v, now.Add(cacheTTL)}
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

// recordUse writes the credential's last use if this task has not in the
// last useInterval. A failure is logged and tried again at the next use.
func (a *authenticator) recordUse(ctx context.Context, keyID string, now time.Time) {
	a.mu.Lock()
	last, ok := a.used[keyID]
	if ok && now.Sub(last) < useInterval {
		a.mu.Unlock()
		return
	}
	if len(a.used) >= sweepAt {
		for k, t := range a.used {
			if now.Sub(t) >= useInterval {
				delete(a.used, k)
			}
		}
	}
	a.used[keyID] = now
	a.mu.Unlock()
	if err := a.creds.Used(ctx, keyID, now); err != nil {
		a.mu.Lock()
		if a.used[keyID].Equal(now) {
			if ok {
				a.used[keyID] = last
			} else {
				delete(a.used, keyID)
			}
		}
		a.mu.Unlock()
		a.log.Warn("recording a credential's use failed", slog.String("key_id", keyID), slog.String("error", err.Error()))
	}
}
