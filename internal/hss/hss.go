package hss

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mathrand "math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/hss/keyring"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/milenage"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// Metrics is what the HSS records; *runtime.Metrics has it.
type Metrics interface {
	Count(name string, n int64)
	Timing(name string, d time.Duration)
}

type noMetrics struct{}

func (noMetrics) Count(string, int64)          {}
func (noMetrics) Timing(string, time.Duration) {}

// DefaultMaxAuthItems caps the AKA vectors one MAR gets, whatever it asks
// for: every vector advances SQN, and the S-CSCF uses one per challenge.
const DefaultMaxAuthItems = 4

// maxUpdateAttempts bounds the retries of the API's own read-modify-write
// loops, which lose a version race only to another task's write of the same
// item at the same moment.
const maxUpdateAttempts = 8

// maxRacedAttempts bounds updateFrom's retries, which the request's deadline
// normally stops first; every caller has one (Cx, the API's store timeout,
// the pushes). A write that lost to another task loses again about as often
// however long it waits, as long as that task keeps writing (#200: some 45%
// of retries under two tasks' MARs for one subscriber, on DynamoDB Local), so
// a small count gave up while the request still had time.
const maxRacedAttempts = 64

// errUnchanged, returned by an update function, skips the write.
var errUnchanged = errors.New("hss: nothing to write")

// errContention means an update kept losing version races, until its count
// or its deadline ran out; with the deadline, the error wraps ctx's too, so
// that it reads as contention and not as a slow store.
var errContention = errors.New("hss: subscription is being written by others; giving up")

// Options configures an HSS.
type Options struct {
	Store store.Store
	Keys  *keyring.Keyring
	// IMSRealm is the Digest realm of SIP Digest registration, normally the
	// home domain; FTRealm is ft-server's realm, empty when no FT
	// credentials are issued.
	IMSRealm string
	FTRealm  string
	// ServerNames are the S-CSCF names offered in Server-Capabilities.
	ServerNames []string
	// MaxAuthItems caps the AKA vectors per MAR; DefaultMaxAuthItems when 0.
	MaxAuthItems int
	// Rand is the source of RAND values and passwords: crypto/rand.Reader
	// outside tests.
	Rand    io.Reader
	Logger  *slog.Logger
	Metrics Metrics
}

// HSS is the subscriber logic shared by the Cx server and the provisioning
// API: reading subscriptions, writing them with optimistic retries, and
// sealing and opening their secrets.
type HSS struct {
	store       store.Store
	keys        *keyring.Keyring
	imsRealm    string
	ftRealm     string
	serverNames []string
	maxItems    int
	rand        io.Reader
	log         *slog.Logger
	metrics     Metrics
	// locks has a semaphore of one per subscription that a request holds
	// or waits for, so that a writer waits for its subscription only as
	// long as its context allows, and never for another's. An entry goes
	// when the last request lets go of it.
	locksMu sync.Mutex
	locks   map[string]*subscriptionLock
	// onLockWait, if set, runs when a request starts waiting for a lock
	// another holds, with the context the wait ends with: a test hook.
	onLockWait func(ctx context.Context)
}

// subscriptionLock is one subscription's lock and the requests that hold it
// or wait for it.
type subscriptionLock struct {
	sem  chan struct{}
	refs int
}

// errBusy means a subscription's lock in this task was not free before the
// request's deadline: another request for it is slow. It is local to this
// task, so Cx answers it with DIAMETER_TOO_BUSY and the client may try
// another HSS task.
var errBusy = errors.New("hss: subscription is busy in this task")

// New returns an HSS.
func New(o Options) (*HSS, error) {
	if o.Store == nil || o.Keys == nil || o.Rand == nil || o.IMSRealm == "" {
		return nil, errors.New("hss: Store, Keys, Rand and IMSRealm are required")
	}
	h := &HSS{
		store: o.Store, keys: o.Keys, imsRealm: o.IMSRealm, ftRealm: o.FTRealm,
		serverNames: o.ServerNames, maxItems: o.MaxAuthItems, rand: o.Rand,
		log: o.Logger, metrics: o.Metrics,
	}
	if h.maxItems <= 0 {
		h.maxItems = DefaultMaxAuthItems
	}
	if h.log == nil {
		h.log = slog.New(slog.DiscardHandler)
	}
	if h.metrics == nil {
		h.metrics = noMetrics{}
	}
	h.locks = map[string]*subscriptionLock{}
	return h, nil
}

// lock serialises writers of one subscription within the task, so that
// version conflicts, and the retries they cost, arise only between tasks.
// It gives up with errBusy when ctx ends first.
func (h *HSS) lock(ctx context.Context, impi string) (unlock func(), err error) {
	unlock, _, err = h.acquire(ctx, impi)
	return unlock, err
}

// acquire is lock, and reports whether the lock was held by another request
// when asked for.
func (h *HSS) acquire(ctx context.Context, impi string) (unlock func(), waited bool, err error) {
	h.locksMu.Lock()
	l := h.locks[impi]
	if l == nil {
		l = &subscriptionLock{sem: make(chan struct{}, 1)}
		h.locks[impi] = l
	}
	l.refs++
	h.locksMu.Unlock()
	done := func() {
		h.locksMu.Lock()
		if l.refs--; l.refs == 0 {
			delete(h.locks, impi)
		}
		h.locksMu.Unlock()
	}
	unlock = func() {
		<-l.sem
		done()
	}
	select {
	case l.sem <- struct{}{}: // free: taken whatever the context's state
		return unlock, false, nil
	default:
	}
	if h.onLockWait != nil {
		h.onLockWait(ctx)
	}
	select {
	case l.sem <- struct{}{}:
		return unlock, true, nil
	case <-ctx.Done():
		done()
		h.metrics.Count("lock.busy", 1)
		return nil, true, errBusy
	}
}

// update reads the subscription, applies fn to a copy and writes it back
// conditional on the version read, retrying from a fresh read when another
// writer got there first. fn runs again on every attempt, so it must decide
// from the subscription it is given only. When fn returns errUnchanged
// nothing is written and the subscription as read is returned.
func (h *HSS) update(ctx context.Context, impi string, fn func(s *store.Subscription) error) (*store.Subscription, error) {
	return h.updateFrom(ctx, impi, nil, fn)
}

// updateFrom is update with read, the subscription the caller has just read,
// as the first attempt's starting point, which saves a read on the Cx path.
// If read is stale the conditional write fails and the next attempt reads.
// A read taken before waiting for the lock is most likely stale, as the
// request that held it most likely wrote the subscription, so it is dropped:
// kept, it cost every queued request a failed write (#200).
//
// The lock is the subscription's own and is held through the retries, which
// run until ctx's deadline, at most maxRacedAttempts (see there): the
// subscription's other requests in this task wait, as they must for their
// writes, and no other subscription's do.
func (h *HSS) updateFrom(ctx context.Context, impi string, read *store.Subscription, fn func(s *store.Subscription) error) (*store.Subscription, error) {
	unlock, waited, err := h.acquire(ctx, impi)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if waited {
		read = nil
	}
	for attempt := 0; attempt < maxRacedAttempts; attempt++ {
		if attempt > 0 {
			h.metrics.Count("store.conflict", 1)
			// Jitter so that two tasks retrying the same write do not
			// collide again, at most 320 ms however many attempts.
			select {
			case <-time.After(time.Duration(mathrand.IntN(5<<min(attempt, 6))) * time.Millisecond):
			case <-ctx.Done():
				return nil, contended(ctx)
			}
		}
		saved, err := h.attempt(ctx, impi, read, fn)
		read = nil
		switch {
		case errors.Is(err, store.ErrConflict):
			continue
		case attempt > 0 && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)):
			// The deadline ended an attempt after a lost one: still
			// contention, though DynamoDB reported it as a context error.
			return nil, contended(ctx)
		}
		return saved, err
	}
	return nil, errContention
}

// attempt is one try of updateFrom: read, unless read is given, apply fn
// and write. It returns store.ErrConflict when another writer was first.
func (h *HSS) attempt(ctx context.Context, impi string, read *store.Subscription, fn func(s *store.Subscription) error) (*store.Subscription, error) {
	cur := read
	if cur == nil {
		var err error
		if cur, err = h.store.Subscription(ctx, impi); err != nil {
			return nil, err
		}
	}
	next := clone(cur)
	if err := fn(next); err != nil {
		if errors.Is(err, errUnchanged) {
			return cur, nil
		}
		return nil, err
	}
	return h.store.UpdateSubscription(ctx, cur, next)
}

// contended is the error of an update whose deadline ended while it was
// losing to other writers: contention, which the API answers "busy" and
// the store's health is not blamed for, as well as ctx's error.
func contended(ctx context.Context) error {
	return fmt.Errorf("%w: %w", errContention, ctx.Err())
}

// clone copies a subscription deeply enough that changing the copy leaves
// the original alone. Sealed values are never changed in place, so they are
// shared.
func clone(s *store.Subscription) *store.Subscription {
	c := *s
	c.PublicIdentities = append([]store.PublicIdentity(nil), s.PublicIdentities...)
	c.Digest = append([]store.DigestCredential(nil), s.Digest...)
	c.StaleSets = slices.Clone(s.StaleSets)
	if s.AKA != nil {
		a := *s.AKA
		c.AKA = &a
	}
	if s.Charging != nil {
		ch := *s.Charging
		c.Charging = &ch
	}
	return &c
}

// Additional data binding each sealed value to its subscription and field
// (internal/hss/keyring). The IMPI is length-prefixed so that no IMPI and
// field pair can be read as another.
func aad(field, impi string, extra ...string) []byte {
	b := fmt.Appendf(nil, "hss/1|%s|%d:%s", field, len(impi), impi)
	for _, e := range extra {
		b = fmt.Appendf(b, "|%d:%s", len(e), e)
	}
	return b
}

// sealAKA seals K and OPc for impi.
func (h *HSS) sealAKA(impi string, k, opc [milenage.KeySize]byte, amf [2]byte, sqn uint64) (*store.AKA, error) {
	sk, err := h.keys.Seal(k[:], aad("k", impi))
	if err != nil {
		return nil, err
	}
	so, err := h.keys.Seal(opc[:], aad("opc", impi))
	if err != nil {
		return nil, err
	}
	return &store.AKA{K: sk, OPc: so, AMF: amf, SQN: sqn}, nil
}

// milenage opens the subscription's K and OPc. The returned value holds them
// sealed in its own redacting type.
func (h *HSS) milenage(s *store.Subscription) (milenage.Milenage, error) {
	k, err := h.keys.Open(s.AKA.K, aad("k", s.IMPI))
	if err != nil {
		return milenage.Milenage{}, fmt.Errorf("hss: opening K: %w", err)
	}
	defer clear(k)
	opc, err := h.keys.Open(s.AKA.OPc, aad("opc", s.IMPI))
	if err != nil {
		return milenage.Milenage{}, fmt.Errorf("hss: opening OPc: %w", err)
	}
	defer clear(opc)
	if len(k) != milenage.KeySize || len(opc) != milenage.KeySize {
		return milenage.Milenage{}, errors.New("hss: stored K or OPc has the wrong size")
	}
	return milenage.New([milenage.KeySize]byte(k), [milenage.KeySize]byte(opc)), nil
}

// sealDigest computes and seals the MD5 and SHA-256 HA1 of password for
// impi in realm. The Digest user name is the IMPI (TS 24.229 §5.1.1.2.3,
// and ft-server's contract in docs/api/).
func (h *HSS) sealDigest(impi, realm string, password []byte) (store.DigestCredential, error) {
	d := store.DigestCredential{Realm: realm}
	for _, alg := range []digest.Algorithm{digest.MD5, digest.SHA256} {
		ha1, err := digest.ComputeHA1(alg, impi, realm, password)
		if err != nil {
			return store.DigestCredential{}, err
		}
		sealed, err := h.keys.Seal([]byte(ha1), aad("ha1", impi, realm, string(alg)))
		if err != nil {
			return store.DigestCredential{}, err
		}
		if alg == digest.MD5 {
			d.HA1MD5 = sealed
		} else {
			d.HA1SHA256 = sealed
		}
	}
	return d, nil
}

// openHA1 returns the hex HA1 of a stored credential for alg.
func (h *HSS) openHA1(impi string, d *store.DigestCredential, alg digest.Algorithm) (string, error) {
	sealed := d.HA1MD5
	if alg == digest.SHA256 {
		sealed = d.HA1SHA256
	}
	ha1, err := h.keys.Open(sealed, aad("ha1", impi, d.Realm, string(alg)))
	if err != nil {
		return "", fmt.Errorf("hss: opening HA1: %w", err)
	}
	return string(ha1), nil
}

// setDigest replaces or adds the credential of its realm.
func setDigest(s *store.Subscription, d store.DigestCredential) {
	if cur := s.DigestFor(d.Realm); cur != nil {
		*cur = d
		return
	}
	s.Digest = append(s.Digest, d)
}

// defaultIdentity is the default public identity of an implicit
// registration set, the first identity that is not barred (TS 29.228
// §6.5.1.1), or "" when every one is barred.
func defaultIdentity(s *store.Subscription, set int) string {
	for _, p := range s.PublicIdentities {
		if p.ImplicitSet == set && !p.Barred {
			return p.IMPU
		}
	}
	return ""
}

// members returns the identities of an implicit registration set, in
// provisioning order.
func members(s *store.Subscription, set int) []store.PublicIdentity {
	var out []store.PublicIdentity
	for _, p := range s.PublicIdentities {
		if p.ImplicitSet == set {
			out = append(out, p)
		}
	}
	return out
}

// setState puts every identity of an implicit registration set in state
// (TS 29.228 §6.5.1).
func setState(s *store.Subscription, set int, state store.RegistrationState) {
	for i := range s.PublicIdentities {
		if s.PublicIdentities[i].ImplicitSet == set {
			s.PublicIdentities[i].State = state
		}
	}
}

// served reports whether any identity of the subscription is registered or
// unregistered, that is, whether an S-CSCF holds its profile.
func served(s *store.Subscription) bool {
	for _, p := range s.PublicIdentities {
		if p.State.Served() {
			return true
		}
	}
	return false
}

// clearServerIfIdle drops the S-CSCF name once nothing needs it: no
// identity is served and no authentication is pending.
func clearServerIfIdle(s *store.Subscription) {
	if !served(s) && !s.AuthPending {
		s.ServerName = ""
	}
}
