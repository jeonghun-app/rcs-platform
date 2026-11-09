package maap

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store/storetest"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
)

// counted counts the reads and recorded uses of a memory registry's
// credentials, and the reads of the registry.
// A read waits for hold to close, if set; a write records whether its
// context was live and bounded.
type counted struct {
	store.Credentials
	reads, uses atomic.Int64
	failUse     error
	hold        chan struct{}
	detached    atomic.Bool
}

func (c *counted) Credential(ctx context.Context, keyID string) (store.Credential, error) {
	c.reads.Add(1)
	if c.hold != nil {
		<-c.hold
	}
	return c.Credentials.Credential(ctx, keyID)
}

func (c *counted) Used(ctx context.Context, keyID string, at time.Time) error {
	c.uses.Add(1)
	_, bounded := ctx.Deadline()
	c.detached.Store(ctx.Err() == nil && bounded)
	if c.failUse != nil {
		return c.failUse
	}
	return c.Credentials.Used(ctx, keyID, at)
}

type countedRegistry struct {
	store.Registry
	reads atomic.Int64
}

func (r *countedRegistry) Chatbot(ctx context.Context, id string) (store.Chatbot, error) {
	r.reads.Add(1)
	return r.Registry.Chatbot(ctx, id)
}

type authFixture struct {
	m     *store.MemoryRegistry
	reg   *countedRegistry
	creds *counted
	a     *authenticator
	h     *runtimetest.Harness
	now   time.Time
}

func newAuthFixture(t *testing.T) *authFixture {
	f := &authFixture{m: store.NewMemoryRegistry(), h: runtimetest.New(t, "maap"), now: issuedAt}
	f.reg, f.creds = &countedRegistry{Registry: f.m}, &counted{Credentials: f.m.Credentials()}
	f.a = newAuthenticator(f.reg, f.creds, func() time.Time { return f.now }, f.h.Runtime.Logger)
	return f
}

// chatbot registers a chatbot and issues it a credential: its key ID and
// secret.
func (f *authFixture) chatbot(t *testing.T) (store.Chatbot, string, string) {
	t.Helper()
	c, err := f.m.Register(context.Background(), storetest.Chatbot())
	if err != nil {
		t.Fatal(err)
	}
	cred := storetest.Credential(c, f.now)
	secret := "secret-of-" + cred.KeyID
	cred.Digest = sha256.Sum256([]byte(secret))
	if err := f.m.Credentials().Issue(context.Background(), cred); err != nil {
		t.Fatal(err)
	}
	return c, cred.KeyID, secret
}

func TestAWrongSecretAnUnknownKeyAndARevokedOneFailAlike(t *testing.T) {
	f := newAuthFixture(t)
	ctx := context.Background()
	c, keyID, secret := f.chatbot(t)
	if got, err := f.a.authenticate(ctx, keyID, secret); err != nil || got.ID != c.ID {
		t.Fatalf("authenticate = %+v, %v", got, err)
	}
	_, other, _ := f.chatbot(t)
	unknown := storetest.Credential(c, f.now).KeyID
	for _, tc := range [][2]string{
		{keyID, secret + "x"}, {keyID, ""}, {other, secret}, {unknown, secret}, {strings.ToLower(keyID), secret}, {keyID + ".", secret}, {"", ""},
	} {
		if _, err := f.a.authenticate(ctx, tc[0], tc[1]); err != errUnauthenticated {
			t.Errorf("authenticate(%q, %q) = %v", tc[0], tc[1], err)
		}
	}
	if err := f.m.Credentials().Revoke(ctx, c.ID, keyID); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(cacheTTL)
	if _, err := f.a.authenticate(ctx, keyID, secret); err != errUnauthenticated {
		t.Fatalf("a revoked credential = %v", err)
	}
}

// What the registry says reaches the task within 30 s: a revocation, a
// suspension, a permission change, a deletion (#712 adds blocks here).
func TestChangesInTheRegistryTakeEffectWithin30s(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, f *authFixture, c store.Chatbot, keyID string)
		after  func(store.Chatbot, error) bool
	}{
		{"Revocation", func(t *testing.T, f *authFixture, c store.Chatbot, keyID string) {
			_ = f.m.Credentials().Revoke(ctx, c.ID, keyID)
		}, func(_ store.Chatbot, err error) bool { return err == errUnauthenticated }},
		{"Suspension", func(t *testing.T, f *authFixture, c store.Chatbot, _ string) {
			next := c
			next.State = store.Suspended
			if _, err := f.m.Update(ctx, c, next); err != nil {
				t.Fatal(err)
			}
		}, func(c store.Chatbot, err error) bool { return err == nil && c.State == store.Suspended }},
		{"PermissionChange", func(t *testing.T, f *authFixture, c store.Chatbot, _ string) {
			next := c
			next.Permissions = store.Permissions{}
			if _, err := f.m.Update(ctx, c, next); err != nil {
				t.Fatal(err)
			}
		}, func(c store.Chatbot, err error) bool { return err == nil && !c.Permissions.MSISDN }},
		{"Deletion", func(t *testing.T, f *authFixture, c store.Chatbot, _ string) {
			_ = f.m.DeleteChatbot(ctx, c.ID)
		}, func(_ store.Chatbot, err error) bool { return err == errUnauthenticated }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuthFixture(t)
			c, keyID, secret := f.chatbot(t)
			if _, err := f.a.authenticate(ctx, keyID, secret); err != nil {
				t.Fatal(err)
			}
			tc.change(t, f, c, keyID)
			// Within the 30 s the task answers what it read, and reads nothing.
			f.now = f.now.Add(cacheTTL - time.Nanosecond)
			if got, err := f.a.authenticate(ctx, keyID, secret); err != nil || got.State != store.Active || !got.Permissions.MSISDN {
				t.Fatalf("within the cache: %+v, %v", got, err)
			}
			if r, cr := f.reg.reads.Load(), f.creds.reads.Load(); r != 1 || cr != 1 {
				t.Fatalf("%d registry and %d credential reads", r, cr)
			}
			f.now = f.now.Add(time.Nanosecond)
			if got, err := f.a.authenticate(ctx, keyID, secret); !tc.after(got, err) {
				t.Fatalf("at 30 s: %+v, %v", got, err)
			}
		})
	}
}

func TestACredentialBehindATombstoneOrOfAnotherRegistrationFails(t *testing.T) {
	ctx := context.Background()
	f := newAuthFixture(t)
	c, keyID, secret := f.chatbot(t)
	// The registry answers the chatbot gone while the credential stays, as
	// after a deletion that stopped part way, or with another registration.
	for _, r := range []store.Registry{failingRegistry{fmt.Errorf("x: %w", store.ErrNotFound)}, staleRegistry{f.m, store.Chatbot{ID: c.ID, Registration: "another"}}} {
		cr := &countedRegistry{Registry: r}
		a := newAuthenticator(cr, f.creds, func() time.Time { return f.now }, f.h.Runtime.Logger)
		for range 2 {
			if _, err := a.authenticate(ctx, keyID, secret); err != errUnauthenticated {
				t.Errorf("over %T: %v", r, err)
			}
		}
		// A chatbot that is gone is cached 30 s too (#746 review).
		if n := cr.reads.Load(); n != 1 {
			t.Errorf("over %T: %d registry reads", r, n)
		}
	}
	// A store that fails is not a refusal, and is not cached.
	down := errors.New("awsstore: get chatbot: InternalServerError")
	a := newAuthenticator(failingRegistry{down}, f.creds, func() time.Time { return f.now }, f.h.Runtime.Logger)
	for range 2 {
		if _, err := a.authenticate(ctx, keyID, secret); !errors.Is(err, down) {
			t.Fatalf("over a failing registry: %v", err)
		}
	}
	if n := f.creds.uses.Load(); n != 0 {
		t.Fatalf("%d uses recorded without a success", n)
	}
}

func TestUnknownKeyIDsAreCached30sAndTheOldestGoFirstAtTheBound(t *testing.T) {
	ctx := context.Background()
	f := newAuthFixture(t)
	c, _, _ := f.chatbot(t)
	ids := make([]string, maxUnknownKeys+1)
	for i := range ids {
		ids[i] = storetest.Credential(c, f.now).KeyID
		if i < maxUnknownKeys {
			_, _ = f.a.authenticate(ctx, ids[i], "x")
		}
	}
	f.now = f.now.Add(time.Second)
	reads := func(id string) int64 {
		before := f.creds.reads.Load()
		if _, err := f.a.authenticate(ctx, id, "x"); err != errUnauthenticated {
			t.Fatal(err)
		}
		return f.creds.reads.Load() - before
	}
	if n := reads(ids[0]); n != 0 {
		t.Fatalf("a cached unknown key ID read the store %d times", n)
	}
	// One more forgets the oldest only.
	if n := reads(ids[maxUnknownKeys]); n != 1 || len(f.a.unknown) != maxUnknownKeys || len(f.a.unknownOrder) != maxUnknownKeys {
		t.Fatalf("%d reads; %d unknown, %d in order", n, len(f.a.unknown), len(f.a.unknownOrder))
	}
	if reads(ids[0]) != 1 || reads(ids[2]) != 0 {
		t.Fatal("the bound evicted other than the oldest")
	}
	// After 30 s each is read again, and the expired ones are dropped.
	f.now = f.now.Add(cacheTTL)
	if reads(ids[3]) != 1 || len(f.a.unknown) != 1 || len(f.a.unknownOrder) != 1 {
		t.Fatalf("%d unknown after they expired", len(f.a.unknown))
	}
}

// Concurrent lookups of one key ID that is not cached share one read and
// one place among the unknown (#746 review): one read per ID per 30 s.
func TestConcurrentLookupsOfAKeyIDShareOneRead(t *testing.T) {
	ctx := context.Background()
	f := newAuthFixture(t)
	c, keyID, secret := f.chatbot(t)
	unknown := storetest.Credential(c, f.now).KeyID
	for _, id := range []string{unknown, keyID} {
		f.creds.reads.Store(0)
		f.creds.hold = make(chan struct{})
		errs := make(chan error, 8)
		for range 8 {
			go func() { _, err := f.a.authenticate(ctx, id, secret); errs <- err }()
		}
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
			f.a.mu.Lock()
			r := f.a.reads[id]
			waiting := r != nil && r.waiters == 7
			f.a.mu.Unlock()
			if waiting {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the lookups never met on one read")
			}
		}
		close(f.creds.hold)
		for range 8 {
			if err := <-errs; (err == nil) != (id == keyID) {
				t.Fatalf("authenticate(%s) = %v", id, err)
			}
		}
		f.creds.hold = nil
		if _, _ = f.a.authenticate(ctx, id, secret); f.creds.reads.Load() != 1 {
			t.Fatalf("%d reads of %s within 30 s", f.creds.reads.Load(), id)
		}
	}
	if len(f.a.unknownOrder) != 1 || len(f.a.reads) != 0 {
		t.Fatalf("%d unknown, %d reads left", len(f.a.unknownOrder), len(f.a.reads))
	}
	f.now = f.now.Add(cacheTTL)
	if _, _ = f.a.authenticate(ctx, unknown, secret); f.creds.reads.Load() != 2 {
		t.Fatalf("%d reads after 30 s", f.creds.reads.Load())
	}
}

func TestTheLastUseIsRecordedAtMostHourlyPerTask(t *testing.T) {
	ctx := context.Background()
	f := newAuthFixture(t)
	_, keyID, secret := f.chatbot(t)
	for _, step := range []struct {
		after time.Duration
		uses  int64
	}{
		{0, 1}, {time.Second, 1}, {useInterval - time.Second - time.Nanosecond, 1}, {time.Nanosecond, 2},
		{useInterval - time.Nanosecond, 2}, {time.Nanosecond, 3},
	} {
		f.now = f.now.Add(step.after)
		if _, err := f.a.authenticate(ctx, keyID, secret); err != nil {
			t.Fatal(err)
		}
		f.a.writes.Wait()
		if n := f.creds.uses.Load(); n != step.uses {
			t.Fatalf("at %v: %d uses recorded, want %d", f.now.Sub(issuedAt), n, step.uses)
		}
	}
	if got, _ := f.m.Credentials().Credential(ctx, keyID); !got.LastUsed.Equal(store.Seconds(f.now)) {
		t.Fatalf("LastUsed = %v", got.LastUsed)
	}
	// The write is off the request's path, on a context of its own: a
	// request that ended does not end it.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	f.now = f.now.Add(useInterval)
	if _, err := f.a.authenticate(cancelled, keyID, secret); err != nil {
		t.Fatal(err)
	}
	if f.a.writes.Wait(); !f.creds.detached.Load() {
		t.Fatal("the write ran on the request's context, or without a timeout")
	}
	// A failed write waits for the next hour (#746 review), and the
	// warnings are one a minute, without the secret.
	_, other, otherSecret := f.chatbot(t)
	f.creds.failUse = errors.New("awsstore: record credential use: InternalServerError")
	f.now = f.now.Add(useInterval)
	for _, step := range []struct {
		after time.Duration
		uses  int64
		warns int
	}{{0, 6, 1}, {time.Second, 6, 1}, {useInterval - time.Second - time.Nanosecond, 6, 1}, {time.Nanosecond, 8, 2}} {
		f.now = f.now.Add(step.after)
		for range 3 {
			for _, k := range [][2]string{{keyID, secret}, {other, otherSecret}} {
				if _, err := f.a.authenticate(ctx, k[0], k[1]); err != nil {
					t.Fatal(err)
				}
			}
		}
		f.a.writes.Wait()
		if n, w := f.creds.uses.Load(), len(f.h.Logs("recording a credential's use failed")); n != step.uses || w != step.warns {
			t.Fatalf("at +%v: %d writes, %d warnings", step.after, n, w)
		}
	}
	if out := f.h.Output(); strings.Contains(out, secret) || !strings.Contains(out, `"not_logged_since":1`) {
		t.Fatalf("log:\n%s", out)
	}
}

// The caches of known items are bounded by the registry, and drop what
// expired once large, at most once per 30 s (#746 review), so revoked and
// deleted ones do not pile up and a large cache is not walked on every
// insert.
func TestLargeCachesDropWhatExpiredOncePer30s(t *testing.T) {
	ctx := context.Background()
	f := newAuthFixture(t)
	_, keyID, secret := f.chatbot(t)
	fill := func() {
		for i := range sweepAt {
			f.a.keys[fmt.Sprint("k", i)] = cached[store.Credential]{expires: f.now}
			f.a.chatbots[fmt.Sprint("c", i)] = cached[*store.Chatbot]{expires: f.now}
			f.a.used[fmt.Sprint("u", i)] = f.now.Add(-useInterval)
		}
	}
	sizes := func() [3]int { return [3]int{len(f.a.keys), len(f.a.chatbots), len(f.a.used)} }
	fill()
	if _, err := f.a.authenticate(ctx, keyID, secret); err != nil || sizes() != [3]int{1, 1, 1} {
		t.Fatalf("after the first sweep: %v, %v", sizes(), err)
	}
	// Within 30 s of it no insert sweeps, however large the caches.
	fill()
	f.now = f.now.Add(cacheTTL - time.Nanosecond)
	if _, err := f.a.authenticate(ctx, keyID, secret); err != nil || sizes() != [3]int{sweepAt + 1, sweepAt + 1, sweepAt + 1} {
		t.Fatalf("within 30 s: %v, %v", sizes(), err)
	}
	f.now = f.now.Add(time.Nanosecond)
	if _, err := f.a.authenticate(ctx, keyID, secret); err != nil || sizes() != [3]int{1, 1, 1} {
		t.Fatalf("at 30 s: %v, %v", sizes(), err)
	}
}
