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
type counted struct {
	store.Credentials
	reads, uses atomic.Int64
	failUse     error
}

func (c *counted) Credential(ctx context.Context, keyID string) (store.Credential, error) {
	c.reads.Add(1)
	return c.Credentials.Credential(ctx, keyID)
}

func (c *counted) Used(ctx context.Context, keyID string, at time.Time) error {
	c.uses.Add(1)
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
		a := newAuthenticator(r, f.creds, func() time.Time { return f.now }, f.h.Runtime.Logger)
		if _, err := a.authenticate(ctx, keyID, secret); err != errUnauthenticated {
			t.Errorf("over %T: %v", r, err)
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
		if n := f.creds.uses.Load(); n != step.uses {
			t.Fatalf("at %v: %d uses recorded, want %d", f.now.Sub(issuedAt), n, step.uses)
		}
	}
	if got, _ := f.m.Credentials().Credential(ctx, keyID); !got.LastUsed.Equal(store.Seconds(f.now)) {
		t.Fatalf("LastUsed = %v", got.LastUsed)
	}
	// A failed write is tried again at the next use, and logs no secret.
	f.creds.failUse = errors.New("awsstore: record credential use: InternalServerError")
	f.now = f.now.Add(useInterval)
	for want := int64(4); want <= 5; want++ {
		if _, err := f.a.authenticate(ctx, keyID, secret); err != nil || f.creds.uses.Load() != want {
			t.Fatalf("%d uses, %v", f.creds.uses.Load(), err)
		}
	}
	if out := f.h.Output(); !strings.Contains(out, "recording a credential's use failed") || strings.Contains(out, secret) {
		t.Fatalf("log:\n%s", out)
	}
}

// The caches of known items are bounded by the registry, and drop what
// expired once large, so revoked and deleted ones do not pile up.
func TestLargeCachesDropWhatExpired(t *testing.T) {
	m := map[string]cached[int]{}
	for i := range sweepAt {
		put(m, fmt.Sprint(i), i, issuedAt)
	}
	put(m, "fresh", 0, issuedAt.Add(cacheTTL-time.Nanosecond))
	if len(m) != sweepAt+1 {
		t.Fatalf("%d cached before any expired", len(m))
	}
	put(m, "late", 0, issuedAt.Add(cacheTTL))
	if _, ok := m["fresh"]; len(m) != 2 || !ok {
		t.Fatalf("%d cached after the sweep", len(m))
	}
	f := newAuthFixture(t)
	_, keyID, secret := f.chatbot(t)
	for i := range sweepAt {
		f.a.used[fmt.Sprint(i)] = issuedAt.Add(-useInterval)
	}
	f.a.used["recent"] = issuedAt.Add(-time.Minute)
	if _, err := f.a.authenticate(context.Background(), keyID, secret); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.a.used["recent"]; len(f.a.used) != 2 || !ok {
		t.Fatalf("%d uses remembered after the sweep", len(f.a.used))
	}
}
