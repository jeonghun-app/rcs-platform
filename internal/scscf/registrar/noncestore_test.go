package registrar

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// failingCounts is a nonce-count store that cannot be reached.
type failingCounts struct{}

func (failingCounts) Advance(context.Context, string, string, uint32, time.Time) (bool, error) {
	return false, errors.New("nonce count table throttled")
}

// withCounts gives g a digest server like its own over counts.
func withCounts(t *testing.T, g *Registrar, counts digest.NonceCountStore) {
	t.Helper()
	srv, err := digest.NewServer(digest.ServerConfig{
		Realm: g.cfg.Realm, NonceKey: g.cfg.NonceKey, NonceLifetime: g.cfg.ChallengeLifetime,
		NonceCounts: counts, Now: g.cfg.Now, Random: g.cfg.Rand,
	})
	if err != nil {
		t.Fatal(err)
	}
	g.digest = srv
}

func TestANonceCountStoreFailureIsAnInternalErrorNotAnAuthFailure(t *testing.T) {
	// #621: the registrar's store is in memory and cannot fail today, but
	// the mapping must not make a store failure a wrong response: that
	// would be 403 to a UE whose answer was right.
	for name, user := range map[string]func(*env) *ue{
		"digest": func(e *env) *ue { return e.digestUser(impi1, impu1) },
		"aka":    func(e *env) *ue { return e.akaUser(impi1, impu1) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			m := &counts{}
			g := e.instance(1, func(c *Config) { c.Metrics = m })
			withCounts(t, g, failingCounts{})
			u := user(e)
			wantStatus(t, u.registerWith(g, 600), 500)
			if got := m.get("registrar.internal_errors"); got != 1 {
				t.Errorf("internal_errors = %d, want 1", got)
			}
			if got := m.get("registrar.auth_failed"); got != 0 {
				t.Errorf("auth_failed = %d for a store failure", got)
			}
			if !strings.Contains(e.logs.String(), "recording the nonce count") {
				t.Errorf("log %q does not say what failed", e.logs.String())
			}
		})
	}
}

func TestAReplayedRegisterIsStillRefused(t *testing.T) {
	e := newEnv(t)
	m := &counts{}
	g := e.instance(1, func(c *Config) { c.Metrics = m })
	u := e.digestUser(impi1, impu1)
	res := g.Register(bg, u.request(600, ""), upstream)
	auth := u.answer(res, 0)
	wantStatus(t, g.Register(bg, u.request(600, auth), upstream), 200)
	// The challenge is taken on first use, so the same credentials again
	// meet no challenge: a fresh one, not a 500.
	wantStatus(t, g.Register(bg, u.request(600, auth), upstream), 401)
	if got := m.get("registrar.internal_errors"); got != 0 {
		t.Errorf("internal_errors = %d", got)
	}
}
