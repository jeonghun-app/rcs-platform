package registrar

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/milenage"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// counts records the registrar's metrics.
type counts struct {
	mu sync.Mutex
	m  map[string]int64
}

func (c *counts) Count(name string, n int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]int64{}
	}
	c.m[name] += n
}

func (c *counts) get(name string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[name]
}

func TestChallengesForOneIMPIAreLimitedAcrossInstances(t *testing.T) {
	e := newEnv(t)
	m := &counts{}
	limit := func(c *Config) { c.ChallengeLimit, c.ChallengeWindow, c.Metrics = 3, time.Minute, m }
	a, b := e.instance(1, limit), e.instance(2, limit)
	u := e.akaUser(impi1, impu1)
	e.clock.advance(15 * time.Second)
	for i, g := range []*Registrar{a, b, a} {
		if res := g.Register(bg, u.request(600, ""), upstream); res.StatusCode != 401 {
			t.Fatalf("REGISTER %d: %d %s, want a 401 within the limit", i+1, res.StatusCode, res.Reason)
		}
	}
	res := b.Register(bg, u.request(600, ""), upstream)
	wantStatus(t, res, 503)
	if got := res.Header.Get("Retry-After"); got != "45" {
		t.Errorf("Retry-After %q, want the 45 s left in the window", got)
	}
	if mars, _ := e.hss.counts(); mars != 3 {
		t.Errorf("%d MARs, want 3: a REGISTER over the limit must not reach the HSS", mars)
	}
	if got := m.get("registrar.challenge_limited"); got != 1 {
		t.Errorf("challenge_limited = %d", got)
	}
	// Another subscriber is not held back by this one's flood.
	other := e.akaUser(impi2, impu2)
	wantStatus(t, a.Register(bg, other.request(600, ""), upstream), 401)
	// The next window starts afresh.
	e.clock.advance(45 * time.Second)
	wantStatus(t, a.Register(bg, u.request(600, ""), upstream), 401)
	if strings.Contains(e.logs.String(), impi1) {
		t.Error("the log names the IMPI")
	}
}

func TestOnlyOneResynchronisationPerIMPIWithinAChallengeLifetime(t *testing.T) {
	e := newEnv(t)
	m := &counts{}
	a := e.instance(1, func(c *Config) { c.Metrics = m })
	b := e.instance(2, func(c *Config) { c.Metrics = m })
	u := e.akaUser(impi1, impu1)
	ms, _ := milenage.NewSQN(1000, 0)
	auts := func(ch digest.Challenge) []byte {
		rnd, _, _ := digest.ParseAKANonce(ch.Nonce)
		a := u.m.AUTS(rnd, ms)
		return a[:]
	}
	// Two challenges, from two instances, each answered with an AUTS: the
	// first resynchronises, the second does not reach the HSS.
	first := u.challengeOf(a.Register(bg, u.request(600, ""), upstream), 0)
	second := u.challengeOf(b.Register(bg, u.request(600, ""), upstream), 0)
	u.challengeOf(b.Register(bg, u.request(600, u.respond(first, auts(first))), upstream), 0)
	mars, _ := e.hss.counts()
	wantStatus(t, a.Register(bg, u.request(600, u.respond(second, auts(second))), upstream), 403)
	if n, _ := e.hss.counts(); n != mars {
		t.Error("a second resynchronisation in the lifetime reached the HSS")
	}
	if got := m.get("registrar.resync_limited"); got != 1 {
		t.Errorf("resync_limited = %d", got)
	}
	// After the lifetime a resynchronisation goes through again.
	e.clock.advance(DefaultChallengeLifetime)
	third := u.challengeOf(a.Register(bg, u.request(600, ""), upstream), 0)
	u.challengeOf(a.Register(bg, u.request(600, u.respond(third, auts(third))), upstream), 0)
}

func TestTheChallengeLimitDefaultsAreTheIssues(t *testing.T) {
	g := newEnv(t).instance(1)
	if g.cfg.ChallengeLimit != 10 || g.cfg.ChallengeWindow != time.Minute {
		t.Errorf("limit %d per %v, want 10 per minute (#201)", g.cfg.ChallengeLimit, g.cfg.ChallengeWindow)
	}
}
