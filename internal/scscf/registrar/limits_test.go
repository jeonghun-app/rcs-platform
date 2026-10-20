package registrar

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/milenage"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// attacker is a client that knows only its victim's IMPI and IMPU, on a P-CSCF
// flow of its own: the P-CSCF writes the Path, so it cannot send over the
// victim's.
func attacker(t *testing.T, impi, impu string, n int) *ue {
	return &ue{t: t, impi: impi, impu: impu, callID: fmt.Sprintf("evil-%d", n),
		contact: fmt.Sprintf("sip:evil@198.51.100.%d:5060;transport=tcp", 1+n%250),
		path:    []string{fmt.Sprintf("<sip:evil-flow-%d@pcscf.%s;lr;ob>", n, realm)}}
}

// forgedAUTS answers ch with an empty password and made-up AUTS (RFC 3310
// §3.4), which needs no K.
func forgedAUTS(t *testing.T, a *ue, ch digest.Challenge) string {
	var auts [14]byte
	for i := range auts {
		auts[i] = byte(0xa0 + i)
	}
	c, err := digest.Respond(ch, digest.ClientParams{Username: a.impi, Method: "REGISTER", URI: "sip:" + realm, CNonce: "deadbeef", NC: 1, AUTS: auts[:]})
	if err != nil {
		t.Fatal(err)
	}
	return c.Header()
}

// roomForResyncs leaves the challenge budgets out of the way of a test of
// the resynchronisation budget: each resynchronisation takes two challenges.
func roomForResyncs(c *Config) { c.ChallengeLimit, c.FlowChallengeLimit = 100, 100 }

// resyncOf answers ch with the AUTS of u's USIM, whose SQN is ahead of the
// HSS's.
func resyncOf(u *ue, ch digest.Challenge) string {
	ms, _ := milenage.NewSQN(1000, 0)
	rnd, _, _ := digest.ParseAKANonce(ch.Nonce)
	auts := u.m.AUTS(rnd, ms)
	return u.respond(ch, auts[:])
}

func TestChallengesForOneIMPIAreLimitedAcrossInstances(t *testing.T) {
	e := newEnv(t)
	m := &counts{}
	limit := func(c *Config) { c.ChallengeLimit, c.ChallengeWindow, c.Metrics = 3, time.Minute, m }
	a, b := e.instance(1, limit), e.instance(2, limit)
	e.akaUser(impi1, impu1)
	e.clock.advance(14*time.Second + 500*time.Millisecond)
	for i, g := range []*Registrar{a, b, a} {
		if res := g.Register(bg, attacker(t, impi1, impu1, i).request(600, ""), upstream); res.StatusCode != 401 {
			t.Fatalf("REGISTER %d: %d %s, want a 401 within the limit", i+1, res.StatusCode, res.Reason)
		}
	}
	res := b.Register(bg, attacker(t, impi1, impu1, 3).request(600, ""), upstream)
	// 500, not 503 (RFC 3261 §21.5.4), with the seconds left, rounded up.
	wantStatus(t, res, 500)
	if got := res.Header.Get("Retry-After"); got != "46" {
		t.Errorf("Retry-After %q, want the 45.5 s left in the window, rounded up", got)
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
	e.clock.advance(46 * time.Second)
	wantStatus(t, a.Register(bg, attacker(t, impi1, impu1, 4).request(600, ""), upstream), 401)
	if strings.Contains(e.logs.String(), impi1) {
		t.Error("the log names the IMPI")
	}
}

// TestOneFlowHasASmallBudgetOfItsOwn: a flow past its budget is refused while
// the IMPI's shared budget still lets other flows through.
func TestOneFlowHasASmallBudgetOfItsOwn(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	e.akaUser(impi1, impu1)
	one := attacker(t, impi1, impu1, 1)
	for i := range DefaultFlowChallengeLimit {
		one.callID = fmt.Sprintf("one-%d", i)
		wantStatus(t, g.Register(bg, one.request(600, ""), upstream), 401)
	}
	wantStatus(t, g.Register(bg, one.request(600, ""), upstream), 500)
	wantStatus(t, g.Register(bg, attacker(t, impi1, impu1, 2).request(600, ""), upstream), 401)
}

// TestARegisteredUEReRegistersThroughAFloodOnOtherFlows: a flood of first
// registrations for the subscriber, ten a minute from other flows at the
// start of each window, uses up the IMPI's shared budget, but the registered
// UE's refreshes over its own flow count in its flow's budget only, so it
// stays registered (QA's and code review's lock-out on #223).
func TestARegisteredUEReRegistersThroughAFloodOnOtherFlows(t *testing.T) {
	e := newEnv(t)
	a, b := e.instance(1), e.instance(2)
	u := e.akaUser(impi1, impu1)
	wantStatus(t, u.registerWith(a, 600), 200)
	for w := range 30 {
		for i := range 10 {
			[]*Registrar{a, b}[i%2].Register(bg, attacker(t, impi1, impu1, w*10+i).request(600, ""), upstream)
		}
		e.clock.advance(time.Second)
		res := b.Register(bg, u.request(600, ""), upstream)
		wantStatus(t, res, 401)
		wantStatus(t, b.Register(bg, u.request(600, u.answer(res, 0)), upstream), 200)
		e.clock.advance(59 * time.Second)
	}
	if mars, _ := e.hss.counts(); mars > 30*(DefaultChallengeLimit+1)+1 {
		t.Errorf("%d MARs: the flood got past the shared budget", mars)
	}
}

// TestAFloodStillHoldsBackAFirstRegistration: the risk left (T12). A UE with
// no live binding has no flow of its own yet, so during a flood it waits for
// the window to end, told so by Retry-After.
func TestAFloodStillHoldsBackAFirstRegistration(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	for i := range DefaultChallengeLimit {
		g.Register(bg, attacker(t, impi1, impu1, i).request(600, ""), upstream)
	}
	res := g.Register(bg, u.request(600, ""), upstream)
	wantStatus(t, res, 500)
	if res.Header.Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
}

// TestRetryAfterIsFromTheCountsOwnClockReading: Now is read once for the
// count and Retry-After, so a count made in the window's last millisecond is
// told 1 s, not the next window's 60, whichever budget refuses it (QA's nit
// 7 on #223).
func TestRetryAfterIsFromTheCountsOwnClockReading(t *testing.T) {
	for name, flows := range map[string]bool{"shared": true, "one flow": false} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			var mu sync.Mutex
			now := t0.Add(30 * time.Second)
			step := false
			tick := func() time.Time {
				mu.Lock()
				defer mu.Unlock()
				if step {
					now = now.Add(time.Millisecond)
				}
				return now
			}
			g := e.instance(1, func(c *Config) { c.Now = tick })
			e.akaUser(impi1, impu1)
			from := func(i int) *ue {
				if flows {
					return attacker(t, impi1, impu1, i)
				}
				a := attacker(t, impi1, impu1, 0)
				a.callID = fmt.Sprintf("one-%d", i)
				return a
			}
			for i := range DefaultChallengeLimit {
				g.Register(bg, from(i).request(600, ""), upstream)
			}
			mu.Lock()
			step, now = true, t0.Add(time.Minute-3*time.Millisecond)
			mu.Unlock()
			res := g.Register(bg, from(99).request(600, ""), upstream)
			wantStatus(t, res, 500)
			if res.Header.Get("Retry-After") != "1" {
				t.Errorf("Retry-After %q for a count in the window's last milliseconds", res.Header.Get("Retry-After"))
			}
		})
	}
}

// TestAnExpiredBindingsFlowIsNoLongerTheRegisteredUEs: a binding that has
// expired, though not swept yet, gives its flow no budget of its own.
func TestAnExpiredBindingsFlowIsNoLongerTheRegisteredUEs(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	wantStatus(t, u.registerWith(g, 600), 200)
	e.clock.advance(601 * time.Second)
	for i := range DefaultChallengeLimit {
		g.Register(bg, attacker(t, impi1, impu1, i).request(600, ""), upstream)
	}
	wantStatus(t, g.Register(bg, u.request(600, ""), upstream), 500)
}

// countingStore counts CountAttempt calls, and fails them while failing is
// set.
type countingAttempts struct {
	state.Store
	mu      sync.Mutex
	calls   int
	failing bool
}

func (c *countingAttempts) CountAttempt(ctx context.Context, a state.Attempt, n int64, expires time.Time) (int64, error) {
	c.mu.Lock()
	c.calls++
	fail := c.failing
	c.mu.Unlock()
	if fail {
		return 0, errors.New("store: throttled")
	}
	return c.Store.CountAttempt(ctx, a, n, expires)
}

// TestAnInstanceRefusesOverTheLimitWithoutAWrite: once an instance has seen
// a count past its limit, it refuses the rest of the window from its note,
// so a flood costs the store nothing more (security's nit 5 on #223).
func TestAnInstanceRefusesOverTheLimitWithoutAWrite(t *testing.T) {
	e := newEnv(t)
	cs := &countingAttempts{Store: e.store}
	g := e.instance(1, func(c *Config) { c.Store = cs })
	e.akaUser(impi1, impu1)
	for i := range DefaultChallengeLimit + 1 {
		g.Register(bg, attacker(t, impi1, impu1, i).request(600, ""), upstream)
	}
	cs.mu.Lock()
	before := cs.calls
	cs.mu.Unlock()
	for i := range 20 {
		wantStatus(t, g.Register(bg, attacker(t, impi1, impu1, 100+i).request(600, ""), upstream), 500)
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	// Each new flow still counts once in its own budget, then the shared
	// one is refused from the note.
	if got := cs.calls - before; got != 20 {
		t.Errorf("%d counts for 20 REGISTERs over the shared limit, want one each, for their flows", got)
	}
}

// TestAStoreThatCannotCountIsLoggedNowAndThen: under a flood a throttled
// store fails every count; the log line is spaced, the counter is not.
func TestAStoreThatCannotCountIsLoggedNowAndThen(t *testing.T) {
	e := newEnv(t)
	m := &counts{}
	cs := &countingAttempts{Store: e.store, failing: true}
	g := e.instance(1, func(c *Config) { c.Store, c.Metrics = cs, m })
	e.akaUser(impi1, impu1)
	for i := range 5 {
		wantStatus(t, g.Register(bg, attacker(t, impi1, impu1, i).request(600, ""), upstream), 500)
	}
	if got := strings.Count(e.logs.String(), "counting an attempt"); got != 1 {
		t.Errorf("%d log lines for 5 failed counts, want 1", got)
	}
	if got := m.get("registrar.internal_errors"); got != 5 {
		t.Errorf("internal_errors = %d", got)
	}
	if mars, _ := e.hss.counts(); mars != 0 {
		t.Errorf("%d MARs without a count", mars)
	}
}

// TestAForgedAUTSLeavesTheUEItsResync: an AUTS needs no K, so a forged one
// takes one of the IMPI's resynchronisations, but not the last: the UE's
// genuine one still reaches the HSS (security's minor 3, QA's major 2).
func TestAForgedAUTSLeavesTheUEItsResync(t *testing.T) {
	e := newEnv(t)
	a, b := e.instance(1), e.instance(2)
	u := e.akaUser(impi1, impu1)
	ev := attacker(t, impi1, impu1, 1)
	ch := ev.challengeOf(a.Register(bg, ev.request(600, ""), upstream), 0)
	b.Register(bg, ev.request(600, forgedAUTS(t, ev, ch)), upstream)
	e.clock.advance(5 * time.Second)
	first := u.challengeOf(a.Register(bg, u.request(600, ""), upstream), 0)
	wantStatus(t, a.Register(bg, u.request(600, resyncOf(u, first)), upstream), 401)
}

// TestTheIMPIHasThreeResyncsAChallengeLifetime: across challenges, the
// fourth resynchronisation in a lifetime is refused without a MAR, still a
// minute later, and goes through after the lifetime (QA's M2 on #223).
func TestTheIMPIHasThreeResyncsAChallengeLifetime(t *testing.T) {
	e := newEnv(t)
	m := &counts{}
	g := e.instance(1, roomForResyncs, func(c *Config) { c.Metrics = m })
	u := e.akaUser(impi1, impu1)
	resync := func() int {
		ch := u.challengeOf(g.Register(bg, u.request(600, ""), upstream), 0)
		return g.Register(bg, u.request(600, resyncOf(u, ch)), upstream).StatusCode
	}
	for i := range DefaultResyncLimit {
		if code := resync(); code != 401 {
			t.Fatalf("resynchronisation %d: %d", i+1, code)
		}
		e.clock.advance(10 * time.Second)
	}
	mars, _ := e.hss.counts()
	if code := resync(); code != 403 {
		t.Fatalf("the fourth resynchronisation: %d", code)
	}
	if n, _ := e.hss.counts(); n != mars+1 {
		t.Errorf("%d MARs for a refused resynchronisation's REGISTERs, want only its challenge's", n-mars)
	}
	e.clock.advance(61 * time.Second)
	if code := resync(); code != 403 {
		t.Errorf("a minute later: %d, want the lifetime's budget still used", code)
	}
	if m.get("registrar.resync_limited") != 2 {
		t.Errorf("resync_limited = %d", m.get("registrar.resync_limited"))
	}
	e.clock.advance(DefaultChallengeLifetime)
	if code := resync(); code != 401 {
		t.Errorf("in the next lifetime: %d", code)
	}
}

// TestTheRegisteredUEsResyncsAreItsOwn: resynchronisations over the
// registered UE's flow do not share the IMPI's budget, which others can use
// up.
func TestTheRegisteredUEsResyncsAreItsOwn(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1, roomForResyncs)
	u := e.akaUser(impi1, impu1)
	wantStatus(t, u.registerWith(g, 600), 200)
	for i := range DefaultResyncLimit {
		ev := attacker(t, impi1, impu1, i)
		ch := ev.challengeOf(g.Register(bg, ev.request(600, ""), upstream), 0)
		g.Register(bg, ev.request(600, forgedAUTS(t, ev, ch)), upstream)
	}
	ch := u.challengeOf(g.Register(bg, u.request(600, ""), upstream), 0)
	wantStatus(t, g.Register(bg, u.request(600, resyncOf(u, ch)), upstream), 401)
}

// TestAResyncCountsAsAChallengeFirst: a resynchronisation is a MAR, so it
// counts in the challenge budget before its own, and over it is refused
// without a MAR and without using a resync slot (QA's M5, code review's
// minor 3 on #223).
func TestAResyncCountsAsAChallengeFirst(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1, func(c *Config) { c.FlowChallengeLimit = 100 })
	u := e.akaUser(impi1, impu1)
	first := u.challengeOf(g.Register(bg, u.request(600, ""), upstream), 0)
	for i := range DefaultChallengeLimit - 1 {
		g.Register(bg, attacker(t, impi1, impu1, i).request(600, ""), upstream)
	}
	mars, _ := e.hss.counts()
	wantStatus(t, g.Register(bg, u.request(600, resyncOf(u, first)), upstream), 500)
	if n, _ := e.hss.counts(); n != mars {
		t.Error("a resynchronisation over the challenge limit reached the HSS")
	}
	// The flood's window over, the slot is still there: all three are.
	e.clock.advance(time.Minute)
	for i := range DefaultResyncLimit {
		ch := u.challengeOf(g.Register(bg, u.request(600, ""), upstream), 0)
		if code := g.Register(bg, u.request(600, resyncOf(u, ch)), upstream).StatusCode; code != 401 {
			t.Fatalf("resynchronisation %d after the flood: %d", i+1, code)
		}
	}
}

// TestAResyncTheHSSDidNotTakeKeepsItsSlot: a resynchronisation whose MAR
// fails gives its slot back (QA's major 2 on #223).
func TestAResyncTheHSSDidNotTakeKeepsItsSlot(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1, roomForResyncs)
	u := e.akaUser(impi1, impu1)
	for range DefaultResyncLimit {
		ch := u.challengeOf(g.Register(bg, u.request(600, ""), upstream), 0)
		e.hss.mu.Lock()
		e.hss.unavailable = true
		e.hss.mu.Unlock()
		wantStatus(t, g.Register(bg, u.request(600, resyncOf(u, ch)), upstream), 480)
		e.hss.mu.Lock()
		e.hss.unavailable = false
		e.hss.mu.Unlock()
	}
	ch := u.challengeOf(g.Register(bg, u.request(600, ""), upstream), 0)
	wantStatus(t, g.Register(bg, u.request(600, resyncOf(u, ch)), upstream), 401)
}

func TestTheChallengeLimitDefaultsAreTheIssues(t *testing.T) {
	g := newEnv(t).instance(1)
	if g.cfg.ChallengeLimit != 10 || g.cfg.ChallengeWindow != time.Minute {
		t.Errorf("limit %d per %v, want 10 per minute (#201)", g.cfg.ChallengeLimit, g.cfg.ChallengeWindow)
	}
	if g.cfg.FlowChallengeLimit != 3 || g.cfg.RegisteredFlowChallengeLimit != 6 || g.cfg.ResyncLimit != 3 {
		t.Errorf("flow %d, registered flow %d, resyncs %d", g.cfg.FlowChallengeLimit, g.cfg.RegisteredFlowChallengeLimit, g.cfg.ResyncLimit)
	}
}

// TestAConcurrentFloodGetsTheSharedBudgetExactly: 400 REGISTERs at once over
// two instances reach the HSS exactly ChallengeLimit times (QA's probe on
// #223; the integration test runs it on DynamoDB).
func TestAConcurrentFloodGetsTheSharedBudgetExactly(t *testing.T) {
	e := newEnv(t)
	gs := []*Registrar{e.instance(1), e.instance(2)}
	e.akaUser(impi1, impu1)
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	start := make(chan struct{})
	for i := range 400 {
		req := attacker(t, impi1, impu1, i).request(600, "")
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			res := gs[i%2].Register(bg, req, upstream)
			mu.Lock()
			codes[res.StatusCode]++
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()
	if mars, _ := e.hss.counts(); mars != DefaultChallengeLimit || codes[401] != DefaultChallengeLimit || codes[500] != 400-DefaultChallengeLimit {
		t.Errorf("%d MARs, codes %v", mars, codes)
	}
}

// TestAWindowsEdgeLetsTwiceTheBudgetThrough: the windows are fixed, so at
// most twice a budget passes across an edge, and no more (documented in
// T12; QA's probe on #223).
func TestAWindowsEdgeLetsTwiceTheBudgetThrough(t *testing.T) {
	e := newEnv(t)
	gs := []*Registrar{e.instance(1), e.instance(2)}
	e.akaUser(impi1, impu1)
	e.clock.advance(time.Minute - time.Millisecond)
	ok := 0
	for i := range 3 * DefaultChallengeLimit {
		if i == DefaultChallengeLimit {
			e.clock.advance(time.Millisecond)
		}
		if gs[i%2].Register(bg, attacker(t, impi1, impu1, i).request(600, ""), upstream).StatusCode == 401 {
			ok++
		}
	}
	if ok != 2*DefaultChallengeLimit {
		t.Errorf("%d challenges across the edge, want twice the budget", ok)
	}
}
