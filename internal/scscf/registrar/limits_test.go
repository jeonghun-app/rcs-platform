package registrar

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
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

// TestAResyncAfterAnHSSFailureFitsTheFlowsBudget: with the production
// limits, a UE whose SQN is out of step gets its challenge, sends its AUTS
// while the HSS is out of reach, and tries again; the failed MAR gave its
// challenge back, so the retry fits the flow's three (QA's minor 2 on #223).
func TestAResyncAfterAnHSSFailureFitsTheFlowsBudget(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	first := u.challengeOf(g.Register(bg, u.request(600, ""), upstream), 0)
	e.hss.mu.Lock()
	e.hss.unavailable = true
	e.hss.mu.Unlock()
	wantStatus(t, g.Register(bg, u.request(600, resyncOf(u, first)), upstream), 480)
	e.hss.mu.Lock()
	e.hss.unavailable = false
	e.hss.mu.Unlock()
	e.clock.advance(30 * time.Second)
	second := u.challengeOf(g.Register(bg, u.request(600, ""), upstream), 0)
	wantStatus(t, g.Register(bg, u.request(600, resyncOf(u, second)), upstream), 401)
}

// gatedHSS holds resynchronisation MARs until gate closes, and then fails
// them if fail is set.
type gatedHSS struct {
	*fakeHSS
	gate    chan struct{}
	entered chan struct{}
	fail    bool
}

func (g *gatedHSS) MAR(ctx context.Context, r *cx.MAR) (*cx.MAA, error) {
	if len(r.AuthDataItem.Authorization) > 0 {
		g.entered <- struct{}{}
		<-g.gate
		if g.fail {
			return nil, errUnreachable
		}
	}
	return g.fakeHSS.MAR(ctx, r)
}

// TestASlotGivenBackClearsTheInstancesNote: three AUTSs wait on the HSS, a
// fourth is refused and noted over the limit; the three fail and give their
// slots back. The instance that noted the fourth then agrees with the one
// that did not (QA's minor 3 on #223).
func TestASlotGivenBackClearsTheInstancesNote(t *testing.T) {
	e := newEnv(t)
	hss := &gatedHSS{fakeHSS: e.hss, gate: make(chan struct{}), entered: make(chan struct{}, 8)}
	a := e.instance(1, roomForResyncs, func(c *Config) { c.HSS = hss })
	b := e.instance(2, roomForResyncs)
	u := e.akaUser(impi1, impu1)
	var wg sync.WaitGroup
	for i := range DefaultResyncLimit {
		ev := attacker(t, impi1, impu1, 700+i)
		ch := ev.challengeOf(b.Register(bg, ev.request(600, ""), upstream), 0)
		req := ev.request(600, forgedAUTS(t, ev, ch))
		wg.Add(1)
		go func() { defer wg.Done(); a.Register(bg, req, upstream) }()
		<-hss.entered
	}
	ch := u.challengeOf(b.Register(bg, u.request(600, ""), upstream), 0)
	wantStatus(t, a.Register(bg, u.request(600, resyncOf(u, ch)), upstream), 403)
	hss.fail = true
	close(hss.gate)
	wg.Wait()
	hss.fail = false
	e.clock.advance(10 * time.Second)
	ch = u.challengeOf(b.Register(bg, u.request(600, ""), upstream), 0)
	wantStatus(t, a.Register(bg, u.request(600, resyncOf(u, ch)), upstream), 401)
}

// TestTheBudgetFollowsTheTopmostPathEntry: the P-CSCF's Path entry is the
// topmost (RFC 3327 §5.3); flows that share a lower entry are still apart,
// and the registered UE keeps its own budget (QA's nit on #223).
func TestTheBudgetFollowsTheTopmostPathEntry(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	below := "<sip:edge@proxy." + realm + ";lr>"
	u.path = []string{"<sip:ue-flow@pcscf." + realm + ";lr;ob>", below}
	wantStatus(t, u.registerWith(g, 600), 200)
	for i := range 3 * DefaultChallengeLimit {
		ev := attacker(t, impi1, impu1, i)
		ev.path = append(ev.path, below)
		g.Register(bg, ev.request(600, ""), upstream)
	}
	res := g.Register(bg, u.request(600, ""), upstream)
	wantStatus(t, res, 401)
}

// TestAChallengeTheHSSDidNotAnswerGivesItsCountsBack: an HSS out of reach
// does not use up a flow's budget, nor the IMPI's.
func TestAChallengeTheHSSDidNotAnswerGivesItsCountsBack(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := e.akaUser(impi1, impu1)
	e.hss.mu.Lock()
	e.hss.unavailable = true
	e.hss.mu.Unlock()
	for range DefaultChallengeLimit + 1 {
		wantStatus(t, g.Register(bg, u.request(600, ""), upstream), 480)
	}
	e.hss.mu.Lock()
	e.hss.unavailable = false
	e.hss.mu.Unlock()
	wantStatus(t, g.Register(bg, u.request(600, ""), upstream), 401)
}

// busyHSS answers every MAR DIAMETER_TOO_BUSY, as an HSS whose subscriber
// lock stayed busy until the deadline does.
type busyHSS struct{ *fakeHSS }

func (b busyHSS) answer() *cx.MAA {
	return &cx.MAA{Answer: cx.Answer{Result: cx.ResultCode(diameter.ResultTooBusy)}}
}

func (b busyHSS) MAR(context.Context, *cx.MAR) (*cx.MAA, error) { return b.answer(), nil }

func (b busyHSS) Authenticate(context.Context, *cx.MAR, []string) (*cx.MAA, error) {
	return b.answer(), nil
}

// TestAChallengeABusyHSSAnsweredKeepsItsCounts: the MAR reached the HSS,
// which served it as far as its lock let it; giving the counts back would
// turn "ten a window" into "ten at a time" exactly while the HSS is loaded
// (code review on #223). Only a MAR that never left gives them back.
func TestAChallengeABusyHSSAnsweredKeepsItsCounts(t *testing.T) {
	e := newEnv(t)
	busy := busyHSS{e.hss}
	g := e.instance(1, func(c *Config) { c.HSS = busy })
	e.akaUser(impi1, impu1)
	for i := range DefaultChallengeLimit {
		wantStatus(t, g.Register(bg, attacker(t, impi1, impu1, i).request(600, ""), upstream), 480)
	}
	healthy := e.instance(2)
	wantStatus(t, healthy.Register(bg, attacker(t, impi1, impu1, 99).request(600, ""), upstream), 500)
}

// overloadedHSS is the HSS under a flood for one subscriber: every MAR
// reaches it, and the answer is DIAMETER_TOO_BUSY (it waited too long for
// the subscriber's lock) or a timeout (it did the work, the answer came too
// late). From QA's probes on #223.
type overloadedHSS struct {
	*fakeHSS
	mu      sync.Mutex
	mode    string // "busy", "timeout", "sent", "resync-timeout", "resync-refused", "resync-sent", ""
	reached int
}

func (o *overloadedHSS) fail(ctx context.Context, r *cx.MAR) (*cx.MAA, error, bool) {
	o.mu.Lock()
	mode := o.mode
	resync := len(r.AuthDataItem.Authorization) > 0
	switch {
	case mode == "resync-timeout" && resync:
		o.mode = ""
		mode = "timeout"
	case mode == "resync-refused" && resync:
		mode = "refused"
	case mode == "resync-sent" && resync:
		mode = "sent"
	case mode == "resync-timeout", mode == "resync-refused", mode == "resync-sent":
		mode = ""
	}
	if mode != "" {
		o.reached++
	}
	o.mu.Unlock()
	switch mode {
	case "busy":
		return nil, &cxclient.ProtocolError{Command: "MAR", Result: cx.Result{Code: diameter.ResultTooBusy}}, true
	case "timeout":
		_, _ = o.fakeHSS.MAR(ctx, r)
		return nil, diameter.ErrTimeout, true
	case "refused":
		return &cx.MAA{Answer: cx.Answer{Result: cx.ResultCode(diameter.ResultAuthorizationRejected)}}, nil, true
	case "sent":
		// What cxclient says of a first attempt answered TOO_BUSY whose
		// retry found its task gone (#261).
		return nil, &cxclient.SentError{Err: fmt.Errorf("cxclient: MAR: %w", diameter.ErrPeerUnavailable)}, true
	}
	return nil, nil, false
}

func (o *overloadedHSS) MAR(ctx context.Context, r *cx.MAR) (*cx.MAA, error) {
	if maa, err, done := o.fail(ctx, r); done {
		return maa, err
	}
	return o.fakeHSS.MAR(ctx, r)
}

func (o *overloadedHSS) Authenticate(ctx context.Context, r *cx.MAR, schemes []string) (*cx.MAA, error) {
	m := *r
	m.AuthDataItem.Scheme = cx.SchemeDigestAKAv1MD5
	if maa, err, done := o.fail(ctx, &m); done {
		return maa, err
	}
	return o.fakeHSS.Authenticate(ctx, r, schemes)
}

// TestAFloodOnAnOverloadedHSSStillGetsOnlyItsBudget: while the HSS answers
// TOO_BUSY or times out, every MAR has reached it, so none gives its counts
// back, and a window still lets ChallengeLimit through (QA's block on
// #223).
func TestAFloodOnAnOverloadedHSSStillGetsOnlyItsBudget(t *testing.T) {
	for _, mode := range []string{"busy", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			o := &overloadedHSS{fakeHSS: e.hss, mode: mode}
			gs := []*Registrar{e.instance(1, func(c *Config) { c.HSS = o }), e.instance(2, func(c *Config) { c.HSS = o })}
			e.akaUser(impi1, impu1)
			for i := range 200 {
				gs[i%2].Register(bg, attacker(t, impi1, impu1, i).request(600, ""), upstream)
			}
			if o.reached != DefaultChallengeLimit {
				t.Errorf("%d MARs reached the HSS in one window, want %d", o.reached, DefaultChallengeLimit)
			}
		})
	}
}

// TestAChallengeTheHSSRefusedKeepsItsCounts: a refusal is an answer, so the
// challenge was spent (QA's surviving mutant on #223).
func TestAChallengeTheHSSRefusedKeepsItsCounts(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	ev := attacker(t, impi1, impu1, 1) // impi1 is not provisioned: user unknown
	for range DefaultFlowChallengeLimit {
		wantStatus(t, g.Register(bg, ev.request(600, ""), upstream), 403)
	}
	wantStatus(t, g.Register(bg, ev.request(600, ""), upstream), 500)
}

// TestAResyncTheHSSRefusedKeepsItsSlot: the HSS answered the AUTS's MAR
// with a refusal; the slot stays used (QA's surviving mutant on #223).
func TestAResyncTheHSSRefusedKeepsItsSlot(t *testing.T) {
	e := newEnv(t)
	o := &overloadedHSS{fakeHSS: e.hss, mode: "resync-refused"}
	m := &counts{}
	g := e.instance(1, roomForResyncs, func(c *Config) { c.HSS, c.Metrics = o, m })
	u := e.akaUser(impi1, impu1)
	for i := range DefaultResyncLimit {
		ch := u.challengeOf(g.Register(bg, u.request(600, ""), upstream), 0)
		if code := g.Register(bg, u.request(600, resyncOf(u, ch)), upstream).StatusCode; code != 403 {
			t.Fatalf("refused resync %d: %d", i+1, code)
		}
	}
	reached := o.reached
	ch := u.challengeOf(g.Register(bg, u.request(600, ""), upstream), 0)
	wantStatus(t, g.Register(bg, u.request(600, resyncOf(u, ch)), upstream), 403)
	if o.reached != reached || m.get("registrar.resync_limited") != 1 {
		t.Errorf("the fourth resync reached the HSS (%d) or was not limited (%d)", o.reached-reached, m.get("registrar.resync_limited"))
	}
}

// TestAResyncOverTheChallengesFlowCostsTheFlowNothing: an AUTS answering a
// challenge issued to the same flow counts only in the shared budget, so a
// UE whose resynchronisation timed out at the HSS, which keeps its counts,
// still fits the flow's three a minute when it tries again.
func TestAResyncOverTheChallengesFlowCostsTheFlowNothing(t *testing.T) {
	e := newEnv(t)
	o := &overloadedHSS{fakeHSS: e.hss, mode: "resync-timeout"}
	g := e.instance(1, func(c *Config) { c.HSS = o })
	u := e.akaUser(impi1, impu1)
	first := u.challengeOf(g.Register(bg, u.request(600, ""), upstream), 0)
	g.Register(bg, u.request(600, resyncOf(u, first)), upstream)
	e.clock.advance(30 * time.Second)
	second := u.challengeOf(g.Register(bg, u.request(600, ""), upstream), 0)
	wantStatus(t, g.Register(bg, u.request(600, resyncOf(u, second)), upstream), 401)
}

// TestAChallengeWhoseFirstAttemptReachedTheHSSKeepsItsCounts: the MAR's
// first attempt was answered TOO_BUSY and its retry found no HSS task; the
// error is the retry's, but the HSS saw the MAR, so the counts stay (#261).
func TestAChallengeWhoseFirstAttemptReachedTheHSSKeepsItsCounts(t *testing.T) {
	e := newEnv(t)
	o := &overloadedHSS{fakeHSS: e.hss, mode: "sent"}
	g := e.instance(1, func(c *Config) { c.HSS = o })
	e.akaUser(impi1, impu1)
	for i := range DefaultChallengeLimit {
		wantStatus(t, g.Register(bg, attacker(t, impi1, impu1, i).request(600, ""), upstream), 480)
	}
	healthy := e.instance(2)
	wantStatus(t, healthy.Register(bg, attacker(t, impi1, impu1, 99).request(600, ""), upstream), 500)
}

// TestAResyncWhoseFirstAttemptReachedTheHSSKeepsItsSlot: as above, for the
// AUTS's MAR (#261).
func TestAResyncWhoseFirstAttemptReachedTheHSSKeepsItsSlot(t *testing.T) {
	e := newEnv(t)
	o := &overloadedHSS{fakeHSS: e.hss, mode: "resync-sent"}
	g := e.instance(1, roomForResyncs, func(c *Config) { c.HSS = o })
	u := e.akaUser(impi1, impu1)
	for i := range DefaultResyncLimit {
		ch := u.challengeOf(g.Register(bg, u.request(600, ""), upstream), 0)
		if code := g.Register(bg, u.request(600, resyncOf(u, ch)), upstream).StatusCode; code != 480 {
			t.Fatalf("resync %d whose retry found no task: %d", i+1, code)
		}
	}
	o.mu.Lock()
	o.mode = ""
	o.mu.Unlock()
	ch := u.challengeOf(g.Register(bg, u.request(600, ""), upstream), 0)
	wantStatus(t, g.Register(bg, u.request(600, resyncOf(u, ch)), upstream), 403)
}

// TestAnAUTSOverAnotherFlowCountsInThatFlowsBudget: an AUTS that comes
// over a flow other than its challenge's is that flow's new attempt, and
// pays its budget (QA on #223: the && at sameFlow).
func TestAnAUTSOverAnotherFlowCountsInThatFlowsBudget(t *testing.T) {
	e := newEnv(t)
	a := e.instance(1, func(c *Config) { c.ResyncLimit = 100 })
	e.akaUser(impi1, impu1)
	one, two := attacker(t, impi1, impu1, 1), attacker(t, impi1, impu1, 2)
	for range DefaultFlowChallengeLimit - 1 { // flow 2 spends all but one
		a.Register(bg, two.request(600, ""), upstream)
	}
	var codes []int
	for range 2 { // flow 1 is challenged, flow 2 answers with an AUTS
		ch := one.challengeOf(a.Register(bg, one.request(600, ""), upstream), 0)
		codes = append(codes, a.Register(bg, two.request(600, forgedAUTS(t, two, ch)), upstream).StatusCode)
	}
	if codes[1] != 500 {
		t.Errorf("cross-flow AUTSs %v: the second did not find flow 2's budget spent", codes)
	}
}
