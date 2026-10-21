package registrar

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// The budgets of challenges and resynchronisations (#201, T12). Every
// instance counts into the same counts (state.Challenges.CountAttempt), in
// fixed windows: up to twice a budget gets through across a window's edge,
// and an instance whose clock is off counts into its own idea of the window.
//
// They are split by the P-CSCF flow a REGISTER came over, the flow token in
// its Path that only the P-CSCF writes (RFC 5626 §5.2). A REGISTER over a
// flow a live binding of the user's registration came over is the registered
// UE refreshing while it stays on that flow: it has a budget of its own for
// that flow and nothing else, so that no one elsewhere can use it up. Every
// other REGISTER counts in a small budget for its flow and in the IMPI's
// shared one, which a flood of first registrations, from any flows, still
// exhausts: that is the risk left, for a first registration and for a
// registered UE that reconnects, whose new flow matches no binding (T12).
//
// The limits count challenges, not MARs: a Digest subscriber's challenge
// costs two when the HSS answers the AKA one with 5006.

// limitChallenges counts a challenge for r at now and refuses it over a
// budget with 500 and Retry-After, the seconds to the window's end. 500
// rather than 503 (RFC 3261 §21.5.1): a 503 says the whole server is out of
// service (§21.5.4), which an upstream proxy then shuns for every user, and
// the P-CSCF tries other I-CSCFs on, counting the REGISTER again each time.
//
// It returns what it counted, which the caller gives back if the HSS does
// not answer the challenge's MAR.
func (g *Registrar) limitChallenges(ctx context.Context, r *register, now time.Time) ([]state.Attempt, *failure) {
	return g.limitChallengesOf(ctx, r, now, true)
}

// limitChallengesOf is limitChallenges, counting in the flow's budget only
// with byFlow.
func (g *Registrar) limitChallengesOf(ctx context.Context, r *register, now time.Time, byFlow bool) ([]state.Attempt, *failure) {
	window := g.cfg.ChallengeWindow
	start := now.Truncate(window)
	var counted []state.Attempt
	if r.flow != "" && byFlow {
		limit := g.cfg.FlowChallengeLimit
		if r.registeredFlow {
			limit = g.cfg.RegisteredFlowChallengeLimit
		}
		a := state.Attempt{IMPI: r.impi, Kind: state.AttemptChallenge, Scope: state.FlowScope(r.flow), Window: start}
		over, f := g.over(ctx, a, window, limit, now)
		if f != nil || over {
			return nil, g.challengeRefused(f, start.Add(window), now)
		}
		counted = append(counted, a)
	}
	if r.registeredFlow {
		return counted, nil
	}
	a := state.Attempt{IMPI: r.impi, Kind: state.AttemptChallenge, Window: start}
	over, f := g.over(ctx, a, window, g.cfg.ChallengeLimit, now)
	if f != nil || over {
		return nil, g.challengeRefused(f, start.Add(window), now)
	}
	return append(counted, a), nil
}

func (g *Registrar) challengeRefused(f *failure, end, now time.Time) *failure {
	if f != nil {
		return f
	}
	g.count("registrar.challenge_limited")
	retry := int64((end.Sub(now) + time.Second - 1) / time.Second)
	return &failure{code: 500, reason: "Too many challenges", fields: [][2]string{{"Retry-After", strconv.FormatInt(retry, 10)}}}
}

// limitResyncs takes a resynchronisation slot for r at now, in the budget of
// its registered flow or else the IMPI's shared one, and returns it, to give
// back if the resynchronisation comes to nothing; over the budget it refuses
// with 403.
func (g *Registrar) limitResyncs(ctx context.Context, r *register, now time.Time) (state.Attempt, *failure) {
	window := g.cfg.ChallengeLifetime
	a := state.Attempt{IMPI: r.impi, Kind: state.AttemptResync, Window: now.Truncate(window)}
	if r.registeredFlow {
		a.Scope = state.FlowScope(r.flow)
	}
	over, f := g.over(ctx, a, window, g.cfg.ResyncLimit, now)
	switch {
	case f != nil:
		return a, f
	case over:
		g.count("registrar.resync_limited")
		return a, refuse(403, "Authentication failed")
	}
	return a, nil
}

// giveBack returns the slots of as; failing that, a slot stays used until
// its window ends. This instance's note that a count was over its limit
// goes too, so that it does not refuse what the count now allows, as an
// instance without the note would not.
func (g *Registrar) giveBack(ctx context.Context, as ...state.Attempt) {
	for _, a := range as {
		g.notes.forget(a)
		if _, err := g.cfg.Store.CountAttempt(ctx, a, -1, a.Window.Add(2*g.windowOf(a.Kind))); err != nil {
			g.count("registrar.internal_errors")
		}
	}
}

func (g *Registrar) windowOf(kind string) time.Duration {
	if kind == state.AttemptResync {
		return g.cfg.ChallengeLifetime
	}
	return g.cfg.ChallengeWindow
}

// over counts a in its window of length window and reports whether the count
// is past limit. A count this instance already saw past it, in the same
// window, is refused from its note without a write: a flood then costs the
// store nothing more.
func (g *Registrar) over(ctx context.Context, a state.Attempt, window time.Duration, limit int, now time.Time) (bool, *failure) {
	end := a.Window.Add(window)
	if g.notes.over(a, now) {
		return true, nil
	}
	n, err := g.cfg.Store.CountAttempt(ctx, a, 1, a.Window.Add(2*window))
	if err != nil {
		return false, g.quietInternal("counting an attempt", err, now)
	}
	if n <= int64(limit) {
		return false, nil
	}
	g.notes.note(a, end, now)
	return true, nil
}

// quietInternal is internal with the log line at most once per
// countLogEvery: a store that refuses counts under a flood would otherwise
// log every REGISTER of it.
func (g *Registrar) quietInternal(what string, err error, now time.Time) *failure {
	last := g.countLogged.Load()
	if now.UnixNano()-last >= int64(countLogEvery) && g.countLogged.CompareAndSwap(last, now.UnixNano()) {
		return g.internal(what, err)
	}
	g.count("registrar.internal_errors")
	return refuse(500, "")
}

// countLogEvery spaces quietInternal's log lines.
const countLogEvery = 10 * time.Second

// maxNotes bounds limitNotes: past it, counts over a limit are not noted and
// go to the store, as without the note.
const maxNotes = 4096

// limitNotes remembers, per instance, the counts seen over their limit
// until their window ends.
type limitNotes struct {
	mu    sync.Mutex
	until map[state.Attempt]time.Time
}

func (l *limitNotes) over(a state.Attempt, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	end, ok := l.until[a]
	return ok && now.Before(end)
}

func (l *limitNotes) forget(a state.Attempt) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.until, a)
}

func (l *limitNotes) note(a state.Attempt, end, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.until == nil {
		l.until = map[state.Attempt]time.Time{}
	}
	if len(l.until) >= maxNotes {
		for k, e := range l.until {
			if !now.Before(e) {
				delete(l.until, k)
			}
		}
		if len(l.until) >= maxNotes {
			return
		}
	}
	l.until[a] = end
}

// pathFlow is the flow token of the topmost Path entry, the P-CSCF's (RFC
// 5626 §5.2), "" without one.
func pathFlow(path []string) string {
	if len(path) == 0 {
		return ""
	}
	a, err := sip.ParseAddress(path[0])
	if err != nil {
		return ""
	}
	return a.URI.User
}

// overRegisteredFlow reports whether flow is the flow of a binding of reg
// that is live at now.
func overRegisteredFlow(reg *state.Registration, flow string, now time.Time) bool {
	if reg == nil || flow == "" {
		return false
	}
	for _, c := range reg.Contacts {
		if !c.Expired(now) && pathFlow(c.Path) == flow {
			return true
		}
	}
	return false
}

// neverSent reports whether a MAR certainly did not reach the HSS
// (cxclient.NeverSent): no HSS task was connected, or every attempt found
// its task gone, or not speaking Cx, before the send. Only then are its
// counts given back. A
// DIAMETER_TOO_BUSY, an HSS that waited for the subscriber's lock, an
// attempt that timed out, or a first attempt that did any of those before
// its retry found no task (#261), which the HSS may have served, keeps
// them: giving those back would loosen the limit exactly while the HSS is
// under the load it guards against (T12).
func neverSent(err error) bool { return cxclient.NeverSent(err) }
