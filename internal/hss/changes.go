package hss

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"slices"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// What the S-CSCF must be told when provisioning changes a subscription it
// serves (TS 29.228 §6.5.2, §6.6.1). The HSS changes the stored state in the
// same write as the provisioning change and sends the requests after the
// write, so a failure to reach an S-CSCF never undoes the change. An
// S-CSCF that missed a push keeps the profile it holds through the
// user's refreshes, which tell the HSS it has the data; a change whose
// pushes ran out of time marks its sets stale, so that the next
// registration of each fetches the data anyway (notify, applySAR).

// push is one HSS-initiated request to send.
type push struct {
	deregister bool
	reason     cx.ReasonCode
	// impus lists the identities an RTR deregisters; none means all.
	impus []string
	// set is the implicit registration set whose User-Data a PPR carries,
	// or -1 for a PPR without User-Data; changed is the set a
	// SERVER_CHANGE RTR is for, whose User-Data a registration must fetch
	// again if the RTR is never sent (staleSets).
	set      int
	changed  int
	charging bool
	digest   bool
}

// reconcile sets the registration state of next, a provisioned replacement
// of old, and returns what to send (TS 29.228 §6.5.2.1):
//
//   - a served set left without identities is deregistered (RTR,
//     PERMANENT_TERMINATION) — a PPR cannot empty a set;
//   - a served set whose default identity changes is deregistered (RTR,
//     SERVER_CHANGE) so the user registers again — a PPR must not change it;
//   - any other served set whose identities, barring or profile change gets
//     its new User-Data (PPR); identities added to it take its state;
//   - a change of charging information alone is a PPR without User-Data
//     (§6.5.2.3).
//
// When an identity moves from one set to another, the S-CSCF updates the
// set losing it first, then the one gaining it (§6.5.2.1), and notify sends
// the pushes in the order returned, each once the one before is answered:
//
//   - first the RTRs of sets that lose an identity: an RTR only takes
//     identities away, and the S-CSCF finds the set an RTR names by its
//     identities, so after a PPR that moved one of them into another set it
//     would end that set too (code review on #476);
//   - then the PPRs of sets that lose an identity, a set that gives one to
//     another before that set (byDependency);
//   - then the rest, the sets that only gain identities among them.
//
// Sets that were not served stay or become not registered.
func reconcile(old, next *store.Subscription, profileChanged bool) []push {
	state := map[int]store.RegistrationState{}
	for _, p := range old.PublicIdentities {
		state[p.ImplicitSet] = p.State
	}
	for i := range next.PublicIdentities {
		next.PublicIdentities[i].State = store.NotRegistered
	}
	chargingChanged := !reflect.DeepEqual(old.Charging, next.Charging)
	var rtrs, others []push
	var losing []int // the sets that lose an identity and get a PPR
	ppr := map[int]push{}
	pprSent := false
	for _, set := range targetSets(old, nil) {
		if !state[set].Served() {
			continue
		}
		was, now := members(old, set), members(next, set)
		loses := lost(was, now)
		switch {
		case len(now) == 0:
			rtrs = append(rtrs, push{deregister: true, reason: cx.PermanentTermination, impus: impusOf(was), set: -1})
		case defaultIdentity(old, set) != defaultIdentity(next, set):
			p := push{deregister: true, reason: cx.ServerChange, impus: impusOf(was), set: -1, changed: set}
			if loses {
				rtrs = append(rtrs, p)
			} else {
				others = append(others, p)
			}
		default:
			setState(next, set, state[set])
			if profileChanged || !sameMembers(was, now) {
				p := push{set: set, charging: chargingChanged}
				if loses {
					losing, ppr[set] = append(losing, set), p
				} else {
					others = append(others, p)
				}
				pprSent = true
			}
		}
	}
	pushes := rtrs
	for _, set := range byDependency(losing, gives(old, next)) {
		pushes = append(pushes, ppr[set])
	}
	pushes = append(pushes, others...)
	if chargingChanged && !pprSent && served(next) {
		pushes = append(pushes, push{set: -1, charging: true})
	}
	clearServerIfIdle(next)
	return pushes
}

// gives maps each implicit set of old to the sets of next its identities
// moved to.
func gives(old, next *store.Subscription) map[int]map[int]bool {
	was := map[string]int{}
	for _, p := range old.PublicIdentities {
		was[p.IMPU] = p.ImplicitSet
	}
	out := map[int]map[int]bool{}
	for _, p := range next.PublicIdentities {
		from, ok := was[p.IMPU]
		if !ok || from == p.ImplicitSet {
			continue
		}
		if out[from] == nil {
			out[from] = map[int]bool{}
		}
		out[from][p.ImplicitSet] = true
	}
	return out
}

// byDependency orders sets so that a set that gives an identity to another
// comes before it, and otherwise as they are. Sets that give to each other,
// as when two swap identities by PPRs alone, keep the order they had: no
// order updates both losing sets first, and the S-CSCF ends with the same
// sets whichever comes first. Such a cycle is broken at its first set, not
// at a set it gives to, which still goes after its giver (QA on #476).
func byDependency(sets []int, gives map[int]map[int]bool) []int {
	left := slices.Clone(sets)
	out := make([]int, 0, len(sets))
	for len(left) > 0 {
		next := slices.IndexFunc(left, func(s int) bool {
			return !slices.ContainsFunc(left, func(o int) bool { return o != s && gives[o][s] })
		})
		if next < 0 {
			next = max(slices.IndexFunc(left, func(s int) bool { return onCycle(s, left, gives) }), 0)
		}
		out = append(out, left[next])
		left = slices.Delete(left, next, next+1)
	}
	return out
}

// onCycle reports whether s gives, through sets among left, back to itself.
func onCycle(s int, left []int, gives map[int]map[int]bool) bool {
	seen := map[int]bool{}
	todo := []int{s}
	for len(todo) > 0 {
		from := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		for _, to := range left {
			if !gives[from][to] {
				continue
			}
			if to == s {
				return true
			}
			if !seen[to] {
				seen[to] = true
				todo = append(todo, to)
			}
		}
	}
	return false
}

// lost reports whether a set whose identities were was and are now has lost
// one of them.
func lost(was, now []store.PublicIdentity) bool {
	for _, p := range was {
		if !slices.ContainsFunc(now, func(q store.PublicIdentity) bool { return q.IMPU == p.IMPU }) {
			return true
		}
	}
	return false
}

func impusOf(ids []store.PublicIdentity) []string {
	out := make([]string, len(ids))
	for i, p := range ids {
		out[i] = p.IMPU
	}
	return out
}

func sameMembers(a, b []store.PublicIdentity) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].IMPU != b[i].IMPU || a[i].Barred != b[i].Barred || a[i].Type != b[i].Type {
			return false
		}
	}
	return true
}

// profilePushes are the PPRs for a subscription whose shared profile
// changed: one per served implicit registration set (§6.6.1).
func profilePushes(s *store.Subscription) []push {
	var pushes []push
	for _, set := range targetSets(s, nil) {
		if members(s, set)[0].State.Served() {
			pushes = append(pushes, push{set: set})
		}
	}
	return pushes
}

// digestPushes is the PPR for a changed SIP Digest credential (TS 29.228
// §6.5.2.4): pushed when an identity is registered, or authentication is
// pending with the old one.
func digestPushes(s *store.Subscription) []push {
	for _, p := range s.PublicIdentities {
		if p.State == store.Registered {
			return []push{{set: -1, digest: true}}
		}
	}
	if s.AuthPending {
		return []push{{set: -1, digest: true}}
	}
	return nil
}

// deletePushes deregisters a deleted subscription that an S-CSCF serves:
// every identity, permanently (§6.1.3).
func deletePushes(s *store.Subscription) []push {
	if !served(s) {
		return nil
	}
	return []push{{deregister: true, reason: cx.PermanentTermination, set: -1}}
}

// notify sends pushes for s, whose profile is p (needed for User-Data), one
// after the other, each with t.each to be answered in: a push that is not
// answered in time leaves the next its own time, so that a slow answer for
// the set losing an identity does not cost the set gaining it its PPR (QA on
// #476). Failures are logged and counted, not returned: the stored change
// stands.
//
// A change the API answers has a budget too (pushTimes.until): the API
// answers once the pushes are done, and must do so within its HTTP write
// timeout (#491). A push that would get less than pushFloor of it is not
// sent, nor any after it: they are counted in push.over_budget, and the
// sets they were for are marked stale (staleSets), so that the S-CSCF gets
// their User-Data with the next registration of each, whatever it says it
// holds (TS 29.228 §6.6).
func (h *HSS) notify(ctx context.Context, n Notifier, s *store.Subscription, p *store.ServiceProfile, pushes []push, t pushTimes) {
	if n == nil {
		return
	}
	for i, ps := range pushes {
		if t.bounded() && t.forPush(ps) < pushFloor {
			h.overBudget(ctx, s, pushes[i:], t)
			return
		}
		if h.notifyOne(ctx, n, s, p, ps, t) {
			// The user is no longer registered at the S-CSCF, which knows
			// it no longer or is deregistering it: a set's PPR after this
			// one, the set gaining a moved identity say, has nothing left
			// to update (#213).
			return
		}
	}
}

// pushFloor is the least time a push of a change is worth starting with.
const pushFloor = 100 * time.Millisecond

// pushTimes bound the pushes of one change (notify): each one, and with an
// until, all of them, from before the profile is read. reserve is kept at
// the end for marking the sets left over stale (overBudget).
//
// A PPR leaves a whole each before the end for what its refusal brings,
// the not-registered write and the RTR (pprRejected), so that an S-CSCF
// refusing at the PPR's deadline still gets its RTR (code review on #524).
type pushTimes struct {
	each    time.Duration
	until   time.Time
	reserve time.Duration
}

func (t pushTimes) bounded() bool { return !t.until.IsZero() }

// left is how long a request may take that must leave keep before the end.
func (t pushTimes) left(keep time.Duration) time.Duration {
	if !t.bounded() {
		return t.each
	}
	return max(min(t.each, time.Until(t.until)-t.reserve-keep), 0)
}

// forPush is how long ps may take: a PPR keeps each for its follow-up.
func (t pushTimes) forPush(ps push) time.Duration {
	if ps.deregister {
		return t.left(0)
	}
	return t.left(t.each)
}

// followUp is how long a refused PPR's write and RTR may each take.
func (t pushTimes) followUp() time.Duration { return t.left(0) }

// overBudget counts the pushes left when the budget ran out, and marks
// the sets they were for stale in the store, within what is left of it.
func (h *HSS) overBudget(ctx context.Context, s *store.Subscription, left []push, t pushTimes) {
	h.metrics.Count("push.over_budget", int64(len(left)))
	h.log.Warn("the S-CSCF requests of a provisioning change ran out of time",
		pii.Identity("impi", s.IMPI), slog.Int("left", len(left)))
	sets := staleSets(left)
	if len(sets) == 0 {
		return
	}
	sctx, cancel := context.WithDeadline(ctx, t.until)
	defer cancel()
	_, err := h.update(sctx, s.IMPI, func(cur *store.Subscription) error {
		before := len(cur.StaleSets)
		for _, set := range sets {
			if !slices.Contains(cur.StaleSets, set) {
				cur.StaleSets = append(cur.StaleSets, set)
			}
		}
		if len(cur.StaleSets) == before {
			return errUnchanged
		}
		slices.Sort(cur.StaleSets)
		return nil
	})
	if err != nil {
		h.log.Warn("could not mark the sets of a provisioning change stale", pii.Identity("impi", s.IMPI),
			slog.String("error", pii.Redact(err.Error())))
		return
	}
	h.metrics.Count("push.stale_marked", 1)
}

// staleSets are the implicit sets whose User-Data the pushes would have
// brought the S-CSCF: a PPR's, and a SERVER_CHANGE RTR's. An emptied set's
// RTR has nothing to fetch: its refreshes are refused, and it ends at the
// S-CSCF within a registration period. A PPR of charging information alone
// carries no set.
func staleSets(pushes []push) []int {
	var out []int
	for _, ps := range pushes {
		switch {
		case !ps.deregister && ps.set >= 0:
			out = append(out, ps.set)
		case ps.deregister && ps.reason == cx.ServerChange && len(ps.impus) > 0:
			out = append(out, ps.changed)
		}
	}
	return out
}

// notifyOne sends ps within t, and reports whether it left the user no
// longer registered (pprRejected).
func (h *HSS) notifyOne(ctx context.Context, n Notifier, s *store.Subscription, p *store.ServiceProfile, ps push, t pushTimes) bool {
	pctx, cancel := context.WithTimeout(ctx, t.forPush(ps))
	defer cancel()
	err := h.send(pctx, n, s, p, ps)
	if err != nil {
		kind := "ppr"
		if ps.deregister {
			kind = "rtr"
		}
		h.log.Warn("could not notify the S-CSCF of a provisioning change",
			pii.Identity("impi", s.IMPI), slog.String("request", kind), slog.String("error", pii.Redact(err.Error())))
	}
	var rejected *RejectedError
	return !ps.deregister && errors.As(err, &rejected) && h.pprRejected(ctx, n, s, rejected.Result, t)
}

// pprRejected acts on a PPA failure as TS 29.228 §6.2.2.1 asks of an HSS
// without restoration support:
//
//   - DIAMETER_ERROR_USER_UNKNOWN: the S-CSCF has lost the user, so the
//     HSS's registration state is wrong; every identity becomes not
//     registered (there is no other registered IMPI to retry with).
//   - DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA or TOO_MUCH_DATA: the S-CSCF
//     keeps the old data and the HSS deregisters the user with
//     SERVER_CHANGE, setting the state to not registered, so that the user
//     registers again and gets an S-CSCF that takes the new data.
//
// It reports whether it acted on the failure: once the user is marked not
// registered here, it is no longer registered at the S-CSCF either.
//
// The not-registered write and the RTR each get t.each of their own, from
// when they start, rather than what the refused PPR left of its own: an
// S-CSCF that refuses late would otherwise leave the RTR almost none, and
// the user registered there with the old data (code review on #476). A
// bounded change kept them that time before its end (pushTimes.forPush).
func (h *HSS) pprRejected(ctx context.Context, n Notifier, s *store.Subscription, r cx.Result, t pushTimes) bool {
	if r.Vendor != cx.Vendor3GPP {
		return false
	}
	switch r.Code {
	case cx.ErrorUserUnknown, cx.ErrorNotSupportedUserData, cx.ErrorTooMuchData:
	default:
		return false
	}
	uctx, cancel := context.WithTimeout(ctx, t.followUp())
	defer cancel()
	_, err := h.update(uctx, s.IMPI, func(cur *store.Subscription) error {
		if !served(cur) && !cur.AuthPending && cur.ServerName == "" {
			return errUnchanged
		}
		for i := range cur.PublicIdentities {
			cur.PublicIdentities[i].State = store.NotRegistered
		}
		cur.AuthPending, cur.ServerName = false, ""
		return nil
	})
	if err != nil {
		h.log.Warn("could not mark a user the S-CSCF refused as not registered", pii.Identity("impi", s.IMPI),
			slog.String("error", pii.Redact(err.Error())))
		// The HSS has not deregistered the user: the change's other
		// pushes still go (code review on #476).
		return false
	}
	if r.Code == cx.ErrorUserUnknown {
		h.metrics.Count("push.ppr.user_unknown", 1)
		return true
	}
	h.metrics.Count("push.ppr.data_refused", 1)
	rctx, rcancel := context.WithTimeout(ctx, t.followUp())
	defer rcancel()
	err = n.Deregister(rctx, &cx.RTR{UserName: s.IMPI, DeregistrationReason: cx.DeregistrationReason{Code: cx.ServerChange}})
	if err != nil {
		h.log.Warn("could not deregister a user whose S-CSCF refused new data", pii.Identity("impi", s.IMPI),
			slog.String("error", pii.Redact(err.Error())))
	}
	return true
}

func (h *HSS) send(ctx context.Context, n Notifier, s *store.Subscription, p *store.ServiceProfile, ps push) error {
	if ps.deregister {
		return n.Deregister(ctx, &cx.RTR{
			UserName: s.IMPI, PublicIdentities: ps.impus,
			DeregistrationReason: cx.DeregistrationReason{Code: ps.reason},
		})
	}
	r := &cx.PPR{UserName: s.IMPI}
	if ps.set >= 0 {
		if p == nil {
			return errors.New("hss: the service profile could not be read for User-Data")
		}
		data, err := userData(s, ps.set, p)
		if errors.Is(err, ifc.ErrTooLarge) {
			h.metrics.Count("userdata.too_large", 1)
		}
		if err != nil {
			return err
		}
		r.UserData = data
	}
	if ps.charging {
		r.ChargingInformation = charging(s.Charging)
	}
	if ps.digest {
		item, err := h.digestItem(s)
		if err != nil {
			return err
		}
		r.AuthDataItem = &item
	}
	if r.UserData == nil && r.ChargingInformation == nil && r.AuthDataItem == nil {
		return nil // charging information was removed: nothing to push
	}
	return n.PushProfile(ctx, r)
}
