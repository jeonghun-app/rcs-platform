package regevent

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// task is one piece of the notifier's background work: run, on a worker,
// does the store's part and returns what is left to do off the worker, the
// wait for a subscriber's answer and what follows it, or nil.
//
// A task for a NOTIFY (sub set) counts against its set's and its next hop's
// concurrency from its start to its end, so that a subscriber or a P-CSCF
// task slow to answer holds back its own NOTIFYs only (#256 security and
// code reviews). A task that lists a change's subscriptions (sub "") needs
// a worker only, and is never dropped: it is what persists the end of a set
// that ended before queueing its final NOTIFYs.
type task struct {
	ctx      context.Context
	set, hop string
	sub      string
	final    bool
	// job is a NOTIFY task's, which a later one merged into it updates.
	job *job
	run func(context.Context) func()
	// done, if set, is called once the task has run or was dropped.
	done func()
}

// scheduler holds the tasks waiting and counts those under way. Its fields
// are guarded by mu.
type scheduler struct {
	mu      sync.Mutex
	waiting []*task
	// byQueuedSub is the NOTIFY task waiting for a subscription: it reads
	// the state when it runs, so another adds nothing but an end.
	byQueuedSub map[string]*task
	// queued is the NOTIFY tasks waiting, and queuedFor those by next hop.
	queued    int
	queuedFor map[string]int
	// working is the tasks on a worker; inSet and inHop the NOTIFY tasks
	// started and not done, by set and by next hop.
	working      int
	inSet, inHop map[string]int
}

func newScheduler() scheduler {
	return scheduler{byQueuedSub: map[string]*task{}, queuedFor: map[string]int{}, inSet: map[string]int{}, inHop: map[string]int{}}
}

// enqueue queues t and reports whether it did. A NOTIFY task for a
// subscription that has one waiting already is merged into it, unless it is
// final, which takes the waiting one's place: the subscription has been
// terminated since, and the waiting one would not end it. Beyond Queue NOTIFY tasks
// waiting, or a quarter of it for t's next hop, t is dropped and counted:
// regevent.notify_dropped for one not final, whose subscriber the next
// NOTIFY makes good, and regevent.notify_deferred for a final one, whose
// subscription its caller has terminated first so that a sweep sends it.
func (n *Notifier) enqueue(t *task) bool {
	t.ctx = context.WithoutCancel(t.ctx)
	sc := &n.sc
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if t.sub != "" {
		if old := sc.byQueuedSub[t.sub]; old != nil {
			if !t.final {
				// What the later change ended, it tells of (#256 QA).
				merged := maps.Clone(old.job.ends)
				if merged == nil {
					merged = map[string]Cause{}
				}
				maps.Copy(merged, t.job.ends)
				old.job.ends = merged
				n.count("regevent.notify_merged")
				finish(t)
				return true
			}
			sc.unqueue(old)
			sc.waiting = slices.DeleteFunc(sc.waiting, func(w *task) bool { return w == old })
			finish(old)
			n.wg.Done()
		}
		if sc.queued >= n.cfg.Queue || sc.queuedFor[t.hop] >= max(n.cfg.Queue/4, 1) {
			if t.final {
				n.count("regevent.notify_deferred")
			} else {
				n.count("regevent.notify_dropped")
			}
			finish(t)
			return false
		}
		sc.queued++
		sc.queuedFor[t.hop]++
		sc.byQueuedSub[t.sub] = t
	}
	n.wg.Add(1)
	sc.waiting = append(sc.waiting, t)
	n.dispatchLocked()
	return true
}

func finish(t *task) {
	if t.done != nil {
		t.done()
	}
}

// unqueue takes t, a NOTIFY task, off the counts of those waiting.
func (sc *scheduler) unqueue(t *task) {
	sc.queued--
	if sc.queuedFor[t.hop]--; sc.queuedFor[t.hop] == 0 {
		delete(sc.queuedFor, t.hop)
	}
	if sc.byQueuedSub[t.sub] == t {
		delete(sc.byQueuedSub, t.sub)
	}
}

// dispatchLocked starts, in order, the waiting tasks a worker and their set
// and next hop have room for. sc.mu is held.
func (n *Notifier) dispatchLocked() {
	sc := &n.sc
	for i := 0; i < len(sc.waiting) && sc.working < n.cfg.Workers; {
		t := sc.waiting[i]
		if t.sub != "" && (sc.inSet[t.set] >= n.cfg.SetConcurrency || sc.inHop[t.hop] >= n.cfg.HopConcurrency) {
			i++
			continue
		}
		sc.waiting = slices.Delete(sc.waiting, i, i+1)
		sc.working++
		if t.sub != "" {
			sc.unqueue(t)
			sc.inSet[t.set]++
			sc.inHop[t.hop]++
		}
		go n.runTask(t)
	}
}

func (n *Notifier) runTask(t *task) {
	defer n.wg.Done()
	defer finish(t)
	rest := t.run(t.ctx)
	sc := &n.sc
	sc.mu.Lock()
	sc.working--
	n.dispatchLocked()
	sc.mu.Unlock()
	if rest != nil {
		rest()
	}
	if t.sub == "" {
		return
	}
	sc.mu.Lock()
	if sc.inSet[t.set]--; sc.inSet[t.set] == 0 {
		delete(sc.inSet, t.set)
	}
	if sc.inHop[t.hop]--; sc.inHop[t.hop] == 0 {
		delete(sc.inHop, t.hop)
	}
	n.dispatchLocked()
	sc.mu.Unlock()
}

// enqueueNotify queues the NOTIFY j to sub, calling done, if set, once it
// has been sent or dropped.
func (n *Notifier) enqueueNotify(ctx context.Context, sub *state.Subscription, j job, done func()) {
	t := &task{ctx: ctx, set: sub.Set.IMPI + "\x00" + sub.Set.IMPU, hop: hopOf(sub), sub: sub.ID, final: j.final, done: done, job: &j}
	t.run = func(ctx context.Context) func() { return n.prepare(ctx, sub, *t.job) }
	n.enqueue(t)
}

// hopOf names the next hop of sub's NOTIFYs: the first route of its dialog,
// or without one its remote target, by host and port.
func hopOf(sub *state.Subscription) string {
	var u sip.URI
	if len(sub.Dialog.RouteSet) > 0 {
		a, err := sip.ParseAddress(sub.Dialog.RouteSet[0])
		if err != nil {
			return ""
		}
		u = a.URI
	} else {
		var err error
		if u, err = sip.ParseURI(sub.Dialog.RemoteTarget); err != nil {
			return ""
		}
	}
	return strings.ToLower(u.Host) + ":" + strconv.Itoa(u.Port)
}
