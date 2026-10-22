package group

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// Defaults of the ownership settings (#121, ADR 0005).
const (
	// DefaultTaskHeartbeat is how often a task renews its heartbeat, and
	// DefaultTaskLease how far ahead of itself: three missed beats lose
	// the task its groups.
	DefaultTaskHeartbeat = 5 * time.Second
	DefaultTaskLease     = 20 * time.Second
	// DefaultTaskSkew is the margin both sides keep for the tasks' clocks
	// (AWS Time Sync keeps them within milliseconds): an owner stops
	// writing that long before its lease ends, and another task takes its
	// groups only that long after.
	DefaultTaskSkew = 2 * time.Second
)

// ErrNotOwner: another task owns the group and is alive; the request is
// for that task (the SIP layer forwards it there, #121) or for later.
var ErrNotOwner = errors.New("group: another task owns the group")

// me is this task as an owner, without an epoch.
func (s *Service) me() groupstore.Owner { return groupstore.Owner{Task: s.cfg.Task, SIP: s.cfg.SIP} }

// alive reports whether this task may write its groups at now: its last
// heartbeat holds them, with the skew to spare. A Service that runs no
// heartbeat (StartHeartbeat), one task with the memory store, always
// may: no other task takes its groups. Once it may not, another task may
// take any of them, so the next beat stored forgets them all (beat).
func (s *Service) alive(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.beating || now.Before(s.lastBeat.Add(s.cfg.TaskLease-s.cfg.TaskSkew))
}

// ownership is a group this task owns: the owner it writes the group
// under, and when the store last said so.
type ownership struct {
	groupstore.Owner
	read time.Time
}

// owner returns the owner this task writes g under, taking g over first
// if its owner has stopped: no heartbeat within its lease and the skew, a
// task that is gone (its record expired), or a task whose address is now
// this one's, which therefore cannot be running. ErrNotOwner if another
// task owns g and is alive, or if this task's own heartbeat has lapsed.
// The groups this task owns are remembered, so that a write to one reads
// nothing more; a fenced write's refusal forgets it (disown).
func (s *Service) owner(ctx context.Context, g groupstore.Group) (groupstore.Owner, error) {
	o, _, err := s.ownerOrOther(ctx, g, 0)
	return o, err
}

// ownerOrOther is owner, taking what this task remembers owning only if
// the store said so within maxAge, any age if it is zero. With
// ErrNotOwner, other is the task the store names, alive, that owns g; it
// is the zero Owner when this task's own heartbeat has lapsed instead.
func (s *Service) ownerOrOther(ctx context.Context, g groupstore.Group, maxAge time.Duration) (mine, other groupstore.Owner, err error) {
	now := s.cfg.Clock.Now()
	if !s.alive(now) {
		s.metrics.Count("group.owner_lapsed", 1)
		return groupstore.Owner{}, groupstore.Owner{}, ErrNotOwner
	}
	s.mu.Lock()
	o, ok := s.owned[g.URI]
	s.mu.Unlock()
	if ok && (maxAge == 0 || now.Before(o.read.Add(maxAge))) {
		return o.Owner, groupstore.Owner{}, nil
	}
	cur, err := s.store.Owner(ctx, g.URI)
	if err != nil {
		return groupstore.Owner{}, groupstore.Owner{}, err
	}
	if cur.Task == s.cfg.Task {
		s.own(g.URI, cur, now)
		return cur, groupstore.Owner{}, nil
	}
	if cur.Task != "" && (cur.SIP == "" || cur.SIP != s.cfg.SIP) {
		t, err := s.store.Task(ctx, cur.Task)
		switch {
		case errors.Is(err, groupstore.ErrNotFound):
		case err != nil:
			return groupstore.Owner{}, groupstore.Owner{}, err
		case now.Before(t.AliveUntil.Add(s.cfg.TaskSkew)):
			s.notOwned(g.URI)
			return groupstore.Owner{}, cur, ErrNotOwner
		}
	}
	token, err := s.randomHex(8)
	if err != nil {
		return groupstore.Owner{}, groupstore.Owner{}, err
	}
	next, err := s.store.TakeOver(ctx, g.URI, cur, s.me(), g.Expires, token)
	if errors.Is(err, groupstore.ErrConflict) {
		// Another takeover came first: of another request on this task
		// (as a group's participants rejoin at once after its owner
		// stopped, #121 Q4), which this one may write under, or of
		// another task, which owns the group now.
		if cur, err = s.store.Owner(ctx, g.URI); err != nil {
			return groupstore.Owner{}, groupstore.Owner{}, err
		}
		if cur.Task == s.cfg.Task {
			s.own(g.URI, cur, now)
			return cur, groupstore.Owner{}, nil
		}
		s.notOwned(g.URI)
		return groupstore.Owner{}, cur, ErrNotOwner
	}
	if err != nil {
		return groupstore.Owner{}, groupstore.Owner{}, err
	}
	s.metrics.Count("group.owner_takeover", 1)
	s.own(g.URI, next, now)
	return next, groupstore.Owner{}, nil
}

// Owns implements messaging.GroupHandler: whether this task owns the
// group uri (Place); an ended group is no one's.
func (s *Service) Owns(ctx context.Context, uri string) (bool, error) {
	mine, _, err := s.Place(ctx, uri)
	if errors.Is(err, ErrNoGroup) || errors.Is(err, ErrNotOwner) {
		return false, nil
	}
	return mine, err
}

// Place says where the group uri is served (#121): here, mine, when this
// task owns it, taking it over first if its owner has stopped (owner);
// else by at, the task that owns it, alive, to whose SIP instance address
// the SIP layer forwards the group's requests. ErrNotOwner, at the zero
// Owner, while this task's own heartbeat has lapsed; ErrNoGroup for a
// group that does not exist or has ended.
//
// Unlike a write, an invitation or a forwarding decision is not fenced by
// the store, so the owner is read again once the store's word is a
// heartbeat old: an owner paused while another task took a group over,
// which never saw its own heartbeat lapse and writes nothing to the group,
// takes it for its own no longer than that (code review and QA on #440).
// That another task owns a group is remembered for TaskHeartbeat too, so
// that a queue of its copies, or its participants' requests, cost no read
// each. A lapse of this task's own is not remembered: once a beat lands
// the group may be its own still.
func (s *Service) Place(ctx context.Context, uri string) (mine bool, at groupstore.Owner, err error) {
	now := s.cfg.Clock.Now()
	s.mu.Lock()
	o, owned := s.owned[uri]
	other, known := s.others[uri]
	s.mu.Unlock()
	switch {
	case owned && now.Before(o.read.Add(s.cfg.TaskHeartbeat)) && s.alive(now):
		return true, groupstore.Owner{}, nil
	case known && now.Before(other.until):
		return false, other.owner, nil
	}
	g, err := s.get(ctx, uri)
	if err != nil {
		return false, groupstore.Owner{}, err
	}
	_, at, err = s.ownerOrOther(ctx, g, s.cfg.TaskHeartbeat)
	switch {
	case err == nil:
		return true, groupstore.Owner{}, nil
	case errors.Is(err, ErrNotOwner) && at.Task != "":
		s.mu.Lock()
		if len(s.others) >= s.cfg.MaxTracked {
			clear(s.others)
		}
		s.others[uri] = otherOwner{until: now.Add(s.cfg.TaskHeartbeat), owner: at}
		s.mu.Unlock()
		return false, at, nil
	}
	return false, groupstore.Owner{}, err
}

// otherOwner is a group another task owns, and until when Place takes
// that for granted.
type otherOwner struct {
	until time.Time
	owner groupstore.Owner
}

// WakeOwner implements messaging.GroupHandler: it asks the task that owns
// the group uri, if another, to read user's queue again (#121): this
// task's queue pass found a copy of the group's for user and left it to
// the owner, which may not know of it, as when user registered here.
func (s *Service) WakeOwner(ctx context.Context, uri, user string) {
	mine, at, err := s.Place(ctx, uri)
	if err != nil || mine {
		return
	}
	if err := s.notifier.WakeOwner(ctx, at.SIP, uri, user); err != nil {
		s.metrics.Count("group.wake_failed", 1)
		return
	}
	s.metrics.Count("group.wake_sent", 1)
}

// Lost implements messaging.GroupHandler: the store refused a copy of a
// message in the group uri queued under this task's fence, as another
// task owns the group now. The group is forgotten, so that the next
// invitation for its copies, or write, reads its owner again.
func (s *Service) Lost(uri string) { s.disown(uri) }

// fence is the store.Fence of g's copies: the owner this task queues them
// under, with a heartbeat running (StartHeartbeat), where another task
// may take the group; none without one.
func (s *Service) fence(ctx context.Context, g groupstore.Group) (*store.Fence, error) {
	s.mu.Lock()
	beating := s.beating
	s.mu.Unlock()
	if !beating {
		return nil, nil
	}
	o, err := s.owner(ctx, g)
	if err != nil {
		return nil, err
	}
	return &store.Fence{Group: g.URI, Task: o.Task, Epoch: o.Epoch}, nil
}

// own records that this task owns uri as o, which the store said when
// asked at read: the time before the call, not after it, so that an answer
// held up in the call, past a lease and another task's takeover, is not
// taken for a fresh one (code review on #440).
func (s *Service) own(uri string, o groupstore.Owner, read time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.owned) >= s.cfg.MaxTracked {
		// A group forgotten is only read again.
		clear(s.owned)
	}
	s.owned[uri] = ownership{Owner: o, read: read}
}

// disown forgets that this task owns uri, after a write the store refused
// for its owner: another task took the group over.
func (s *Service) disown(uri string) {
	s.notOwned(uri)
	s.metrics.Count("group.fenced", 1)
}

// notOwned forgets that this task owns uri, which the store says another
// task does. If this task held it till now, the SIP layer ends what it
// holds of the group (Notifier.Disowned), which the owner serves now.
func (s *Service) notOwned(uri string) {
	s.mu.Lock()
	_, held := s.owned[uri]
	delete(s.owned, uri)
	s.mu.Unlock()
	if held {
		s.disowned([]string{uri})
	}
}

// disowned tells the SIP layer of the groups this task no longer owns.
func (s *Service) disowned(uris []string) {
	s.metrics.Count("group.owner_lost", int64(len(uris)))
	for _, uri := range uris {
		s.notifier.Disowned(uri)
	}
}

// StartHeartbeat keeps this task's groups its own (#121): it stores the
// task's heartbeat, AliveUntil TaskLease ahead, every TaskHeartbeat until
// ctx ends, then one at the present time, so that another task may take
// the groups at once rather than after the lease. It stores the first
// beat before it returns, within TaskHeartbeat. Should that one fail, and
// once beats have failed for TaskLease less TaskSkew, the Service writes
// no group (ErrNotOwner) until one lands: another task may have taken
// them. stopped returns once the last beat is stored. It runs where more
// than one task may serve groups; without it, a Service owns whatever it
// touches.
func (s *Service) StartHeartbeat(ctx context.Context) (stopped func()) {
	s.mu.Lock()
	s.beating = true
	s.mu.Unlock()
	bctx, cancel := context.WithTimeout(ctx, s.cfg.TaskHeartbeat)
	s.beat(bctx, s.cfg.Clock.Now().Add(s.cfg.TaskLease))
	cancel()
	// The next beat's timer is set here, before the call returns, so that
	// a clock moved on at once finds it.
	next, t := s.nextBeat()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.heartbeat(ctx, next, t)
	}()
	return func() { <-done }
}

func (s *Service) nextBeat() (chan struct{}, msrp.Timer) {
	next := make(chan struct{})
	return next, s.cfg.Clock.AfterFunc(s.cfg.TaskHeartbeat, func() { close(next) })
}

// beat stores this task's heartbeat, alive until until.
func (s *Service) beat(ctx context.Context, until time.Time) {
	at := s.cfg.Clock.Now()
	if err := s.store.Beat(ctx, groupstore.Task{ID: s.cfg.Task, SIP: s.cfg.SIP, AliveUntil: until}); err != nil {
		s.metrics.Count("task.heartbeat_failed", 1)
		return
	}
	stored := s.cfg.Clock.Now()
	var lost []string
	s.mu.Lock()
	if !stored.Before(s.lastBeat.Add(s.cfg.TaskLease - s.cfg.TaskSkew)) {
		// The last beat's hold ran out before this one was stored, whether
		// this task saw itself lapse (alive) or, paused or held up in the
		// call, never did: another task may have taken any group meanwhile
		// (#121 §4), so each is read again before it is written, and what
		// the SIP layer holds of it ends, as for a group taken over: its
		// participants come back through the owner, whichever it is now.
		lost = slices.Collect(maps.Keys(s.owned))
		clear(s.owned)
	}
	s.lastBeat = at
	s.mu.Unlock()
	s.disowned(lost)
}

// heartbeat beats at next, and every TaskHeartbeat after, until ctx ends.
func (s *Service) heartbeat(ctx context.Context, next chan struct{}, t msrp.Timer) {
	for {
		select {
		case <-next:
		case <-ctx.Done():
			t.Stop()
			rctx, cancel := context.WithTimeout(context.Background(), s.cfg.TaskHeartbeat)
			defer cancel()
			s.beat(rctx, s.cfg.Clock.Now())
			s.mu.Lock()
			s.lastBeat = time.Time{} // and writes no more
			s.mu.Unlock()
			return
		}
		// The next timer before this beat, so that a clock moved on as
		// soon as the beat is stored finds it.
		at := s.cfg.Clock.Now()
		next, t = s.nextBeat()
		bctx, cancel := context.WithTimeout(ctx, s.cfg.TaskHeartbeat)
		s.beat(bctx, at.Add(s.cfg.TaskLease))
		cancel()
	}
}
