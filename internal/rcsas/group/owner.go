package group

import (
	"context"
	"errors"
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
// may: no other task takes its groups.
func (s *Service) alive(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.beating || now.Before(s.lastBeat.Add(s.cfg.TaskLease-s.cfg.TaskSkew))
}

// owner returns the owner this task writes g under, taking g over first
// if its owner has stopped: no heartbeat within its lease and the skew, a
// task that is gone (its record expired), or a task whose address is now
// this one's, which therefore cannot be running. ErrNotOwner if another
// task owns g and is alive, or if this task's own heartbeat has lapsed.
// The groups this task owns are remembered, so that a write to one reads
// nothing more; a fenced write's refusal forgets it (disown).
func (s *Service) owner(ctx context.Context, g groupstore.Group) (groupstore.Owner, error) {
	now := s.cfg.Clock.Now()
	if !s.alive(now) {
		s.metrics.Count("group.owner_lapsed", 1)
		return groupstore.Owner{}, ErrNotOwner
	}
	s.mu.Lock()
	o, ok := s.owned[g.URI]
	s.mu.Unlock()
	if ok {
		return o, nil
	}
	cur, err := s.store.Owner(ctx, g.URI)
	if err != nil {
		return groupstore.Owner{}, err
	}
	if cur.Task == s.cfg.Task {
		s.own(g.URI, cur)
		return cur, nil
	}
	if cur.Task != "" && (cur.SIP == "" || cur.SIP != s.cfg.SIP) {
		t, err := s.store.Task(ctx, cur.Task)
		switch {
		case errors.Is(err, groupstore.ErrNotFound):
		case err != nil:
			return groupstore.Owner{}, err
		case now.Before(t.AliveUntil.Add(s.cfg.TaskSkew)):
			return groupstore.Owner{}, ErrNotOwner
		}
	}
	token, err := s.randomHex(8)
	if err != nil {
		return groupstore.Owner{}, err
	}
	next, err := s.store.TakeOver(ctx, g.URI, cur, s.me(), g.Expires, token)
	if errors.Is(err, groupstore.ErrConflict) {
		// Another takeover came first: of another request on this task
		// (as a group's participants rejoin at once after its owner
		// stopped, #121 Q4), which this one may write under, or of
		// another task, which owns the group now.
		if cur, err = s.store.Owner(ctx, g.URI); err != nil {
			return groupstore.Owner{}, err
		}
		if cur.Task == s.cfg.Task {
			s.own(g.URI, cur)
			return cur, nil
		}
		return groupstore.Owner{}, ErrNotOwner
	}
	if err != nil {
		return groupstore.Owner{}, err
	}
	s.metrics.Count("group.owner_takeover", 1)
	s.own(g.URI, next)
	return next, nil
}

// Owns implements messaging.GroupHandler: whether this task owns the
// group uri, taking it over if its owner has stopped (owner). That another
// task owns it is remembered for TaskHeartbeat, so that a queue of copies
// of its messages costs no read for each; an ended group is no one's.
func (s *Service) Owns(ctx context.Context, uri string) (bool, error) {
	now := s.cfg.Clock.Now()
	s.mu.Lock()
	_, mine := s.owned[uri]
	until, other := s.others[uri]
	s.mu.Unlock()
	switch {
	case mine && s.alive(now):
		return true, nil
	case other && now.Before(until):
		return false, nil
	}
	g, err := s.get(ctx, uri)
	if errors.Is(err, ErrNoGroup) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, err = s.owner(ctx, g)
	if errors.Is(err, ErrNotOwner) {
		s.mu.Lock()
		if len(s.others) >= s.cfg.MaxTracked {
			clear(s.others)
		}
		s.others[uri] = now.Add(s.cfg.TaskHeartbeat)
		s.mu.Unlock()
		return false, nil
	}
	return err == nil, err
}

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

func (s *Service) own(uri string, o groupstore.Owner) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.owned) >= s.cfg.MaxTracked {
		// A group forgotten is only read again.
		clear(s.owned)
	}
	s.owned[uri] = o
}

// disown forgets that this task owns uri, after a write the store refused
// for its owner: another task took the group over.
func (s *Service) disown(uri string) {
	s.mu.Lock()
	delete(s.owned, uri)
	s.mu.Unlock()
	s.metrics.Count("group.fenced", 1)
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
	s.mu.Lock()
	s.lastBeat = at
	s.mu.Unlock()
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
