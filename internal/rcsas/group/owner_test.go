package group

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// ownedStore is a groups store that counts what each change costs, and
// whose heartbeats can be made to fail, as when a task loses the store.
type ownedStore struct {
	*groupstore.Memory
	failBeats                                   atomic.Bool
	gets, updates, owners, tasks, takeovers, bs atomic.Int64
	// takeOverGate, when set, holds each TakeOver until it is closed.
	takeOverGate atomic.Pointer[chan struct{}]
	arrived      atomic.Int64
}

func newOwnedStore() *ownedStore { return &ownedStore{Memory: groupstore.NewMemory()} }

func (s *ownedStore) Get(ctx context.Context, uri string, now time.Time) (groupstore.Group, error) {
	s.gets.Add(1)
	return s.Memory.Get(ctx, uri, now)
}

func (s *ownedStore) Update(ctx context.Context, g groupstore.Group, o groupstore.Owner, token string) error {
	s.updates.Add(1)
	return s.Memory.Update(ctx, g, o, token)
}

func (s *ownedStore) Owner(ctx context.Context, uri string) (groupstore.Owner, error) {
	s.owners.Add(1)
	return s.Memory.Owner(ctx, uri)
}

func (s *ownedStore) Task(ctx context.Context, id string) (groupstore.Task, error) {
	s.tasks.Add(1)
	return s.Memory.Task(ctx, id)
}

func (s *ownedStore) TakeOver(ctx context.Context, uri string, from, to groupstore.Owner, expires time.Time, token string) (groupstore.Owner, error) {
	s.takeovers.Add(1)
	if g := s.takeOverGate.Load(); g != nil {
		s.arrived.Add(1)
		<-*g
	}
	return s.Memory.TakeOver(ctx, uri, from, to, expires, token)
}

func (s *ownedStore) Beat(ctx context.Context, t groupstore.Task) error {
	s.bs.Add(1)
	if s.failBeats.Load() {
		return errors.New("fake: the store failed")
	}
	return s.Memory.Beat(ctx, t)
}

// twoTasks are tasks a and b sharing one table, each through a store of
// its own (whose heartbeats fail apart) and with a clock of its own, so
// that one may lag behind the other as a task paused would.
func twoTasks(t *testing.T, cfgA, cfgB Config) (a, b *rig, sa, sb *ownedStore) {
	shared := groupstore.NewMemory()
	sa, sb = &ownedStore{Memory: shared}, &ownedStore{Memory: shared}
	a = newRigWith(t, cfgA, engineConfig(), store.NewMemory(), sa, newFakeClock(), 1)
	b = newRigWith(t, cfgB, engineConfig(), store.NewMemory(), sb, newFakeClock(), 2)
	a.beat(t)
	b.beat(t)
	return a, b, sa, sb
}

// add has who add someone new to uri, a change to write.
func (r *rig) add(t *testing.T, uri, who string) error {
	t.Helper()
	return r.s.Add(t.Context(), uri, alice, []Invitee{{Identity: who}})
}

// #121 T3: a task whose heartbeat has lapsed loses its groups to the next
// task that changes one, at a raised epoch, but not before the lease and
// the skew have passed.
func TestAGroupIsTakenOverOnceItsOwnersHeartbeatLapses(t *testing.T) {
	a, b, sa, _ := twoTasks(t, Config{}, Config{})
	g := a.create(bob)
	sa.failBeats.Store(true) // a can no longer beat
	b.pass(t, DefaultTaskLease+DefaultTaskSkew-time.Second)
	if err := b.add(t, g.URI, carol); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("b's Add before a's lease and skew passed = %v", err)
	}
	b.pass(t, time.Second)
	if err := b.add(t, g.URI, carol); err != nil {
		t.Fatalf("b's Add after = %v", err)
	}
	if o := b.owner(t, g.URI); o.Task != b.s.cfg.Task || o.Epoch != 2 || b.m.get("group.owner_takeover") != 1 {
		t.Fatalf("owner %+v, %d takeovers", o, b.m.get("group.owner_takeover"))
	}
}

// #121 T4: the old owner, paused while another task took its group (its
// own clock still sees its lease), writes nothing: the store refuses its
// fence, and it gives the group up. Two tasks never both change a group.
func TestAPausedOwnerThatLostItsGroupWritesNothing(t *testing.T) {
	a, b, sa, _ := twoTasks(t, Config{}, Config{})
	g := a.create(bob)
	sa.failBeats.Store(true)
	b.pass(t, DefaultTaskLease+DefaultTaskSkew)
	if err := b.add(t, g.URI, carol); err != nil {
		t.Fatal(err)
	}
	before, _ := b.s.Get(t.Context(), g.URI)
	// a has not seen time pass: its own heartbeat still holds, in its view.
	if err := a.add(t, g.URI, dave); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("the paused owner's Add = %v", err)
	}
	if after, _ := b.s.Get(t.Context(), g.URI); after.Rev != before.Rev || a.m.get("group.fenced") != 1 {
		t.Fatalf("rev %d, was %d; %d fenced", after.Rev, before.Rev, a.m.get("group.fenced"))
	}
	// Forgotten: a reads the owner again, which is b, alive.
	if err := a.add(t, g.URI, dave); !errors.Is(err, ErrNotOwner) || a.m.get("group.fenced") != 1 {
		t.Fatalf("a's next Add = %v, %d fenced", err, a.m.get("group.fenced"))
	}
}

// #121 T5: a task that comes up on a dead task's address takes its groups
// at once: that task cannot be running, and requests forwarded to the
// address would come back to the new one.
func TestATaskOnTheOwnersAddressTakesItsGroupsAtOnce(t *testing.T) {
	a, b, _, sb := twoTasks(t, Config{SIP: "10.0.1.1:5060"}, Config{SIP: "10.0.1.1:5060"})
	g := a.create(bob)
	if err := b.add(t, g.URI, carol); err != nil {
		t.Fatalf("Add on a's address = %v", err)
	}
	if o := b.owner(t, g.URI); o.Task != b.s.cfg.Task || sb.tasks.Load() != 0 {
		t.Fatalf("owner %+v; %d heartbeats read", o, sb.tasks.Load())
	}
}

// #121 T9: a task that stops stores a last heartbeat at its present time,
// so that its groups are taken at once, and writes no more itself.
func TestAStoppedTasksGroupsAreTakenAtOnce(t *testing.T) {
	st := newOwnedStore()
	a := newRigWith(t, Config{}, engineConfig(), store.NewMemory(), st, newFakeClock(), 1)
	b := newRigWith(t, Config{}, engineConfig(), store.NewMemory(), st, a.clock, 2)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := a.s.StartHeartbeat(ctx)
	waitFor(t, "a's first heartbeat", func() bool { return a.s.alive(a.clock.Now()) })
	b.beat(t)
	g := a.create(bob)
	cancel()
	stopped()
	if err := a.add(t, g.URI, carol); !errors.Is(err, ErrNotOwner) || a.m.get("group.owner_lapsed") != 1 {
		t.Fatalf("the stopped task's Add = %v", err)
	}
	if err := b.add(t, g.URI, carol); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("b's Add within the skew of a's last heartbeat = %v", err)
	}
	b.pass(t, DefaultTaskSkew) // the last heartbeat's time, and the skew
	if err := b.add(t, g.URI, carol); err != nil {
		t.Fatalf("b's Add = %v", err)
	}
}

// A task whose own heartbeat has failed for its lease less the skew writes
// no group, made or changed: another task may have taken them already.
// Once a beat lands again, it writes again.
func TestATaskWhoseHeartbeatLapsedStopsWriting(t *testing.T) {
	st := newOwnedStore()
	r := newRigWith(t, Config{}, engineConfig(), store.NewMemory(), st, newFakeClock(), 1)
	r.beat(t)
	g := r.create(bob)
	st.failBeats.Store(true)
	for i := range 4 {
		r.clock.Advance(DefaultTaskHeartbeat)
		waitFor(t, "a failed beat", func() bool { return r.m.get("task.heartbeat_failed") == int64(i+1) })
	}
	if _, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: []Invitee{{Identity: carol}}}); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("Create = %v", err)
	}
	if err := r.add(t, g.URI, carol); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("Add = %v", err)
	}
	st.failBeats.Store(false)
	r.clock.Advance(DefaultTaskHeartbeat)
	waitFor(t, "a beat again", func() bool { return r.s.alive(r.clock.Now()) })
	if err := r.add(t, g.URI, carol); err != nil {
		t.Fatalf("Add after the heartbeat came back = %v", err)
	}
}

// A group stored before #121 has no owner: the first task to change it
// takes it from none, at epoch 1.
func TestAGroupWithoutAnOwnerIsTakenByTheFirstWriter(t *testing.T) {
	st := newOwnedStore()
	r := newRigWith(t, Config{}, engineConfig(), store.NewMemory(), st, newFakeClock(), 1)
	r.beat(t)
	g := r.create(bob)
	st.Disown(g.URI)
	r2 := newRigWith(t, Config{}, engineConfig(), store.NewMemory(), st, r.clock, 2)
	r2.beat(t)
	if err := r2.add(t, g.URI, carol); err != nil {
		t.Fatal(err)
	}
	if o := r2.owner(t, g.URI); o.Task != r2.s.cfg.Task || o.Epoch != 1 {
		t.Fatalf("owner %+v", o)
	}
}

// #121 T11: a change of a group this task owns costs what it did before
// #121, a read and a write of the group: the owner is remembered once read
// (Create does not know the epoch the store gave it, code review on #431),
// and no heartbeat is read.
func TestAChangeOfAnOwnedGroupReadsNoOwner(t *testing.T) {
	st := newOwnedStore()
	r := newRigWith(t, Config{}, engineConfig(), store.NewMemory(), st, newFakeClock(), 1)
	r.beat(t)
	g, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: []Invitee{{Identity: bob}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.add(t, g.URI, carol); err != nil || st.owners.Load() != 1 {
		t.Fatalf("the first change = %v, %d owner reads", err, st.owners.Load())
	}
	gets, updates, owners := st.gets.Load(), st.updates.Load(), st.owners.Load()
	if _, err := r.s.Join(t.Context(), g.URI, bob, "Bob"); err != nil || st.updates.Load() == updates {
		t.Fatalf("Join = %v, no write", err)
	}
	if st.gets.Load()-gets != 1 || st.updates.Load()-updates != 1 || st.owners.Load()-owners+st.tasks.Load()+st.takeovers.Load() != 0 {
		t.Fatalf("a change: %d gets, %d updates, %d owner reads, %d heartbeat reads, %d takeovers",
			st.gets.Load()-gets, st.updates.Load()-updates, st.owners.Load()-owners, st.tasks.Load(), st.takeovers.Load())
	}
}

// Code review on #431: two requests of one task take a group over at once,
// as its participants rejoin together after its owner stopped (#121 Q4).
// The one whose takeover came second finds its own task the owner, and
// goes on: both changes land, after one takeover.
func TestTwoRequestsOfOneTaskTakeAGroupOverAtOnce(t *testing.T) {
	a, b, sa, sb := twoTasks(t, Config{}, Config{})
	g := a.create(bob)
	sa.failBeats.Store(true)
	b.pass(t, DefaultTaskLease+DefaultTaskSkew)
	gate := make(chan struct{})
	sb.takeOverGate.Store(&gate)
	errs := make(chan error, 2)
	for _, who := range []string{carol, dave} {
		go func() { errs <- b.add(t, g.URI, who) }()
	}
	waitFor(t, "both takeovers", func() bool { return sb.arrived.Load() == 2 })
	close(gate)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("an Add = %v", err)
		}
	}
	got, _ := b.s.Get(t.Context(), g.URI)
	if _, ok := got.Participant(carol); !ok || b.m.get("group.owner_takeover") != 1 {
		t.Fatalf("participants %+v, %d takeovers", got.Participants, b.m.get("group.owner_takeover"))
	}
	if _, ok := got.Participant(dave); !ok {
		t.Fatalf("participants %+v", got.Participants)
	}
}

// write has who write text in uri through r's engine.
func (r *rig) write(t *testing.T, uri, who, id string) error {
	t.Helper()
	return r.e.SubmitGroup(t.Context(), messaging.GroupOrigin{Group: uri, Sender: who, CPIM: message(t, who, id, "x", 0)})
}

// #121 D2: a message written on a task that does not own the group, its
// owner alive, is refused there and queues nothing: its copies are the
// owner's to queue (D3 forwards the session there).
func TestAMessageOnATaskThatDoesNotOwnTheGroupQueuesNothing(t *testing.T) {
	a, b, _, _ := twoTasks(t, Config{}, Config{})
	g := a.create(bob)
	if err := b.write(t, g.URI, alice, "m1"); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("the write on b = %v", err)
	}
	if n := b.queues.Len(bob); n != 0 {
		t.Fatalf("%d copies queued on b", n)
	}
	if err := a.write(t, g.URI, alice, "m2"); err != nil {
		t.Fatalf("the write on the owner = %v", err)
	}
	if n := a.queues.Len(bob); n != 1 {
		t.Fatalf("%d copies queued on a", n)
	}
}

// #121 D2 (T4): an owner paused while another task took its group over
// (its own clock still sees its lease, and it remembers the group as its
// own) queues no copy of a message written to it: each is queued under its
// fence, which the store no longer holds.
func TestAPausedOwnerQueuesNoCopy(t *testing.T) {
	a, b, sa, _ := twoTasks(t, Config{}, Config{})
	g := a.create(bob)
	if err := a.write(t, g.URI, alice, "m1"); err != nil {
		t.Fatal(err)
	}
	sa.failBeats.Store(true)
	b.pass(t, DefaultTaskLease+DefaultTaskSkew)
	if err := b.add(t, g.URI, carol); err != nil {
		t.Fatal(err)
	}
	before := a.queues.Len(bob)
	if err := a.write(t, g.URI, alice, "m2"); !errors.Is(err, store.ErrNotOwner) {
		t.Fatalf("the paused owner's write = %v", err)
	}
	if a.queues.Len(bob) != before || a.m.get("group.fanout.not_owner") != 1 {
		t.Fatalf("bob's queue %d, was %d; %d refused", a.queues.Len(bob), before, a.m.get("group.fanout.not_owner"))
	}
}

// #121 D2: whether this task owns a group is remembered for a heartbeat
// when another task does, so that a queue of the group's copies costs no
// read of the store each.
func TestThatAnotherTaskOwnsAGroupIsRemembered(t *testing.T) {
	a, b, _, sb := twoTasks(t, Config{}, Config{})
	g := a.create(bob)
	if owns, err := b.s.Owns(t.Context(), g.URI); err != nil || owns {
		t.Fatalf("b owns a's group: %v, %v", owns, err)
	}
	reads := sb.gets.Load() + sb.owners.Load() + sb.tasks.Load()
	if owns, _ := b.s.Owns(t.Context(), g.URI); owns || sb.gets.Load()+sb.owners.Load()+sb.tasks.Load() != reads {
		t.Fatal("b read the store again within a heartbeat")
	}
	if owns, err := a.s.Owns(t.Context(), g.URI); err != nil || !owns {
		t.Fatalf("a does not own its group: %v, %v", owns, err)
	}
	b.pass(t, DefaultTaskHeartbeat)
	if b.s.Owns(t.Context(), g.URI); sb.gets.Load()+sb.owners.Load()+sb.tasks.Load() == reads {
		t.Fatal("b never asked again")
	}
}
