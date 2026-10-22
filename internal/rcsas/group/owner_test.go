package group

import (
	"context"
	"errors"
	"slices"
	"strings"
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
	// takeOverGate, when set, holds each TakeOver until it is closed, and
	// beatGate each Beat, as a store call slower than the lease would;
	// ownerGate holds the answer of each Owner read, made already.
	takeOverGate, beatGate, ownerGate atomic.Pointer[chan struct{}]
	arrived, beatsHeld, ownersHeld    atomic.Int64
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
	o, err := s.Memory.Owner(ctx, uri)
	if g := s.ownerGate.Load(); g != nil {
		s.ownersHeld.Add(1)
		<-*g
	}
	return o, err
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
	if g := s.beatGate.Load(); g != nil {
		s.beatsHeld.Add(1)
		<-*g
	}
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

// sharedTasks are twoTasks that share their queues too, as tasks do the
// messages table, so that one task's queue pass finds the other's copies.
func sharedTasks(t *testing.T) (a, b *rig, sa, sb *ownedStore) {
	shared, queues := groupstore.NewMemory(), store.NewMemory()
	sa, sb = &ownedStore{Memory: shared}, &ownedStore{Memory: shared}
	a = newRigWith(t, Config{}, engineConfig(), queues, sa, newFakeClock(), 1)
	b = newRigWith(t, Config{}, engineConfig(), queues, sb, newFakeClock(), 2)
	a.beat(t)
	b.beat(t)
	return a, b, sa, sb
}

// passFailing is pass for a rig whose heartbeats fail (st's): it waits at
// each for the beat to have been tried, as none is stored.
func (r *rig) passFailing(t *testing.T, st *ownedStore, d time.Duration) {
	t.Helper()
	for d > 0 {
		step := min(d, r.s.cfg.TaskHeartbeat-r.clock.Now().Sub(r.lastBeat())%r.s.cfg.TaskHeartbeat)
		tried := st.bs.Load()
		r.clock.Advance(step)
		d -= step
		if r.clock.Now().Sub(r.lastBeat())%r.s.cfg.TaskHeartbeat == 0 {
			waitFor(t, "the heartbeat tried", func() bool { return st.bs.Load() > tried })
		}
	}
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

// The code review's reproduction (#440, major 1): a's beat is held up in
// the store past its lease, b takes the group over meanwhile, and the
// beat lands. a never saw itself lapse, by its own clock, so it would go
// on taking the group for its own: it reads the owner again instead, and
// writes nothing under it.
func TestABeatStoredAfterItsLeaseRanOutForgetsTheGroups(t *testing.T) {
	a, b, sa, _ := twoTasks(t, Config{}, Config{})
	g := a.create(bob) // bob's Join leaves a remembering the group
	sa.failBeats.Store(true)
	a.passFailing(t, sa, 2*DefaultTaskHeartbeat)
	sa.failBeats.Store(false)
	gate := make(chan struct{})
	sa.beatGate.Store(&gate)
	a.clock.Advance(DefaultTaskHeartbeat) // the third beat, held
	waitFor(t, "the held beat", func() bool { return sa.beatsHeld.Load() == 1 })
	a.clock.Advance(DefaultTaskLease - 2*DefaultTaskHeartbeat + DefaultTaskSkew + time.Second)
	b.pass(t, DefaultTaskLease+DefaultTaskSkew)
	if err := b.add(t, g.URI, carol); err != nil {
		t.Fatal(err)
	}
	sa.beatGate.Store(nil)
	close(gate)
	waitFor(t, "a's beats", func() bool { return a.lastBeat().Equal(a.clock.Now()) })
	if !a.s.alive(a.clock.Now()) {
		t.Fatal("a's own heartbeat lapsed: the test means a task that never saw it")
	}
	updates := sa.updates.Load()
	if err := a.add(t, g.URI, dave); !errors.Is(err, ErrNotOwner) || sa.updates.Load() != updates || a.m.get("group.fenced") != 0 {
		t.Fatalf("a's Add = %v; %d writes tried, %d fenced", err, sa.updates.Load()-updates, a.m.get("group.fenced"))
	}
	if owns, err := a.s.Owns(t.Context(), g.URI); err != nil || owns {
		t.Fatalf("a's Owns = %v, %v", owns, err)
	}
}

// #121 §4: a task that sees its own heartbeat lapse forgets the groups it
// owned, so that once a beat lands again it reads each one's owner before
// it writes it, rather than trying a write the store refuses.
func TestATaskWhoseHeartbeatLapsedForgetsItsGroups(t *testing.T) {
	a, b, sa, _ := twoTasks(t, Config{}, Config{})
	g := a.create(bob)
	sa.failBeats.Store(true)
	a.passFailing(t, sa, DefaultTaskLease)
	b.pass(t, DefaultTaskLease+DefaultTaskSkew)
	if err := b.add(t, g.URI, carol); err != nil {
		t.Fatal(err)
	}
	if err := a.add(t, g.URI, dave); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("a's Add while lapsed = %v", err)
	}
	sa.failBeats.Store(false)
	a.pass(t, DefaultTaskHeartbeat)
	updates := sa.updates.Load()
	if err := a.add(t, g.URI, dave); !errors.Is(err, ErrNotOwner) || sa.updates.Load() != updates || a.m.get("group.fenced") != 0 {
		t.Fatalf("a's Add = %v; %d writes tried, %d fenced", err, sa.updates.Load()-updates, a.m.get("group.fenced"))
	}
}

// QA's reproduction (#440): an owner paused while another task took its
// group over, which beats again and writes nothing to the group, invites
// nobody for the new owner's copies: an invitation is not fenced, so
// Owns reads the owner again once a heartbeat has passed.
func TestQAResumedOwnerInvitesNothingForTheNewOwnersCopies(t *testing.T) {
	a, b, sa, _ := sharedTasks(t)
	g := a.create(bob)
	sa.failBeats.Store(true) // a pauses
	b.pass(t, DefaultTaskLease+DefaultTaskSkew)
	if err := b.add(t, g.URI, carol); err != nil { // b takes the group over
		t.Fatal(err)
	}
	if err := b.write(t, g.URI, alice, "m1"); err != nil { // a copy for bob, queued by b
		t.Fatal(err)
	}
	sa.failBeats.Store(false) // a resumes and beats again
	a.pass(t, DefaultTaskLease+DefaultTaskSkew+time.Second)
	a.e.Wake(bob, g.URI, false) // as bob registering on a would
	waitFor(t, "a's queue pass", func() bool { return a.m.get("delivery.group_not_owned") > 0 })
	a.quiet()
	if n := a.invitesOf(g, bob); n != 0 {
		t.Fatalf("a, which lost the group, invited bob %d times for b's copy", n)
	}
	// What Owns read, a's next write takes too: it tries none.
	updates := sa.updates.Load()
	if err := a.add(t, g.URI, dave); !errors.Is(err, ErrNotOwner) || sa.updates.Load() != updates {
		t.Fatalf("a's Add = %v; %d writes tried", err, sa.updates.Load()-updates)
	}
}

// QA on #440: a copy the store refused for its fence tells the group
// service at once that the group is another task's, before a heartbeat
// has passed.
func TestARefusedCopyForgetsTheGroup(t *testing.T) {
	a, b, sa, _ := twoTasks(t, Config{}, Config{})
	g := a.create(bob)
	sa.failBeats.Store(true)
	b.pass(t, DefaultTaskLease+DefaultTaskSkew)
	if err := b.add(t, g.URI, carol); err != nil {
		t.Fatal(err)
	}
	if err := a.write(t, g.URI, alice, "m1"); !errors.Is(err, store.ErrNotOwner) {
		t.Fatalf("a's write = %v", err)
	}
	if owns, err := a.s.Owns(t.Context(), g.URI); err != nil || owns {
		t.Fatalf("a's Owns after its copy was refused = %v, %v", owns, err)
	}
}

// Code review on #440 (minor 2): Owns during a brief lapse of this task's
// own heartbeat is false, but not remembered as another task owning the
// group: once a beat lands, the group is this task's again at once.
func TestALapseOfItsOwnIsNotTakenForAnotherOwner(t *testing.T) {
	a, _, sa, _ := twoTasks(t, Config{}, Config{})
	g := a.create(bob)
	sa.failBeats.Store(true)
	a.passFailing(t, sa, DefaultTaskLease-time.Second)
	if owns, err := a.s.Owns(t.Context(), g.URI); err != nil || owns {
		t.Fatalf("a's Owns while lapsed = %v, %v", owns, err)
	}
	sa.failBeats.Store(false)
	a.pass(t, time.Second) // the next beat lands, within a heartbeat
	if owns, err := a.s.Owns(t.Context(), g.URI); err != nil || !owns {
		t.Fatalf("a's Owns once a beat landed = %v, %v", owns, err)
	}
}

func (n *notifier) disownedOnes() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.disowned...)
}

func (n *notifier) wakesSent() []wake {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]wake(nil), n.wakes...)
}

// #121 D3: Place names where a group is served: here for its owner, else
// the owner's SIP instance address, which the SIP layer forwards to.
func TestPlaceNamesTheOwnersAddress(t *testing.T) {
	a, b, _, _ := twoTasks(t, Config{SIP: "10.0.1.1:5060"}, Config{SIP: "10.0.1.2:5060"})
	g := a.create(bob)
	if mine, at, err := a.s.Place(t.Context(), g.URI); err != nil || !mine || at != (groupstore.Owner{}) {
		t.Fatalf("a's Place = %v, %+v, %v", mine, at, err)
	}
	mine, at, err := b.s.Place(t.Context(), g.URI)
	if err != nil || mine || at.SIP != "10.0.1.1:5060" || at.Task != a.s.cfg.Task {
		t.Fatalf("b's Place = %v, %+v, %v", mine, at, err)
	}
	// Remembered for a heartbeat, the address with it.
	if _, at, _ := b.s.Place(t.Context(), g.URI); at.SIP != "10.0.1.1:5060" {
		t.Fatalf("b's Place again names %q", at.SIP)
	}
	if _, _, err := b.s.Place(t.Context(), "sip:chat-"+strings.Repeat("0", 32)+"@"+host); !errors.Is(err, ErrNoGroup) {
		t.Fatalf("Place of no group = %v", err)
	}
}

// #121 D3: the conference URI of a Contribution-ID is the one Create gives
// the group, so that the SIP layer finds a creator's group, and its
// owner, before it is asked to make it.
func TestURIForIsTheGroupsURI(t *testing.T) {
	r := newRig(t, Config{})
	g, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: []Invitee{{Identity: bob}}, Contribution: "gch4t1"})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.s.URIFor("gch4t1"); got != g.URI {
		t.Fatalf("URIFor = %s, the group is %s", got, g.URI)
	}
}

// #121 Q4: a task that finds another owns a group it held tells the SIP
// layer, which ends what it holds of the group; one that never held the
// group says nothing, at every look.
func TestAGroupTakenOverIsDisownedOnce(t *testing.T) {
	a, b, sa, _ := twoTasks(t, Config{}, Config{})
	g := a.create(bob) // bob's Join: a holds the group
	sa.failBeats.Store(true)
	b.pass(t, DefaultTaskLease+DefaultTaskSkew)
	if err := b.add(t, g.URI, carol); err != nil {
		t.Fatal(err)
	}
	if err := a.add(t, g.URI, dave); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("a's Add = %v", err)
	}
	if got := a.n.disownedOnes(); len(got) != 1 || got[0] != g.URI || a.m.get("group.owner_lost") != 1 {
		t.Fatalf("disowned %v, %d lost", got, a.m.get("group.owner_lost"))
	}
	if err := a.add(t, g.URI, dave); !errors.Is(err, ErrNotOwner) || len(a.n.disownedOnes()) != 1 {
		t.Fatalf("a's Add again = %v; disowned %v", err, a.n.disownedOnes())
	}
	if _, _, err := b.s.Place(t.Context(), g.URI); err != nil || len(b.n.disownedOnes()) != 0 {
		t.Fatalf("b's Place = %v; b disowned %v", err, b.n.disownedOnes())
	}
}

// #121 §4 and Q4, the lead's decision on #464: a task whose own lease runs
// out with no beat stored gives up every group it held then, without
// waiting for a beat to land: whether the store is out for every task, or
// this one alone and another takes the groups over, the sessions here can
// deliver nothing. Their participants come back through whichever task
// owns them. A beat that lands later gives nothing up twice.
func TestALapseDisownsEveryGroupHeld(t *testing.T) {
	for _, outage := range []string{"every task", "this task only"} {
		t.Run(outage, func(t *testing.T) {
			a, b, sa, sb := twoTasks(t, Config{}, Config{})
			g1, g2 := a.create(bob), a.create(carol)
			sa.failBeats.Store(true)
			if outage == "every task" {
				sb.failBeats.Store(true)
			}
			a.passFailing(t, sa, DefaultTaskLease-DefaultTaskSkew-time.Second)
			if got := a.n.disownedOnes(); len(got) != 0 {
				t.Fatalf("disowned %v while the lease held", got)
			}
			a.passFailing(t, sa, DefaultTaskHeartbeat)
			got := a.n.disownedOnes()
			slices.Sort(got)
			want := []string{g1.URI, g2.URI}
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("disowned %v once the lease ran out, want %v", got, want)
			}
			if outage == "this task only" {
				b.pass(t, DefaultTaskLease+DefaultTaskSkew)
				if err := b.add(t, g1.URI, dave); err != nil {
					t.Fatalf("b's takeover: %v", err)
				}
			}
			sa.failBeats.Store(false)
			a.pass(t, DefaultTaskHeartbeat)
			if got := a.n.disownedOnes(); len(got) != 2 {
				t.Errorf("disowned %v once a beat landed, want the two only", got)
			}
		})
	}
}

// QA on #464: a group dropped from what this task remembers owning, at
// MaxTracked, is given up as a lost one is, so that a takeover found later
// does not leave its sessions here.
func TestQA464AGroupForgottenAtMaxTrackedIsStillDisowned(t *testing.T) {
	a, b, sa, _ := twoTasks(t, Config{MaxTracked: 3}, Config{})
	g1 := a.create(bob)
	a.create(carol)
	a.create(dave)
	a.create(bob, carol)
	sa.failBeats.Store(true)
	b.pass(t, DefaultTaskLease+DefaultTaskSkew)
	if err := b.add(t, g1.URI, erin); err != nil {
		t.Fatal(err)
	}
	if err := a.add(t, g1.URI, dave); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("a's Add = %v", err)
	}
	if got := a.n.disownedOnes(); !slices.Contains(got, g1.URI) {
		t.Fatalf("a held g1 and lost it, but disowned %v", got)
	}
}

// QA on #464: an ended group is not kept among those this task owns.
func TestAnEndedGroupIsForgotten(t *testing.T) {
	r := newRig(t, Config{})
	g := r.create(bob)
	r.s.mu.Lock()
	_, held := r.s.owned[g.URI]
	r.s.mu.Unlock()
	if !held {
		t.Fatal("the group is not remembered as owned")
	}
	r.clock.Advance(DefaultIdleTTL + time.Hour)
	if _, _, err := r.s.Place(t.Context(), g.URI); !errors.Is(err, ErrNoGroup) {
		t.Fatalf("Place of an ended group = %v", err)
	}
	r.s.mu.Lock()
	_, ok := r.s.owned[g.URI]
	r.s.mu.Unlock()
	if ok {
		t.Error("an ended group is still remembered as owned")
	}
}

// #121 T8: WakeOwner asks the owner, another task, to read a queue, at
// its address; a task that owns the group itself has no one to ask.
func TestWakeOwnerAsksTheOwner(t *testing.T) {
	a, b, _, _ := twoTasks(t, Config{SIP: "10.0.1.1:5060"}, Config{SIP: "10.0.1.2:5060"})
	g := a.create(bob)
	b.s.WakeOwner(t.Context(), g.URI, bob, true)
	if got := b.n.wakesSent(); len(got) != 1 || got[0] != (wake{"10.0.1.1:5060", g.URI, bob, true}) || b.m.get("group.wake_sent") != 1 {
		t.Fatalf("wakes %+v", got)
	}
	a.s.WakeOwner(t.Context(), g.URI, bob, false)
	if got := a.n.wakesSent(); len(got) != 0 {
		t.Fatalf("the owner woke %+v", got)
	}
}

// The code review's reproduction (#440, re-review minor): an owner read
// whose answer is held up past the lease, while another task takes the
// group over and this task's late beat forgets its groups, is remembered
// as of when it was asked, not when it came: the next Owns reads the
// owner again, rather than taking the old answer for a fresh one for a
// heartbeat.
func TestAnOwnerAnswerHeldPastTheLeaseIsNotTakenForFresh(t *testing.T) {
	a, b, sa, _ := twoTasks(t, Config{}, Config{})
	g := a.create(bob)
	a.pass(t, DefaultTaskHeartbeat) // what a remembers is a heartbeat old
	gate := make(chan struct{})
	sa.ownerGate.Store(&gate)
	asked := make(chan bool, 1)
	go func() {
		owns, _ := a.s.Owns(context.Background(), g.URI)
		asked <- owns
	}()
	waitFor(t, "the held owner read", func() bool { return sa.ownersHeld.Load() == 1 })
	sa.failBeats.Store(true)
	a.passFailing(t, sa, DefaultTaskLease)
	// a's last stored beat was a heartbeat in.
	b.pass(t, DefaultTaskHeartbeat+DefaultTaskLease+DefaultTaskSkew)
	if err := b.add(t, g.URI, carol); err != nil {
		t.Fatal(err)
	}
	sa.failBeats.Store(false)
	a.pass(t, DefaultTaskHeartbeat) // the late beat forgets a's groups
	sa.ownerGate.Store(nil)
	close(gate)
	<-asked // the held call's own answer is the old one: no fence for it
	if owns, err := a.s.Owns(t.Context(), g.URI); err != nil || owns {
		t.Fatalf("a's next Owns = %v, %v", owns, err)
	}
}

// QA on #440 (minor 2): the bound is one heartbeat, not a lease. a, paused
// while b took its group over, its clock behind b's, wakes bob's queue a
// heartbeat and a second after it beats again: it reads the owner again,
// and invites nobody for b's copy.
func TestAResumedOwnerInvitesNothingOneHeartbeatLater(t *testing.T) {
	a, b, sa, _ := sharedTasks(t)
	g := a.create(bob)
	sa.failBeats.Store(true)
	b.pass(t, DefaultTaskLease+DefaultTaskSkew)
	if err := b.add(t, g.URI, carol); err != nil {
		t.Fatal(err)
	}
	if err := b.write(t, g.URI, alice, "m1"); err != nil {
		t.Fatal(err)
	}
	sa.failBeats.Store(false)
	a.pass(t, DefaultTaskHeartbeat+time.Second)
	a.e.Wake(bob, g.URI, false)
	waitFor(t, "a's queue pass", func() bool { return a.m.get("delivery.group_not_owned") > 0 || a.invitesOf(g, bob) > 0 })
	a.quiet()
	if n := a.invitesOf(g, bob); n != 0 {
		t.Fatalf("a invited bob %d times a heartbeat after it resumed", n)
	}
}

// QA on #440 (minor 2): the threshold is the last beat's hold, the lease
// less the skew. a's beat is held in the store until a second past it,
// while b, its clock the skew ahead, takes the group over: a's next write
// is not even tried.
func TestABeatStoredJustPastItsHoldForgetsTheGroups(t *testing.T) {
	a, b, sa, _ := twoTasks(t, Config{}, Config{})
	g := a.create(bob)
	t0 := a.clock.Now()
	b.pass(t, DefaultTaskSkew) // b's clock the skew ahead of a's
	gate := make(chan struct{})
	sa.beatGate.Store(&gate)
	a.clock.Advance(DefaultTaskHeartbeat) // a's next beat, held
	waitFor(t, "the held beat", func() bool { return sa.beatsHeld.Load() == 1 })
	b.pass(t, DefaultTaskLease) // b at t0 + lease + skew: a's record has run out
	if err := b.add(t, g.URI, carol); err != nil {
		t.Fatal(err)
	}
	a.clock.Advance(t0.Add(DefaultTaskLease - DefaultTaskSkew + time.Second).Sub(a.clock.Now()))
	sa.beatGate.Store(nil)
	close(gate)
	waitFor(t, "a's beat stored", func() bool { return !a.lastBeat().Equal(t0) })
	updates := sa.updates.Load()
	if err := a.add(t, g.URI, dave); !errors.Is(err, ErrNotOwner) || sa.updates.Load() != updates {
		t.Fatalf("a's Add = %v; %d writes tried", err, sa.updates.Load()-updates)
	}
}

// QA on #440 (nit): the owner's own Owns reads nothing within a heartbeat
// of the store's word, as docs/rcs-as.md counts it: a queue pass asks for
// every copy.
func TestTheOwnersOwnsReadsNothingWithinAHeartbeat(t *testing.T) {
	a, _, sa, _ := twoTasks(t, Config{}, Config{})
	g := a.create(bob)
	if owns, err := a.s.Owns(t.Context(), g.URI); err != nil || !owns {
		t.Fatalf("a's Owns = %v, %v", owns, err)
	}
	reads := sa.gets.Load() + sa.owners.Load() + sa.tasks.Load()
	for range 10 {
		if owns, _ := a.s.Owns(t.Context(), g.URI); !owns {
			t.Fatal("a does not own its group")
		}
	}
	if n := sa.gets.Load() + sa.owners.Load() + sa.tasks.Load() - reads; n != 0 {
		t.Fatalf("10 Owns by the owner within a heartbeat read the store %d times", n)
	}
}

// Security review on #464: that there is no such group is remembered a
// moment, so that requests for one cost no read each, and forgotten once
// this task makes it.
func TestNoGroupIsRememberedAMoment(t *testing.T) {
	a, _, sa, _ := twoTasks(t, Config{}, Config{})
	uri := a.s.URIFor("gch4t9")
	if _, _, err := a.s.Place(t.Context(), uri); !errors.Is(err, ErrNoGroup) {
		t.Fatalf("Place = %v", err)
	}
	gets := sa.gets.Load()
	if _, _, err := a.s.Place(t.Context(), uri); !errors.Is(err, ErrNoGroup) || sa.gets.Load() != gets {
		t.Fatalf("Place again = %v, %d reads", err, sa.gets.Load()-gets)
	}
	if _, err := a.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: []Invitee{{Identity: bob}}, Contribution: "gch4t9"}); err != nil {
		t.Fatal(err)
	}
	if mine, _, err := a.s.Place(t.Context(), uri); err != nil || !mine {
		t.Fatalf("Place of the group made = %v, %v", mine, err)
	}
	other := a.s.URIFor("gch4t8")
	_, _, _ = a.s.Place(t.Context(), other)
	a.clock.Advance(absentFor)
	gets = sa.gets.Load()
	if _, _, _ = a.s.Place(t.Context(), other); sa.gets.Load() == gets {
		t.Error("no read once the moment had passed")
	}
}
