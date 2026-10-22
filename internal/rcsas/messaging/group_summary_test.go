package messaging

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// queuedReceipts counts the group notifications in user's queue, and the
// summaries among them apart.
func queuedReceipts(t *testing.T, r *rig, user string) (notes, summaries int) {
	t.Helper()
	ms, err := r.store.Pending(context.Background(), user, "", r.clock.Now(), 10_000)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		switch {
		case m.Summary:
			summaries++
		case m.Notification && m.Mode == store.Group:
			notes++
		}
	}
	return notes, summaries
}

// summaryID is the ID of the one summary queued for user.
func summaryID(t *testing.T, r *rig, user string) string {
	t.Helper()
	ms, err := r.store.Pending(context.Background(), user, "", r.clock.Now(), 10_000)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.Summary {
			return m.ID
		}
	}
	t.Fatal("no summary queued")
	return ""
}

// author is an author's client in a group as rcsjta reads notifications
// there (GroupChatSession): only a CPIM message whose content is
// message/imdn+xml and whose To is the author, one status for the
// participant in its From; a display status stands for delivery too.
// readByAll is rcsjta's GroupChatImpl.isDisplayedByAllRecipients.
type author struct {
	me     string
	mu     sync.Mutex
	status map[string]map[string]imdn.Kind // Message-ID → participant → strongest kind
	got    atomic.Int64
	// changed counts the notifications that raised a status, which a
	// sender repeating itself does not.
	changed atomic.Int64
}

// sentDateTime is the DateTime of every message chat builds.
const sentDateTime = "2026-03-04T05:06:07.000Z"

func newAuthor(me string) *author {
	return &author{me: me, status: map[string]map[string]imdn.Kind{}}
}

func (a *author) take(t *testing.T, body []byte) {
	t.Helper()
	c, err := cpim.Parse(body)
	if err != nil {
		t.Fatalf("not CPIM: %v", err)
	}
	if !strings.HasPrefix(c.ContentType(), imdn.ContentType) {
		return
	}
	to, err := c.To()
	if err != nil || len(to) != 1 || to[0].URI != a.me {
		t.Fatalf("a notification To %v, %v: rcsjta drops it", to, err)
	}
	from, err := c.From()
	if err != nil {
		t.Fatal(err)
	}
	n, err := imdn.ParseNotificationMessage(c)
	if err != nil {
		t.Fatal(err)
	}
	if n.DateTime != sentDateTime {
		// RFC 5438 §11.1.2: the DateTime of the message reported on.
		t.Errorf("a notification about %s says it was sent at %q", n.MessageID, n.DateTime)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.got.Add(1)
	if a.status[n.MessageID] == nil {
		a.status[n.MessageID] = map[string]imdn.Kind{}
	}
	if kindRank[n.Kind] > kindRank[a.status[n.MessageID][from.URI]] {
		a.status[n.MessageID][from.URI] = n.Kind
		a.changed.Add(1)
	}
}

// deliveredWork counts the work done toward alice reading her messages by
// all: statuses raised, and her queue emptying. A notification sent again,
// or a summary resent every pass, does not count, so a delivery that loops
// stands still (code review on #335). Nor do summaries expanded: one
// removed already shows in the queue, and the count, which has no bound,
// would let a summary expanded but never removed look like progress for
// ever (QA of #335).
func deliveredWork(r *rig, a *author) int64 {
	return a.changed.Load() - int64(r.store.(*store.Memory).Len(alice))
}

func (a *author) readByAll(id string, recipients []string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range recipients {
		if a.status[id][p] != imdn.DisplayNotification {
			return false
		}
	}
	return true
}

// listen reads what c gets into a until the test ends.
func (a *author) listen(t *testing.T, c *client) {
	go func() {
		for {
			select {
			case m := <-c.got:
				a.take(t, m.Body.Bytes())
			case <-t.Context().Done():
				return
			}
		}
	}()
}

func participants(n int) []string {
	out := []string{alice}
	for i := range n - 1 {
		out = append(out, fmt.Sprintf("sip:u%d@example.net", i))
	}
	return out
}

// receiptsFrom has every participant but the author report delivery and
// display of id in group.
func receiptsFrom(t *testing.T, r *rig, group string, everyone []string, id string) {
	t.Helper()
	for _, p := range everyone[1:] {
		for _, k := range []struct {
			kind   imdn.Kind
			status imdn.Status
		}{{imdn.DeliveryNotification, imdn.Delivered}, {imdn.DisplayNotification, imdn.Displayed}} {
			o := GroupOrigin{Group: group, Sender: p, Conversation: conv, CPIM: receipt(t, id, k.kind, k.status)}
			if err := r.e.SubmitGroup(t.Context(), o); err != nil {
				t.Fatalf("%s's receipt: %v", p, err)
			}
		}
	}
}

// Test plan 1 (#166): an offline author of one message to a full group of
// 100 gets, once back, every participant's display notification, so that
// the reference client marks the message read by all, though its queue
// kept only a share of the 198 receipts.
func TestAnOfflineAuthorSeesItsMessageReadByAll(t *testing.T) {
	everyone := participants(100)
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: everyone})
	drainInvites(t, r.d)
	r.d.onInvite(func(Invitation) error { return ErrOffline })
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi all", imdn.PositiveDelivery|imdn.Display))); err != nil {
		t.Fatal(err)
	}
	receiptsFrom(t, r, groupURI, everyone, "m1")
	share := queueLimit(r.e.cfg).SenderCount
	if notes, sums := queuedReceipts(t, r, alice); notes != share || sums != 1 {
		t.Fatalf("%d receipts and %d summaries queued", notes, sums)
	}
	a := newAuthor(alice)
	l := r.listen(t)
	_, c := r.connect(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group})
	a.listen(t, c)
	// 99 and more notifications: on a loaded host that takes longer than
	// hangGuard, so the waits fail only when nothing moves (#306).
	progress := func() int64 { return deliveredWork(r, a) }
	waitProgress(t, "read by all", func() bool { return a.readByAll("m1", everyone[1:]) }, progress)
	waitProgress(t, "alice's queue empty", func() bool { return r.store.(*store.Memory).Len(alice) == 0 }, progress)
	waitProgress(t, "the summary expanded", func() bool { return r.m.get("group.summary.expanded") == 1 }, progress)
	if r.m.get("group.summary.sent") != 99 {
		t.Fatalf("metrics %v", r.m)
	}
	// One per participant from the summary, its strongest: displayed.
	waitProgress(t, "every notification taken", func() bool { return a.got.Load() >= int64(share)+99 }, a.got.Load)
	if got := a.got.Load(); got != int64(share)+99 {
		t.Fatalf("alice got %d notifications, want %d receipts and 99 from the summary", got, share)
	}
}

// Test plan 2: the reviews' nine groups. The queue holds its total of
// receipts and a summary per message, a 1-to-1 message still goes in, and
// once back the author sees all nine messages read by all.
func TestNineGroupsOfReceiptsAreAllReadByAll(t *testing.T) {
	everyone := participants(100)
	r := newRig(t, Config{})
	r.e.SetGroupHandler(everyGroup{members{all: everyone}})
	drainInvites(t, r.d)
	r.d.onInvite(func(Invitation) error { return ErrOffline })
	group := func(g int) string { return fmt.Sprintf("sip:chat-%d@conf.example.net", g) }
	for g := range 9 {
		o := GroupOrigin{Group: group(g), Sender: alice, Conversation: conv, CPIM: chat(t, fmt.Sprint("g", g), "hi", imdn.PositiveDelivery|imdn.Display)}
		if err := r.e.SubmitGroup(t.Context(), o); err != nil {
			t.Fatal(err)
		}
		receiptsFrom(t, r, group(g), everyone, fmt.Sprint("g", g))
	}
	if notes, sums := queuedReceipts(t, r, alice); notes != 250 || sums != 9 {
		t.Fatalf("%d receipts and %d summaries queued", notes, sums)
	}
	if err := r.e.Submit(t.Context(), standalone(bob, alice, chat(t, "d1", "are you there?", 0))); err != nil {
		t.Fatalf("a 1-to-1 message to alice: %v", err)
	}
	a := newAuthor(alice)
	l := r.listen(t)
	for g := range 9 {
		_, c := r.connect(t, l, LegParams{User: alice, Peer: group(g), Conversation: conv, Mode: store.Group})
		a.listen(t, c)
	}
	// Some 900 notifications go out: on a loaded host that takes longer
	// than hangGuard, so the waits fail only when nothing moves (#306).
	progress := func() int64 { return deliveredWork(r, a) }
	for g := range 9 {
		waitProgress(t, fmt.Sprint("g", g, " read by all"), func() bool { return a.readByAll(fmt.Sprint("g", g), everyone[1:]) }, progress)
	}
	waitProgress(t, "the summaries expanded", func() bool { return r.m.get("group.summary.expanded") == 9 }, progress)
}

// interrupting runs hook before the first RemoveSummary, once.
type interrupting struct {
	store.Store
	once sync.Once
	hook func()
	sent func()
	// settled counts the calls that end a claim on the message watched: a
	// release, which puts it back in the queue, or a removal (#405).
	watched atomic.Value // string
	settled atomic.Int64
}

func (s *interrupting) settle(id string) {
	if w, _ := s.watched.Load().(string); w != "" && w == id {
		s.settled.Add(1)
	}
}

func (s *interrupting) RemoveSummary(ctx context.Context, m store.Message, owner string, marks int64) error {
	if s.hook != nil {
		s.once.Do(s.hook)
	}
	defer s.settle(m.ID)
	return s.Store.RemoveSummary(ctx, m, owner, marks)
}

func (s *interrupting) Release(ctx context.Context, recipient, id, owner string) error {
	// Only a release that took effect ends the claim (QA of #424).
	err := s.Store.Release(ctx, recipient, id, owner)
	if err == nil {
		s.settle(id)
	}
	return err
}

func (s *interrupting) Remove(ctx context.Context, m store.Message, owner string) error {
	defer s.settle(m.ID)
	return s.Store.Remove(ctx, m, owner)
}

func (s *interrupting) Sent(ctx context.Context, sender, id string, now time.Time) (store.Sent, error) {
	if s.sent != nil && strings.HasPrefix(sender, "sip:chat-") {
		f := s.sent
		s.sent = nil
		f()
	}
	return s.Store.Sent(ctx, sender, id, now)
}

// smallQueue makes a group of three summarize from the second receipt on:
// one receipt per share, two in all.
var smallQueue = Config{MaxQueueMessages: 8, QueueSenderShare: 8}

// Test plan 3: a receipt that comes in while a summary is being sent is
// not lost. carol's delivery takes the share bob's left, so her display is
// summarized; the summary's removal finds the new mark, so it stays, and
// goes out again with hers only: bob's has not changed.
func TestAReceiptDuringASummaryIsSentToo(t *testing.T) {
	everyone := []string{alice, bob, carol}
	st := &interrupting{Store: store.NewMemory()}
	r := newRigWith(t, smallQueue, st, newFakeClock())
	r.e.SetGroupHandler(members{all: everyone})
	drainInvites(t, r.d)
	r.d.onInvite(func(Invitation) error { return ErrOffline })
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", imdn.PositiveDelivery|imdn.Display))); err != nil {
		t.Fatal(err)
	}
	for _, k := range []struct {
		kind   imdn.Kind
		status imdn.Status
	}{{imdn.DeliveryNotification, imdn.Delivered}, {imdn.DisplayNotification, imdn.Displayed}} {
		if err := r.e.SubmitGroup(t.Context(), groupFrom(bob, receipt(t, "m1", k.kind, k.status))); err != nil {
			t.Fatal(err)
		}
	}
	if _, sums := queuedReceipts(t, r, alice); sums != 1 {
		t.Fatalf("%d summaries", sums)
	}
	st.hook = func() {
		for _, k := range []struct {
			kind   imdn.Kind
			status imdn.Status
		}{{imdn.DeliveryNotification, imdn.Delivered}, {imdn.DisplayNotification, imdn.Displayed}} {
			if err := r.e.SubmitGroup(t.Context(), groupFrom(carol, receipt(t, "m1", k.kind, k.status))); err != nil {
				t.Errorf("carol's receipt: %v", err)
			}
		}
		if got := r.m.get("group.notification.summarized"); got != 2 {
			t.Errorf("carol's display went in whole: %d summarized", got)
		}
	}
	a := newAuthor(alice)
	l := r.listen(t)
	_, c := r.connect(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group})
	a.listen(t, c)
	waitFor(t, "read by all", func() bool { return a.readByAll("m1", []string{bob, carol}) })
	waitFor(t, "alice's queue empty", func() bool { return st.Store.(*store.Memory).Len(alice) == 0 })
	waitFor(t, "the summary expanded", func() bool { return r.m.get("group.summary.expanded") == 1 })
	if got := r.m.get("group.summary.sent"); got != 2 {
		t.Fatalf("the summary sent %d notifications, want bob's, then carol's", got)
	}
}

// Test plan 4: a session that ends while a summary is sent leaves the
// summary queued, and the next session gets it whole.
func TestASummaryCutShortIsSentAgain(t *testing.T) {
	everyone := []string{alice, bob, carol}
	st := &interrupting{Store: store.NewMemory()}
	r := newRigWith(t, smallQueue, st, newFakeClock())
	r.e.SetGroupHandler(members{all: everyone})
	drainInvites(t, r.d)
	r.d.onInvite(func(Invitation) error { return ErrOffline })
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", imdn.Display))); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{bob, carol} {
		if err := r.e.SubmitGroup(t.Context(), groupFrom(p, receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed))); err != nil {
			t.Fatal(err)
		}
	}
	if _, sums := queuedReceipts(t, r, alice); sums != 1 {
		t.Fatalf("%d summaries", sums)
	}
	st.watched.Store(summaryID(t, r, alice))
	l := r.listen(t)
	var first *Leg
	var mu sync.Mutex
	st.sent = func() {
		mu.Lock()
		defer mu.Unlock()
		_ = first.Close() // the session ends just as the summary is read
	}
	mu.Lock()
	first, _ = r.connect(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group})
	mu.Unlock()
	// The failure is counted before the summary's claim is released, and
	// while it is claimed the queue does not list it: wait for the attempt
	// to end the summary's claim, whichever way, then look (#405).
	waitFor(t, "the first attempt", func() bool { return r.m.get("delivery.msrp_failed") >= 1 && st.settled.Load() >= 1 })
	if _, sums := queuedReceipts(t, r, alice); sums != 1 {
		t.Fatalf("the summary is gone after a failed attempt: %d", sums)
	}
	a := newAuthor(alice)
	_, c := r.connect(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group})
	a.listen(t, c)
	waitFor(t, "read by all", func() bool { return a.readByAll("m1", []string{bob, carol}) })
}

// Test plan 5: what the summary sends is only what was accepted. A forged
// receipt, one not asked for and a repeat change neither the marks nor the
// summary.
func TestASummaryCarriesOnlyAcceptedReceipts(t *testing.T) {
	everyone := []string{alice, bob, carol}
	r := newRigWith(t, smallQueue, store.NewMemory(), newFakeClock())
	r.e.SetGroupHandler(members{all: everyone})
	drainInvites(t, r.d)
	r.d.onInvite(func(Invitation) error { return ErrOffline })
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", imdn.Display))); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{bob, carol} {
		if err := r.e.SubmitGroup(t.Context(), groupFrom(p, receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed))); err != nil {
			t.Fatal(err)
		}
	}
	before, err := r.store.Sent(t.Context(), groupURI, "m1", r.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		o    GroupOrigin
		want Reason
	}{
		"from no recipient": {GroupOrigin{Group: groupURI, Sender: intermediary, CPIM: receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed)}, ReasonIMDNForged},
		"not asked for":     {groupFrom(bob, receipt(t, "m1", imdn.DeliveryNotification, imdn.Delivered)), ReasonIMDNNotRequested},
	} {
		if got := rejected(r.e.SubmitGroup(t.Context(), c.o)); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	if err := r.e.SubmitGroup(t.Context(), groupFrom(carol, receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed))); err != nil {
		t.Fatal(err)
	}
	after, err := r.store.Sent(t.Context(), groupURI, "m1", r.clock.Now())
	if err != nil || after.MarkCount != before.MarkCount || len(after.Marks) != 2 {
		t.Fatalf("marks %d → %d, %v", before.MarkCount, after.MarkCount, err)
	}
	if _, sums := queuedReceipts(t, r, alice); sums != 1 {
		t.Fatalf("%d summaries", sums)
	}
	bodies, err := r.e.summaryNotifications(after, r.clock.Now())
	if err != nil || len(bodies) != 2 {
		t.Fatalf("%d notifications, %v", len(bodies), err)
	}
}

// Test plan 6: a summary expires with the sent record it summarizes and
// goes without a word: a notification is never answered with another.
func TestASummaryExpiresQuietly(t *testing.T) {
	everyone := []string{alice, bob, carol}
	r := newRigWith(t, smallQueue, store.NewMemory(), newFakeClock())
	r.e.SetGroupHandler(members{all: everyone})
	drainInvites(t, r.d)
	r.d.onInvite(func(Invitation) error { return ErrOffline })
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", imdn.Display))); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{bob, carol} {
		if err := r.e.SubmitGroup(t.Context(), groupFrom(p, receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed))); err != nil {
			t.Fatal(err)
		}
	}
	ms, _ := r.store.Pending(t.Context(), alice, "", r.clock.Now(), 10)
	var sum store.Message
	for _, m := range ms {
		if m.Summary {
			sum = m
		}
	}
	sent, _ := r.store.Sent(t.Context(), groupURI, "m1", r.clock.Now())
	if !sum.Expires.Equal(sent.Expires) {
		t.Fatalf("summary expires %v, its record %v", sum.Expires, sent.Expires)
	}
	r.clock.Advance(r.e.cfg.SentTTL)
	for {
		n, err := r.e.Sweep(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
	}
	if _, sums := queuedReceipts(t, r, alice); sums != 0 {
		t.Fatalf("%d summaries after expiry", sums)
	}
	for _, u := range []string{alice, bob, carol} {
		ms, _ := r.store.Pending(t.Context(), u, "", r.clock.Now(), 10)
		for _, m := range ms {
			if m.Notification && m.Sender == groupURI && m.Author == "" {
				t.Fatalf("an expired summary was answered: %+v", m)
			}
		}
	}
}

// Test plan 7: an author with its session open takes its receipts as they
// come, and nothing is summarized.
func TestAConnectedAuthorGetsItsReceiptsAsTheyCome(t *testing.T) {
	everyone := participants(100)
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: everyone})
	drainInvites(t, r.d)
	a := newAuthor(alice)
	l := r.listen(t)
	_, c := r.connect(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group})
	a.listen(t, c)
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi all", imdn.Display))); err != nil {
		t.Fatal(err)
	}
	for _, p := range everyone[1:] {
		if err := r.e.SubmitGroup(t.Context(), groupFrom(p, receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed))); err != nil {
			t.Fatal(err)
		}
	}
	waitProgress(t, "read by all", func() bool { return a.readByAll("m1", everyone[1:]) }, a.changed.Load)
	if r.m.get("group.notification.summarized") != 0 || r.m.get("group.summary.expanded") != 0 {
		t.Fatalf("metrics %v", r.m)
	}
}

// offlineSummary is an author, alice, offline while bob and carol display
// its message m1 in a group of three: bob's notification is queued whole,
// carol's summarized. The passes the receipts started are over when it
// returns, so that only the session a test opens runs from there.
func offlineSummary(t *testing.T, cfg Config, st store.Store) (*rig, *fakeClock) {
	t.Helper()
	clock := newFakeClock()
	r := newRigWith(t, cfg, st, clock)
	r.e.SetGroupHandler(members{all: []string{alice, bob, carol}})
	drainInvites(t, r.d)
	r.d.onInvite(func(Invitation) error { return ErrOffline })
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", imdn.Display))); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{bob, carol} {
		if err := r.e.SubmitGroup(t.Context(), groupFrom(p, receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed))); err != nil {
			t.Fatal(err)
		}
	}
	if notes, sums := queuedReceipts(t, r, alice); notes != 1 || sums != 1 {
		t.Fatalf("%d receipts and %d summaries queued", notes, sums)
	}
	waitFor(t, "the receipts' passes", r.idle)
	return r, clock
}

// readByAllNext opens alice's next session and waits until it shows m1
// read by all and the summary expanded.
func readByAllNext(t *testing.T, r *rig, l net.Listener) {
	t.Helper()
	a := newAuthor(alice)
	_, c := r.connect(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group})
	a.listen(t, c)
	waitFor(t, "read by all", func() bool { return a.readByAll("m1", []string{bob, carol}) })
	waitFor(t, "the summary expanded", func() bool { return r.m.get("group.summary.expanded") == 1 })
}

// A summary goes only once the client confirms it has every notification:
// all but the last are sent without reports, the last with a success
// report, and a client that takes the bytes and processes none of them
// leaves the summary queued.
func TestASummaryStaysUntilTheClientConfirmsIt(t *testing.T) {
	// #291: a delivery timeout of its own. msrp's timers of 30 s, the
	// default (each connection's UnboundTimeout, never stopped, and its
	// transactions'), are armed before the last send, so armed(30 s) told
	// nothing about it, and on a loaded host the clock could be advanced
	// before the last send had set its timer, which then never fired.
	const deliveryTimeout = 27 * time.Second
	cfg := smallQueue
	cfg.DeliveryTimeout = deliveryTimeout
	r, clock := offlineSummary(t, cfg, store.NewMemory())
	// The client answers bob's receipt, queued whole, and then hangs.
	var taken atomic.Int32
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	l := r.listen(t)
	leg, c := r.connectAnswering(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group}, func(*msrp.Message) error {
		if taken.Add(1) > 1 {
			<-stuck
		}
		return nil
	})
	queued := c.next(t)
	first := c.next(t)
	if queued.SuccessReport != msrp.ReportYes || first.SuccessReport != msrp.ReportUnset || first.FailureReport != msrp.ReportNo {
		t.Fatalf("reports asked: queued %v/%v, summary's first %v/%v", queued.SuccessReport, queued.FailureReport,
			first.SuccessReport, first.FailureReport)
	}
	waitFor(t, "the summary's last sent", func() bool { return r.m.get("group.summary.sent") == 1 && clock.armed(deliveryTimeout) })
	clock.Advance(deliveryTimeout)
	waitFor(t, "the attempt given up", func() bool { return r.m.get("delivery.msrp_failed") == 1 && r.idle() })
	if n := r.store.(*store.Memory).Len(alice); n != 1 || r.m.get("group.summary.expanded") != 0 {
		t.Fatalf("%d queued, metrics %v", n, r.m)
	}
	// The next session gets what the stuck one did not confirm.
	_ = leg.Close()
	readByAllNext(t, r, l)
}

// QA's case: the peer fails the summary's notifications, as msrp-relay
// answers 408 once the client's connection is gone. The summary stays for
// the next session.
func TestASummaryThePeerFailedIsSentAgain(t *testing.T) {
	r, _ := offlineSummary(t, smallQueue, store.NewMemory())
	var taken atomic.Int32
	l := r.listen(t)
	leg, _ := r.connectAnswering(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group}, func(*msrp.Message) error {
		if taken.Add(1) == 1 {
			return nil // bob's receipt, queued whole
		}
		return &msrp.StatusError{Code: msrp.StatusRequestTimeout, Comment: "no client"}
	})
	waitFor(t, "the summary's attempt", func() bool { return r.m.get("delivery.msrp_failed") == 1 && r.idle() })
	if _, sums := queuedReceipts(t, r, alice); sums != 1 || r.m.get("group.summary.expanded") != 0 {
		t.Fatalf("%d summaries after a failed attempt, metrics %v", sums, r.m)
	}
	_ = leg.Close()
	readByAllNext(t, r, l)
}

// QA's other case: the client stalls on the summary and is then killed.
// What it had not handled is lost with it, and the summary stays.
func TestASummaryToAClientKilledWhileStalledIsSentAgain(t *testing.T) {
	r, _ := offlineSummary(t, smallQueue, store.NewMemory())
	var taken atomic.Int32
	stuck := make(chan struct{})
	l := r.listen(t)
	leg, c := r.connectAnswering(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group}, func(*msrp.Message) error {
		if taken.Add(1) == 1 {
			return nil
		}
		<-stuck
		return errors.New("gone")
	})
	c.next(t)
	c.next(t)          // the summary's first reaches the client, which stalls
	_ = c.conn.Close() // the app is killed
	close(stuck)
	select {
	case <-leg.Done():
	case <-time.After(hangGuard):
		t.Fatal("the leg did not end")
	}
	waitFor(t, "the attempt over", func() bool { return r.m.get("delivery.msrp_failed") == 1 && r.idle() })
	if _, sums := queuedReceipts(t, r, alice); sums != 1 || r.m.get("group.summary.expanded") != 0 {
		t.Fatalf("%d summaries after the client was killed, metrics %v", sums, r.m)
	}
	readByAllNext(t, r, l)
}

// goneRecord answers reads of the group's sent records with an error once
// one is set.
type goneRecord struct {
	store.Store
	mu  sync.Mutex
	err error
}

func (s *goneRecord) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *goneRecord) Sent(ctx context.Context, sender, id string, now time.Time) (store.Sent, error) {
	s.mu.Lock()
	err := s.err
	s.mu.Unlock()
	if err != nil && sender == groupURI {
		return store.Sent{}, err
	}
	return s.Store.Sent(ctx, sender, id, now)
}

// A summary whose record cannot be read is kept for a later attempt; one
// whose record is gone is removed and sends nothing.
func TestASummaryWithoutItsRecord(t *testing.T) {
	st := &goneRecord{Store: store.NewMemory()}
	r, _ := offlineSummary(t, smallQueue, st)
	st.fail(errStore)
	l := r.listen(t)
	leg, c := r.connect(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group})
	c.next(t) // bob's receipt, queued whole
	waitFor(t, "the summary's attempt", func() bool { return r.m.get("store.failed") >= 1 && r.idle() })
	if _, sums := queuedReceipts(t, r, alice); sums != 1 {
		t.Fatalf("%d summaries after its record failed", sums)
	}
	_ = leg.Close()
	st.fail(store.ErrNotFound)
	_, c = r.connect(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group})
	waitFor(t, "alice's queue empty", func() bool { return st.Store.(*store.Memory).Len(alice) == 0 && r.idle() })
	select {
	case m := <-c.got:
		t.Fatalf("a summary without its record sent %q", m.Body.Bytes())
	default:
	}
	if r.m.get("group.summary.sent") != 0 || r.m.get("group.summary.expanded") != 0 {
		t.Fatalf("metrics %v", r.m)
	}
}

// A receipt over the share that finds the whole queue full cannot be
// summarized either: it is dropped and counted.
func TestAReceiptForAFullQueueIsDropped(t *testing.T) {
	const dave = "tel:+15550100005"
	r := newRigWith(t, Config{MaxQueueMessages: 4, QueueSenderShare: 1, SenderRate: Rate{PerMinute: -1}}, store.NewMemory(), newFakeClock())
	r.e.SetGroupHandler(members{all: []string{alice, bob, carol}})
	drainInvites(t, r.d)
	r.d.onInvite(func(Invitation) error { return ErrOffline })
	r.d.onPager(func(Delivery) error { return errors.New("480 Temporarily Unavailable") })
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", imdn.Display))); err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		if err := r.e.Submit(t.Context(), standalone(dave, alice, chat(t, fmt.Sprint("d", i), "hi", 0))); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.e.SubmitGroup(t.Context(), groupFrom(bob, receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed))); err != nil {
		t.Fatal(err)
	}
	if got := r.m.get("group.notification.dropped"); got != 1 {
		t.Fatalf("metrics %v", r.m)
	}
	if notes, sums := queuedReceipts(t, r, alice); notes != 0 || sums != 0 {
		t.Fatalf("%d receipts and %d summaries in a full queue", notes, sums)
	}
}

// The reviews' scaled case: an author's summaries have a total of their
// own, so that with its receipts they never fill the queue. Queue 40,
// receipts' total 10, summaries' 5: of the 40 receipts bob sends, 10 are
// queued, 5 summarized and 25 dropped, and dave's 1-to-1 message goes in.
func TestSummariesLeaveTheQueueTo1To1Messages(t *testing.T) {
	const dave = "tel:+15550100005"
	r := newRig(t, Config{MaxQueueMessages: 40, QueueSenderShare: 1, SenderRate: Rate{PerMinute: -1}})
	r.e.SetGroupHandler(members{all: []string{alice, bob, carol}})
	drainInvites(t, r.d)
	r.d.onInvite(func(Invitation) error { return ErrOffline })
	for i := range 40 {
		id := fmt.Sprint("m", i)
		if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, id, "hi", imdn.Display))); err != nil {
			t.Fatal(err)
		}
		if err := r.e.SubmitGroup(t.Context(), groupFrom(bob, receipt(t, id, imdn.DisplayNotification, imdn.Displayed))); err != nil {
			t.Fatal(err)
		}
	}
	if notes, sums := queuedReceipts(t, r, alice); notes != 10 || sums != 5 {
		t.Fatalf("%d receipts and %d summaries queued", notes, sums)
	}
	if got := r.m.get("group.notification.dropped"); got != 25 {
		t.Fatalf("%d dropped", got)
	}
	if err := r.e.Submit(t.Context(), standalone(dave, alice, chat(t, "d1", "are you there?", 0))); err != nil {
		t.Fatalf("dave's 1-to-1 message: %v", err)
	}
}

// failingRemoval answers the RemoveSummary calls with script, in order,
// and fails every one after.
type failingRemoval struct {
	store.Store
	script []error
	tries  atomic.Int32
}

func (s *failingRemoval) RemoveSummary(context.Context, store.Message, string, int64) error {
	if n := int(s.tries.Add(1)); n <= len(s.script) {
		return s.script[n-1]
	}
	return errStore
}

// removalRig is offlineSummary with a store whose RemoveSummary fails
// (st) and alice's session open.
func removalRig(t *testing.T, st *failingRemoval) (*rig, *fakeClock, *author) {
	t.Helper()
	cfg := smallQueue
	cfg.RetryInterval, cfg.MaxRetryInterval = time.Minute, time.Minute
	r, clock := offlineSummary(t, cfg, st)
	a := newAuthor(alice)
	l := r.listen(t)
	_, c := r.connect(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group})
	a.listen(t, c)
	return r, clock, a
}

// failedRemoval waits for removal try to fail, checks that the summary
// stays, and lets the retry come.
func failedRemoval(t *testing.T, r *rig, clock *fakeClock, st *failingRemoval, try int32) {
	t.Helper()
	waitFor(t, fmt.Sprint("removal ", try), func() bool { return st.tries.Load() == try && r.idle() })
	if _, sums := queuedReceipts(t, r, alice); sums != 1 {
		t.Fatalf("%d summaries after removal %d", sums, try)
	}
	waitFor(t, "the retry", func() bool { return clock.armed(time.Minute) })
	clock.Advance(time.Minute)
}

// A summary whose removal keeps failing is tried again later, not at once,
// sends only what it has not sent, and after MaxSummaryFailures in a row
// is given up.
func TestASummaryThatCannotBeRemovedIsGivenUp(t *testing.T) {
	st := &failingRemoval{Store: store.NewMemory()}
	r, clock, a := removalRig(t, st)
	for try := int32(1); try < MaxSummaryFailures; try++ {
		failedRemoval(t, r, clock, st, try)
	}
	waitFor(t, "the summary given up", func() bool { return r.m.get("group.summary.abandoned") == 1 && r.idle() })
	if _, sums := queuedReceipts(t, r, alice); sums != 0 || st.tries.Load() != MaxSummaryFailures {
		t.Fatalf("%d summaries after %d removals", sums, st.tries.Load())
	}
	// Two notifications from the summary (bob's went whole), once: the
	// passes after the first had nothing new to send. The author's client
	// reads them on its own goroutine.
	if got := r.m.get("group.summary.sent"); got != 2 {
		t.Fatalf("summary sent %d notifications", got)
	}
	waitFor(t, "read by all", func() bool { return a.readByAll("m1", []string{bob, carol}) })
}

// New marks are not a failed removal: the failures counted before them
// start over.
func TestNewMarksStartTheFailedRemovalsOver(t *testing.T) {
	st := &failingRemoval{Store: store.NewMemory(), script: []error{errStore, errStore, store.ErrMarksChanged}}
	r, clock, _ := removalRig(t, st)
	failedRemoval(t, r, clock, st, 1)
	failedRemoval(t, r, clock, st, 2)
	// The third finds new marks, and the queue is read again at once.
	failedRemoval(t, r, clock, st, 4)
	failedRemoval(t, r, clock, st, 5)
	waitFor(t, "the summary given up", func() bool { return r.m.get("group.summary.abandoned") == 1 && r.idle() })
	if got := st.tries.Load(); got != 6 {
		t.Fatalf("given up after %d removals", got)
	}
}

// hookedRemoval fails every RemoveSummary with err, and runs hook in the
// try numbered at, before it fails.
type hookedRemoval struct {
	store.Store
	err   error
	at    int32
	hook  func()
	tries atomic.Int32
}

func (s *hookedRemoval) RemoveSummary(context.Context, store.Message, string, int64) error {
	if s.tries.Add(1) == s.at && s.hook != nil {
		s.hook()
	}
	return s.err
}

// mergedDuringRemovals is QA's case: alice offline, bob's display queued
// whole and carol's summarized; just before the summary's third removal
// fails, dave's delivery takes the share again and his display is merged
// into the summary. alice's session is open.
func mergedDuringRemovals(t *testing.T, st *hookedRemoval) (*rig, *fakeClock, *author) {
	t.Helper()
	const dave = "tel:+15550100005"
	clock := newFakeClock()
	cfg := smallQueue
	cfg.RetryInterval, cfg.MaxRetryInterval = time.Minute, time.Minute
	r := newRigWith(t, cfg, st, clock)
	r.e.SetGroupHandler(members{all: []string{alice, bob, carol, dave}})
	drainInvites(t, r.d)
	r.d.onInvite(func(Invitation) error { return ErrOffline })
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", imdn.PositiveDelivery|imdn.Display))); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{bob, carol} {
		if err := r.e.SubmitGroup(t.Context(), groupFrom(p, receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed))); err != nil {
			t.Fatal(err)
		}
	}
	st.at = MaxSummaryFailures
	st.hook = func() {
		for _, k := range []struct {
			kind   imdn.Kind
			status imdn.Status
		}{{imdn.DeliveryNotification, imdn.Delivered}, {imdn.DisplayNotification, imdn.Displayed}} {
			if err := r.e.SubmitGroup(context.Background(), groupFrom(dave, receipt(t, "m1", k.kind, k.status))); err != nil {
				t.Errorf("dave: %v", err)
			}
		}
		if got := r.m.get("group.notification.summarized"); got != 2 {
			t.Errorf("dave's display went in whole: %d summarized", got)
		}
	}
	waitFor(t, "the receipts' passes", r.idle)
	a := newAuthor(alice)
	l := r.listen(t)
	_, c := r.connect(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group})
	a.listen(t, c)
	return r, clock, a
}

// retried waits for removal try to have failed and lets the retry come.
func retried(t *testing.T, r *rig, clock *fakeClock, st *hookedRemoval, try int32) {
	t.Helper()
	waitFor(t, fmt.Sprint("removal ", try), func() bool { return st.tries.Load() == try && r.idle() })
	waitFor(t, "the retry", func() bool { return clock.armed(time.Minute) })
	clock.Advance(time.Minute)
}

// A summary whose removal the store is too busy for is never given up:
// the conflicting writes are the marks, which keep coming while it is
// tried. Each try sends what changed, dave's display among them.
func TestASummaryIsNotGivenUpForABusyStore(t *testing.T) {
	st := &hookedRemoval{Store: store.NewMemory(), err: fmt.Errorf("fake: remove summary: %w", store.ErrBusy)}
	r, clock, a := mergedDuringRemovals(t, st)
	for try := int32(1); try <= 2*MaxSummaryFailures; try++ {
		retried(t, r, clock, st, try)
	}
	// Idle, the summary is not claimed by a pass, so Pending counts it.
	waitFor(t, "read by all", func() bool { return a.readByAll("m1", []string{bob, carol, "tel:+15550100005"}) && r.idle() })
	if _, sums := queuedReceipts(t, r, alice); sums != 1 || r.m.get("group.summary.abandoned") != 0 {
		t.Fatalf("%d summaries queued, metrics %v", sums, r.m)
	}
}

// QA's failing test: notifications merged into a summary while its
// removals failed are sent before it is given up. The third failure finds
// dave's display marked since the pass read the record, so the count
// starts over and the summary goes again, with his only.
func TestNotificationsMergedBeforeASummaryIsGivenUpAreSent(t *testing.T) {
	st := &hookedRemoval{Store: store.NewMemory(), err: errStore}
	r, clock, a := mergedDuringRemovals(t, st)
	retried(t, r, clock, st, 1)
	retried(t, r, clock, st, 2)
	// The third fails with new marks: the queue is read again at once.
	retried(t, r, clock, st, MaxSummaryFailures+1)
	retried(t, r, clock, st, MaxSummaryFailures+2)
	waitFor(t, "the summary given up", func() bool { return r.m.get("group.summary.abandoned") == 1 && r.idle() })
	if got := st.tries.Load(); got != 2*MaxSummaryFailures {
		t.Fatalf("given up after %d removals", got)
	}
	waitFor(t, "dave's display, not given up with the summary", func() bool {
		return a.readByAll("m1", []string{bob, carol, "tel:+15550100005"})
	})
	// bob's and carol's from the first pass, dave's from the fourth.
	if got := r.m.get("group.summary.sent"); got != 3 {
		t.Fatalf("summary sent %d notifications", got)
	}
}

// A summary whose record cannot be read when its removal has failed a
// third time is kept: notifications merged into it may be unsent.
func TestASummaryIsNotGivenUpOnARecordItCannotRead(t *testing.T) {
	records := &goneRecord{Store: store.NewMemory()}
	st := &hookedRemoval{Store: records, err: errStore, at: MaxSummaryFailures, hook: func() { records.fail(errStore) }}
	cfg := smallQueue
	cfg.RetryInterval, cfg.MaxRetryInterval = time.Minute, time.Minute
	r, clock := offlineSummary(t, cfg, st)
	l := r.listen(t)
	_, _ = r.connect(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group})
	retried(t, r, clock, st, 1)
	retried(t, r, clock, st, 2)
	waitFor(t, "the third removal", func() bool { return st.tries.Load() == MaxSummaryFailures && r.idle() })
	if n := records.Store.(*store.Memory).Len(alice); n != 1 || r.m.get("group.summary.abandoned") != 0 {
		t.Fatalf("%d queued, metrics %v", n, r.m)
	}
}

// A client that refuses the summary's last notification for good (403)
// will never take it: the summary is given up at once, without a
// notification about a notification.
func TestASummaryRefusedForGoodIsGivenUp(t *testing.T) {
	r, _ := offlineSummary(t, smallQueue, store.NewMemory())
	var taken atomic.Int32
	l := r.listen(t)
	_, _ = r.connectAnswering(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group}, func(*msrp.Message) error {
		if taken.Add(1) < 3 {
			return nil // bob's receipt queued whole, then the summary's first
		}
		return &msrp.StatusError{Code: msrp.StatusForbidden}
	})
	waitFor(t, "the refusal", func() bool { return r.m.get("delivery.refused") == 1 && r.idle() })
	if n := r.store.(*store.Memory).Len(alice); n != 0 || r.m.get("group.summary.expanded") != 0 {
		t.Fatalf("%d queued, metrics %v", n, r.m)
	}
	// bob and carol hold their copies of m1, and nothing else: no
	// notification about the refused one (the queues are idle, so
	// Pending sees every item).
	for _, u := range []string{bob, carol} {
		ms, err := r.store.Pending(t.Context(), u, "", r.clock.Now(), 10)
		if err != nil || len(ms) != 1 || ms[0].Notification {
			t.Fatalf("%s's queue %+v, %v", u, ms, err)
		}
	}
}

// busyMarks reports every mark busy (store.ErrBusy).
type busyMarks struct{ store.Store }

func (busyMarks) MarkNotified(context.Context, string, string, string, string, string, time.Time) error {
	return fmt.Errorf("fake: mark notified: %w", store.ErrBusy)
}

// A notification the store is too busy to mark is answered 503, which a
// client may send again at once, not the 500 of a failed store.
func TestABusyStoreIsAnsweredServiceUnavailable(t *testing.T) {
	r := newRigWith(t, Config{}, busyMarks{store.NewMemory()}, newFakeClock())
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	drainInvites(t, r.d)
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", imdn.Display))); err != nil {
		t.Fatal(err)
	}
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m2", "hi", imdn.Display))); err != nil {
		t.Fatal(err)
	}
	l := r.listen(t)
	_, g := r.connect(t, l, LegParams{User: bob, Peer: groupURI, Conversation: conv, Mode: store.Group})
	if code := g.outcome(t, cpim.ContentType, receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed)); code != StatusBusy {
		t.Fatalf("group receipt answered %d", code)
	}
	_, c := r.connect(t, l, LegParams{User: bob, Peer: alice, Conversation: conv, Mode: store.Chat})
	if code := c.outcome(t, cpim.ContentType, receipt(t, "m2", imdn.DisplayNotification, imdn.Displayed)); code != StatusBusy {
		t.Fatalf("1-to-1 receipt answered %d", code)
	}
}
