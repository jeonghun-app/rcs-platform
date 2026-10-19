package messaging

import (
	"context"
	"fmt"
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
}

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
	a.mu.Lock()
	defer a.mu.Unlock()
	a.got.Add(1)
	if a.status[n.MessageID] == nil {
		a.status[n.MessageID] = map[string]imdn.Kind{}
	}
	if kindRank[n.Kind] > kindRank[a.status[n.MessageID][from.URI]] {
		a.status[n.MessageID][from.URI] = n.Kind
	}
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
				a.take(t, m.Body)
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
	waitFor(t, "read by all", func() bool { return a.readByAll("m1", everyone[1:]) })
	waitFor(t, "alice's queue empty", func() bool { return r.store.(*store.Memory).Len(alice) == 0 })
	waitFor(t, "the summary expanded", func() bool { return r.m.get("group.summary.expanded") == 1 })
	if r.m.get("group.summary.sent") != 99 {
		t.Fatalf("metrics %v", r.m)
	}
	// One per participant from the summary, its strongest: displayed.
	waitFor(t, "every notification taken", func() bool { return a.got.Load() >= int64(share)+99 })
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
	for g := range 9 {
		waitFor(t, fmt.Sprint("g", g, " read by all"), func() bool { return a.readByAll(fmt.Sprint("g", g), everyone[1:]) })
	}
	waitFor(t, "the summaries expanded", func() bool { return r.m.get("group.summary.expanded") == 9 })
}

// interrupting runs hook before the first RemoveSummary, once.
type interrupting struct {
	store.Store
	once sync.Once
	hook func()
	sent func()
}

func (s *interrupting) RemoveSummary(ctx context.Context, m store.Message, owner string, marks int64) error {
	if s.hook != nil {
		s.once.Do(s.hook)
	}
	return s.Store.RemoveSummary(ctx, m, owner, marks)
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
	waitFor(t, "the first attempt", func() bool { return r.m.get("delivery.msrp_failed") >= 1 })
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
	waitFor(t, "read by all", func() bool { return a.readByAll("m1", everyone[1:]) })
	if r.m.get("group.notification.summarized") != 0 || r.m.get("group.summary.expanded") != 0 {
		t.Fatalf("metrics %v", r.m)
	}
}

// A summary goes only once the client confirms it has every notification:
// all but the last are sent without reports, the last with a success
// report, and a client that takes the bytes and processes none of them
// leaves the summary queued.
func TestASummaryStaysUntilTheClientConfirmsIt(t *testing.T) {
	everyone := []string{alice, bob, carol}
	clock := newFakeClock()
	r := newRigWith(t, smallQueue, store.NewMemory(), clock)
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
	// The client answers bob's receipt, queued whole, and then hangs.
	var taken atomic.Int32
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	l := r.listen(t)
	leg, c := r.connectHolding(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group}, func(*msrp.Message) {
		if taken.Add(1) > 1 {
			<-stuck
		}
	})
	queued := c.next(t)
	first := c.next(t)
	if queued.SuccessReport != msrp.ReportYes || first.SuccessReport != msrp.ReportUnset || first.FailureReport != msrp.ReportNo {
		t.Fatalf("reports asked: queued %v/%v, summary's first %v/%v", queued.SuccessReport, queued.FailureReport,
			first.SuccessReport, first.FailureReport)
	}
	waitFor(t, "the summary's last sent", func() bool { return r.m.get("group.summary.sent") == 1 && clock.armed(DefaultDeliveryTimeout) })
	clock.Advance(DefaultDeliveryTimeout)
	// A kick that came during the pass may start another at once, which
	// hangs the same way: the summary is kept either way.
	waitFor(t, "the attempt given up", func() bool { return r.m.get("delivery.msrp_failed") >= 1 })
	if n := r.store.(*store.Memory).Len(alice); n != 1 || r.m.get("group.summary.expanded") != 0 {
		t.Fatalf("%d queued, metrics %v", n, r.m)
	}
	// The next session gets what the stuck one did not confirm.
	_ = leg.Close()
	a := newAuthor(alice)
	_, c2 := r.connect(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group})
	a.listen(t, c2)
	waitFor(t, "read by all", func() bool { return a.readByAll("m1", []string{bob, carol}) })
	waitFor(t, "the summary expanded", func() bool { return r.m.get("group.summary.expanded") == 1 })
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

// failingRemoval fails every RemoveSummary.
type failingRemoval struct {
	store.Store
	tries atomic.Int32
}

func (s *failingRemoval) RemoveSummary(context.Context, store.Message, string, int64) error {
	s.tries.Add(1)
	return errStore
}

// A summary whose removal keeps failing is tried again later, not at once,
// sends only what it has not sent, and after MaxSummaryFailures in a row
// is given up.
func TestASummaryThatCannotBeRemovedIsGivenUp(t *testing.T) {
	everyone := []string{alice, bob, carol}
	st := &failingRemoval{Store: store.NewMemory()}
	clock := newFakeClock()
	cfg := smallQueue
	cfg.RetryInterval, cfg.MaxRetryInterval = time.Minute, time.Minute
	r := newRigWith(t, cfg, st, clock)
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
	a := newAuthor(alice)
	l := r.listen(t)
	_, c := r.connect(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group})
	a.listen(t, c)
	for try := int32(1); try < MaxSummaryFailures; try++ {
		waitFor(t, fmt.Sprint("removal ", try), func() bool { return st.tries.Load() == try && r.idle() })
		if _, sums := queuedReceipts(t, r, alice); sums != 1 {
			t.Fatalf("%d summaries after %d failed removals", sums, try)
		}
		waitFor(t, "the retry", func() bool { return clock.armed(time.Minute) })
		clock.Advance(time.Minute)
	}
	waitFor(t, "the summary given up", func() bool { return r.m.get("group.summary.abandoned") == 1 && r.idle() })
	if _, sums := queuedReceipts(t, r, alice); sums != 0 || st.tries.Load() != MaxSummaryFailures {
		t.Fatalf("%d summaries after %d removals", sums, st.tries.Load())
	}
	// Two notifications from the summary (bob's went whole), once: the
	// passes after the first had nothing new to send.
	if got := r.m.get("group.summary.sent"); got != 2 || !a.readByAll("m1", []string{bob, carol}) {
		t.Fatalf("summary sent %d notifications", got)
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
