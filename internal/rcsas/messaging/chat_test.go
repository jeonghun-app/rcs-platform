package messaging

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

func TestChatFlowsBetweenTwoClientsOverLoopbackMSRP(t *testing.T) {
	r := newRig(t, Config{})
	l := r.listen(t)
	_, a := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	_, b := r.connect(t, l, LegParams{User: bob, Peer: alice, Conversation: conv, Mode: store.Chat})

	msg := chat(t, "Xs8kLz1", "hello bob", imdn.PositiveDelivery|imdn.Display)
	a.send(t, msg)
	if rep := a.report(t); rep.Code != msrp.StatusOK {
		t.Fatalf("alice's message was answered with %d", rep.Code)
	}
	got := b.next(t)
	if !bytes.Equal(got.Body, msg) || got.MediaType() != cpim.ContentType {
		t.Fatalf("bob got %q", got.Body)
	}

	// Bob's client confirms delivery and display; both reach alice.
	for _, s := range []imdn.Status{imdn.Delivered, imdn.Displayed} {
		k := imdn.DeliveryNotification
		if s == imdn.Displayed {
			k = imdn.DisplayNotification
		}
		rcpt := receipt(t, "Xs8kLz1", k, s)
		b.send(t, rcpt)
		if rep := b.report(t); rep.Code != msrp.StatusOK {
			t.Fatalf("bob's %s notification was answered with %d", s, rep.Code)
		}
		got := a.next(t)
		if !bytes.Equal(got.Body, rcpt) {
			t.Fatalf("alice got %q", got.Body)
		}
		if n := readNotification(t, got.Body); n.Status != s || n.MessageID != "Xs8kLz1" {
			t.Fatalf("alice got %+v", n)
		}
	}
	waitFor(t, "the three deliveries to be confirmed", func() bool { return r.m.get("delivery.msrp") == 3 })
	if r.queued(t, bob) != 0 || r.queued(t, alice) != 0 || r.m.get("message.accepted") != 1 || r.m.get("message.accepted.notification") != 2 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestChatQueuedForAnAbsentRecipientWaitsForItsSession(t *testing.T) {
	r := newRig(t, Config{})
	l := r.listen(t)
	_, a := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})

	first, second := chat(t, "m1", "one", 0), chat(t, "m2", "two", 0)
	a.send(t, first)
	a.send(t, second)
	inv := r.d.nextInvite(t)
	if inv.Recipient != bob || inv.Peer != alice || inv.Mode != store.Chat || inv.Conversation != conv {
		t.Fatalf("invitation %+v", inv)
	}
	waitFor(t, "both messages stored", func() bool { return r.queued(t, bob) == 2 })
	select {
	case inv := <-r.d.invites:
		t.Fatalf("a second invitation while the first is pending: %+v", inv)
	default:
	}

	// The SIP layer gets bob's answer and opens his leg; the stored
	// messages arrive in order.
	_, b := r.connect(t, l, LegParams{User: bob, Peer: alice, Conversation: conv, Mode: store.Chat})
	if got := b.next(t); !bytes.Equal(got.Body, first) {
		t.Fatalf("first delivery %q", got.Body)
	}
	if got := b.next(t); !bytes.Equal(got.Body, second) {
		t.Fatalf("second delivery %q", got.Body)
	}
	waitFor(t, "both deliveries to be confirmed", func() bool { return r.m.get("delivery.msrp") == 2 })
}

func TestARecipientThatRefusesAMessageCausesANegativeNotification(t *testing.T) {
	r := newRig(t, Config{})
	l := r.listen(t)
	_, a := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	_, b := r.connect(t, l, LegParams{User: bob, Peer: alice, Conversation: conv, Mode: store.Chat})
	b.refuse = &msrp.StatusError{Code: msrp.StatusUnsupportedMediaType}

	a.send(t, chat(t, "m1", "hi", imdn.NegativeDelivery))
	b.next(t)
	got := a.next(t)
	if n := readNotification(t, got.Body); n.Status != imdn.Failed || n.MessageID != "m1" || n.Kind != imdn.DeliveryNotification {
		t.Fatalf("alice got %+v", n)
	}
	waitFor(t, "the refusal to be counted", func() bool { return r.m.get("delivery.refused") == 1 })
	if r.queued(t, bob) != 0 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestMessagesOnALegAreRefusedWithTheMSRPCodeOfTheirReason(t *testing.T) {
	r := newRig(t, Config{MaxMessageSize: 2048})
	l := r.listen(t)
	_, a := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	for name, c := range map[string]struct {
		body []byte
		want int
	}{
		"malformed":    {[]byte("not cpim"), msrp.StatusBadRequest},
		"too large":    {chat(t, "m1", string(bytes.Repeat([]byte("x"), 2048)), 0), msrp.StatusMessageTooLarge},
		"someone else": {cpimMessage(t, cpim.Address{URI: carol}, "m2", "hi", 0), msrp.StatusForbidden},
		"unknown imdn": {receipt(t, "nope", imdn.DeliveryNotification, imdn.Delivered), msrp.StatusForbidden},
	} {
		if code := a.outcome(t, cpim.ContentType, c.body); code != c.want {
			t.Errorf("%s: %d, want %d", name, code, c.want)
		}
	}
	if code := a.outcome(t, "text/plain", []byte("hi")); code != msrp.StatusUnsupportedMediaType {
		t.Errorf("text/plain: %d", code)
	}
	if r.queued(t, bob) != 0 {
		t.Fatal("a refused message was queued")
	}
}

func TestLegsNeedAUserAPeerAModeAndADirection(t *testing.T) {
	r := newRig(t, Config{})
	remote := []msrp.URI{clientURI()}
	for _, p := range []LegParams{
		{Remote: remote, Peer: bob, Mode: store.Chat, Direction: Originating},
		{Remote: remote, User: alice, Mode: store.Chat, Direction: Originating},
		{Remote: remote, User: alice, Peer: bob, Direction: Originating},
		{Remote: remote, User: alice, Peer: bob, Mode: store.Chat},
		{User: alice, Peer: bob, Mode: store.Chat, Direction: Originating}, // OpenLeg needs the path
		{Remote: remote, User: alice, Peer: bob, Mode: store.Standalone, Direction: Terminating},
		{Remote: remote, User: alice, Peer: bob, Mode: store.Chat, Direction: Terminating, QueueID: "q"},
		{Remote: remote, User: alice, Peer: bob, Mode: store.Standalone, Direction: Originating, QueueID: "q"},
	} {
		if _, err := r.e.OpenLeg(p); err == nil {
			t.Errorf("OpenLeg(%+v) succeeded", p)
		}
	}
	if _, err := r.e.Offer(LegParams{Remote: remote, User: bob, Peer: alice, Mode: store.Chat, Direction: Terminating}); err == nil {
		t.Error("Offer with a remote path succeeded")
	}
}

// The race ADR 0004 leaves open: in a session rcs-as offers, the relay can
// connect before the answer has come back through the CSCFs. The offered
// leg binds at once and sends only once it has the path.
func TestARelayConnectingBeforeTheAnswerIsServed(t *testing.T) {
	r := newRig(t, Config{MSRPHost: "127.0.0.1", MSRPPort: 2855})
	l := r.listen(t)
	_, a := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	a.send(t, chat(t, "m1", "for bob", 0))
	inv := r.d.nextInvite(t)
	leg, err := r.e.Offer(LegParams{User: inv.Recipient, Peer: inv.Peer, Conversation: inv.Conversation, Mode: inv.Mode, Direction: Terminating})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = leg.Close() })
	if u := leg.Local(); u.Host != "127.0.0.1" || u.Port != 2855 || len(u.SessionID) < 26 || u.Transport != "tcp" {
		t.Fatalf("Local = %v", u)
	}
	// Bob's side connects and binds before the answer arrives, and may
	// already send.
	bobURI := clientURI()
	b := r.dial(t, l, bobURI, leg.Local())
	b.send(t, chat(t, "m2", "early from bob", 0))
	if got := a.next(t); !bytes.Equal(got.Body, chat(t, "m2", "early from bob", 0)) {
		t.Fatalf("alice got %q", got.Body)
	}
	select {
	case m := <-b.got:
		t.Fatalf("delivered before the answer: %q", m.Body)
	case <-time.After(50 * time.Millisecond):
	}
	if err := leg.Answer([]msrp.URI{bobURI}); err != nil {
		t.Fatal(err)
	}
	if got := b.next(t); !bytes.Equal(got.Body, chat(t, "m1", "for bob", 0)) {
		t.Fatalf("bob got %q", got.Body)
	}
	if err := leg.Answer([]msrp.URI{bobURI}); err == nil {
		t.Fatal("answered twice")
	}
}

// #260: a pass that found no open leg for a message and asks for a
// session only once the one asked for earlier has opened asks for none. A
// second session's leg would be the newer, which every delivery after
// goes on, and the client may never bind it; the message goes on the leg
// that is open instead.
func TestNoSecondSessionIsAskedForOnceOneHasOpened(t *testing.T) {
	for _, mode := range []store.Mode{store.Chat, store.Group} {
		t.Run(mode.String(), func(t *testing.T) {
			r := newRig(t, Config{})
			body := chat(t, "m1", "for bob", 0)
			peer := alice
			if mode == store.Group {
				r.e.SetGroupHandler(members{all: []string{alice, bob}})
				peer = groupURI
				if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, body)); err != nil {
					t.Fatal(err)
				}
			} else if err := r.e.Submit(t.Context(), Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: mode, CPIM: body}); err != nil {
				t.Fatal(err)
			}
			inv := r.d.nextInvite(t)
			if inv.Recipient != bob || inv.Peer != peer || inv.Mode != mode {
				t.Fatalf("invitation %+v", inv)
			}
			waitFor(t, "idle", r.idle)
			// What the pass read before the session opened.
			ms, err := r.store.Pending(t.Context(), bob, "", r.clock.Now(), 10)
			if err != nil || len(ms) != 1 {
				t.Fatalf("Pending = %d, %v", len(ms), err)
			}
			l := r.listen(t)
			leg, err := r.e.Offer(LegParams{User: inv.Recipient, Peer: inv.Peer, Conversation: inv.Conversation, Mode: inv.Mode, Direction: Terminating})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = leg.Close() })
			bobURI := clientURI()
			if err := leg.Answer([]msrp.URI{bobURI}); err != nil {
				t.Fatal(err)
			}
			// That pass carries on to ask for the message's session.
			r.e.invite(t.Context(), ms[0])
			select {
			case again := <-r.d.invites:
				t.Fatalf("a second session was asked for: %+v", again)
			default:
			}
			b := r.dial(t, l, bobURI, leg.Local())
			if got := b.next(t); !bytes.Contains(got.Body, []byte("for bob")) {
				t.Fatalf("bob got %q", got.Body)
			}
		})
	}
}

// QA on #269: the guard in invite records nothing. Had it left the key in
// e.invites, a leg that ends before it carries the message would hold the
// message's next invitation back for InviteTimeout.
func TestAGuardedInviteLeavesNoKeyBehind(t *testing.T) {
	r := newRig(t, Config{})
	if err := r.e.Submit(t.Context(), Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: chat(t, "m1", "for bob", 0)}); err != nil {
		t.Fatal(err)
	}
	inv := r.d.nextInvite(t)
	waitFor(t, "idle", r.idle)
	ms, err := r.store.Pending(t.Context(), bob, "", r.clock.Now(), 10)
	if err != nil || len(ms) != 1 {
		t.Fatalf("Pending = %d, %v", len(ms), err)
	}
	leg, err := r.e.Offer(LegParams{User: inv.Recipient, Peer: inv.Peer, Conversation: inv.Conversation, Mode: inv.Mode, Direction: Terminating})
	if err != nil {
		t.Fatal(err)
	}
	if err := leg.Answer([]msrp.URI{clientURI()}); err != nil {
		t.Fatal(err)
	}
	r.e.invite(t.Context(), ms[0])
	select {
	case again := <-r.d.invites:
		t.Fatalf("a second session was asked for: %+v", again)
	default:
	}
	_ = leg.Close()
	waitFor(t, "the leg to be gone", func() bool { return r.e.chatLeg(bob, alice) == nil })
	r.e.invite(t.Context(), ms[0])
	if got := r.d.nextInvite(t); got.Recipient != bob || got.Mode != store.Chat {
		t.Fatalf("invitation %+v", got)
	}
}

func TestAnOfferWithoutAnAnswerExpires(t *testing.T) {
	r := newRig(t, Config{AnswerTimeout: 10 * time.Second})
	leg, err := r.e.Offer(LegParams{User: bob, Peer: alice, Mode: store.Chat, Direction: Terminating})
	if err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(9 * time.Second)
	select {
	case <-leg.Done():
		t.Fatal("closed before the answer timeout")
	default:
	}
	r.clock.Advance(time.Second)
	waitDone(t, leg.Done())
	if err := leg.Answer([]msrp.URI{clientURI()}); err == nil {
		t.Fatal("an expired offer was answered")
	}
	if r.m.get("leg.unanswered") != 1 {
		t.Fatalf("metrics %v", r.m)
	}
	// An answered offer, whose relay connected, does not expire.
	leg, err = r.e.Offer(LegParams{User: bob, Peer: alice, Mode: store.Chat, Direction: Terminating})
	if err != nil {
		t.Fatal(err)
	}
	defer leg.Close()
	u := clientURI()
	r.dial(t, r.listen(t), u, leg.Local())
	if err := leg.Answer([]msrp.URI{u}); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(time.Minute)
	select {
	case <-leg.Done():
		t.Fatal("an answered leg expired")
	default:
	}
}

// A leg whose peer's path is known but that no connection binds is closed
// after AnswerTimeout, whether it was opened on an offer (OpenLeg) or
// answered (security review on #252): a client that never connects to
// msrp-relay would otherwise hold it, and its SIP session, until the task
// stops (threat model T9).
func TestALegNoConnectionBindsIsClosed(t *testing.T) {
	r := newRig(t, Config{AnswerTimeout: 10 * time.Second})
	opened, err := r.e.OpenLeg(LegParams{Remote: []msrp.URI{clientURI()}, User: alice, Peer: bob, Mode: store.Chat, Direction: Originating})
	if err != nil {
		t.Fatal(err)
	}
	answered, err := r.e.Offer(LegParams{User: bob, Peer: alice, Mode: store.Chat, Direction: Terminating})
	if err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(5 * time.Second)
	if err := answered.Answer([]msrp.URI{clientURI()}); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(5 * time.Second) // the opened leg's deadline
	waitDone(t, opened.Done())
	select {
	case <-answered.Done():
		t.Fatal("the answered leg closed before its own deadline")
	default:
	}
	r.clock.Advance(5 * time.Second)
	waitDone(t, answered.Done())
	if r.m.get("leg.unbound") != 2 || r.m.get("leg.unanswered") != 0 {
		t.Fatalf("metrics %v", r.m)
	}
}

func waitDone(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(hangGuard):
		t.Fatal("not done")
	}
}

func TestIsComposingIsForwardedToThePeerWithoutBeingStored(t *testing.T) {
	r := newRig(t, Config{})
	l := r.listen(t)
	_, a := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	// As rcsjta sends it: in the chat session, not wrapped in CPIM.
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<isComposing xmlns="urn:ietf:params:xml:ns:im-iscomposing"><state>active</state><contenttype>text/plain</contenttype><refresh>60</refresh></isComposing>`)
	// With no leg to bob it is dropped, and still answered 200.
	if code := a.outcome(t, IsComposingType, body); code != msrp.StatusOK {
		t.Fatalf("is-composing answered %d", code)
	}
	_, b := r.connect(t, l, LegParams{User: bob, Peer: alice, Conversation: conv, Mode: store.Chat})
	if code := a.outcome(t, IsComposingType, body); code != msrp.StatusOK {
		t.Fatalf("is-composing answered %d", code)
	}
	got := b.next(t)
	if got.MediaType() != IsComposingType || !bytes.Equal(got.Body, body) {
		t.Fatalf("bob got %s %q", got.MediaType(), got.Body)
	}
	waitFor(t, "the count", func() bool { return r.m.get("iscomposing.forwarded") == 1 })
	if r.queued(t, bob) != 0 || r.m.get("iscomposing.dropped") != 1 || r.m.get("message.accepted") != 0 {
		t.Fatalf("metrics %v", r.m)
	}
	if got := AcceptTypes(store.Chat); len(got) != 2 || got[1] != IsComposingType {
		t.Fatalf("AcceptTypes(chat) = %v", got)
	}
	// A large-mode session carries one CPIM message and nothing else.
	_, s := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Standalone})
	if code := s.outcome(t, IsComposingType, body); code != msrp.StatusUnsupportedMediaType {
		t.Fatalf("is-composing on a large-mode leg answered %d", code)
	}
}

func TestAStoreFailureOnALegIsAnsweredAsRetryable(t *testing.T) {
	r := newRigWith(t, Config{}, failingStore{store.NewMemory()}, newFakeClock())
	l := r.listen(t)
	_, a := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	if code := a.outcome(t, cpim.ContentType, chat(t, "m1", "hi", 0)); code != StatusTryAgain {
		t.Fatalf("a message rcs-as could not store was answered %d", code)
	}
}

func TestIsComposingIsRateLimitedPerLeg(t *testing.T) {
	r := newRig(t, Config{})
	l := r.listen(t)
	_, a := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	_, b := r.connect(t, l, LegParams{User: bob, Peer: alice, Conversation: conv, Mode: store.Chat})
	body := []byte(`<isComposing xmlns="urn:ietf:params:xml:ns:im-iscomposing"><state>active</state></isComposing>`)
	seen := int64(0)
	send := func(n int) {
		for range n {
			if code := a.outcome(t, IsComposingType, body); code != msrp.StatusOK {
				t.Fatalf("answered %d", code)
			}
			// One at a time is not what limits here: let each go first.
			seen++
			waitFor(t, "the forward", func() bool { return r.m.get("iscomposing.forwarded")+r.m.get("iscomposing.dropped") == seen })
		}
	}
	send(IsComposingRate.Burst + 3)
	waitFor(t, "the counts", func() bool {
		return r.m.get("iscomposing.forwarded")+r.m.get("iscomposing.dropped") == int64(IsComposingRate.Burst+3)
	})
	if got := r.m.get("iscomposing.forwarded"); got != int64(IsComposingRate.Burst) {
		t.Fatalf("%d forwarded from a burst of %d", got, IsComposingRate.Burst+3)
	}
	r.clock.Advance(time.Second)
	send(1)
	if got := r.m.get("iscomposing.forwarded"); got != int64(IsComposingRate.Burst+1) {
		t.Fatalf("%d forwarded after a token refilled", got)
	}
	for range IsComposingRate.Burst + 1 {
		b.next(t)
	}
}

// At the answer timeout's boundary either the answer wins and the leg
// stays, or the timeout wins and the answer is refused: never an answered
// leg that then closes.
// The timeout decides under the leg's lock and closes the leg after: an
// Answer in between finds the decision and is refused.
func TestAnAnswerAfterTheTimeoutDecidedIsRefused(t *testing.T) {
	r := newRig(t, Config{})
	leg, err := r.e.Offer(LegParams{User: bob, Peer: alice, Mode: store.Chat, Direction: Terminating})
	if err != nil {
		t.Fatal(err)
	}
	defer leg.Close()
	leg.mu.Lock()
	leg.expired = true // as the timeout leaves it just before it closes the leg
	leg.mu.Unlock()
	if err := leg.Answer([]msrp.URI{clientURI()}); err == nil {
		t.Fatal("an answer after the timeout decided was taken")
	}
}

func TestAnAnswerAtTheTimeoutEitherWinsOrIsRefused(t *testing.T) {
	for range 50 {
		r := newRig(t, Config{AnswerTimeout: time.Second})
		leg, err := r.e.Offer(LegParams{User: bob, Peer: alice, Mode: store.Chat, Direction: Terminating})
		if err != nil {
			t.Fatal(err)
		}
		answered := make(chan error, 1)
		go func() { answered <- leg.Answer([]msrp.URI{clientURI()}) }()
		r.clock.Advance(time.Second)
		err = <-answered
		select {
		case <-leg.Done():
			// An answer just before the clock moved also starts the bind
			// deadline, which the same Advance may reach: that close is
			// the bind deadline's, not the answer timeout's.
			if err == nil && r.m.get("leg.unbound") == 0 {
				t.Fatal("an answered leg was closed by the timeout")
			}
		default:
			if err != nil {
				t.Fatalf("a refused answer left the leg open: %v", err)
			}
		}
		leg.Close()
	}
}

// The session for waiting messages opens while a pass over the queue is
// half-way: a later message must not go ahead of the waiting ones.
func TestASessionOpeningMidwayKeepsTheQueueInOrder(t *testing.T) {
	r := newRig(t, Config{SenderRate: Rate{PerMinute: -1}})
	l := r.listen(t)
	for _, id := range []string{"m1", "m2", "m3"} {
		if err := r.e.Submit(t.Context(), Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: chat(t, id, id, 0)}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "idle", r.idle)
	drainInvites(t, r.d)
	opened := make(chan *client, 1)
	var once sync.Once
	r.d.onInvite(func(Invitation) error {
		// The answer arrives while the pass that asked is still going.
		once.Do(func() {
			_, c := r.connect(t, l, LegParams{User: bob, Peer: alice, Conversation: conv, Mode: store.Chat})
			opened <- c
		})
		return nil
	})
	r.e.UserRegistered(bob, true)
	b := <-opened
	for _, want := range []string{"m1", "m2", "m3"} {
		if got := b.next(t); !bytes.HasSuffix(got.Body, []byte(want)) {
			t.Fatalf("got %q, want %s", got.Body, want)
		}
	}
}

// The same for new messages tried on their own: one from a sender with a
// message waiting for the session that has just opened does not go first.
func TestANewMessageDoesNotOvertakeOnesWaitingForTheSameSession(t *testing.T) {
	r := newRig(t, Config{SenderRate: Rate{PerMinute: -1}, RetryInterval: time.Hour})
	l := r.listen(t)
	drainInvites(t, r.d)
	// alice's m1 waits for a session to bob.
	if err := r.e.Submit(t.Context(), Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: chat(t, "m1", "m1", 0)}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "idle", r.idle)
	// carol's pager-mode messages hold the worker, one at a time.
	entered, proceed := make(chan struct{}, 4), make(chan struct{}, 4)
	r.d.onPager(func(Delivery) error { entered <- struct{}{}; <-proceed; return nil })
	if err := r.e.Submit(t.Context(), standalone(carol, bob, chat(t, "c1", "c1", 0))); err != nil {
		t.Fatal(err)
	}
	<-entered
	// While it is held, carol's c2 and alice's m2 arrive: the next pass
	// tries them on their own, c2 first.
	for _, o := range []Origin{
		standalone(carol, bob, chat(t, "c2", "c2", 0)),
		{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: chat(t, "m2", "m2", 0)},
	} {
		if err := r.e.Submit(t.Context(), o); err != nil {
			t.Fatal(err)
		}
	}
	proceed <- struct{}{}
	<-entered // c2
	// bob's session with alice opens now, before m2 is tried.
	_, b := r.connect(t, l, LegParams{User: bob, Peer: alice, Conversation: conv, Mode: store.Chat})
	proceed <- struct{}{}
	for _, want := range []string{"m1", "m2"} {
		if got := b.next(t); !bytes.HasSuffix(got.Body, []byte(want)) {
			t.Fatalf("got %q, want %s", got.Body, want)
		}
	}
}
