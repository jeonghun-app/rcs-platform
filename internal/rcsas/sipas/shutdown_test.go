package sipas

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// heldStore holds every Enqueue until release is closed, and says when
// one starts.
type heldStore struct {
	store.Store
	entered chan struct{}
	release chan struct{}
}

func (h *heldStore) Enqueue(ctx context.Context, m store.Message, l store.Limit) error {
	h.entered <- struct{}{}
	<-h.release
	return h.Store.Enqueue(ctx, m, l)
}

// shutdownRig is a rig whose store holds every Enqueue until released, so
// that a first-message INVITE stays unanswered.
type shutdownRig struct {
	*chatRig
	held    *heldStore
	release func()
	p       *peer
	closed  chan struct{}
}

func newShutdownRig(t *testing.T, wait time.Duration) *shutdownRig {
	t.Helper()
	held := &heldStore{Store: store.NewMemory(), entered: make(chan struct{}, 1), release: make(chan struct{})}
	r := newChatRigStore(t, messaging.Config{}, Config{closeWait: wait}, transport.Config{}, held)
	var once sync.Once
	sr := &shutdownRig{chatRig: r, held: held, release: func() { once.Do(func() { close(held.release) }) }, closed: make(chan struct{})}
	// Before the rig's own cleanup, which would wait for the held write.
	t.Cleanup(sr.release)
	sr.p = r.a.dial(t)
	return sr
}

// heldInvite sends a first-message INVITE, whose answer waits for the
// store, and returns where its final response will come.
func (r *shutdownRig) heldInvite(t *testing.T) <-chan *sip.Response {
	t.Helper()
	answered := make(chan *sip.Response, 1)
	body := firstMessageBody([2]string{sdpType, offerSDP(relayPath(), "active")}, [2]string{cpim.ContentType, chatCPIM("first1", "hi")})
	go func() {
		res, err := r.p.try(r.withFirstMessage(body))
		if err != nil {
			res = nil
		}
		answered <- res
	}()
	select {
	case <-r.held.entered:
	case <-time.After(waitFor):
		t.Fatal("the first message was not stored")
	}
	return answered
}

// close starts Close and returns once the Server is closing.
func (r *shutdownRig) close() {
	go func() { r.a.srv.Close(); close(r.closed) }()
	for {
		r.a.srv.mu.Lock()
		closing := r.a.srv.closed
		r.a.srv.mu.Unlock()
		if closing {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// quiet fails if the core gets a request, or Close returns when it must
// not, within d.
func (r *shutdownRig) quiet(t *testing.T, d time.Duration, closeMayReturn bool, what string) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case req := <-r.core.got:
			t.Fatalf("%s: %s sent", what, req.Method)
		case <-r.closed:
			if !closeMayReturn {
				t.Fatalf("%s: Close returned", what)
			}
			r.closed = nil // a nil channel never receives again
		case <-deadline:
			return
		}
	}
}

// ackOf acknowledges the 2xx res of a chat INVITE from alice.
func (r *shutdownRig) ackOf(t *testing.T, res *sip.Response) {
	t.Helper()
	to, _ := res.Header.To()
	if _, err := r.p.try(msg{method: "ACK", uri: bob, toTag: to.Tag(), callID: res.Header.Get("Call-ID"), cseq: 1}); err != nil {
		t.Fatal(err)
	}
}

// byeFor waits for the BYE of the session res set up.
func (r *shutdownRig) byeFor(t *testing.T, res *sip.Response) {
	t.Helper()
	to, _ := res.Header.To()
	bye := r.core.nextOf(t, "BYE")
	if from, _ := bye.Header.From(); bye.Header.Get("Call-ID") != res.Header.Get("Call-ID") || from.Tag() != to.Tag() {
		t.Fatalf("BYE for %q, want the session the 200 set up", bye.Header.Get("Call-ID"))
	}
}

func (r *shutdownRig) waitClosed(t *testing.T) {
	t.Helper()
	if r.closed == nil {
		return
	}
	select {
	case <-r.closed:
	case <-time.After(waitFor):
		t.Fatal("Close did not return")
	}
}

func answeredOK(t *testing.T, answered <-chan *sip.Response) *sip.Response {
	t.Helper()
	select {
	case res := <-answered:
		if res == nil || res.StatusCode != 200 {
			t.Fatalf("answered %+v", res)
		}
		return res
	case <-time.After(waitFor):
		t.Fatal("no answer")
		return nil
	}
}

// #270: a shutdown while a first message is being stored, before the
// INVITE's 200, waits for that 200 and the client's ACK, and only then ends
// the session with a BYE: never a BYE for a dialog the client does not
// have yet.
func TestShutdownAnswersAnInviteBeforeEndingIt(t *testing.T) {
	r := newShutdownRig(t, time.Hour)
	answered := r.heldInvite(t)
	r.close()
	// Close waits for the session's 200, which waits for the store.
	r.quiet(t, 200*time.Millisecond, false, "before the INVITE was answered")
	r.release()
	res := answeredOK(t, answered)
	// The BYE waits for the 2xx's ACK too (RFC 3261 §15).
	r.quiet(t, 200*time.Millisecond, false, "before the 2xx's ACK")
	r.ackOf(t, res)
	r.byeFor(t, res)
	r.waitClosed(t)
}

// Code review on #273: a first message stored for longer than Close's
// bound (RCSAS_STORE_TIMEOUT is 5 s, closeWait 2 s) still gets its 200
// before any BYE. Close returns at its bound without ending the session,
// which ends itself once its answer and the ACK are out.
func TestAnInviteAnsweredAfterShutdownEndsItself(t *testing.T) {
	r := newShutdownRig(t, 50*time.Millisecond)
	answered := r.heldInvite(t)
	r.close()
	r.waitClosed(t)
	r.quiet(t, 100*time.Millisecond, true, "after Close's bound, before the answer")
	r.release()
	res := answeredOK(t, answered)
	r.ackOf(t, res)
	r.byeFor(t, res)
}

// A session answered but not acknowledged when the shutdown comes gets its
// BYE once the ACK comes, or once Close's bound runs out without one,
// rather than waiting 32 s for the transaction to end.
func TestShutdownWaitsForAnACKWithinItsBound(t *testing.T) {
	r := newShutdownRig(t, 100*time.Millisecond)
	res := r.p.send(r.chatInvite(offerSDP(relayPath(), "active")))
	if res.StatusCode != 200 {
		t.Fatalf("answered %d", res.StatusCode)
	}
	r.close()
	r.byeFor(t, res)
	r.waitClosed(t)
}

// The BYEs' answers have a bound of their own: a shutdown that spent its
// first bound on a session still being stored still waits for the answer
// to another session's BYE.
func TestTheByesHaveTheirOwnBound(t *testing.T) {
	const wait = 300 * time.Millisecond
	r := newShutdownRig(t, wait)
	answerBye := make(chan struct{})
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method == "BYE" {
			<-answerBye
		}
		res, _ := sip.NewResponse(req, 200, "", "core1")
		return []*sip.Response{res}
	})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(answerBye) }) })
	live := r.p.send(r.chatInvite(offerSDP(relayPath(), "active")))
	if live.StatusCode != 200 {
		t.Fatalf("answered %d", live.StatusCode)
	}
	r.ackOf(t, live)
	r.heldInvite(t)
	start := time.Now()
	r.close()
	// The first bound passes waiting for the stored message; then the
	// live session's BYE goes, and Close waits for its answer.
	r.byeFor(t, live)
	for time.Since(start) < wait+wait/2 {
		select {
		case <-r.closed:
			t.Fatalf("Close returned %v after it began, before the BYE was answered", time.Since(start))
		case <-time.After(10 * time.Millisecond):
		}
	}
	once.Do(func() { close(answerBye) })
	r.waitClosed(t)
}

// A session rcs-as started is confirmed once rcs-as sent its ACK: its
// BYE on shutdown goes at once, without waiting for any bound.
func TestShutdownEndsASessionRCSASStartedAtOnce(t *testing.T) {
	r := newShutdownRig(t, time.Hour)
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method == "INVITE" {
			return []*sip.Response{r.answerInvite(t, req, relayPath(), "active")}
		}
		res, _ := sip.NewResponse(req, 200, "", "core1")
		return []*sip.Response{res}
	})
	if err := r.a.srv.Invite(t.Context(), invitation()); err != nil {
		t.Fatal(err)
	}
	inv := r.core.nextOf(t, "INVITE")
	r.core.nextOf(t, "ACK")
	r.close()
	if bye := r.core.nextOf(t, "BYE"); bye.Header.Get("Call-ID") != inv.Header.Get("Call-ID") {
		t.Fatalf("BYE for %q", bye.Header.Get("Call-ID"))
	}
	r.waitClosed(t)
}

// QA on #273 (the test that failed on 6a8c757): RFC 3261 §15, no BYE
// after the 200 before the client's ACK, which it withholds for 500 ms.
func TestQA273ByeWaitsForTheACK(t *testing.T) {
	r := newShutdownRig(t, time.Hour)
	answered := r.heldInvite(t)
	r.close()
	r.release()
	res := answeredOK(t, answered)
	s := answeredBy(t, res)
	select {
	case req := <-r.core.got:
		t.Errorf("%s sent after the 200, before the client's ACK (RFC 3261 §15)", req.Method)
	case <-time.After(500 * time.Millisecond):
	}
	r.p.ack(s)
	r.byeFor(t, res)
	r.waitClosed(t)
}

// QA on #273: past Close's bound, no BYE while the INVITE is unanswered;
// its 200, and its BYE once the store write ends and the ACK is in.
func TestQA273AnInviteAnsweredAfterCloseIsEndedAfterIts200(t *testing.T) {
	r := newShutdownRig(t, 100*time.Millisecond)
	answered := r.heldInvite(t)
	r.a.srv.Close() // returns after its 100 ms bound
	select {
	case req := <-r.core.got:
		t.Fatalf("%s sent before the INVITE was answered", req.Method)
	case <-time.After(200 * time.Millisecond):
	}
	r.release()
	res := answeredOK(t, answered)
	r.ackOf(t, res)
	r.byeFor(t, res)
}

// QA on #273: a session answered after Close's bound, whose client never
// ACKs, is ended within closeWait of its 200, not at Timer H.
func TestALateAnswerWithoutAnACKIsEndedWithinTheBound(t *testing.T) {
	const w = 150 * time.Millisecond
	r := newShutdownRig(t, w)
	answered := r.heldInvite(t)
	r.a.srv.Close()
	// Timed from just before the release (QA on #279): settle, and its
	// bound, come after it, whereas the client may read the 200 late on a
	// loaded host.
	at := time.Now()
	r.release()
	<-answered
	select {
	case req := <-r.core.got:
		if d := time.Since(at); req.Method != "BYE" || d < w {
			t.Fatalf("%s %v after the release", req.Method, d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no BYE within 3 s of a 200 answered after Close, with no ACK")
	}
}

// QA on #273: Close called three times at once ends a session once.
func TestCloseRunsOnce(t *testing.T) {
	r := newChatRigWith(t, messaging.Config{}, Config{closeWait: 200 * time.Millisecond})
	p := r.a.dial(t)
	s := answeredBy(t, p.send(r.chatInvite(offerSDP(relayPath(), "active"))))
	p.ack(s)
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(r.a.srv.Close)
	}
	wg.Wait()
	time.Sleep(100 * time.Millisecond)
	n := 0
	for len(r.core.got) > 0 {
		if (<-r.core.got).Method == "BYE" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d BYEs", n)
	}
}

// QA on #273 and #279 (the merged-tree test): Close ends a group session
// with a BYE like any other, and does not sit out its bound for it.
func TestQABothCloseEndsAGroupSession(t *testing.T) {
	r := newChatRigWith(t, messaging.Config{}, Config{closeWait: 2 * time.Second})
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		code := 486
		if req.Method == "BYE" {
			code = 200
		}
		res, _ := sip.NewResponse(req, code, "", "core1")
		return []*sip.Response{res}
	})
	p := r.a.dial(t)
	_, s := r.create(t, p, relayPath(), bob)
	r.core.nextOf(t, "INVITE")
	start := time.Now()
	r.a.srv.Close()
	if took := time.Since(start); took > time.Second {
		t.Errorf("Close sat out its bound (%v): the group session never settled", took)
	}
	if bye := r.core.nextOf(t, "BYE"); bye.Header.Get("Call-ID") != s.callID {
		t.Errorf("BYE for %q, want alice's group session", bye.Header.Get("Call-ID"))
	}
}

// heldByes has the fake core hold its answer to each BYE until the test
// releases it, by Call-ID.
type heldByes struct {
	mu      sync.Mutex
	release map[string]chan struct{}
}

func (h *heldByes) gate(callID string) chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.release[callID] == nil {
		h.release[callID] = make(chan struct{})
	}
	return h.release[callID]
}

func (h *heldByes) open(callID string) {
	c := h.gate(callID)
	select {
	case <-c:
	default:
		close(c)
	}
}

func holdByes(t *testing.T, r *shutdownRig) *heldByes {
	h := &heldByes{release: map[string]chan struct{}{}}
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method == "BYE" {
			<-h.gate(req.Header.Get("Call-ID"))
		}
		res, _ := sip.NewResponse(req, 200, "", "core1")
		return []*sip.Response{res}
	})
	t.Cleanup(func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		for _, c := range h.release {
			select {
			case <-c:
			default:
				close(c)
			}
		}
	})
	return h
}

// QA on #273: a session settled while Close still waits for the sessions
// being answered is one of Close's own: Close sends its BYE and waits for
// the answer, which settle's own BYE would have left it no part in.
func TestASessionSettledDuringCloseIsClosesOwn(t *testing.T) {
	for range 5 {
		r := newShutdownRig(t, time.Hour)
		held := holdByes(t, r)
		answered := r.heldInvite(t)
		r.close()
		r.release()
		res := answeredOK(t, answered)
		r.ackOf(t, res)
		r.core.nextOf(t, "BYE")
		r.quiet(t, 100*time.Millisecond, false, "before its BYE was answered")
		held.open(res.Header.Get("Call-ID"))
		r.waitClosed(t)
	}
}

// QA on #273: a session that settles once Close has taken its sessions,
// while Close still waits for its own BYEs, ends itself, and Close waits
// for that BYE's answer too.
func TestCloseWaitsForALateSessionsBye(t *testing.T) {
	// Close's bound must outlast the late session's answer, ACK and BYE
	// on a loaded host: the late BYE is waited for only until Close's own
	// deadline, twice the bound from its start.
	const wait = 3 * time.Second
	r := newShutdownRig(t, wait)
	held := holdByes(t, r)
	live := r.p.send(r.chatInvite(offerSDP(relayPath(), "active")))
	if live.StatusCode != 200 {
		t.Fatalf("answered %d", live.StatusCode)
	}
	r.ackOf(t, live)
	answered := r.heldInvite(t)
	r.close()
	// Close's first bound passes waiting for the stored message; then the
	// live session's BYE goes, and its answer is held.
	r.byeFor(t, live)
	r.release()
	late := answeredOK(t, answered)
	r.ackOf(t, late)
	held.open(live.Header.Get("Call-ID"))
	r.byeFor(t, late)
	r.quiet(t, 200*time.Millisecond, false, "before the late session's BYE was answered")
	held.open(late.Header.Get("Call-ID"))
	r.waitClosed(t)
}

// QA on #273: Close runs once, and a second call waits for the first,
// rather than returning while its BYEs are still unanswered.
func TestASecondCloseWaitsForTheFirst(t *testing.T) {
	r := newShutdownRig(t, time.Hour)
	held := holdByes(t, r)
	res := r.p.send(r.chatInvite(offerSDP(relayPath(), "active")))
	if res.StatusCode != 200 {
		t.Fatalf("answered %d", res.StatusCode)
	}
	r.ackOf(t, res)
	r.close()
	r.byeFor(t, res)
	second := make(chan struct{})
	go func() { r.a.srv.Close(); close(second) }()
	select {
	case <-second:
		t.Fatal("a second Close returned before the first's BYE was answered")
	case <-time.After(100 * time.Millisecond):
	}
	held.open(res.Header.Get("Call-ID"))
	<-second
	r.waitClosed(t)
}
