package sipas

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// A panic in the work an answer to rcs-as's INVITE starts, here the
// engine's InviteFailed, ends that work only: it is counted as
// background.panics, and the next invitation is handled (#471 QA).
func TestAPanicInAnInvitesAnswerWorkEndsThatWorkOnly(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	r.core.setAnswer(func(req *sip.Request) int {
		if req.Method == "INVITE" {
			return 600
		}
		return 200
	})
	r.e.panics.Store(1)
	p := r.a.dial(t)
	uri, _ := r.create(t, p, relayPath(), bob)
	r.core.nextOf(t, "INVITE")
	if err := r.e.nextFailure(t); err == nil {
		t.Fatal("no failure")
	}
	deadline := time.Now().Add(waitFor)
	for r.metrics.get(MetricBackgroundPanics) != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("%s = %d, want 1", MetricBackgroundPanics, r.metrics.get(MetricBackgroundPanics))
		}
		time.Sleep(time.Millisecond)
	}
	inv := messaging.Invitation{Recipient: bob, Peer: uri, Mode: store.Group, Conversation: messaging.Conversation{Contribution: "gch4t1"}}
	if err := r.a.srv.Invite(t.Context(), inv); err != nil {
		t.Fatal(err)
	}
	if err := r.e.nextFailure(t); err == nil {
		t.Fatal("the next invitation did not fail as answered")
	}
}

// ackPanics panics on the first ACK it is given to send, as a bug on the
// way to the transport would.
type ackPanics struct {
	transaction.Sender
	sent atomic.Bool
}

func (a *ackPanics) SendRequest(req *sip.Request, dst transport.Destination, opts ...transport.SendOption) (transport.Network, error) {
	if req.Method == "ACK" && a.sent.CompareAndSwap(false, true) {
		panic("ack")
	}
	return a.Sender.SendRequest(req, dst, opts...)
}

// A panic sending the ACK of a 2xx to rcs-as's INVITE, once the session
// took its slot, ends the session as one that cannot be kept is: the
// engine hears the invitation failed, the session is ended with a BYE, and
// its slot is given back and settled, so that a stop does not wait for its
// first answer (#471 code review).
func TestAPanicSendingAnInvitesACKEndsTheSession(t *testing.T) {
	// A stop waits up to closeWait for a session that is not settled:
	// longer than the wait below, and short enough for the test's own
	// stop to end if it fails.
	r := newChatRigWith(t, messaging.Config{}, Config{closeWait: 3 * waitFor})
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method == "INVITE" {
			return []*sip.Response{r.answerInvite(t, req, relayPath(), "active")}
		}
		return nil
	})
	r.a.srv.sender = &ackPanics{Sender: r.a.srv.sender}
	if err := r.a.srv.Invite(t.Context(), invitation()); err != nil {
		t.Fatal(err)
	}
	r.core.nextOf(t, "INVITE")
	if err := r.e.nextFailure(t); !errors.Is(err, messaging.ErrOffline) {
		t.Fatalf("the engine was told %v, want the message kept for the next session", err)
	}
	r.core.nextOf(t, "BYE")
	deadline := time.Now().Add(waitFor)
	for {
		r.a.srv.mu.Lock()
		left := len(r.a.srv.sessions)
		r.a.srv.mu.Unlock()
		if left == 0 && r.metrics.get(MetricBackgroundPanics) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d sessions left, %s = %d", left, MetricBackgroundPanics, r.metrics.get(MetricBackgroundPanics))
		}
		time.Sleep(time.Millisecond)
	}
	closed := make(chan struct{})
	go func() { r.a.srv.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(waitFor):
		t.Fatal("Close waits for the session's first answer")
	}
}
