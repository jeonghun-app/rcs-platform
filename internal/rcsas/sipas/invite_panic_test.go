package sipas

import (
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
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
