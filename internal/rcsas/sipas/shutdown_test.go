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

// #270: a shutdown while a first message is being stored, before the
// INVITE's 200, sends that 200 first and the session's BYE after it,
// never a BYE for a dialog the client does not have yet.
func TestShutdownAnswersAnInviteBeforeEndingIt(t *testing.T) {
	held := &heldStore{Store: store.NewMemory(), entered: make(chan struct{}, 1), release: make(chan struct{})}
	r := newChatRigStore(t, messaging.Config{}, Config{closeWait: time.Hour}, transport.Config{}, held)
	var once sync.Once
	release := func() { once.Do(func() { close(held.release) }) }
	// Before the rig's own cleanup, which would wait for the held write.
	t.Cleanup(release)
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		res, _ := sip.NewResponse(req, 200, "", "core1")
		return []*sip.Response{res}
	})
	p := r.a.dial(t)
	answered := make(chan *sip.Response, 1)
	body := firstMessageBody([2]string{sdpType, offerSDP(relayPath(), "active")}, [2]string{cpim.ContentType, chatCPIM("first1", "hi")})
	go func() {
		res, err := p.try(r.withFirstMessage(body))
		if err != nil {
			res = nil
		}
		answered <- res
	}()
	select {
	case <-held.entered:
	case <-time.After(waitFor):
		t.Fatal("the first message was not stored")
	}
	closed := make(chan struct{})
	go func() { r.a.srv.Close(); close(closed) }()
	// Close waits for the session's 200, which waits for the store.
	for {
		r.a.srv.mu.Lock()
		closing := r.a.srv.closed
		r.a.srv.mu.Unlock()
		if closing {
			break
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case req := <-r.core.got:
		t.Fatalf("%s sent before the INVITE was answered", req.Method)
	case <-closed:
		t.Fatal("Close returned before the INVITE was answered")
	case <-time.After(200 * time.Millisecond):
	}
	release()
	res := <-answered
	if res == nil || res.StatusCode != 200 {
		t.Fatalf("answered %+v", res)
	}
	to, _ := res.Header.To()
	bye := r.core.nextOf(t, "BYE")
	if from, _ := bye.Header.From(); bye.Header.Get("Call-ID") != res.Header.Get("Call-ID") || from.Tag() != to.Tag() {
		t.Fatalf("BYE for %q, want the session the 200 set up", bye.Header.Get("Call-ID"))
	}
	select {
	case <-closed:
	case <-time.After(waitFor):
		t.Fatal("Close did not return")
	}
}
