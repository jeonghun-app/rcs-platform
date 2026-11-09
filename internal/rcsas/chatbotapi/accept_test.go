package chatbotapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
)

// stubAcceptor answers err to every request, and keeps the deadline of the
// context it was handed.
type stubAcceptor struct {
	err      error
	deadline time.Time
}

func (s *stubAcceptor) AcceptMessage(ctx context.Context, _ chatbot.BotMessage) error {
	s.deadline, _ = ctx.Deadline()
	return s.err
}

func (s *stubAcceptor) AcceptNotification(context.Context, chatbot.BotNotification) error {
	return s.err
}

// serve answers one message with acc behind the API of e's configuration.
func (e *env) serve(acc Acceptor) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, messagesPath, strings.NewReader(message(nil)))
	req.Header.Set("Authorization", "Bearer "+currentToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	New(e.api.cfg, acc, e.h.Runtime.Logger, e.h.Runtime.Metrics).ServeHTTP(w, req)
	return w
}

// The acceptor works on at most Accepts requests at once, messages and
// notifications together; one past them is 503 at once, as for the decode
// cap, and the cap frees when the held one ends.
func TestARequestOverTheAcceptCapIs503(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Accepts = 1 })
	e.acc.entered, e.acc.release = make(chan struct{}), make(chan struct{})
	done := make(chan int, 1)
	go func() { done <- e.post(t, messagesPath, message(nil)) }()
	<-e.acc.entered
	status, h, body := e.do(t, http.MethodPost, notesPath, "Bearer "+currentToken, "application/json", notification(nil))
	if status != 503 || h.Get("Retry-After") != "1" || !strings.Contains(body, "being accepted") {
		t.Errorf("past the cap: %d %v %q", status, h, body)
	}
	if n, _ := e.h.Metric("chatbot.api.accept_busy"); n != 1 {
		t.Errorf("chatbot.api.accept_busy = %v", n)
	}
	close(e.acc.release)
	if status := <-done; status != 202 {
		t.Fatalf("the held message: %d", status)
	}
	if status := e.post(t, notesPath, notification(nil)); status != 202 {
		t.Fatalf("after the cap freed: %d", status)
	}
}

// The acceptor's context ends within acceptTimeout, well before the
// server's WriteTimeout, so that a slow store cannot hold a request's
// memory longer than that.
func TestTheAcceptorHasADeadlineBeforeTheWriteTimeout(t *testing.T) {
	e := newEnv(t, nil)
	acc := &stubAcceptor{}
	before := time.Now()
	if w := e.serve(acc); w.Code != 202 {
		t.Fatalf("status %d", w.Code)
	}
	after := time.Now()
	if acc.deadline.Before(before.Add(acceptTimeout)) || acc.deadline.After(after.Add(acceptTimeout)) || acceptTimeout >= e.api.Server().WriteTimeout {
		t.Fatalf("deadline %v after the request, timeout %v", acc.deadline.Sub(before), acceptTimeout)
	}
}

// A refusal of the engine's is 403 naming its rule, as a person's message
// refused for it is; a store failure is 503 with Retry-After.
func TestTheAcceptorsAnswersMapToStatuses(t *testing.T) {
	e := newEnv(t, nil)
	for _, c := range []struct {
		err          error
		status       int
		retry, error string
	}{
		{messaging.Reject(messaging.ReasonQueueShareFull), 403, "", "refused: queue_share_full"},
		{messaging.Reject(messaging.ReasonQueueFull), 403, "", "refused: queue_full"},
		{ErrUnavailable, 503, "5", "rcs-as cannot take it now"},
		{context.DeadlineExceeded, 500, "", "internal error"},
	} {
		w := e.serve(&stubAcceptor{err: c.err})
		if w.Code != c.status || w.Header().Get("Retry-After") != c.retry || !strings.Contains(w.Body.String(), `"`+c.error+`"`) {
			t.Errorf("%v: %d %v %q", c.err, w.Code, w.Header(), w.Body)
		}
	}
}
