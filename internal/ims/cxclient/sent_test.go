package cxclient

import (
	"context"
	"errors"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

// scripted makes the k-th send (1-based) fail with errs[k-1]; a nil entry
// sends for real.
func scripted(c *Client, errs ...error) {
	n := 0
	real := c.send
	c.send = func(ctx context.Context, p *diameter.Peer, m *diameter.Message) (*diameter.Message, error) {
		n++
		if n <= len(errs) && errs[n-1] != nil {
			return nil, errs[n-1]
		}
		return real(ctx, p, m)
	}
}

func twoTasks(t *testing.T) *env {
	e := newEnv(t, nil)
	startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	startHSS(t, e.net, "192.0.2.2", "hss-b.rcs.local")
	e.refresh("192.0.2.1", "192.0.2.2")
	return e
}

func mar() *cx.MAR { return &cx.MAR{UserName: impi1, PublicIdentity: impu1, NumberAuthItems: 1} }

// TestAFirstAttemptThatTimedOutWasSent: the issue's other case, a first
// attempt that timed out (it left, and the HSS may have served it) before
// the retry found its task unavailable (#261, QA on #296).
func TestAFirstAttemptThatTimedOutWasSent(t *testing.T) {
	e := twoTasks(t)
	scripted(e.client, diameter.ErrTimeout, diameter.ErrPeerUnavailable)
	_, err := e.client.MAR(ctx(t), mar())
	if !errors.Is(err, diameter.ErrPeerUnavailable) || NeverSent(err) {
		t.Errorf("error %v, NeverSent %v; want sent", err, NeverSent(err))
	}
}

// TestAnAttemptRefusedAsNotNegotiatedNeverLeft: a peer that did not
// negotiate Cx refuses before the send; with the retry unavailable too,
// nothing left.
func TestAnAttemptRefusedAsNotNegotiatedNeverLeft(t *testing.T) {
	e := twoTasks(t)
	scripted(e.client, diameter.ErrApplicationNotNegotiated, diameter.ErrPeerUnavailable)
	_, err := e.client.MAR(ctx(t), mar())
	if !NeverSent(err) {
		t.Errorf("error %v: NeverSent false, want true", err)
	}
}

// TestAnAuthenticationWhoseMARFoundNoTaskWasNeverSent: the first scheme's
// MAR found every task unavailable, so the registrar's challenge path still
// gives the counts back (#223).
func TestAnAuthenticationWhoseMARFoundNoTaskWasNeverSent(t *testing.T) {
	e := twoTasks(t)
	scripted(e.client, diameter.ErrPeerUnavailable, diameter.ErrPeerUnavailable)
	schemes, _ := Schemes("", nil)
	_, err := e.client.Authenticate(ctx(t), mar(), schemes)
	if !NeverSent(err) {
		t.Errorf("error %v: NeverSent false, want true", err)
	}
}

// TestAnAuthenticationWithoutATaskWasNeverSent: no task connected at all.
func TestAnAuthenticationWithoutATaskWasNeverSent(t *testing.T) {
	e := newEnv(t, nil)
	schemes, _ := Schemes("", nil)
	_, err := e.client.Authenticate(ctx(t), mar(), schemes)
	if !errors.Is(err, ErrNoPeer) || !NeverSent(err) {
		t.Errorf("error %v, NeverSent %v; want ErrNoPeer, never sent", err, NeverSent(err))
	}
}

// TestAnAuthenticationAnsweredBusyBeforeItsRetryWasSent: a 3004, then the
// retry unavailable, through Authenticate, the challenge path.
func TestAnAuthenticationAnsweredBusyBeforeItsRetryWasSent(t *testing.T) {
	e := newEnv(t, nil)
	a := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	b := startHSS(t, e.net, "192.0.2.2", "hss-b.rcs.local")
	a.setAnswer(busy)
	b.setAnswer(busy)
	e.refresh("192.0.2.1", "192.0.2.2")
	scripted(e.client, nil, diameter.ErrPeerUnavailable)
	schemes, _ := Schemes("", nil)
	_, err := e.client.Authenticate(ctx(t), mar(), schemes)
	if !errors.Is(err, diameter.ErrPeerUnavailable) || NeverSent(err) || ErrorOutcome(err) != Unavailable {
		t.Errorf("error %v, NeverSent %v, outcome %v", err, NeverSent(err), ErrorOutcome(err))
	}
}

// TestASentErrorStaysSentWhateverWrapsIt: a caller that wraps the error
// again, or joins it, keeps what NeverSent says.
func TestASentErrorStaysSentWhateverWrapsIt(t *testing.T) {
	err := fmtWrap(&SentError{Err: diameter.ErrPeerUnavailable})
	if NeverSent(err) || !errors.Is(err, diameter.ErrPeerUnavailable) {
		t.Error("rewrapped SentError")
	}
	if NeverSent(errors.Join(ErrNoPeer, &SentError{Err: ErrNoPeer})) {
		t.Error("joined")
	}
	if NeverSent(nil) {
		t.Error("nil is never sent")
	}
}

func fmtWrap(err error) error { return &wrapErr{err} }

type wrapErr struct{ e error }

func (w *wrapErr) Error() string { return "x: " + w.e.Error() }
func (w *wrapErr) Unwrap() error { return w.e }
