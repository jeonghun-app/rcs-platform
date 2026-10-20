package transaction

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// 128*T1 by default, later than a proxy TU's own Timer F after routing
// (decided on #156).
func TestUnansweredNonInviteGets500After128T1AndTheTUIsTold(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{})
	req := request(t, "MESSAGE", "z9hG4bKsafe1")
	h.receive(req)
	tx := h.tu.lastTx()
	// A provisional does not extend a non-INVITE transaction.
	h.clock.advance(20 * time.Second)
	if err := tx.Respond(response(t, req, 100)); err != nil {
		t.Fatal(err)
	}
	h.clock.advance(44*time.Second - time.Millisecond)
	if tx.Context().Err() != nil || len(h.sender.take()) != 1 {
		t.Fatal("the safety timer fired early")
	}
	h.clock.advance(time.Millisecond)
	if res := lastResponse(t, h); res.StatusCode != 500 {
		t.Fatalf("sent %d, want 500", res.StatusCode)
	}
	if !errors.Is(context.Cause(tx.Context()), ErrNoFinalResponse) {
		t.Fatalf("Context cause = %v, want ErrNoFinalResponse", context.Cause(tx.Context()))
	}
	if tx.State() != Completed {
		t.Fatalf("state = %s, want Completed", tx.State())
	}
	// The TU's answer comes too late: dropped and counted.
	h.sender.take()
	if err := tx.Respond(response(t, req, 200)); !errors.Is(err, ErrNoFinalResponse) {
		t.Fatalf("late Respond = %v", err)
	}
	if got := h.sender.take(); len(got) != 0 {
		t.Fatalf("a late final response was sent: %q", got)
	}
	if s := h.layer.Stats(); s.ServerTransactionsTimedOut != 1 || s.LateFinalResponses != 1 {
		t.Fatalf("stats = %+v", s)
	}
	// It then ends as any completed non-INVITE transaction does (Timer J).
	h.clock.advance(32 * time.Second)
	if tx.State() != Terminated {
		t.Fatalf("state = %s, want Terminated", tx.State())
	}
}

func TestInviteSafetyTimerOutlastsTimerCAndRestartsOnEveryProvisional(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{})
	req := request(t, "INVITE", "z9hG4bKsafe2")
	h.receive(req)
	tx := h.tu.lastTx()
	check(t, "sent", h.sender.take(), []string{"100"})
	limit := DefaultTimerC + 64*DefaultT1

	// Ringing: a 180 every minute keeps the transaction alive well past the
	// limit, as a UAS does for proxies (RFC 3261 §13.3.1.1).
	ringing := response(t, req, 180)
	for range 5 {
		h.clock.advance(time.Minute)
		if err := tx.Respond(ringing); err != nil {
			t.Fatal(err)
		}
	}
	if tx.Context().Err() != nil || h.layer.Stats().ServerTransactionsTimedOut != 0 {
		t.Fatal("a ringing INVITE was answered for its TU")
	}
	// Silence after the last 180: the layer answers once the limit has passed.
	h.clock.advance(limit - time.Millisecond)
	if tx.Context().Err() != nil {
		t.Fatal("the safety timer fired early")
	}
	h.clock.advance(time.Millisecond)
	res := lastResponse(t, h)
	if res.StatusCode != 500 {
		t.Fatalf("sent %d, want 500", res.StatusCode)
	}
	// The 500 stays in the early dialog the 180 began.
	if to, _ := res.Header.To(); to.Tag() != "b1" {
		t.Fatalf("500 To tag = %q, want the provisional's", to.Tag())
	}
	if !errors.Is(context.Cause(tx.Context()), ErrNoFinalResponse) || tx.State() != Completed {
		t.Fatalf("cause %v, state %s", context.Cause(tx.Context()), tx.State())
	}
	// As after any failure response, Timer G retransmits it over UDP.
	h.sender.take()
	h.clock.advance(DefaultT1)
	check(t, "retransmitted", h.sender.take(), []string{"500"})
}

func TestSafetyTimerGivesA500WithoutAProvisionalItsOwnTag(t *testing.T) {
	h := newHarness(t, transport.TCP, Config{InviteFinalTimeout: time.Minute,
		IDs: sip.IDGenerator{Rand: constantBytes(0xab)}})
	h.receive(request(t, "INVITE", "z9hG4bKsafe3"))
	h.clock.advance(time.Minute)
	res := lastResponse(t, h)
	if to, _ := res.Header.To(); res.StatusCode != 500 || to.Tag() != strings.Repeat("ab", 8) {
		t.Fatalf("sent %d with To tag %q", res.StatusCode, to.Tag())
	}
}

// A provisional too large to be kept under the byte bound (#170) still
// began the early dialog, so the 500 keeps its To tag.
func TestSafetyTimer500KeepsTheTagOfAProvisionalNotKept(t *testing.T) {
	h := newHarness(t, transport.TCP, Config{InviteFinalTimeout: time.Minute, MaxServerTransactionBytes: 64 << 10,
		IDs: sip.IDGenerator{Rand: constantBytes(0xab)}})
	req := request(t, "INVITE", "z9hG4bKsafe6")
	h.receive(req)
	tx := h.tu.lastTx()
	ringing, err := sip.NewResponse(req, 183, "", "early1")
	if err != nil {
		t.Fatal(err)
	}
	ringing.Body = make([]byte, 100<<10)
	if err := tx.Respond(ringing); err != nil {
		t.Fatal(err)
	}
	h.clock.advance(time.Minute)
	res := lastResponse(t, h)
	if to, _ := res.Header.To(); res.StatusCode != 500 || to.Tag() != "early1" {
		t.Fatalf("sent %d with To tag %q, want 500 in the 183's early dialog", res.StatusCode, to.Tag())
	}
}

// constantBytes is a randomness source that always yields the same byte, so a
// generated tag is known in advance (and does not look like an identifier).
type constantBytes byte

func (c constantBytes) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(c)
	}
	return len(p), nil
}

func TestTransactionAnsweredInTimeIsNotTouched(t *testing.T) {
	h := newHarness(t, transport.TCP, Config{})
	req := request(t, "MESSAGE", "z9hG4bKsafe4")
	h.receive(req)
	tx := h.tu.lastTx()
	if err := tx.Respond(response(t, req, 200)); err != nil {
		t.Fatal(err)
	}
	h.clock.advance(time.Hour)
	check(t, "sent", h.sender.take(), []string{"200"})
	// It ended normally, so the Context is cancelled without the timeout cause.
	if tx.Context().Err() == nil || errors.Is(context.Cause(tx.Context()), ErrNoFinalResponse) {
		t.Fatalf("Context err %v, cause %v", tx.Context().Err(), context.Cause(tx.Context()))
	}
	if s := h.layer.Stats(); s.ServerTransactionsTimedOut != 0 || s.LateFinalResponses != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestFinalTimeoutsAreConfigurable(t *testing.T) {
	h := newHarness(t, transport.TCP, Config{NonInviteFinalTimeout: 40 * time.Second})
	h.receive(request(t, "OPTIONS", "z9hG4bKsafe5"))
	h.clock.advance(40 * time.Second)
	if res := lastResponse(t, h); res.StatusCode != 500 {
		t.Fatalf("sent %d", res.StatusCode)
	}
	l := mustNew(t, &fakeSender{}, &tuRecorder{}, Config{T1: 100 * time.Millisecond})
	if l.nonInviteFinal != 128*100*time.Millisecond || l.inviteFinal != DefaultTimerC+64*100*time.Millisecond {
		t.Fatalf("defaults = %v, %v", l.nonInviteFinal, l.inviteFinal)
	}
	// Under 64*T1, of the configured T1 or the default, it would answer
	// before the client and a proxy TU have given up (decided on #156).
	for _, cfg := range []Config{
		{NonInviteFinalTimeout: -1}, {InviteFinalTimeout: -1},
		{NonInviteFinalTimeout: 32*time.Second - time.Millisecond},
		{T1: 100 * time.Millisecond, NonInviteFinalTimeout: 6400*time.Millisecond - 1},
	} {
		if cfg.Validate() == nil {
			t.Errorf("%+v accepted", cfg)
		}
	}
	for _, cfg := range []Config{
		{NonInviteFinalTimeout: 32 * time.Second},
		{T1: 100 * time.Millisecond, NonInviteFinalTimeout: 6400 * time.Millisecond},
	} {
		if err := cfg.Validate(); err != nil {
			t.Errorf("%+v refused: %v", cfg, err)
		}
	}
}

func TestClosingTheLayerCancelsTheContextOfItsServerTransactions(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{})
	h.receive(request(t, "MESSAGE", "z9hG4bKsafe6"))
	tx := h.tu.lastTx()
	h.layer.Close()
	if tx.Context().Err() == nil {
		t.Fatal("Context still live after Close")
	}
}
