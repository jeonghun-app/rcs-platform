package transaction

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strconv"
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
	// Timer C of a default proxy, 64*T1 for the 487 to its CANCEL, and the
	// margin.
	limit := 3*time.Minute + time.Second + 64*DefaultT1 + 5*time.Second

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
	if l.nonInviteFinal != 128*100*time.Millisecond || l.inviteFinal != 3*time.Minute+time.Second+6400*time.Millisecond+5*time.Second {
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

// The safety-net path gives back the transaction's slot and bytes (#170): held
// while the 500 is in Completed, as for any final response, and returned when
// the transaction ends, by Timer I after the ACK or by Timer H without one. A
// 500 the client never acknowledges is the layer's, not the TU's, so Timer H
// does not report it through ServerFailed.
func TestTheSafetyNetGivesBackTheSlotAndItsBytes(t *testing.T) {
	for _, tc := range []struct {
		method  string
		network transport.Network
		ack     bool
	}{
		{"MESSAGE", transport.UDP, false},
		{"MESSAGE", transport.TCP, false},
		{"INVITE", transport.UDP, true},
		{"INVITE", transport.TCP, true},
		{"INVITE", transport.UDP, false},
		{"INVITE", transport.TCP, false},
	} {
		t.Run(tc.method+"/"+string(tc.network)+"/ack="+strconv.FormatBool(tc.ack), func(t *testing.T) {
			h := newHarness(t, tc.network, Config{NonInviteFinalTimeout: time.Minute, InviteFinalTimeout: time.Minute})
			req := request(t, tc.method, "z9hG4bKsafe-release")
			h.receive(req)
			tx := h.tu.lastTx()
			h.tu.take()
			h.clock.advance(time.Minute)
			if res := lastResponse(t, h); res.StatusCode != 500 {
				t.Fatalf("sent %d, want 500", res.StatusCode)
			}
			if s := h.layer.Stats(); tx.State() == Completed && (s.ServerTransactions != 1 || s.ServerTransactionBytes <= 0) {
				t.Fatalf("a Completed transaction gave back its slot early: %+v", s)
			}
			if tc.ack {
				ack(h, req)
			}
			h.clock.advance(time.Hour)
			s := h.layer.Stats()
			if tx.State() != Terminated || s.ServerTransactions != 0 || s.ServerTransactionBytes != 0 {
				t.Fatalf("state %s, stats %+v", tx.State(), s)
			}
			if ev := h.tu.take(); len(ev) != 0 {
				t.Fatalf("the TU was told %q", ev)
			}
		})
	}
}

// Nor is a transport failure on a retransmission of the layer's 500 the TU's.
func TestARetransmissionOfTheLayers500ThatFailsIsNotReported(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{InviteFinalTimeout: time.Minute})
	h.receive(request(t, "INVITE", "z9hG4bKsafe-g"))
	tx := h.tu.lastTx()
	h.tu.take()
	h.clock.advance(time.Minute)
	h.sender.failWith(errNetwork)
	h.clock.advance(DefaultT1)
	if tx.State() != Terminated {
		t.Fatalf("state %s, want Terminated after Timer G failed", tx.State())
	}
	if ev := h.tu.take(); len(ev) != 0 {
		t.Fatalf("the TU was told %q", ev)
	}
}

// A final response stops the safety timer, and one that fires anyway changes
// nothing: with a short timeout the transaction is still in Accepted or
// Completed when it would fall due.
func TestAFinalResponseStopsTheSafetyTimer(t *testing.T) {
	const (
		inviteTimeout    = time.Second + 7*time.Millisecond
		nonInviteTimeout = 32*time.Second + 7*time.Millisecond
	)
	for _, tc := range []struct {
		name, method string
		code         int
		due          time.Duration
	}{
		{"INVITE 2xx", "INVITE", 200, inviteTimeout},
		{"INVITE 486", "INVITE", 486, inviteTimeout},
		{"MESSAGE 200", "MESSAGE", 200, nonInviteTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, transport.UDP, Config{InviteFinalTimeout: inviteTimeout, NonInviteFinalTimeout: nonInviteTimeout})
			req := request(t, tc.method, "z9hG4bKsafe-stop")
			h.receive(req)
			tx := h.tu.lastTx()
			if !h.clock.pendingAt(tc.due) {
				t.Fatal("no safety timer armed at the request")
			}
			h.clock.advance(500 * time.Millisecond)
			if err := tx.Respond(response(t, req, tc.code)); err != nil {
				t.Fatal(err)
			}
			if h.clock.pendingAt(tc.due) {
				t.Error("the safety timer is still armed after the final response")
			}
			h.sender.take()
			h.clock.advance(tc.due)
			if got := h.sender.take(); slices.Contains(got, "500") {
				t.Fatalf("sent %q after the TU's %d", got, tc.code)
			}
			if s := h.layer.Stats(); s.ServerTransactionsTimedOut != 0 || errors.Is(context.Cause(tx.Context()), ErrNoFinalResponse) {
				t.Fatalf("answered for the TU after its %d: %+v, cause %v", tc.code, s, context.Cause(tx.Context()))
			}
		})
	}
}

// Progress starts the safety timer again, so it measures a stalled TU, not the
// whole request: a proxy forwarding to its next fork group calls it. Once a
// final response was sent it does nothing.
func TestProgressStartsTheSafetyTimerAgain(t *testing.T) {
	for _, method := range []string{"MESSAGE", "INVITE"} {
		t.Run(method, func(t *testing.T) {
			h := newHarness(t, transport.TCP, Config{NonInviteFinalTimeout: 40 * time.Second, InviteFinalTimeout: 40 * time.Second})
			req := request(t, method, "z9hG4bKsafe-progress")
			h.receive(req)
			tx := h.tu.lastTx()
			h.sender.take()
			h.clock.advance(30 * time.Second)
			tx.Progress()
			h.clock.advance(40*time.Second - time.Millisecond)
			if got := h.sender.take(); len(got) != 0 || tx.Context().Err() != nil {
				t.Fatalf("answered before 40 s since Progress: %q", got)
			}
			h.clock.advance(time.Millisecond)
			if res := lastResponse(t, h); res.StatusCode != 500 {
				t.Fatalf("sent %d, want 500", res.StatusCode)
			}
			// Completed now: Progress arms nothing.
			tx.Progress()
			if h.clock.pendingAt(h.clock.elapsed() + 40*time.Second) {
				t.Fatal("Progress re-armed the safety timer after the 500")
			}
		})
	}
}

// A 500 that cannot get a To tag is not sent: the transaction ends quietly, its
// slot and bytes come back, and the TU still learns why from its Context.
func TestASafetyTimerThatCannotDrawATagEndsTheTransactionQuietly(t *testing.T) {
	h := newHarness(t, transport.TCP, Config{InviteFinalTimeout: time.Minute,
		IDs: sip.IDGenerator{Rand: &keyOnly{}}})
	h.receive(request(t, "INVITE", "z9hG4bKsafe-notag"))
	tx := h.tu.lastTx()
	h.sender.take()
	h.tu.take()
	h.clock.advance(time.Minute)
	if got := h.sender.take(); len(got) != 0 {
		t.Fatalf("sent %q", got)
	}
	s := h.layer.Stats()
	if tx.State() != Terminated || s.ServerTransactions != 0 || s.ServerTransactionBytes != 0 || s.ServerTransactionsTimedOut != 1 {
		t.Fatalf("state %s, stats %+v", tx.State(), s)
	}
	if !errors.Is(context.Cause(tx.Context()), ErrNoFinalResponse) {
		t.Fatalf("cause %v", context.Cause(tx.Context()))
	}
	if ev := h.tu.take(); len(ev) != 0 {
		t.Fatalf("the TU was told %q", ev)
	}
}

// keyOnly yields the layer's key in New, then fails, as a broken source of
// randomness would.
type keyOnly struct{ n int }

func (k *keyOnly) Read(p []byte) (int, error) {
	if k.n >= sha256.Size {
		return 0, errors.New("randomness unavailable")
	}
	n := min(len(p), sha256.Size-k.n)
	k.n += n
	return n, nil
}
