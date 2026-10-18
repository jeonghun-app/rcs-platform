package transaction

import (
	"errors"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// serverStep is one event in a server transaction table test. req is the request
// that created the transaction.
type serverStep func(h *harness, req *sip.Request)

func respondWith(code int) serverStep {
	return func(h *harness, req *sip.Request) {
		if err := h.tu.lastTx().Respond(response(h.t, req, code)); err != nil {
			h.t.Fatalf("Respond(%d): %v", code, err)
		}
	}
}

// respondRefused passes a response the state must refuse.
func respondRefused(code int) serverStep {
	return func(h *harness, req *sip.Request) {
		if err := h.tu.lastTx().Respond(response(h.t, req, code)); !errors.Is(err, ErrState) {
			h.t.Fatalf("Respond(%d) = %v, want ErrState", code, err)
		}
	}
}

// retransmit delivers the request again.
func retransmit(h *harness, req *sip.Request) { h.receive(req) }

// ack delivers the ACK for the last response, with the INVITE's branch as it is
// for a non-2xx response (§17.1.1.3).
func ack(h *harness, req *sip.Request) {
	a, err := buildACK(req, response(h.t, req, 400))
	if err != nil {
		h.t.Fatal(err)
	}
	h.receive(a)
}

func elapse(d time.Duration) serverStep {
	return func(h *harness, _ *sip.Request) { h.clock.advance(d) }
}

func failServerSends(h *harness, _ *sip.Request) { h.sender.failWith(errNetwork) }

type serverCase struct {
	name      string
	network   transport.Network
	cfg       Config
	steps     []serverStep
	wantSent  []string
	wantTU    []string
	wantState State
}

func runServerCases(t *testing.T, method string, cases []serverCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.network, tc.cfg)
			req := request(t, method, "z9hG4bKs1")
			h.receive(req)
			for _, s := range tc.steps {
				s(h, req)
			}
			check(t, "sent", h.sender.take(), tc.wantSent)
			check(t, "TU calls", h.tu.take(), append([]string{"request " + method}, tc.wantTU...))
			if got := h.tu.lastTx().State(); got != tc.wantState {
				t.Errorf("state = %s, want %s", got, tc.wantState)
			}
			if _, s := h.layer.Len(); (s == 0) != (tc.wantState == Terminated) {
				t.Errorf("%d server transactions left in state %s", s, tc.wantState)
			}
		})
	}
}

func TestServerInviteTransitions(t *testing.T) {
	const timerH, timerL = 32 * time.Second, 32 * time.Second
	timerI := DefaultT4
	runServerCases(t, "INVITE", []serverCase{
		{name: "starts in Proceeding and sends 100 Trying at once", network: transport.UDP,
			wantSent: []string{"100"}, wantState: Proceeding},
		{name: "Proceeding: a retransmitted INVITE gets the last provisional again", network: transport.UDP,
			steps:    []serverStep{retransmit, respondWith(180), retransmit},
			wantSent: []string{"100", "100", "180", "180"}, wantState: Proceeding},
		{name: "Proceeding: an ACK is absorbed", network: transport.UDP,
			steps:    []serverStep{ack},
			wantSent: []string{"100"}, wantState: Proceeding},
		{name: "Proceeding: 2xx moves to Accepted (RFC 6026)", network: transport.UDP,
			steps:    []serverStep{respondWith(200)},
			wantSent: []string{"100", "200"}, wantState: Accepted},
		{name: "Accepted: INVITE retransmissions are absorbed", network: transport.UDP,
			steps:    []serverStep{respondWith(200), retransmit, retransmit},
			wantSent: []string{"100", "200"}, wantState: Accepted},
		{name: "Accepted: the TU's 2xx retransmissions are sent", network: transport.UDP,
			steps:    []serverStep{respondWith(200), respondWith(200)},
			wantSent: []string{"100", "200", "200"}, wantState: Accepted},
		{name: "Accepted: a non-2xx is refused", network: transport.UDP,
			steps:    []serverStep{respondWith(200), respondRefused(486), respondRefused(180)},
			wantSent: []string{"100", "200"}, wantState: Accepted},
		{name: "Accepted: an ACK is passed to the TU", network: transport.UDP,
			steps:    []serverStep{respondWith(200), ack},
			wantSent: []string{"100", "200"}, wantTU: []string{"stray ACK"}, wantState: Accepted},
		{name: "Accepted: Timer L terminates", network: transport.TCP,
			steps:    []serverStep{respondWith(200), elapse(timerL)},
			wantSent: []string{"100", "200"}, wantState: Terminated},
		{name: "Proceeding: failure moves to Completed", network: transport.UDP,
			steps:    []serverStep{respondWith(486)},
			wantSent: []string{"100", "486"}, wantState: Completed},
		{name: "Completed: a retransmitted INVITE gets the failure again", network: transport.TCP,
			steps:    []serverStep{respondWith(486), retransmit},
			wantSent: []string{"100", "486", "486"}, wantState: Completed},
		{name: "Completed: Timer G retransmits over UDP", network: transport.UDP,
			steps:    []serverStep{respondWith(486), elapse(DefaultT1)},
			wantSent: []string{"100", "486", "486"}, wantState: Completed},
		{name: "Completed: a further final response is refused", network: transport.UDP,
			steps:    []serverStep{respondWith(486), respondRefused(500), respondRefused(200)},
			wantSent: []string{"100", "486"}, wantState: Completed},
		{name: "Completed: ACK moves to Confirmed, which Timer I ends", network: transport.UDP,
			steps:    []serverStep{respondWith(486), ack, elapse(10 * time.Second)},
			wantSent: []string{"100", "486"}, wantState: Terminated},
		{name: "Confirmed: ACK and INVITE retransmissions are absorbed", network: transport.UDP,
			steps:    []serverStep{respondWith(486), ack, ack, retransmit},
			wantSent: []string{"100", "486"}, wantState: Confirmed},
		{name: "Confirmed: Timer I terminates", network: transport.UDP,
			steps:    []serverStep{respondWith(486), ack, elapse(timerI)},
			wantSent: []string{"100", "486"}, wantState: Terminated},
		{name: "Completed: Timer H fails the transaction", network: transport.TCP,
			steps:    []serverStep{respondWith(486), elapse(timerH)},
			wantSent: []string{"100", "486"}, wantTU: []string{"failed: " + ErrTimeout.Error()}, wantState: Terminated},
		{name: "reliable: no Timer G, and Timer I is zero", network: transport.TLS,
			steps:    []serverStep{respondWith(486), elapse(timerH - time.Millisecond), ack},
			wantSent: []string{"100", "486"}, wantState: Terminated},
		{name: "a failed Timer G retransmission fails the transaction", network: transport.UDP,
			steps:    []serverStep{respondWith(486), failServerSends, elapse(DefaultT1)},
			wantSent: []string{"100", "486"}, wantTU: []string{"failed: " + errNetwork.Error()}, wantState: Terminated},
		{name: "a failed answer to a retransmission fails the transaction", network: transport.UDP,
			steps:    []serverStep{failServerSends, retransmit},
			wantSent: []string{"100"}, wantTU: []string{"failed: " + errNetwork.Error()}, wantState: Terminated},
		{name: "DelayTrying: 100 Trying after 200 ms of silence", network: transport.UDP, cfg: Config{DelayTrying: true},
			steps:    []serverStep{elapse(199 * time.Millisecond), retransmit, elapse(time.Millisecond)},
			wantSent: []string{"100"}, wantState: Proceeding},
		{name: "DelayTrying: no 100 Trying when the TU answers first", network: transport.UDP, cfg: Config{DelayTrying: true},
			steps:    []serverStep{elapse(100 * time.Millisecond), respondWith(180), elapse(time.Second)},
			wantSent: []string{"180"}, wantState: Proceeding},
		{name: "DelayTrying: a failed delayed 100 Trying fails the transaction", network: transport.UDP, cfg: Config{DelayTrying: true},
			steps:  []serverStep{failServerSends, elapse(200 * time.Millisecond)},
			wantTU: []string{"failed: " + errNetwork.Error()}, wantState: Terminated},
	})
}

func TestServerNonInviteTransitions(t *testing.T) {
	const timerJ = 32 * time.Second
	runServerCases(t, "MESSAGE", []serverCase{
		{name: "starts in Trying without a 100", network: transport.UDP,
			wantState: Trying},
		{name: "Trying: retransmissions are absorbed", network: transport.UDP,
			steps:     []serverStep{retransmit, retransmit},
			wantState: Trying},
		{name: "Trying: 1xx moves to Proceeding", network: transport.UDP,
			steps:    []serverStep{respondWith(100)},
			wantSent: []string{"100"}, wantState: Proceeding},
		{name: "Proceeding: a retransmission gets the provisional again", network: transport.UDP,
			steps:    []serverStep{respondWith(100), retransmit},
			wantSent: []string{"100", "100"}, wantState: Proceeding},
		{name: "Trying: final response moves to Completed", network: transport.UDP,
			steps:    []serverStep{respondWith(202)},
			wantSent: []string{"202"}, wantState: Completed},
		{name: "Proceeding: final response moves to Completed", network: transport.UDP,
			steps:    []serverStep{respondWith(100), respondWith(200)},
			wantSent: []string{"100", "200"}, wantState: Completed},
		{name: "Completed: a retransmission gets the final response again", network: transport.UDP,
			steps:    []serverStep{respondWith(200), retransmit},
			wantSent: []string{"200", "200"}, wantState: Completed},
		{name: "Completed: further responses are refused", network: transport.UDP,
			steps:    []serverStep{respondWith(200), respondRefused(500), respondRefused(100)},
			wantSent: []string{"200"}, wantState: Completed},
		{name: "Completed: lasts until Timer J", network: transport.UDP,
			steps:    []serverStep{respondWith(200), elapse(timerJ - time.Millisecond)},
			wantSent: []string{"200"}, wantState: Completed},
		{name: "Completed: Timer J terminates once it fires", network: transport.UDP,
			steps:    []serverStep{respondWith(200), elapse(timerJ)},
			wantSent: []string{"200"}, wantState: Terminated},
		{name: "reliable: Timer J is zero", network: transport.TCP,
			steps:    []serverStep{respondWith(200)},
			wantSent: []string{"200"}, wantState: Terminated},
	})
}

func TestServerInviteRetransmitsWithTimerGCappedAtT2UntilTimerH(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{})
	req := request(t, "INVITE", "z9hG4bKg")
	h.receive(req)
	if err := h.tu.lastTx().Respond(response(t, req, 486)); err != nil {
		t.Fatal(err)
	}
	h.clock.advance(time.Minute)
	want := []string{at("100", 0)}
	for _, d := range []int{0, 500, 1500, 3500, 7500, 11500, 15500, 19500, 23500, 27500, 31500} {
		want = append(want, at("486", ms(d)))
	}
	check(t, "sends", h.sender.times(), want)
}

func TestFailedRespondReturnsTheErrorAndTerminates(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{})
	req := request(t, "MESSAGE", "z9hG4bKr")
	h.receive(req)
	tx := h.tu.lastTx()
	h.sender.failWith(errNetwork)
	if err := tx.Respond(response(t, req, 200)); !errors.Is(err, errNetwork) {
		t.Fatalf("Respond = %v", err)
	}
	if tx.State() != Terminated {
		t.Fatalf("state = %s", tx.State())
	}
	if err := tx.Respond(&sip.Response{StatusCode: 99}); err == nil {
		t.Fatal("status code 99 accepted")
	}
}

func TestImmediate100TryingThatCannotBeSentDropsTheRequest(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{})
	h.sender.failWith(errNetwork)
	h.receive(request(t, "INVITE", "z9hG4bKdrop"))
	if got := h.tu.take(); len(got) != 0 {
		t.Fatalf("TU calls = %q", got)
	}
	if _, s := h.layer.Len(); s != 0 {
		t.Fatal("transaction left behind")
	}
}

func TestServerTransactionsAreMatchedOnBranchSentByAndMethod(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{})
	inv := request(t, "INVITE", "z9hG4bKm")
	h.receive(inv)
	h.receive(inv) // retransmission: same branch, sent-by and method

	otherSentBy := request(t, "INVITE", "z9hG4bKm")
	otherSentBy.Header.Set("Via", "SIP/2.0/UDP other.example.com:5060;branch=z9hG4bKm")
	h.receive(otherSentBy)

	cancel := request(t, "CANCEL", "z9hG4bKm")
	h.receive(cancel)
	check(t, "TU calls", h.tu.take(), []string{"request INVITE", "request INVITE", "request CANCEL"})
	if _, s := h.layer.Len(); s != 3 {
		t.Fatalf("%d server transactions, want 3", s)
	}

	// A CANCEL finds the INVITE it cancels (RFC 3261 §9.2).
	target, ok := h.layer.InviteFor(cancel)
	if !ok || target.Request() != inv {
		t.Fatal("InviteFor did not find the INVITE")
	}
	if _, ok := h.layer.InviteFor(inv); ok {
		t.Fatal("InviteFor accepted a request that is not a CANCEL")
	}
	if _, ok := h.layer.InviteFor(request(t, "CANCEL", "z9hG4bKnone")); ok {
		t.Fatal("InviteFor matched a CANCEL for no INVITE")
	}
	if target.Source().Network != transport.UDP {
		t.Fatalf("Source = %+v", target.Source())
	}
}

func TestAckMatchingNoTransactionIsPassedToTheTU(t *testing.T) {
	// The ACK for a 2xx has a branch of its own (RFC 3261 §13.2.2.4).
	h := newHarness(t, transport.UDP, Config{})
	h.receive(request(t, "ACK", "z9hG4bKnew"))
	check(t, "TU calls", h.tu.take(), []string{"stray ACK"})
	if _, s := h.layer.Len(); s != 0 {
		t.Fatal("an ACK created a transaction")
	}
}

func TestRFC2543RequestsAreMatchedWithoutABranch(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{})
	inv := request(t, "INVITE", "old1")
	h.receive(inv)
	h.receive(request(t, "INVITE", "old1")) // a retransmission, parsed anew
	check(t, "TU calls", h.tu.take(), []string{"request INVITE"})
	tx := h.tu.lastTx()
	if err := tx.Respond(response(t, inv, 486)); err != nil {
		t.Fatal(err)
	}

	// The ACK carries the To tag of the response, which the INVITE did not.
	wrongTag, _ := buildACK(inv, response(t, inv, 486))
	wrongTag.Header.Set("To", "<sip:bob@example.com>;tag=other")
	h.receive(wrongTag)
	check(t, "TU calls", h.tu.take(), []string{"stray ACK"})
	if tx.State() != Completed {
		t.Fatalf("an ACK with the wrong To tag moved the transaction to %s", tx.State())
	}
	good, _ := buildACK(inv, response(t, inv, 486))
	h.receive(good)
	if tx.State() != Confirmed {
		t.Fatalf("state = %s, want Confirmed", tx.State())
	}

	// A different CSeq is a different transaction.
	next := request(t, "INVITE", "old1")
	next.Header.Set("CSeq", "2 INVITE")
	h.receive(next)
	check(t, "TU calls", h.tu.take(), []string{"request INVITE"})
}

func TestRFC2543AckForAReInviteMatchesOnItsToTag(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{})
	reinvite := request(t, "INVITE", "old2")
	reinvite.Header.Set("To", "<sip:bob@example.com>;tag=dialog")
	h.receive(reinvite)
	tx := h.tu.lastTx()
	res, err := sip.NewResponse(reinvite, 488, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Respond(res); err != nil {
		t.Fatal(err)
	}
	a, _ := buildACK(reinvite, res)
	h.receive(a)
	if tx.State() != Confirmed {
		t.Fatalf("state = %s, want Confirmed", tx.State())
	}
}

func TestRequestsThatCannotBeKeyedAreDropped(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{})
	req := request(t, "OPTIONS", "old3")
	req.Header.Del("From")
	h.receive(req)
	if got := h.tu.take(); len(got) != 0 {
		t.Fatalf("TU calls = %q", got)
	}
}

func TestClosedLayerDropsEverything(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{})
	h.startClient(request(t, "OPTIONS", "z9hG4bKc"))
	h.receive(request(t, "MESSAGE", "z9hG4bKs"))
	h.tu.take()
	h.layer.Close()
	if c, s := h.layer.Len(); c != 0 || s != 0 {
		t.Fatalf("%d client and %d server transactions after Close", c, s)
	}
	h.clock.advance(time.Minute)
	if got := h.takeResponses(); len(got) != 0 {
		t.Fatalf("a closed transaction reported %q", got)
	}
	h.receive(request(t, "MESSAGE", "z9hG4bKs2"))
	if got := h.tu.take(); len(got) != 0 {
		t.Fatalf("closed layer delivered %q", got)
	}
	if _, err := h.layer.Request(request(t, "OPTIONS", "z9hG4bKc2"), transport.Destination{Network: transport.UDP}, h.handler); !errors.Is(err, ErrClosed) {
		t.Fatalf("Request = %v", err)
	}
}

func TestTUMayRespondFromInsideRequest(t *testing.T) {
	// The TU is called without a lock held, so it can answer straight away.
	h := newHarness(t, transport.UDP, Config{})
	h.tu.onRequest = func(tx *ServerTransaction) {
		if err := tx.Respond(response(t, tx.Request(), 200)); err != nil {
			t.Error(err)
		}
	}
	h.receive(request(t, "MESSAGE", "z9hG4bKin"))
	check(t, "sent", h.sender.take(), []string{"200"})
}
