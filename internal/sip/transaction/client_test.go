package transaction

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

var errNetwork = errors.New("network down")

// clientStep is one event in a client transaction table test.
type clientStep func(h *harness, tx *ClientTransaction)

// recv delivers a response to the transaction's request.
func recv(code int) clientStep {
	return func(h *harness, tx *ClientTransaction) { h.receive(response(h.t, tx.Request(), code)) }
}

func wait(d time.Duration) clientStep {
	return func(h *harness, _ *ClientTransaction) { h.clock.advance(d) }
}

func failSends() clientStep {
	return func(h *harness, _ *ClientTransaction) { h.sender.failWith(errNetwork) }
}

type clientCase struct {
	name    string
	network transport.Network
	steps   []clientStep
	// wantSent is everything sent, the initial request included.
	wantSent  []string
	wantTU    []string
	wantState State
}

func runClientCases(t *testing.T, method string, cases []clientCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.network, Config{})
			tx := h.startClient(request(t, method, "z9hG4bKc1"))
			for _, s := range tc.steps {
				s(h, tx)
			}
			check(t, "sent", h.sender.take(), tc.wantSent)
			check(t, "passed to the TU", h.takeResponses(), tc.wantTU)
			if got := tx.State(); got != tc.wantState {
				t.Errorf("state = %s, want %s", got, tc.wantState)
			}
			if c, _ := h.layer.Len(); (c == 0) != (tc.wantState == Terminated) {
				t.Errorf("%d client transactions left in state %s", c, tc.wantState)
			}
		})
	}
}

func TestClientInviteTransitions(t *testing.T) {
	const timerB, timerD, timerM = 32 * time.Second, 32 * time.Second, 32 * time.Second
	runClientCases(t, "INVITE", []clientCase{
		{name: "starts in Calling", network: transport.UDP,
			wantSent: []string{"INVITE"}, wantState: Calling},
		{name: "Calling: 1xx moves to Proceeding and stops Timer A", network: transport.UDP,
			steps:    []clientStep{recv(180), wait(10 * time.Second)},
			wantSent: []string{"INVITE"}, wantTU: []string{"180"}, wantState: Proceeding},
		{name: "Proceeding: further 1xx are passed up", network: transport.UDP,
			steps:    []clientStep{recv(100), recv(180), recv(183)},
			wantSent: []string{"INVITE"}, wantTU: []string{"100", "180", "183"}, wantState: Proceeding},
		{name: "Calling: Timer B times out", network: transport.UDP,
			steps:    []clientStep{wait(timerB)},
			wantSent: []string{"INVITE", "INVITE", "INVITE", "INVITE", "INVITE", "INVITE", "INVITE"},
			wantTU:   []string{"error: " + ErrTimeout.Error()}, wantState: Terminated},
		{name: "Proceeding: Timer B no longer applies", network: transport.UDP,
			steps:    []clientStep{recv(180), wait(10 * timerB)},
			wantSent: []string{"INVITE"}, wantTU: []string{"180"}, wantState: Proceeding},
		{name: "Calling: 2xx moves to Accepted (RFC 6026)", network: transport.UDP,
			steps:    []clientStep{recv(200)},
			wantSent: []string{"INVITE"}, wantTU: []string{"200"}, wantState: Accepted},
		{name: "Proceeding: 2xx moves to Accepted", network: transport.TCP,
			steps:    []clientStep{recv(180), recv(200)},
			wantSent: []string{"INVITE"}, wantTU: []string{"180", "200"}, wantState: Accepted},
		{name: "Accepted: 2xx retransmissions reach the TU, 1xx and failures do not", network: transport.UDP,
			steps:    []clientStep{recv(200), recv(200), recv(180), recv(486), recv(200)},
			wantSent: []string{"INVITE"}, wantTU: []string{"200", "200", "200"}, wantState: Accepted},
		{name: "Accepted: Timer M terminates", network: transport.TCP,
			steps:    []clientStep{recv(200), wait(timerM)},
			wantSent: []string{"INVITE"}, wantTU: []string{"200"}, wantState: Terminated},
		{name: "Calling: failure response is ACKed and moves to Completed", network: transport.UDP,
			steps:    []clientStep{recv(486)},
			wantSent: []string{"INVITE", "ACK"}, wantTU: []string{"486"}, wantState: Completed},
		{name: "Proceeding: failure response is ACKed and moves to Completed", network: transport.UDP,
			steps:    []clientStep{recv(180), recv(603)},
			wantSent: []string{"INVITE", "ACK"}, wantTU: []string{"180", "603"}, wantState: Completed},
		{name: "Completed: a retransmitted failure response is ACKed again, not passed up", network: transport.UDP,
			steps:    []clientStep{recv(486), recv(486), recv(486)},
			wantSent: []string{"INVITE", "ACK", "ACK", "ACK"}, wantTU: []string{"486"}, wantState: Completed},
		{name: "Completed: a 2xx from another fork branch is passed up", network: transport.UDP,
			steps:    []clientStep{recv(486), recv(200)},
			wantSent: []string{"INVITE", "ACK"}, wantTU: []string{"486", "200"}, wantState: Completed},
		{name: "Completed: lasts until Timer D", network: transport.UDP,
			steps:    []clientStep{recv(486), wait(timerD - time.Millisecond)},
			wantSent: []string{"INVITE", "ACK"}, wantTU: []string{"486"}, wantState: Completed},
		{name: "Completed: Timer D terminates once it fires", network: transport.UDP,
			steps:    []clientStep{recv(486), wait(timerD)},
			wantSent: []string{"INVITE", "ACK"}, wantTU: []string{"486"}, wantState: Terminated},
		{name: "reliable: no Timer A", network: transport.TCP,
			steps:    []clientStep{wait(timerB - time.Millisecond)},
			wantSent: []string{"INVITE"}, wantState: Calling},
		{name: "reliable: Timer B still times out", network: transport.TLS,
			steps:    []clientStep{wait(timerB)},
			wantSent: []string{"INVITE"}, wantTU: []string{"error: " + ErrTimeout.Error()}, wantState: Terminated},
		{name: "reliable: Timer D is zero", network: transport.TCP,
			steps:    []clientStep{recv(486)},
			wantSent: []string{"INVITE", "ACK"}, wantTU: []string{"486"}, wantState: Terminated},
		{name: "Calling: a failed retransmission is a transport error", network: transport.UDP,
			steps:    []clientStep{failSends(), wait(time.Second)},
			wantSent: []string{"INVITE"}, wantTU: []string{"error: " + errNetwork.Error()}, wantState: Terminated},
		{name: "Calling: a failed ACK still passes the response up", network: transport.UDP,
			steps:    []clientStep{failSends(), recv(486)},
			wantSent: []string{"INVITE"}, wantTU: []string{"486"}, wantState: Terminated},
		{name: "Completed: a failed ACK retransmission terminates quietly", network: transport.UDP,
			steps:    []clientStep{recv(486), failSends(), recv(486)},
			wantSent: []string{"INVITE", "ACK"}, wantTU: []string{"486"}, wantState: Terminated},
	})
}

func TestClientNonInviteTransitions(t *testing.T) {
	const timerF = 32 * time.Second
	timerK := DefaultT4
	runClientCases(t, "MESSAGE", []clientCase{
		{name: "starts in Trying", network: transport.UDP,
			wantSent: []string{"MESSAGE"}, wantState: Trying},
		{name: "Trying: 1xx moves to Proceeding", network: transport.UDP,
			steps:    []clientStep{recv(100)},
			wantSent: []string{"MESSAGE"}, wantTU: []string{"100"}, wantState: Proceeding},
		{name: "Trying: final response moves to Completed", network: transport.UDP,
			steps:    []clientStep{recv(202)},
			wantSent: []string{"MESSAGE"}, wantTU: []string{"202"}, wantState: Completed},
		{name: "Proceeding: final response moves to Completed", network: transport.UDP,
			steps:    []clientStep{recv(100), recv(404)},
			wantSent: []string{"MESSAGE"}, wantTU: []string{"100", "404"}, wantState: Completed},
		{name: "Completed: retransmitted responses are absorbed", network: transport.UDP,
			steps:    []clientStep{recv(200), recv(200), recv(100)},
			wantSent: []string{"MESSAGE"}, wantTU: []string{"200"}, wantState: Completed},
		{name: "Completed: Timer K terminates", network: transport.UDP,
			steps:    []clientStep{recv(200), wait(timerK)},
			wantSent: []string{"MESSAGE"}, wantTU: []string{"200"}, wantState: Terminated},
		{name: "Trying: Timer F times out", network: transport.TCP,
			steps:    []clientStep{wait(timerF)},
			wantSent: []string{"MESSAGE"}, wantTU: []string{"error: " + ErrTimeout.Error()}, wantState: Terminated},
		{name: "Proceeding: Timer F times out", network: transport.TCP,
			steps:    []clientStep{recv(100), wait(timerF)},
			wantSent: []string{"MESSAGE"}, wantTU: []string{"100", "error: " + ErrTimeout.Error()}, wantState: Terminated},
		{name: "Trying: Timer E retransmits over UDP", network: transport.UDP,
			steps:    []clientStep{wait(DefaultT1)},
			wantSent: []string{"MESSAGE", "MESSAGE"}, wantState: Trying},
		{name: "Proceeding: Timer E keeps retransmitting", network: transport.UDP,
			steps:    []clientStep{recv(100), wait(DefaultT1 + DefaultT2)},
			wantSent: []string{"MESSAGE", "MESSAGE", "MESSAGE"}, wantTU: []string{"100"}, wantState: Proceeding},
		{name: "reliable: no Timer E", network: transport.TCP,
			steps:    []clientStep{wait(timerF - time.Millisecond)},
			wantSent: []string{"MESSAGE"}, wantState: Trying},
		{name: "reliable: Timer K is zero", network: transport.TLS,
			steps:    []clientStep{recv(200)},
			wantSent: []string{"MESSAGE"}, wantTU: []string{"200"}, wantState: Terminated},
		{name: "a failed retransmission is a transport error", network: transport.UDP,
			steps:    []clientStep{failSends(), wait(DefaultT1)},
			wantSent: []string{"MESSAGE"}, wantTU: []string{"error: " + errNetwork.Error()}, wantState: Terminated},
	})
}

func TestClientInviteRetransmitsWithTimerADoublingUntilTimerB(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{})
	h.startClient(request(t, "INVITE", "z9hG4bKa"))
	h.clock.advance(time.Minute)
	check(t, "sends", h.sender.times(), []string{
		at("INVITE", 0), at("INVITE", ms(500)), at("INVITE", ms(1500)), at("INVITE", ms(3500)),
		at("INVITE", ms(7500)), at("INVITE", ms(15500)), at("INVITE", ms(31500)),
	})
	check(t, "passed to the TU", h.takeResponses(), []string{"error: " + ErrTimeout.Error()})
}

func TestClientNonInviteRetransmitsWithTimerECappedAtT2(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{})
	h.startClient(request(t, "OPTIONS", "z9hG4bKe"))
	h.clock.advance(time.Minute)
	var want []string
	for _, d := range []int{0, 500, 1500, 3500, 7500, 11500, 15500, 19500, 23500, 27500, 31500} {
		want = append(want, at("OPTIONS", ms(d)))
	}
	check(t, "sends", h.sender.times(), want)
}

func TestClientNonInviteRetransmitsAtT2OnceAProvisionalArrives(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{})
	tx := h.startClient(request(t, "OPTIONS", "z9hG4bKe"))
	h.clock.advance(ms(400))
	h.receive(response(t, tx.Request(), 100))
	h.clock.advance(ms(100 + 4000 + 4000))
	check(t, "sends", h.sender.times(), []string{at("OPTIONS", 0), at("OPTIONS", ms(500)), at("OPTIONS", ms(4500)), at("OPTIONS", ms(8500))})
}

func TestTimerBasesAreConfigurable(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{T1: ms(100), T2: ms(200), T4: ms(300)})
	tx := h.startClient(request(t, "OPTIONS", "z9hG4bKcfg"))
	h.clock.advance(ms(700))
	check(t, "sends", h.sender.times(), []string{at("OPTIONS", 0), at("OPTIONS", ms(100)), at("OPTIONS", ms(300)), at("OPTIONS", ms(500)), at("OPTIONS", ms(700))})
	h.receive(response(t, tx.Request(), 200))
	h.clock.advance(ms(299))
	if tx.State() != Completed {
		t.Fatalf("state = %s before T4", tx.State())
	}
	h.clock.advance(ms(1))
	if tx.State() != Terminated {
		t.Fatalf("Timer K did not use T4: state %s", tx.State())
	}

	// Timer F is 64*T1 and Timer D at least 32 s even with a small T1.
	h2 := newHarness(t, transport.UDP, Config{T1: ms(100)})
	inv := h2.startClient(request(t, "INVITE", "z9hG4bKd"))
	h2.receive(response(t, inv.Request(), 500))
	h2.clock.advance(32*time.Second - time.Millisecond)
	if inv.State() != Completed {
		t.Fatalf("Timer D shorter than 32 s: state %s", inv.State())
	}
}

func TestDefaultTimerBasesFollowRFC3261(t *testing.T) {
	l := New(&fakeSender{}, &tuRecorder{}, Config{})
	if l.t1 != 500*time.Millisecond || l.t2 != 4*time.Second || l.t4 != 5*time.Second || l.clock != SystemClock {
		t.Fatalf("defaults = %v %v %v", l.t1, l.t2, l.t4)
	}
}

func TestAckForAFailureResponseFollowsRFC3261Section17113(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{})
	req := request(t, "INVITE", "z9hG4bKack", "Route: <sip:pcscf.example.com;lr>", "Route: <sip:scscf.example.com;lr>",
		"Contact: <sip:alice@192.0.2.1>")
	req.Header.Set("Via", "SIP/2.0/UDP top.example.com;branch=z9hG4bKack, SIP/2.0/UDP below.example.com;branch=z9hG4bKold")
	tx := h.startClient(req)
	h.receive(response(t, tx.Request(), 486))

	ack, ok := h.sender.last().(*sip.Request)
	if !ok || ack.Method != "ACK" {
		t.Fatalf("last sent = %v", h.sender.last())
	}
	if ack.URI.String() != req.URI.String() {
		t.Errorf("Request-URI = %s", ack.URI.String())
	}
	if got := ack.Header.Values("Via"); len(got) != 1 || got[0] != "SIP/2.0/UDP top.example.com;branch=z9hG4bKack" {
		t.Errorf("Via = %q, want the INVITE's top Via alone", got)
	}
	if to, _ := ack.Header.To(); to.Tag() != "b1" {
		t.Errorf("To tag = %q, want the response's", to.Tag())
	}
	if cseq, _ := ack.Header.CSeq(); cseq.Seq != 1 || cseq.Method != "ACK" {
		t.Errorf("CSeq = %v", cseq)
	}
	if got := strings.Join(ack.Header.Values("Route"), ","); got != "<sip:pcscf.example.com;lr>,<sip:scscf.example.com;lr>" {
		t.Errorf("Route = %s", got)
	}
	for _, name := range []string{"From", "Call-ID"} {
		if ack.Header.Get(name) != req.Header.Get(name) {
			t.Errorf("%s differs from the INVITE", name)
		}
	}
	if ack.Header.Has("Contact") {
		t.Error("ACK carries the INVITE's Contact")
	}
	if err := ack.Validate(); err != nil {
		t.Errorf("ACK does not validate: %v", err)
	}
}

func TestResponsesAreMatchedOnBranchAndMethod(t *testing.T) {
	h := newHarness(t, transport.TCP, Config{})
	invite := h.startClient(request(t, "INVITE", "z9hG4bKsame"))
	var cancelGot []string
	cancel, err := h.layer.Request(request(t, "CANCEL", "z9hG4bKsame"), transport.Destination{Network: transport.TCP},
		func(res *sip.Response, err error) { cancelGot = append(cancelGot, label(res)) })
	if err != nil {
		t.Fatal(err)
	}
	h.receive(response(t, cancel.Request(), 200))
	h.receive(response(t, invite.Request(), 487))
	check(t, "INVITE responses", h.takeResponses(), []string{"487"})
	check(t, "CANCEL responses", cancelGot, []string{"200"})

	// A response with an unknown branch, or no branch at all, matches nothing.
	h.receive(response(t, request(t, "INVITE", "z9hG4bKother"), 200))
	noBranch := response(t, request(t, "INVITE", "z9hG4bKx"), 200)
	noBranch.Header.Set("Via", "SIP/2.0/UDP client.example.com")
	h.receive(noBranch)
	check(t, "strays", h.tu.take(), []string{"stray 200", "stray 200"})
}

func TestRequestRefusesWhatCannotStartAClientTransaction(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{})
	dst := transport.Destination{Network: transport.UDP}
	invalid := request(t, "OPTIONS", "z9hG4bKv")
	invalid.Header.Del("Call-ID")
	for name, req := range map[string]*sip.Request{
		"ACK":             request(t, "ACK", "z9hG4bKack"),
		"no magic cookie": request(t, "OPTIONS", "rfc2543branch"),
		"invalid":         invalid,
	} {
		if _, err := h.layer.Request(req, dst, h.handler); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := h.layer.Request(request(t, "OPTIONS", "z9hG4bKok"), dst, nil); err == nil {
		t.Error("nil handler accepted")
	}

	h.startClient(request(t, "OPTIONS", "z9hG4bKdup"))
	if _, err := h.layer.Request(request(t, "OPTIONS", "z9hG4bKdup"), dst, h.handler); !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate branch: %v", err)
	}
	if c, _ := h.layer.Len(); c != 1 {
		t.Errorf("%d client transactions, want 1", c)
	}
}

func TestFailedFirstSendReturnsTheErrorAndLeavesNoTransaction(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{})
	h.sender.failWith(errNetwork)
	if _, err := h.layer.Request(request(t, "INVITE", "z9hG4bKf"), transport.Destination{Network: transport.UDP}, h.handler); !errors.Is(err, errNetwork) {
		t.Fatalf("Request = %v", err)
	}
	if c, _ := h.layer.Len(); c != 0 {
		t.Fatal("a transaction that never started is still in the table")
	}
	h.clock.advance(time.Minute)
	if got := h.takeResponses(); len(got) != 0 {
		t.Fatalf("handler called: %q", got)
	}
}

func TestReliabilityFollowsTheTransportActuallyUsed(t *testing.T) {
	// The transport may send a large UDP request over TCP (RFC 3261 §18.1.1); the
	// transaction must then not retransmit.
	h := newHarness(t, transport.TCP, Config{})
	if _, err := h.layer.Request(request(t, "MESSAGE", "z9hG4bKbig"), transport.Destination{Network: transport.UDP}, h.handler); err != nil {
		t.Fatal(err)
	}
	h.clock.advance(10 * time.Second)
	check(t, "sent", h.sender.take(), []string{"MESSAGE"})
}

func TestStateNamesAreReadable(t *testing.T) {
	for s, want := range map[State]string{Calling: "Calling", Trying: "Trying", Proceeding: "Proceeding", Accepted: "Accepted",
		Completed: "Completed", Confirmed: "Confirmed", Terminated: "Terminated", State(0): "State(?)"} {
		if s.String() != want {
			t.Errorf("%d = %s", s, s.String())
		}
	}
}
