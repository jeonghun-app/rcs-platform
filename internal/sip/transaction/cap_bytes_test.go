package transaction

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// nullSender sends nothing and keeps nothing, so a heap measurement sees only
// what the layer holds.
type nullSender struct{}

func (nullSender) SendRequest(*sip.Request, transport.Destination, ...transport.SendOption) (transport.Network, error) {
	return transport.TCP, nil
}

func (nullSender) SendResponse(*sip.Response, transport.Source, ...transport.SendOption) error {
	return nil
}

// heapAlloc is the live heap after a collection.
func heapAlloc() int64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapAlloc)
}

// Code review and QA (PR #170, second round): a CANCEL for a live INVITE is
// exempt from the count but not from the bytes. Before, 100 CANCELs with 60
// KiB bodies held 5.9 MiB against a 1 MiB bound.
func TestMatchingCancelsAreChargedAgainstTheByteBound(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{MaxServerTransactions: 100, MaxServerTransactionBytes: 1 << 20})
	var invites []*sip.Request
	for i := range 100 {
		inv := request(t, "INVITE", fmt.Sprintf("z9hG4bKinv%d", i))
		invites = append(invites, inv)
		h.receive(inv)
	}
	h.tu.take()
	for _, inv := range invites {
		cancel := request(t, "CANCEL", branchOf(t, inv))
		cancel.Body = make([]byte, 60<<10)
		h.receive(cancel)
	}
	s := h.layer.Stats()
	if s.ServerTransactionBytes > 1<<20 || s.ServerTransactionsRejected < 80 {
		t.Fatalf("after 100 large CANCELs: %+v", s)
	}
	// An ordinary CANCEL still gets in although the count is full.
	h.tu.take()
	h.receive(request(t, "CANCEL", branchOf(t, invites[99])))
	check(t, "TU calls", h.tu.take(), []string{"request CANCEL"})
}

// Code review and QA (PR #170, second round): a transaction in Accepted keeps
// only the 2xx's To tag. Before, 200 INVITEs answered with 1 MiB 200s held
// 200 MiB of heap while 0.05 MiB was counted.
func TestA2xxToAnInviteIsNotHeldThroughTimerL(t *testing.T) {
	tu := &tuRecorder{}
	l := mustNew(t, nullSender{}, tu, Config{Clock: &fakeClock{}, MaxServerTransactionBytes: 1 << 20})
	before := heapAlloc()
	for i := range 200 {
		inv := request(t, "INVITE", fmt.Sprintf("z9hG4bKok%d", i))
		l.Receive(inbound(inv, transport.TCP))
		res := response(t, inv, 200)
		res.Body = make([]byte, 1<<20)
		if err := tu.lastTx().Respond(res); err != nil {
			t.Fatal(err)
		}
	}
	grown := heapAlloc() - before
	s := l.Stats()
	if s.ServerTransactions != 200 || s.ServerTransactionsRejected != 0 {
		t.Fatalf("stats = %+v", s)
	}
	if grown > 40<<20 {
		t.Errorf("the heap grew by %d MiB for 200 transactions in Accepted", grown>>20)
	}
	if s.ServerTransactionBytes > 1<<20 {
		t.Errorf("counted %d bytes, which should be the requests only", s.ServerTransactionBytes)
	}
	// The To tag still identifies the 2xx for the ACK and retransmissions.
	tx := tu.lastTx()
	if tx.State() != Accepted || tx.responseToTag() != "b1" {
		t.Errorf("state %v, To tag %q", tx.State(), tx.responseToTag())
	}
	runtime.KeepAlive(l)
}

// A response kept for retransmission counts against the byte bound while it
// is kept, and replacing a provisional by the final changes the count by the
// difference.
func TestHeldResponsesCountAgainstTheByteBound(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{MaxServerTransactionBytes: 1 << 20})
	inv := request(t, "INVITE", "z9hG4bKbusy")
	h.receive(inv)
	tx := h.tu.lastTx()
	base := h.layer.Stats().ServerTransactionBytes

	ringing := response(t, inv, 183)
	ringing.Body = make([]byte, 100<<10)
	if err := tx.Respond(ringing); err != nil {
		t.Fatal(err)
	}
	if got := h.layer.Stats().ServerTransactionBytes - base; got < 100<<10 || got > 110<<10 {
		t.Fatalf("a 100 KiB 183 counts %d bytes", got)
	}
	busy := response(t, inv, 486)
	busy.Body = make([]byte, 600<<10)
	if err := tx.Respond(busy); err != nil {
		t.Fatal(err)
	}
	if got := h.layer.Stats().ServerTransactionBytes - base; got < 600<<10 || got > 610<<10 {
		t.Fatalf("the 600 KiB 486 replacing the 183 counts %d bytes", got)
	}

	// While it is held, a request that would pass the bound is refused.
	big := request(t, "MESSAGE", "z9hG4bKbig")
	big.Body = make([]byte, 500<<10)
	h.tu.take()
	h.receive(big)
	if got := h.tu.take(); len(got) != 0 || lastResponse(t, h).StatusCode != 503 {
		t.Fatalf("TU got %q, last sent %d", got, lastResponse(t, h).StatusCode)
	}

	// Timer H ends the transaction and gives everything back.
	h.clock.advance(64 * DefaultT1)
	if got := h.layer.Stats().ServerTransactionBytes; got != 0 {
		t.Fatalf("%d bytes left after Timer H", got)
	}
}

// QA (PR #170, second round): requests from client-facing listeners may use
// only ClientShare of the byte bound, as of the count.
func TestClientShareAppliesToTheByteBound(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{MaxServerTransactionBytes: 100 << 10, ClientShare: 0.8})
	from := func(branch string, client bool) {
		req := request(t, "MESSAGE", branch)
		req.Body = make([]byte, 30<<10)
		h.layer.Receive(transport.Inbound{Message: req, Source: transport.Source{Flow: "f", Network: transport.UDP, ClientFacing: client}})
	}
	for i := range 3 {
		from(fmt.Sprintf("z9hG4bKclient%d", i), true)
	}
	if s := h.layer.Stats(); s.ServerTransactions != 2 || s.ServerTransactionsRejected != 1 {
		t.Fatalf("clients past 80 KiB: %+v", s)
	}
	h.tu.take()
	from("z9hG4bKcore", false)
	check(t, "TU calls", h.tu.take(), []string{"request MESSAGE"})
}

// QA (PR #170, second round): a request that brings the bytes exactly to the
// bound is admitted, and one byte more is not.
func TestARequestExactlyAtTheByteBoundIsAdmitted(t *testing.T) {
	req := request(t, "MESSAGE", "z9hG4bKexact")
	size := requestSize(req)
	for _, tc := range []struct {
		bound int64
		want  []string
	}{
		{size, []string{"request MESSAGE"}},
		{size - 1, nil},
	} {
		h := newHarness(t, transport.UDP, Config{MaxServerTransactionBytes: tc.bound})
		h.receive(req)
		check(t, fmt.Sprintf("TU calls at a bound of %d for %d bytes", tc.bound, size), h.tu.take(), tc.want)
	}
}

// Code review (PR #170, second round), finding 4: the client share rounds
// up, so a count of 1 still admits a client request.
func TestClientShareRoundsUp(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{MaxServerTransactions: 1})
	h.layer.Receive(transport.Inbound{Message: request(t, "MESSAGE", "z9hG4bKone"), Source: transport.Source{Flow: "f", Network: transport.UDP, ClientFacing: true}})
	check(t, "TU calls", h.tu.take(), []string{"request MESSAGE"})
}

// QA (PR #170, second round): the bytes counted follow the heap whatever the
// shape of the header: padded fields, many short ones, a large value. Before,
// padding counted 3% of what it held.
func TestCountedBytesTrackTheHeap(t *testing.T) {
	shapes := map[string][]string{
		"plain":           nil,
		"padded fields":   repeatField(60, "X-Pad: v"+strings.Repeat(" ", 240)),
		"many short ones": repeatField(120, "X-S: 1"),
		"one large value": {"X-Large: " + strings.Repeat("a", 12<<10)},
	}
	for name, extra := range shapes {
		t.Run(name, func(t *testing.T) {
			// What the layer holds is the heap with it alive less the heap
			// once it is dropped, measured back to back. A heap measured
			// before and after filling it would also see memory freed in
			// between, such as transactions of the integration tests whose
			// real-clock timers fire meanwhile.
			fill := func() (counted, alive int64) {
				tu := &tuRecorder{}
				l := mustNew(t, nullSender{}, tu, Config{Clock: &fakeClock{}, MaxServerTransactions: MaxMaxServerTransactions, MaxServerTransactionBytes: 1 << 40})
				for i := range 2000 {
					l.Receive(inbound(request(t, "INVITE", fmt.Sprintf("z9hG4bKshape%d", i), extra...), transport.TCP))
				}
				counted, alive = l.Stats().ServerTransactionBytes, heapAlloc()
				runtime.KeepAlive(l)
				runtime.KeepAlive(tu)
				return counted, alive
			}
			counted, alive := fill()
			held := alive - heapAlloc()
			t.Logf("held %d bytes, counted %d (ratio %.2f)", held, counted, float64(held)/float64(counted))
			if ratio := float64(held) / float64(counted); ratio > 1.5 || ratio < 0.5 {
				t.Errorf("held %d bytes, counted %d (ratio %.2f)", held, counted, ratio)
			}
		})
	}
}

func repeatField(n int, f string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = f
	}
	return out
}

func branchOf(t *testing.T, req *sip.Request) string {
	t.Helper()
	vias, err := req.Header.Via()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := vias[0].Params.Get("branch")
	return b
}
