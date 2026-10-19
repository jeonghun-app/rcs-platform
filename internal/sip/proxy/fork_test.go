package proxy

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// labels names responses as "code METHOD", which tells the answer to a CANCEL
// from the answer to its INVITE.
func labels(rs []*sip.Response) []string {
	var out []string
	for _, r := range rs {
		cseq, _ := r.Header.CSeq()
		out = append(out, itoa(r.StatusCode)+" "+cseq.Method)
	}
	return out
}

func threeTargets() Decision {
	return Decision{Targets: []Target{target("sip:a@192.0.2.1"), target("sip:b@192.0.2.2"), target("sip:c@192.0.2.3")}}
}

func TestParallelForkForwardsTheFirst2xxAndCancelsTheOtherBranches(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(threeTargets())
	h.receive(invite(t))
	sent := h.sent()
	a := byURI(t, sent, "INVITE", "sip:a@192.0.2.1")
	b := byURI(t, sent, "INVITE", "sip:b@192.0.2.2")
	c := byURI(t, sent, "INVITE", "sip:c@192.0.2.3")

	h.reply(a, 180)
	h.reply(b, 183)
	h.reply(a, 200)
	check(t, "upstream", labels(h.upstreamResponses()), []string{"180 INVITE", "183 INVITE", "200 INVITE"})
	// b has a provisional response, so it is cancelled now; c has none yet, so
	// its CANCEL waits for one (§9.1).
	check(t, "sent after the 2xx", h.sentMethods(), []string{"CANCEL sip:b@192.0.2.2"})

	h.reply(c, 180)
	check(t, "sent after c's provisional", h.sentMethods(), []string{"CANCEL sip:c@192.0.2.3"})
	check(t, "upstream after the final", h.upstream(), nil)

	h.reply(b, 487)
	h.reply(c, 487)
	check(t, "upstream after the 487s", h.upstream(), nil)
	check(t, "ACKs for the 487s", h.sentMethods(), []string{"ACK sip:b@192.0.2.2", "ACK sip:c@192.0.2.3"})
	if n := h.p.Stats().Contexts; n != 0 {
		t.Errorf("Contexts = %d once every branch ended, want 0", n)
	}
}

func TestEvery2xxToAnInviteIsForwarded(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:a@192.0.2.1"), target("sip:b@192.0.2.2")}})
	h.receive(invite(t))
	sent := h.sent()
	h.reply(byURI(t, sent, "INVITE", "sip:a@192.0.2.1"), 200)
	h.reply(byURI(t, sent, "INVITE", "sip:b@192.0.2.2"), 200)
	// §16.7 step 5: both 2xx go upstream; the UAC ACKs one and BYEs the other.
	check(t, "upstream", h.upstream(), codes(200, 200))
}

func TestA2xxRetransmissionIsForwarded(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:a@192.0.2.1")}})
	h.receive(invite(t))
	a := h.one()
	h.reply(a, 200)
	h.reply(a, 200)
	check(t, "upstream", h.upstream(), codes(200, 200))
}

func TestResponsesGoUpstreamWithoutTheProxysVia(t *testing.T) {
	h := newHarness(t, Config{})
	h.receive(invite(t))
	h.reply(h.one(), 180)
	res := h.upstreamResponses()
	if len(res) != 1 {
		t.Fatalf("upstream = %v", labels(res))
	}
	vias, _ := res[0].Header.Via()
	if len(vias) != 1 || vias[0].Branch() != "z9hG4bKup-INVITE" {
		t.Errorf("Via = %v, want the upstream Via alone", res[0].Header.Values("Via"))
	}
	if to, _ := res[0].Header.To(); to.Tag() != "tag-example-com" {
		t.Errorf("To tag = %q, want the UAS's", to.Tag())
	}
}

func TestA100IsNotForwarded(t *testing.T) {
	h := newHarness(t, Config{})
	h.receive(invite(t))
	h.reply(h.one(), 100)
	check(t, "upstream", h.upstream(), nil)
}

func TestSequentialForkTriesLowerQOnlyAfterHigherQFails(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{
		{URI: mustURI("sip:low1@192.0.2.3"), Q: 500},
		{URI: mustURI("sip:high@192.0.2.1"), Q: 1000},
		{URI: mustURI("sip:low2@192.0.2.4"), Q: 500},
	}})
	h.receive(invite(t))
	high := h.one()
	if high.URI.User != "high" {
		t.Fatalf("first branch to %s, want the highest q", high.URI.String())
	}
	h.reply(high, 486)
	sent := h.sent()
	check(t, "second group", methodsOf(sent), []string{"ACK sip:high@192.0.2.1", "INVITE sip:low1@192.0.2.3", "INVITE sip:low2@192.0.2.4"})
	check(t, "upstream", h.upstream(), nil)
	h.reply(byURI(t, sent, "INVITE", "sip:low1@192.0.2.3"), 404)
	h.reply(byURI(t, sent, "INVITE", "sip:low2@192.0.2.4"), 480)
	// All 4xx and none preferred: the first received stays.
	check(t, "upstream", h.upstream(), codes(486))
}

func TestSequentialForkStopsAtA2xx(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{{URI: mustURI("sip:high@192.0.2.1"), Q: 1000}, {URI: mustURI("sip:low@192.0.2.2"), Q: 100}}})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	h.reply(h.one(), 202)
	check(t, "sent", h.sentMethods(), nil)
	check(t, "upstream", h.upstream(), codes(202))
}

func methodsOf(sent []sentRequest) []string {
	var out []string
	for _, s := range sent {
		out = append(out, s.req.Method+" "+s.req.URI.String())
	}
	slices.Sort(out)
	return out
}

// TestBestResponse checks the choice of §16.7 step 6 among the final responses
// of parallel branches, given in the order they arrive.
func TestBestResponse(t *testing.T) {
	tests := []struct {
		name   string
		finals []int
		want   int
	}{
		{"the first of a class stays", []int{486, 404}, 486},
		{"the lowest class wins", []int{503, 404, 302}, 302},
		{"401 is preferred within 4xx", []int{404, 401}, 401},
		{"407 is preferred within 4xx", []int{480, 407}, 407},
		{"415 is preferred within 4xx", []int{404, 415}, 415},
		{"420 is preferred within 4xx", []int{404, 420}, 420},
		{"484 is preferred within 4xx", []int{404, 484}, 484},
		{"a 6xx beats a lower class", []int{404, 302, 603}, 603},
		{"a 6xx that arrives first still wins", []int{600, 404}, 600},
		{"a 503 is not passed on when only 503s came", []int{503, 503}, 500},
		{"another 5xx beats a 503", []int{503, 502}, 502},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, Config{})
			var d Decision
			for i := range tt.finals {
				d.Targets = append(d.Targets, target("sip:u"+itoa(i)+"@192.0.2.1"))
			}
			h.decide(d)
			h.receive(invite(t))
			sent := h.sent()
			for i, code := range tt.finals {
				h.reply(byURI(t, sent, "INVITE", "sip:u"+itoa(i)+"@192.0.2.1"), code)
			}
			check(t, "upstream", h.upstream(), codes(tt.want))
		})
	}
}

func TestChallengesOfEvery401And407AreGatheredIntoTheOneForwarded(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(threeTargets())
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	sent := h.sent()
	h.reply(byURI(t, sent, "MESSAGE", "sip:a@192.0.2.1"), 401, `WWW-Authenticate: Digest realm="a.example.com", nonce="n-a"`)
	h.reply(byURI(t, sent, "MESSAGE", "sip:b@192.0.2.2"), 407, `Proxy-Authenticate: Digest realm="b.example.com", nonce="n-b"`)
	h.reply(byURI(t, sent, "MESSAGE", "sip:c@192.0.2.3"), 404)
	res := h.upstreamResponses()
	if len(res) != 1 || res[0].StatusCode != 401 {
		t.Fatalf("upstream = %v, want the 401", labels(res))
	}
	check(t, "WWW-Authenticate", res[0].Header.Values("WWW-Authenticate"), []string{`Digest realm="a.example.com", nonce="n-a"`})
	check(t, "Proxy-Authenticate", res[0].Header.Values("Proxy-Authenticate"), []string{`Digest realm="b.example.com", nonce="n-b"`})
}

func TestA6xxCancelsThePendingBranchesAndIsForwardedOnceTheyEnd(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(threeTargets())
	h.receive(invite(t))
	sent := h.sent()
	a := byURI(t, sent, "INVITE", "sip:a@192.0.2.1")
	b := byURI(t, sent, "INVITE", "sip:b@192.0.2.2")
	h.reply(a, 180)
	h.reply(b, 180)
	h.upstream()
	h.reply(byURI(t, sent, "INVITE", "sip:c@192.0.2.3"), 603)
	check(t, "sent", h.sentMethods(), []string{"ACK sip:c@192.0.2.3", "CANCEL sip:a@192.0.2.1", "CANCEL sip:b@192.0.2.2"})
	check(t, "upstream while branches are pending", h.upstream(), nil)
	h.reply(a, 487)
	h.reply(b, 487)
	check(t, "upstream", h.upstream(), codes(603))
}

func TestA6xxStopsSequentialForking(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{{URI: mustURI("sip:high@192.0.2.1"), Q: 1000}, {URI: mustURI("sip:low@192.0.2.2"), Q: 100}}})
	h.receive(invite(t))
	h.reply(h.one(), 600)
	check(t, "sent", h.sentMethods(), []string{"ACK sip:high@192.0.2.1"})
	check(t, "upstream", h.upstream(), codes(600))
}

func TestA2xxRacingA6xxStillWins(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:a@192.0.2.1"), target("sip:b@192.0.2.2")}})
	h.receive(invite(t))
	sent := h.sent()
	a := byURI(t, sent, "INVITE", "sip:a@192.0.2.1")
	h.reply(a, 180)
	h.reply(byURI(t, sent, "INVITE", "sip:b@192.0.2.2"), 603)
	h.reply(a, 200)
	check(t, "upstream", h.upstream(), codes(180, 200))
}

func TestANonInviteForkForwardsTheFirst2xxOnlyAndCancelsNothing(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:a@192.0.2.1"), target("sip:b@192.0.2.2")}})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	sent := h.sent()
	h.reply(byURI(t, sent, "MESSAGE", "sip:a@192.0.2.1"), 200)
	h.reply(byURI(t, sent, "MESSAGE", "sip:b@192.0.2.2"), 202)
	check(t, "upstream", h.upstream(), codes(200))
	check(t, "sent", h.sentMethods(), nil)
}

func TestABranchWithoutAnyResponseCountsAs408(t *testing.T) {
	h := newHarness(t, Config{})
	h.receive(invite(t))
	h.one()
	// Timer B is 64*T1; the 100 Trying the server transaction sends itself
	// after 200 ms comes first.
	h.advance(64 * 500 * time.Millisecond)
	check(t, "upstream", h.upstream(), codes(100, 408))
}

func TestTransportFailures(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		want       int
		retryAfter bool
	}{
		{"a vanished flow counts as 430", transport.ErrNoFlow, 430, false},
		{"a full send queue counts as 503 with Retry-After, passed on", transport.ErrQueueFull, 503, true},
		{"no room for a connection counts as 503 with Retry-After", transport.ErrTooManyConnections, 503, true},
		{"any other failure counts as a 503 from the next hop, which becomes 500", transport.ErrUnroutable, 500, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, Config{})
			h.net.setFail(func(*sip.Request, transport.Destination) error { return tt.err })
			h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
			res := h.upstreamResponses()
			if len(res) != 1 || res[0].StatusCode != tt.want {
				t.Fatalf("upstream = %v, want %d", labels(res), tt.want)
			}
			if got := res[0].Header.Has("Retry-After"); got != tt.retryAfter {
				t.Errorf("Retry-After present = %v, want %v", got, tt.retryAfter)
			}
		})
	}
}

func TestAFailedBranchLeavesTheOthersToAnswer(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:a@192.0.2.1"), target("sip:b@192.0.2.2")}})
	h.net.setFail(func(req *sip.Request, _ transport.Destination) error {
		if req.URI.User == "a" {
			return transport.ErrUnroutable
		}
		return nil
	})
	h.receive(invite(t))
	h.reply(h.one(), 486)
	check(t, "upstream", h.upstream(), codes(486))
}

func TestTheSameTargetIsNotForwardedToTwice(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:a@192.0.2.1"), target("sip:A@192.0.2.1"), target("sip:a@192.0.2.1")}})
	h.receive(invite(t))
	// URI user parts are case-sensitive (RFC 3261 §19.1.4), so A is another.
	check(t, "sent", h.sentMethods(), []string{"INVITE sip:A@192.0.2.1", "INVITE sip:a@192.0.2.1"})
}

func TestTargetsBeyondMaxBranchesAreDropped(t *testing.T) {
	h := newHarness(t, Config{MaxBranches: 2})
	h.decide(threeTargets())
	h.receive(invite(t))
	if n := len(h.sent()); n != 2 {
		t.Errorf("sent %d branches, want 2", n)
	}
	if n := h.p.Stats().TargetsDropped; n != 1 {
		t.Errorf("TargetsDropped = %d, want 1", n)
	}
}

func TestOnResponseSeesAndChangesEveryForwardedResponseInOrder(t *testing.T) {
	h := newHarness(t, Config{})
	var seen []int
	h.decide(Decision{
		Targets: []Target{target("sip:a@192.0.2.1")},
		OnResponse: func(_ contextT, res *sip.Response) {
			seen = append(seen, res.StatusCode)
			if err := res.Header.Add("Service-Route", "<sip:scscf.example.net;lr>"); err != nil {
				t.Error(err)
			}
		},
	})
	h.receive(request(t, "REGISTER", "sip:example.com"))
	a := h.one()
	h.reply(a, 183)
	h.reply(a, 200)
	check(t, "OnResponse saw", seen, codes(183, 200))
	for _, res := range h.upstreamResponses() {
		if !res.Header.Has("Service-Route") {
			t.Errorf("the %d went upstream without OnResponse's change", res.StatusCode)
		}
	}
}

// TestOnBranchFailureReplacesAFailedFlow is the authoritative proxy of RFC 5626
// §7: a 430 from the edge proxy makes it try the same instance over another
// flow, and the user's other device is not disturbed.
func TestOnBranchFailureReplacesAFailedFlow(t *testing.T) {
	h := newHarness(t, Config{})
	var failures []BranchFailure
	other := Target{URI: mustURI("sip:alice@192.0.2.10"), Destination: &transport.Destination{Flow: "flow-2"}}
	h.decide(Decision{
		Targets: []Target{{URI: mustURI("sip:alice@192.0.2.10"), Destination: &transport.Destination{Flow: "flow-1"}}},
		OnBranchFailure: func(_ contextT, f BranchFailure) []Target {
			failures = append(failures, f)
			if f.Target.Destination.Flow == "flow-1" {
				return []Target{other}
			}
			return nil
		},
	})
	h.net.setFail(func(_ *sip.Request, dst transport.Destination) error {
		if dst.Flow == "flow-1" {
			return transport.ErrNoFlow
		}
		return nil
	})
	h.receive(invite(t))
	sent := h.sent()
	if len(sent) != 1 || sent[0].dst.Flow != "flow-2" {
		t.Fatalf("sent %v, want the INVITE over flow-2", methodsOf(sent))
	}
	if len(failures) != 1 || failures[0].Response.StatusCode != 430 || failures[0].Err == nil {
		t.Fatalf("failures = %v, want one 430 with its error", failures)
	}
	h.reply(sent[0].req, 200)
	check(t, "upstream", h.upstream(), codes(200))
}

func TestOnBranchFailureTargetsAreIgnoredOnceTheRequestIsAnswered(t *testing.T) {
	h := newHarness(t, Config{})
	calls := 0
	h.decide(Decision{
		Targets: []Target{target("sip:a@192.0.2.1"), target("sip:b@192.0.2.2")},
		OnBranchFailure: func(contextT, BranchFailure) []Target {
			calls++
			return []Target{target("sip:late@192.0.2.9")}
		},
	})
	h.receive(invite(t))
	sent := h.sent()
	b := byURI(t, sent, "INVITE", "sip:b@192.0.2.2")
	h.reply(b, 180)
	h.reply(byURI(t, sent, "INVITE", "sip:a@192.0.2.1"), 200)
	h.reply(b, 487)
	if calls != 1 {
		t.Errorf("OnBranchFailure called %d times, want once for b", calls)
	}
	for _, m := range h.sentMethods() {
		if strings.Contains(m, "late") {
			t.Errorf("sent %s after the 2xx", m)
		}
	}
}

// TestAFinalResponseThatLostTheUpstreamViasEndsTheBranchAs502 delivers a
// response carrying only the proxy's Via: it cannot be forwarded, but the
// request must still get its answer and the context must end.
func TestAFinalResponseThatLostTheUpstreamViasEndsTheBranchAs502(t *testing.T) {
	h := newHarness(t, Config{})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	out := h.one()
	broken := out.Clone()
	vias, _ := broken.Header.Elements("Via")
	broken.Header.Del("Via")
	if err := broken.Header.Add("Via", vias[0]); err != nil {
		t.Fatal(err)
	}
	h.reply(broken, 180)
	h.reply(broken, 200)
	check(t, "upstream", h.upstream(), codes(502))
	if n := h.p.Stats().Contexts; n != 0 {
		t.Errorf("Contexts = %d, want 0", n)
	}
}
