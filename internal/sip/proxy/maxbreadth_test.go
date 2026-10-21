package proxy

import (
	"context"
	"slices"
	"strconv"
	"testing"
)

// breadths returns the Max-Breadth of each request sent since the last
// call, by Request-URI.
func breadths(t *testing.T, h *harness) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, s := range h.sent() {
		if vs := s.req.Header.Values("Max-Breadth"); len(vs) != 1 {
			t.Fatalf("%s carries Max-Breadth %q, want one value", s.req.URI.String(), vs)
		}
		n, err := s.req.Header.MaxBreadth()
		if err != nil {
			t.Fatal(err)
		}
		out[s.req.URI.String()] = n
	}
	return out
}

// RFC 5393 §5.3.3: every forwarded request carries one Max-Breadth: the
// request's own, at most MaxBreadth, or MaxBreadth when it has none, split
// among the branches that go out together.
func TestForwardedRequestsShareTheirMaxBreadth(t *testing.T) {
	two := []Target{target("sip:a@192.0.2.1"), target("sip:b@192.0.2.2")}
	three := append(slices.Clone(two), target("sip:c@192.0.2.3"))
	for _, tc := range []struct {
		name    string
		header  string
		targets []Target
		want    map[string]int
	}{
		{"none, one target", "", two[:1], map[string]int{"sip:a@192.0.2.1": 60}},
		{"none, three in parallel", "", three, map[string]int{"sip:a@192.0.2.1": 20, "sip:b@192.0.2.2": 20, "sip:c@192.0.2.3": 20}},
		{"7 between two", "Max-Breadth: 7", two, map[string]int{"sip:a@192.0.2.1": 4, "sip:b@192.0.2.2": 3}},
		{"past the most allowed", "Max-Breadth: 1000", two[:1], map[string]int{"sip:a@192.0.2.1": 60}},
		{"replacing several values", "Max-Breadth: 9\r\nMax-Breadth: 9", two[:1], nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, Config{})
			h.decide(Decision{Targets: tc.targets})
			var extra []string
			if tc.header != "" {
				extra = append(extra, tc.header)
			}
			h.receive(request(t, "MESSAGE", "sip:bob@example.com", extra...))
			if tc.want == nil {
				// Two values make the field malformed: refused 400 (§5.3.1).
				check(t, "upstream", h.upstream(), codes(400))
				check(t, "sent", h.sentMethods(), nil)
				return
			}
			if got := breadths(t, h); !mapsEqual(got, tc.want) {
				t.Errorf("Max-Breadth %v, want %v", got, tc.want)
			}
		})
	}
}

// A Max-Breadth that is not a positive integer is refused 400, before the
// Router is asked.
func TestAMalformedMaxBreadthIsRefused(t *testing.T) {
	for _, v := range []string{"0", "-1", "two", ""} {
		t.Run(strconv.Quote(v), func(t *testing.T) {
			h := newHarness(t, Config{})
			routed := false
			h.route(func(_ context.Context, r *Request) Decision { routed = true; return Forward(r) })
			h.receive(request(t, "MESSAGE", "sip:bob@example.com", "Max-Breadth: "+v))
			check(t, "upstream", h.upstream(), codes(400))
			if routed {
				t.Error("the Router was asked")
			}
		})
	}
}

// Targets that go out together beyond the Max-Breadth left fail at once as
// 440 Max-Breadth Exceeded (RFC 5393 §5.3.3): with 2, three parallel
// targets send two branches, and when they fail too the 440 goes upstream.
// A branch that has failed frees its share for a replacement (§5.3.3.1).
func TestTargetsBeyondTheMaxBreadthFail440(t *testing.T) {
	h := newHarness(t, Config{})
	var replaced bool
	h.decide(Decision{
		Targets: []Target{target("sip:a@192.0.2.1"), target("sip:b@192.0.2.2"), target("sip:c@192.0.2.3")},
		OnBranchFailure: func(_ context.Context, f BranchFailure) []Target {
			if f.Response.StatusCode == 486 && !replaced {
				replaced = true
				return []Target{target("sip:d@192.0.2.4")}
			}
			return nil
		},
	})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com", "Max-Breadth: 2"))
	sent := h.sent()
	if len(sent) != 2 {
		t.Fatalf("sent %d branches, want 2", len(sent))
	}
	if n := h.p.Stats().BreadthExceeded; n != 1 {
		t.Errorf("BreadthExceeded %d, want 1", n)
	}
	// The first fails 486; its share goes to the replacement.
	h.reply(sent[0].req, 486)
	d := h.one()
	if n, _ := d.Header.MaxBreadth(); d.URI.String() != "sip:d@192.0.2.4" || n != 1 {
		t.Fatalf("the replacement went to %s with Max-Breadth %d", d.URI.String(), n)
	}
	h.reply(sent[1].req, 503)
	h.reply(d, 503)
	res := h.upstreamResponses()
	if len(res) != 1 {
		t.Fatalf("upstream got %d responses", len(res))
	}
	// 486 is the best of 486, 503, 503 and the proxy's 440 (§16.7 step 6).
	if res[0].StatusCode != 486 {
		t.Errorf("upstream got %d, want 486", res[0].StatusCode)
	}
}

// With nothing better, the 440 is the answer.
func TestNoMaxBreadthLeftAnswers440(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:a@192.0.2.1"), target("sip:b@192.0.2.2")}})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com", "Max-Breadth: 1"))
	h.reply(h.one(), 503)
	res := h.upstreamResponses()
	if len(res) != 1 || res[0].StatusCode != 440 || res[0].Reason != "Max-Breadth Exceeded" {
		t.Fatalf("upstream got %v, want 440 Max-Breadth Exceeded", res)
	}
}

func mapsEqual(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// An ACK forwarded statelessly carries the Max-Breadth too: it is a proxied
// request (RFC 5393 §5.3.3), one that never forks.
func TestAStatelessACKCarriesItsMaxBreadth(t *testing.T) {
	for _, tc := range []struct {
		extra []string
		want  int
	}{{nil, MaxBreadth}, {[]string{"Max-Breadth: 5"}, 5}} {
		h := newHarness(t, Config{})
		h.receive(ackFor2xx(t, tc.extra...))
		if got := breadths(t, h); len(got) != 1 || got["sip:bob@192.0.2.30"] != tc.want {
			t.Errorf("%v: Max-Breadth %v, want %d", tc.extra, got, tc.want)
		}
	}
}
