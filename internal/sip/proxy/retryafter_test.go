package proxy

import "testing"

// TestANextHops500WithRetryAfterReachesTheClient: the S-CSCF answers a
// REGISTER over its challenge limit 500 with Retry-After (#201), which a
// proxy passes on as it is, unlike a 503, which it replaces with a 500 of
// its own (RFC 3261 §16.7 step 6). So the UE behind the P-CSCF and I-CSCF
// learns when to come back.
func TestANextHops500WithRetryAfterReachesTheClient(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:scscf.example.com")}})
	h.receive(request(t, "REGISTER", "sip:example.com"))
	h.reply(byURI(t, h.sent(), "REGISTER", "sip:scscf.example.com"), 500, "Retry-After: 45")
	res := h.upstreamResponses()
	if len(res) != 1 || res[0].StatusCode != 500 || res[0].Header.Get("Retry-After") != "45" {
		for _, r := range res {
			t.Logf("client got %d Retry-After %q", r.StatusCode, r.Header.Get("Retry-After"))
		}
		t.Fatal("the client did not get the next hop's 500 with its Retry-After")
	}
}
