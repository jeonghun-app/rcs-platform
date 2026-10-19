package scenario_test

import (
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

func TestTheRegEventFollowsTheClientsRegistration(t *testing.T) {
	cfg, core := sipStack(t)
	ok, results := runAll(t, cfg, "reg-event")
	if !ok {
		t.Fatalf("results %+v", results)
	}
	steps := byStep(results)
	// RFC 3680 §5.3.1: the first version is 0, and each NOTIFY one more.
	for i, s := range []string{"subscribe", "re-register", "unregister"} {
		if !steps[s].OK || steps[s].Detail["version"] != int64(i) {
			t.Fatalf("%s: %+v", s, steps[s])
		}
	}
	if steps["subscribe"].Detail["status"] != 200 {
		t.Fatalf("subscribe %+v", steps["subscribe"])
	}
	if core.Registered(self.URI) {
		t.Fatal("a binding outlived the scenario")
	}
}

func TestARegEventTheClientCannotTrustFailsItsStep(t *testing.T) {
	// The core changes the NOTIFY of one step: that step must fail.
	for name, tc := range map[string]struct {
		cseq    string
		rewrite func(*sip.Request)
		step    string
		err     string
	}{
		"contact not active": {"1 NOTIFY", func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), `<contact id="c1" state="active"`, `<contact id="c1" state="terminated"`, 1))
		}, "subscribe", "the client's contact is \"terminated\", want \"active\""},
		"contact missing": {"1 NOTIFY", func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), "<uri>sip:", "<uri>sip:other@", 1))
		}, "subscribe", "the reginfo does not list the client's contact"},
		"partial first": {"1 NOTIFY", func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), `state="full"`, `state="partial"`, 1))
		}, "subscribe", "the first NOTIFY is not the full state"},
		"version skipped": {"2 NOTIFY", func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), `version="1"`, `version="2"`, 1))
		}, "re-register", "the reginfo version went from 0 to 2, want one more"},
		"version repeated": {"2 NOTIFY", func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), `version="1"`, `version="0"`, 1))
		}, "re-register", "the reginfo version went from 0 to 0, want one more"},
		"subscription kept": {"3 NOTIFY", func(req *sip.Request) {
			_ = req.Header.Set("Subscription-State", "active;expires=600000")
		}, "unregister", "the NOTIFY's subscription state is \"active\", want \"terminated\""},
		"contact kept": {"3 NOTIFY", func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), `<contact id="c1" state="terminated"`, `<contact id="c1" state="active"`, 1))
		}, "unregister", "the client's contact is \"active\", want \"terminated\""},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, core := sipStack(t)
			core.Rewrite = func(req *sip.Request) {
				if req.Header.Get("CSeq") == tc.cseq {
					tc.rewrite(req)
				}
			}
			ok, results := runAll(t, cfg, "reg-event")
			last := results[len(results)-1]
			if ok || last.Step != tc.step || last.OK || last.Error != tc.err {
				t.Fatalf("results %+v", results)
			}
		})
	}
}
