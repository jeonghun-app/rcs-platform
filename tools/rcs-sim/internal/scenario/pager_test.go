package scenario_test

import (
	"context"
	"regexp"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/scenario"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/simtest"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/sipua"
)

// Two test subscribers, on .github/allowed-test-identifiers.txt, with
// made-up passwords.
const (
	imsDomain = "ims.mnc001.mcc001.3gppnetwork.org"
	selfIMPI  = "001010000000001@" + imsDomain
	peerIMPI  = "001010000000002@" + imsDomain
)

// sipStack is stack with the two SIP clients registering at an in-process
// IMS core stand-in, until pcscf and scscf exist (#135).
func sipStack(t *testing.T) (scenario.Config, *simtest.IMSCore) {
	t.Helper()
	cfg := stack(t)
	core := simtest.StartIMSCore(t, imsDomain, map[string]string{selfIMPI: "self-password", peerIMPI: "peer-password"})
	client := func(impu, impi, password, instance string) *sipua.Config {
		u, err := sip.ParseURI(impu)
		if err != nil {
			t.Fatal(err)
		}
		creds, err := sipua.DigestCredentials(impi, []byte(password))
		if err != nil {
			t.Fatal(err)
		}
		return &sipua.Config{
			Network: transport.TCP, Proxy: core.Addr, Domain: imsDomain, IMPU: u,
			InstanceID: instance, Credentials: creds,
		}
	}
	cfg.SIP = client(self.URI, selfIMPI, "self-password", "urn:uuid:00000000-0000-4000-8000-000000000001")
	cfg.SIPPeer = client(peer.URI, peerIMPI, "peer-password", "urn:uuid:00000000-0000-4000-8000-000000000002")
	return cfg, core
}

func TestAPagerMessageIsDeliveredAndItsNotificationComesBack(t *testing.T) {
	cfg, core := sipStack(t)
	ok, results := runAll(t, cfg, "pager-message")
	if !ok {
		t.Fatalf("results %+v", results)
	}
	steps := byStep(results)
	for _, s := range []string{"register", "message", "receive", "delivery-notification"} {
		if !steps[s].OK {
			t.Fatalf("%s: %+v", s, steps[s])
		}
	}
	if steps["message"].Detail["status"] != 200 {
		t.Fatalf("message %+v", steps["message"])
	}
	// The scenario leaves no binding behind.
	if core.Registered(self.URI) || core.Registered(peer.URI) {
		t.Fatal("a binding outlived the scenario")
	}
}

func TestAPeerThatCannotRegisterFailsThePagerWithTheStatusOnly(t *testing.T) {
	// The peer's password is wrong, so it never registers: its step fails,
	// with the status only, and no identity in the error.
	cfg, _ := sipStack(t)
	creds, _ := sipua.DigestCredentials(peerIMPI, []byte("not-the-password"))
	cfg.SIPPeer.Credentials = creds
	ok, results := runAll(t, cfg, "pager-message")
	last := results[len(results)-1]
	if ok || last.Step != "register" || last.Error != "peer: sipua: REGISTER answered 403" {
		t.Fatalf("results %+v", results)
	}
}

func TestAPagerMessageToAnUnregisteredPeerReports480(t *testing.T) {
	// #135 AC 5: B is not registered when A's message comes, so the core
	// answers 480 (RFC 3261 §21.4.18), and the message step says so.
	cfg, core := sipStack(t)
	var results []scenario.Result
	ok, err := scenario.Run(context.Background(), cfg, []string{"pager-message"}, func(r scenario.Result) {
		results = append(results, r)
		if r.Step == "register" && r.OK {
			// Reported before the next step starts: B's binding expires
			// between the two.
			core.Expire(peer.URI)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	last := results[len(results)-1]
	if ok || last.Step != "message" || last.OK || last.Detail["status"] != 480 || last.Error != "MESSAGE answered 480" {
		t.Fatalf("results %+v", results)
	}
}

func TestSIPScenariosWaitForASIPConfiguration(t *testing.T) {
	// "all" leaves them out without one; named, they fail at once.
	cfg := stack(t)
	_, results := runAll(t, cfg, "all")
	for _, r := range results {
		if r.Scenario == "pager-message" || r.Scenario == "reg-event" {
			t.Fatalf("all ran %+v without SIP", r)
		}
	}
	for _, name := range []string{"pager-message", "reg-event"} {
		ok, results := runAll(t, cfg, name)
		if ok || len(results) != 1 || results[0].OK {
			t.Fatalf("%s: results %+v", name, results)
		}
	}
}

func TestAllRunsThePagerWithSIPButNoPeerAndFailsIt(t *testing.T) {
	// Code review on #209: with SIP configured, a missing peer is said,
	// not left out without a line.
	cfg, _ := sipStack(t)
	cfg.SIPPeer = nil
	ok, results := runAll(t, cfg, "all")
	for _, r := range results {
		if r.Scenario == "pager-message" {
			if ok || r.Step != "register" || r.OK || r.Error != "no SIP peer configured (-sip-peer-impi)" {
				t.Fatalf("pager-message %+v, run ok %v", r, ok)
			}
			return
		}
	}
	t.Fatalf("all left pager-message out: %+v", results)
}

func TestAPagerMessageOrNotificationChangedOnTheWayFails(t *testing.T) {
	// The core rewrites the Message-ID, of the message or of the
	// notification's report: the step that reads it must fail.
	for name, tc := range map[string]struct {
		rewrite func(body string) string
		step    string
	}{
		"message": {func(b string) string {
			return regexp.MustCompile(`imdn\.Message-ID: \S+`).ReplaceAllString(b, "imdn.Message-ID: another0message0id")
		}, "receive"},
		"notification": {func(b string) string {
			return regexp.MustCompile(`<message-id>[^<]*</message-id>`).ReplaceAllString(b, "<message-id>another0message0id</message-id>")
		}, "delivery-notification"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, core := sipStack(t)
			core.Rewrite = func(req *sip.Request) {
				req.Body = []byte(tc.rewrite(string(req.Body)))
			}
			ok, results := runAll(t, cfg, "pager-message")
			last := results[len(results)-1]
			if ok || last.Step != tc.step || last.OK {
				t.Fatalf("results %+v", results)
			}
		})
	}
}
