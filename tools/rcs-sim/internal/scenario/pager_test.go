package scenario_test

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/scenario"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/simtest"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/sipua"
)

// Test subscribers, on .github/allowed-test-identifiers.txt, with made-up
// passwords: the client, the peer, and a third that plays an earlier run's
// leftovers.
const (
	imsDomain  = "ims.mnc001.mcc001.3gppnetwork.org"
	selfIMPI   = "001010000000001@" + imsDomain
	peerIMPI   = "001010000000002@" + imsDomain
	thirdIMPI  = "001010000000003@" + imsDomain
	thirdIMPU  = "sip:+15550100003@" + imsDomain
	thirdToken = "third-password"
)

// sipStack is stack with the two SIP clients registering at an in-process
// IMS core stand-in, until pcscf and scscf exist (#135).
func sipStack(t *testing.T) (scenario.Config, *simtest.IMSCore) {
	t.Helper()
	cfg := stack(t)
	core := simtest.StartIMSCore(t, imsDomain, map[string]string{selfIMPI: "self-password", peerIMPI: "peer-password", thirdIMPI: thirdToken})
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
	// As an operator's DELETE through the HSS API would (#135 AC 3).
	cfg.Deregister = func(_ context.Context, impu sip.URI) error {
		core.Deregister(impu.String(), "deactivated")
		return nil
	}
	return cfg, core
}

func TestAPagerMessageIsDeliveredAndItsNotificationComesBack(t *testing.T) {
	cfg, core := sipStack(t)
	ok, results := runAll(t, cfg, "pager-message")
	if !ok {
		t.Fatalf("results %+v", results)
	}
	steps := byStep(results)
	for _, s := range []string{"register", "message", "receive", "delivery-notification", "peer-offline"} {
		if !steps[s].OK {
			t.Fatalf("%s: %+v", s, steps[s])
		}
	}
	if steps["message"].Detail["status"] != 200 || steps["receive"].Detail["skipped"] != 0 {
		t.Fatalf("message %+v, receive %+v", steps["message"], steps["receive"])
	}
	// What the platform does today for an unregistered IMPU.
	if d := steps["peer-offline"].Detail; d["status"] != 480 || d["stored"] != 0 {
		t.Fatalf("peer-offline %+v", steps["peer-offline"])
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

func TestPeerOfflineTakesStoreAndForwardButNotALostMessage(t *testing.T) {
	// QA on #209 (#135 AC 5): a core that stores the message for the
	// unregistered peer and delivers it at its next registration passes;
	// one that answers 200 and loses it fails.
	t.Run("stored", func(t *testing.T) {
		cfg, core := sipStack(t)
		core.Offline = simtest.StoreAndForward
		ok, results := runAll(t, cfg, "pager-message")
		if d := byStep(results)["peer-offline"]; !ok || d.Detail["status"] != 202 || d.Detail["stored"] != 1 {
			t.Fatalf("results %+v", results)
		}
	})
	t.Run("refused otherwise", func(t *testing.T) {
		// QA on #209: 404 is not the platform's answer, nor a store.
		cfg, core := sipStack(t)
		core.Offline = simtest.RefuseNotFound
		ok, results := runAll(t, cfg, "pager-message")
		last := results[len(results)-1]
		if ok || last.Step != "peer-offline" || last.Detail["status"] != 404 ||
			last.Error != "MESSAGE to the unregistered peer answered 404, want 480 or store-and-forward" {
			t.Fatalf("results %+v", results)
		}
	})
	t.Run("changed in store", func(t *testing.T) {
		cfg, core := sipStack(t)
		core.Offline = simtest.StoreAndChange
		ok, results := runAll(t, cfg, "pager-message")
		last := results[len(results)-1]
		if ok || last.Step != "peer-offline" || last.Error != "the stored message changed on the way" {
			t.Fatalf("results %+v", results)
		}
	})
	t.Run("lost", func(t *testing.T) {
		cfg, core := sipStack(t)
		cfg.StepTimeout = 2 * time.Second
		core.Offline = simtest.Drop
		ok, results := runAll(t, cfg, "pager-message")
		last := results[len(results)-1]
		if ok || last.Step != "peer-offline" || last.OK || last.Detail["status"] != 200 ||
			last.Error != "MESSAGE to the unregistered peer answered 200, and it never arrived after the peer registered again" {
			t.Fatalf("results %+v", results)
		}
	})
}

func TestMessagesAnEarlierRunLeftAreSkipped(t *testing.T) {
	// QA on #209: a store-and-forward network may first deliver what an
	// earlier run left. A third subscriber sends the peer such a message,
	// same text but another Message-ID and no token of this run, as soon
	// as the peer has registered: receive skips it.
	cfg, core := sipStack(t)
	u, _ := sip.ParseURI(thirdIMPU)
	creds, err := sipua.DigestCredentials(thirdIMPI, []byte(thirdToken))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	third, err := sipua.Dial(ctx, sipua.Config{Network: transport.TCP, Proxy: core.Addr, Domain: imsDomain, IMPU: u,
		InstanceID: "urn:uuid:00000000-0000-4000-8000-000000000003", Credentials: creds})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = third.Close() })
	if _, err := third.Register(ctx); err != nil {
		t.Fatal(err)
	}
	leftover := "imdn.Message-ID: 0ld0message0id\r\nimdn.Disposition-Notification: positive-delivery\r\n"
	body := "From: <" + thirdIMPU + ">\r\nTo: <" + peer.URI + ">\r\nNS: imdn <urn:ietf:params:imdn>\r\n" + leftover +
		"\r\nContent-Type: text/plain;charset=utf-8\r\n\r\nrcs-sim pager-mode message"
	var results []scenario.Result
	ok, err := scenario.Run(context.Background(), cfg, []string{"pager-message"}, func(r scenario.Result) {
		results = append(results, r)
		if r.Step == "register" && r.OK {
			pu, _ := sip.ParseURI(peer.URI)
			req, err := third.NewMessage(pu, "message/cpim", []byte(body))
			if err != nil {
				t.Error(err)
				return
			}
			if res, err := third.Send(ctx, req); err != nil || res.StatusCode != 200 {
				t.Errorf("leftover MESSAGE: %v, %v", res, err)
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if d := byStep(results)["receive"]; !ok || !d.OK || d.Detail["skipped"] != 1 {
		t.Fatalf("results %+v", results)
	}
}

func TestEveryPagerCheckFailsItsStep(t *testing.T) {
	// QA on #209: each check of the scenario fails its step.
	isNotification := func(r *sip.Request) bool { return strings.Contains(string(r.Body), "imdn+xml") }
	sub := func(re, to string) func(string) string {
		return func(b string) string { return regexp.MustCompile(re).ReplaceAllString(b, to) }
	}
	refuse := func(r *sip.Request) { // the far end answers 420 (RFC 3261 §8.2.2.3)
		r.Header.Add("Require", "x-qa-unknown")
	}
	for name, tc := range map[string]struct {
		notification bool
		rewrite      func(*sip.Request)
		step         string
	}{
		"text changed": {false, func(r *sip.Request) {
			r.Body = []byte(sub(`rcs-sim pager-mode message`, `rcs-sim pager-mode messagf`)(string(r.Body)))
		}, "receive"},
		"display requested only": {false, func(r *sip.Request) {
			r.Body = []byte(sub(`imdn.Disposition-Notification: \S+`, `imdn.Disposition-Notification: display`)(string(r.Body)))
		}, "receive"},
		"message not cpim": {false, func(r *sip.Request) { _ = r.Header.Set("Content-Type", "text/plain") }, "receive"},
		"message refused":  {false, refuse, "message"},
		"notification failed": {true, func(r *sip.Request) {
			r.Body = []byte(sub(`<delivered></delivered>`, `<failed/>`)(string(r.Body)))
		}, "delivery-notification"},
		"notification is display": {true, func(r *sip.Request) {
			r.Body = []byte(sub(`<delivery-notification><status><delivered></delivered></status></delivery-notification>`,
				`<display-notification><status><displayed/></status></display-notification>`)(string(r.Body)))
		}, "delivery-notification"},
		"notification no disposition": {true, func(r *sip.Request) {
			r.Body = []byte(sub(`Content-Disposition: notification\r\n`, ``)(string(r.Body)))
		}, "delivery-notification"},
		"notification refused": {true, refuse, "delivery-notification"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, core := sipStack(t)
			core.Rewrite = func(r *sip.Request) {
				if r.Method == "MESSAGE" && isNotification(r) == tc.notification {
					tc.rewrite(r)
				}
			}
			ok, results := runAll(t, cfg, "pager-message")
			last := results[len(results)-1]
			if ok || last.Step != tc.step || last.OK {
				t.Fatalf("results %+v", results)
			}
		})
	}
}

func TestThisRunsMessageWithAnotherIDIsNamedNotSkipped(t *testing.T) {
	// QA on #209: this run's message with a rewritten Message-ID is still
	// this run's (the token in its text): the step names it at once, and
	// does not skip it until the step times out.
	cfg, core := sipStack(t)
	cfg.StepTimeout = 3 * time.Second
	core.Rewrite = func(r *sip.Request) {
		r.Body = []byte(regexp.MustCompile(`imdn\.Message-ID: \S+`).ReplaceAllString(string(r.Body), "imdn.Message-ID: another0message0id"))
	}
	ok, results := runAll(t, cfg, "pager-message")
	last := results[len(results)-1]
	if ok || last.Step != "receive" || last.Error != "the message received is not the one sent" || last.Detail["skipped"] != 0 {
		t.Fatalf("results %+v", results)
	}
}

func TestAWaitThatTimesOutReportsWhatItSkipped(t *testing.T) {
	// QA on #209: a stale store and a message that never came read
	// differently. Every MESSAGE to the peer here looks like an earlier
	// run's, so receive skips it and times out.
	cfg, core := sipStack(t)
	cfg.StepTimeout = 2 * time.Second
	core.Rewrite = func(r *sip.Request) {
		body := regexp.MustCompile(`imdn\.Message-ID: \S+`).ReplaceAllString(string(r.Body), "imdn.Message-ID: 0ld0message0id")
		r.Body = []byte(regexp.MustCompile(`rcs-sim pager-mode message \S+`).ReplaceAllString(body, "rcs-sim pager-mode message"))
	}
	ok, results := runAll(t, cfg, "pager-message")
	last := results[len(results)-1]
	if ok || last.Step != "receive" || last.Detail["skipped"] != 1 {
		t.Fatalf("results %+v", results)
	}
}

func TestANotificationWaitThatTimesOutReportsWhatItSkipped(t *testing.T) {
	// QA on #216: the delivery notification's wait says what it skipped
	// too. Its own Message-ID rewritten, the notification looks like an
	// earlier run's and is skipped.
	cfg, core := sipStack(t)
	cfg.StepTimeout = 2 * time.Second
	core.Rewrite = func(r *sip.Request) {
		if strings.Contains(string(r.Body), "imdn+xml") {
			r.Body = []byte(regexp.MustCompile(`imdn\.Message-ID: \S+`).ReplaceAllString(string(r.Body), "imdn.Message-ID: 0ld0notification"))
		}
	}
	ok, results := runAll(t, cfg, "pager-message")
	last := results[len(results)-1]
	if ok || last.Step != "delivery-notification" || last.Detail["skipped"] != 1 {
		t.Fatalf("results %+v", results)
	}
}
