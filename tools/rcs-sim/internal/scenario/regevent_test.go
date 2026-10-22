package scenario_test

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

func TestTheRegEventFollowsTheClientsRegistration(t *testing.T) {
	cfg, core := sipStack(t)
	ok, results := runAll(t, cfg, "reg-event")
	if !ok {
		t.Fatalf("results %+v", results)
	}
	steps := byStep(results)
	// RFC 3680 §5.1, §5.2: the first version is 0, and each NOTIFY one more.
	for i, s := range []string{"subscribe", "re-register", "unregister"} {
		if !steps[s].OK || steps[s].Detail["version"] != int64(i) {
			t.Fatalf("%s: %+v", s, steps[s])
		}
	}
	// #563: a subscription of its own refreshed and then ended, each
	// answered 200.
	if d := steps["refresh"]; !d.OK || d.Detail["status"] != 200 || d.Detail["version"] != 0 {
		t.Fatalf("refresh %+v", d)
	}
	if d := steps["unsubscribe"]; !d.OK || d.Detail["status"] != 200 {
		t.Fatalf("unsubscribe %+v", d)
	}
	// Another subscription of its own, its versions from 0: 0, then the
	// deregistration's 1.
	if d := steps["network-deregister"]; !d.OK || d.Detail["version"] != 1 || d.Detail["others"] != 0 {
		t.Fatalf("network-deregister %+v", d)
	}
	if steps["subscribe"].Detail["status"] != 200 || steps["unregister"].Detail["others"] != 0 {
		t.Fatalf("subscribe %+v, unregister %+v", steps["subscribe"], steps["unregister"])
	}
	if core.Registered(self.URI) {
		t.Fatal("a binding outlived the scenario")
	}
}

func TestARegEventPassesWhatTheRFCsAllow(t *testing.T) {
	// The core changes NOTIFYs within what RFC 3680, RFC 6665 and TS 24.229
	// allow: the run must pass.
	for name, rewrite := range map[string]func(*sip.Request){
		// RFC 3261 §19.1.4: hosts compare without regard to case (QA on
		// #216).
		"aor host in upper case": func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), `aor="sip:+15550100001@ims.mnc001`, `aor="sip:+15550100001@IMS.MNC001`, 1))
		},
		// A binding an earlier run left keeps a registration active: the
		// client's contact ends, the subscription goes on (TS 24.229
		// §5.4.2.1.2; code review on #216).
		"a stale binding keeps the subscription": func(req *sip.Request) {
			if req.Header.Get("CSeq") != "3 NOTIFY" {
				return
			}
			_ = req.Header.Set("Subscription-State", "active;expires=600")
			req.Body = []byte(staleContact(string(req.Body)))
		},
		// TS 24.229 §5.4.1.5: the network's deregistration ends the
		// subscription with "terminated" and no reason, and the contact
		// may end as unregistered (code review on #216).
		"deregistered for no reason": func(req *sip.Request) {
			if strings.HasPrefix(req.Header.Get("Subscription-State"), "terminated;reason=deactivated") {
				_ = req.Header.Set("Subscription-State", "terminated")
			}
		},
		"deregistered as unregistered": func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), `event="deactivated"`, `event="unregistered"`, 1))
		},
		// The client's contact URI bound twice (RFC 5626 §6): the other
		// binding, an earlier run's with another +sip.instance and still
		// active, comes first; the client's is told by its instance.
		"the contact URI bound twice": func(req *sip.Request) {
			if req.Header.Get("CSeq") != "3 NOTIFY" {
				return
			}
			_ = req.Header.Set("Subscription-State", "active;expires=600")
			body := strings.Replace(string(req.Body), `id="r1" state="terminated"`, `id="r1" state="active"`, 1)
			uri := regexp.MustCompile(`<uri>[^<]*</uri>`).FindString(body)
			body = strings.Replace(body, `<contact id="c1"`,
				`<contact id="c0" state="active" event="registered" expires="600">`+uri+
					`<unknown-param name="+sip.instance">"&lt;urn:uuid:00000000-0000-4000-8000-000000000009&gt;"</unknown-param></contact><contact id="c1"`, 1)
			req.Body = []byte(strings.Replace(body, `</uri></contact></registration>`,
				`</uri><unknown-param name="+sip.instance">"&lt;urn:uuid:00000000-0000-4000-8000-000000000001&gt;"</unknown-param></contact></registration>`, 1))
		},
		// Code review on #253: the same, but the client's contact carries no
		// instance, so it is the one without; the other device's, ahead of
		// it and still active, is never taken for it.
		"another instance ahead of the client's without one": func(req *sip.Request) {
			if req.Header.Get("CSeq") != "3 NOTIFY" {
				return
			}
			_ = req.Header.Set("Subscription-State", "active;expires=600")
			body := strings.Replace(string(req.Body), `id="r1" state="terminated"`, `id="r1" state="active"`, 1)
			uri := regexp.MustCompile(`<uri>[^<]*</uri>`).FindString(body)
			req.Body = []byte(strings.Replace(body, `<contact id="c1"`,
				`<contact id="c0" state="active" event="registered" expires="600">`+uri+
					`<unknown-param name="+sip.instance">"&lt;urn:uuid:00000000-0000-4000-8000-000000000009&gt;"</unknown-param></contact><contact id="c1"`, 1))
		},
		// QA on #253: the client's own +sip.instance written back in upper
		// case is still the client's, and still told from another's.
		"the client's instance in upper case": func(req *sip.Request) {
			if req.Header.Get("CSeq") != "3 NOTIFY" {
				return
			}
			_ = req.Header.Set("Subscription-State", "active;expires=600")
			body := strings.Replace(string(req.Body), `id="r1" state="terminated"`, `id="r1" state="active"`, 1)
			uri := regexp.MustCompile(`<uri>[^<]*</uri>`).FindString(body)
			body = strings.Replace(body, `<contact id="c1"`,
				`<contact id="c0" state="active" event="registered" expires="600">`+uri+
					`<unknown-param name="+sip.instance">"&lt;urn:uuid:00000000-0000-4000-8000-000000000009&gt;"</unknown-param></contact><contact id="c1"`, 1)
			req.Body = []byte(strings.Replace(body, `</uri></contact></registration>`,
				`</uri><unknown-param name="+sip.instance">"&lt;URN:UUID:00000000-0000-4000-8000-000000000001&gt;"</unknown-param></contact></registration>`, 1))
		},
		// QA on #253: a network deregistration may end the subscription
		// with noresource (RFC 6665 §4.1.3), unlike the user's.
		"deregistered for noresource": func(req *sip.Request) {
			if strings.HasPrefix(req.Header.Get("Subscription-State"), "terminated;reason=deactivated") {
				_ = req.Header.Set("Subscription-State", "terminated;reason=noresource")
			}
		},
		// A terminated subscription without a reason (RFC 6665 §4.1.3).
		"unregister with timeout": func(req *sip.Request) {
			if req.Header.Get("CSeq") == "3 NOTIFY" {
				_ = req.Header.Set("Subscription-State", "terminated;reason=timeout")
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, core := sipStack(t)
			main := mainSubscription()
			core.Rewrite = func(req *sip.Request) {
				if req.Method == "NOTIFY" && main(req) {
					rewrite(req)
				}
			}
			ok, results := runAll(t, cfg, "reg-event")
			if !ok {
				t.Fatalf("results %+v", results)
			}
			if name == "a stale binding keeps the subscription" && byStep(results)["unregister"].Detail["others"] != 1 {
				t.Fatalf("unregister %+v", byStep(results)["unregister"])
			}
		})
	}
}

func TestARejectedDeregistrationEndsTheContactAsRejected(t *testing.T) {
	cfg, core := sipStack(t)
	cfg.Deregister = func(_ context.Context, impu sip.URI) error {
		core.Deregister(impu.String(), "rejected")
		return nil
	}
	if ok, results := runAll(t, cfg, "reg-event"); !ok {
		t.Fatalf("results %+v", results)
	}
}

func TestNetworkDeregisterIsSkippedWithoutAWayToAskTheNetwork(t *testing.T) {
	// Until the HSS API's DELETE and scscf's RTR exist (#14), a stack gives
	// no Deregister: the step is skipped, said in a fixed text, and the run
	// passes; with RequireAll it fails instead.
	cfg, _ := sipStack(t)
	cfg.Deregister = nil
	ok, results := runAll(t, cfg, "reg-event")
	last := results[len(results)-1]
	if !ok || last.Step != "network-deregister" || !last.OK || last.Skipped != "network deregistration not configured" || last.Error != "" {
		t.Fatalf("results %+v", results)
	}
	cfg.RequireAll = true
	ok, results = runAll(t, cfg, "reg-event")
	last = results[len(results)-1]
	if ok || last.Step != "network-deregister" || last.OK || last.Skipped != "" || last.Error != "network deregistration not configured" {
		t.Fatalf("with RequireAll: results %+v", results)
	}
}

func TestARegEventTheClientCannotTrustFailsItsStep(t *testing.T) {
	// The core changes one NOTIFY, keyed by its CSeq (each subscription
	// counts from 1), and that step must fail with its fixed reason.
	version := regexp.MustCompile(`version="(\d+)" state="full"`)
	for name, tc := range map[string]struct {
		cseq    string // "" for every NOTIFY
		rewrite func(*sip.Request)
		step    string
		err     string
	}{
		// Code review on #253: the only contact at the client's URI carries
		// another device's +sip.instance, so it is not the client's (RFC
		// 5626 §4.1).
		"only another instance at the URI": {"1 NOTIFY", func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), `</uri></contact>`,
				`</uri><unknown-param name="+sip.instance">"&lt;urn:uuid:00000000-0000-4000-8000-000000000009&gt;"</unknown-param></contact>`, 1))
		}, "subscribe", "the reginfo does not list the client's contact"},
		"contact not active": {"1 NOTIFY", func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), `<contact id="c1" state="active"`, `<contact id="c1" state="terminated"`, 1))
		}, "subscribe", "the client's contact is not active"},
		"contact missing": {"1 NOTIFY", func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), "<uri>sip:", "<uri>sip:other@", 1))
		}, "subscribe", "the reginfo does not list the client's contact"},
		"contact under another AOR": {"1 NOTIFY", func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), `aor="sip:+15550100001@`, `aor="sip:+15550100005@`, 1))
		}, "subscribe", "the reginfo does not list the client's contact"},
		"partial first": {"1 NOTIFY", func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), `state="full"`, `state="partial"`, 1))
		}, "subscribe", "the first NOTIFY is not the full state"},
		// RFC 3680 §5.1: versions start at 0 (QA on #216).
		"versions start at 1": {"", func(req *sip.Request) {
			req.Body = version.ReplaceAllFunc(req.Body, func(m []byte) []byte {
				n, _ := strconv.Atoi(version.FindStringSubmatch(string(m))[1])
				return []byte(`version="` + strconv.Itoa(n+1) + `" state="full"`)
			})
		}, "subscribe", "the first reginfo version is not 0"},
		"version beyond 32 bits": {"1 NOTIFY", func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), `version="0"`, `version="4294967296"`, 1))
		}, "subscribe", "reginfo: malformed document: version is not a 32-bit unsigned integer"},
		// RFC 3680 §4.7.1: a registration with a contact bound is active.
		"registration terminated, contact active": {"1 NOTIFY", func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), `id="r1" state="active"`, `id="r1" state="terminated"`, 1))
		}, "subscribe", "the client's active contact is in a registration that is not active"},
		"no body": {"1 NOTIFY", func(req *sip.Request) {
			req.Body = nil
			req.Header.Del("Content-Type")
		}, "subscribe", "the NOTIFY has no reginfo"},
		"version skipped": {"2 NOTIFY", func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), `version="1"`, `version="2"`, 1))
		}, "re-register", "the reginfo version did not rise by one"},
		"version repeated": {"2 NOTIFY", func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), `version="1"`, `version="0"`, 1))
		}, "re-register", "the reginfo version did not rise by one"},
		"body not reginfo": {"2 NOTIFY", func(req *sip.Request) {
			req.Body = []byte("<reginfo")
		}, "re-register", "reginfo: malformed document: XML syntax error on line 1"},
		"no NOTIFY (another dialog's Call-ID)": {"2 NOTIFY", func(req *sip.Request) {
			_ = req.Header.Set("Call-ID", "qa-another-dialog")
		}, "re-register", "no NOTIFY came"},
		"subscription kept": {"3 NOTIFY", func(req *sip.Request) {
			_ = req.Header.Set("Subscription-State", "active;expires=600000")
		}, "unregister", "the subscription did not end with the last registration"},
		"contact kept": {"3 NOTIFY", func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), `<contact id="c1" state="terminated"`, `<contact id="c1" state="active"`, 1))
		}, "unregister", "the client's active contact is in a registration that is not active"},
		// QA on #216: the contact's event is checked too.
		"unregistered as expired": {"3 NOTIFY", func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), `event="unregistered"`, `event="expired"`, 1))
		}, "unregister", "the client's contact did not end as unregistered"},
		// QA on #216: after the user's de-registration, no reason, timeout
		// or deactivated.
		"unregister ended on probation": {"3 NOTIFY", func(req *sip.Request) {
			_ = req.Header.Set("Subscription-State", "terminated;reason=probation;retry-after=10")
		}, "unregister", "the subscription ended for a reason it should not"},
		"subscription ended with a registration left": {"3 NOTIFY", func(req *sip.Request) {
			req.Body = []byte(staleContact(string(req.Body)))
		}, "unregister", "the subscription ended while a registration is still active"},
		"deregistered as expired": {"", func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), `event="deactivated"`, `event="expired"`, 1))
		}, "network-deregister", "the client's contact did not end as unregistered, deactivated or rejected"},
		"deregistered, contact kept": {"", func(req *sip.Request) {
			if strings.Contains(string(req.Body), `event="deactivated"`) {
				req.Body = []byte(strings.Replace(string(req.Body), `<contact id="c1" state="terminated" event="deactivated"`, `<contact id="c1" state="active" event="registered"`, 1))
				req.Body = []byte(strings.Replace(string(req.Body), `id="r1" state="terminated"`, `id="r1" state="active"`, 1))
			}
		}, "network-deregister", "the client's contact did not end with the network's deregistration"},
		// Code review on #216: after the user's de-registration,
		// noresource fails (see regevent.go).
		"unregister ended for noresource": {"3 NOTIFY", func(req *sip.Request) {
			_ = req.Header.Set("Subscription-State", "terminated;reason=noresource")
		}, "unregister", "the subscription ended for a reason it should not"},
	} {
		t.Run(name, func(t *testing.T) {
			// The rig's step timeout: a shorter one also held the steps
			// before the one a case checks, which a loaded host can take
			// seconds for (#387, #396).
			cfg, core := sipStack(t)
			// A case with a CSeq rewrites that NOTIFY of the first
			// subscription, and one without, every NOTIFY. The one
			// rewritten is kept to know its answer by, as its Call-ID may
			// be what the case changes.
			main := mainSubscription()
			var rewritten atomic.Pointer[sip.Request]
			core.Rewrite = func(req *sip.Request) {
				if req.Method != "NOTIFY" {
					return
				}
				if first := main(req); tc.cseq == "" || first && req.Header.Get("CSeq") == tc.cseq {
					rewritten.Store(req)
					tc.rewrite(req)
				}
			}
			// A NOTIFY the client must drop leaves its step waiting for
			// one that never comes. The run ends once the client has
			// answered the dropped NOTIFY, which must be 481: a request in
			// a dialog the client does not have (RFC 3261 §12.2.2).
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			dropped := make(chan int, 1)
			if tc.err == "no NOTIFY came" {
				core.NotifyAnswered = func(req *sip.Request, res *sip.Response, err error) {
					if req == rewritten.Load() {
						code := 0
						if err == nil {
							code = res.StatusCode
						}
						select { // the first answer counts; the hook must not block
						case dropped <- code:
						default:
						}
						cancel()
					}
				}
			}
			ok, results := runAllWithin(t, ctx, cfg, "reg-event")
			last := results[len(results)-1]
			if ok || last.Step != tc.step || last.OK || last.Error != tc.err {
				t.Fatalf("results %+v", results)
			}
			if tc.err == "no NOTIFY came" {
				// The run ended, so the answer is in, or never came.
				select {
				case code := <-dropped:
					if code != 481 {
						t.Fatalf("the client answered the NOTIFY it should drop with %d, want 481", code)
					}
				case <-time.After(cfg.StepTimeout):
					t.Fatal("the client never answered the NOTIFY it should drop")
				}
			}
		})
	}
}

func TestRegEventChecksQARound2Pins(t *testing.T) {
	// QA on #216: five checks no other case pins.
	for name, tc := range map[string]struct {
		cseq    string
		rewrite func(*sip.Request)
		dereg   func(context.Context, sip.URI) error
		step    string
		err     string
	}{
		"pending at subscribe": {"1 NOTIFY", func(req *sip.Request) {
			_ = req.Header.Set("Subscription-State", "pending;expires=600")
		}, nil, "subscribe", "the subscription is not active"},
		"terminated at re-register": {"2 NOTIFY", func(req *sip.Request) {
			_ = req.Header.Set("Subscription-State", "terminated;reason=rejected")
		}, nil, "re-register", "the subscription is not active after the refresh"},
		"contact expired at re-register": {"2 NOTIFY", func(req *sip.Request) {
			req.Body = []byte(strings.Replace(string(req.Body), `state="active" event="refreshed"`, `state="terminated" event="expired"`, 1))
		}, nil, "re-register", "the client's contact is not active after the refresh"},
		"contact still active, event unregistered, registration active": {"3 NOTIFY", func(req *sip.Request) {
			s := strings.Replace(string(req.Body), `<contact id="c1" state="terminated"`, `<contact id="c1" state="active"`, 1)
			req.Body = []byte(strings.Replace(s, `id="r1" state="terminated"`, `id="r1" state="active"`, 1))
		}, nil, "unregister", "the client's contact did not end as unregistered"},
		"deregister hook fails": {"", nil, func(context.Context, sip.URI) error { return errors.New("refused") },
			"network-deregister", "the network deregistration could not be asked for"},
	} {
		t.Run(name, func(t *testing.T) {
			// The rig's step timeout: every check here fails its step at
			// once, and a shorter one only bounded the steps before it,
			// such as the register a loaded host took 3.6 s for (#387).
			cfg, core := sipStack(t)
			if tc.dereg != nil {
				cfg.Deregister = tc.dereg
			}
			if tc.rewrite != nil {
				main := mainSubscription()
				core.Rewrite = func(req *sip.Request) {
					if req.Method == "NOTIFY" && main(req) && req.Header.Get("CSeq") == tc.cseq {
						tc.rewrite(req)
					}
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

func TestRegEventContactUnderANonIMPUAorIsNotTheClients(t *testing.T) {
	// QA on #216: the client's contact listed only under an aor that is
	// not a public identity is not the client's registration.
	for name, tc := range map[string]struct{ aor, err string }{
		// internal/sip/reginfo refuses a document whose aor is no URI.
		"empty aor":     {`aor=""`, "reginfo: malformed document: aor is not a SIP or tel URI"},
		"aor with port": {`aor="sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org:5060"`, "the reginfo does not list the client's contact"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, core := sipStack(t)
			core.Rewrite = func(req *sip.Request) {
				if req.Method == "NOTIFY" && req.Header.Get("CSeq") == "1 NOTIFY" {
					req.Body = []byte(strings.Replace(string(req.Body), `aor="sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org"`, tc.aor, 1))
				}
			}
			ok, results := runAll(t, cfg, "reg-event")
			last := results[len(results)-1]
			if ok || last.Step != "subscribe" || last.Error != tc.err {
				t.Fatalf("results %+v", results)
			}
		})
	}
}

// staleContact adds to a reginfo body's registration a contact an earlier
// run left, still active, so the registration is active too (RFC 3680
// §4.7.1): one registration per AOR, as internal/sip/reginfo requires.
func staleContact(body string) string {
	body = strings.Replace(body, `id="r1" state="terminated"`, `id="r1" state="active"`, 1)
	return strings.Replace(body, `</registration>`,
		`<contact id="c9" state="active" event="registered" expires="600"><uri>sip:192.0.2.9:5060;transport=tcp</uri></contact></registration>`, 1)
}

// TestTheRegEventToleratesARepeatedFullNotify (#473 QA): a network that
// sends a subscription's first NOTIFY twice, the state the same and the
// version raised, still passes: each step waits for the NOTIFY of the
// change it made, and skips, counted, those before it.
func TestTheRegEventToleratesARepeatedFullNotify(t *testing.T) {
	cfg, core := sipStack(t)
	cfg.StepTimeout = 3 * time.Second
	core.RepeatFirstNotify = true
	ok, results := runAll(t, cfg, "reg-event")
	if !ok {
		t.Fatalf("results %+v", results)
	}
	if got := byStep(results)["re-register"].Detail["skipped"]; got != 1 {
		t.Errorf("re-register skipped %d NOTIFYs, want the repeated one", got)
	}
}

// mainSubscription reports whether a NOTIFY is of the scenario's first
// subscription, the one its steps follow up to the unregister: the refresh
// and unsubscribe steps have a subscription of their own (#563), whose
// NOTIFYs number their CSeq from 1 as well. The first NOTIFY it sees names
// it, so it must see every NOTIFY, before any other test on it.
func mainSubscription() func(*sip.Request) bool {
	var mu sync.Mutex
	first := ""
	return func(req *sip.Request) bool {
		mu.Lock()
		defer mu.Unlock()
		if first == "" {
			first = req.Header.Get("Call-ID")
		}
		return req.Header.Get("Call-ID") == first
	}
}

// #563: the refresh and unsubscribe steps judge their own subscription,
// the second the run makes, by the NOTIFY each SUBSCRIBE brings: a refresh
// must leave it active (RFC 6665 §4.2.1.2), an unsubscribe end it
// (§4.2.1.4).
func TestARefreshOrUnsubscribeTheNotifierMisreadsFailsItsStep(t *testing.T) {
	for name, tc := range map[string]struct {
		cseq, state, step, err string
	}{
		"refresh ended":    {"2 NOTIFY", "terminated;reason=timeout", "refresh", "the subscription is not active after its refresh"},
		"unsubscribe kept": {"3 NOTIFY", "active;expires=600000", "unsubscribe", "the subscription did not end at its unsubscribe"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, core := sipStack(t)
			var mu sync.Mutex
			var callIDs []string
			core.Rewrite = func(req *sip.Request) {
				if req.Method != "NOTIFY" {
					return
				}
				mu.Lock()
				id := req.Header.Get("Call-ID")
				if !slices.Contains(callIDs, id) {
					callIDs = append(callIDs, id)
				}
				second := len(callIDs) > 1 && callIDs[1] == id
				mu.Unlock()
				if second && req.Header.Get("CSeq") == tc.cseq {
					_ = req.Header.Set("Subscription-State", tc.state)
				}
			}
			ok, results := runAll(t, cfg, "reg-event")
			last := results[len(results)-1]
			if ok || last.Step != tc.step || last.Error != tc.err || last.Detail["status"] != 200 {
				t.Fatalf("results %+v", results)
			}
		})
	}
}
