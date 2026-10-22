package scenario_test

import (
	"bytes"
	"context"
	"github.com/jeonghun-app/rcs-platform/internal/content"
	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/sdp"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/anchor"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/chat"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/scenario"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/simtest"
)

// chatAnchor plays pcscf's MSRP anchoring and rcs-as's end of each leg in
// the in-process stack, for chats over SIP: the core stand-in forwards the
// client's INVITE to the peer itself, with no rcs-as, so the anchor gives
// each client a binding of its own at msrp-relay, and a leg of its own on a
// core stand-in that sends what it receives on the other leg, as rcs-as, a
// B2BUA, does. Each client then sees what it sees on the platform: an
// answer or offer naming the relay's client_path, which it connects to
// (ADR 0004), and its message reported by the network. A BYE releases both
// bindings, as pcscf does, unless keep is set.
type chatAnchor struct {
	t    *testing.T
	ctrl *anchor.Control
	core *chat.Core
	// keep leaves the bindings at the BYE. answerSetup and offerSetup, if
	// set, are the a=setup the client gets in the answer and the peer in
	// the offer, instead of passive and actpass; answerElsewhere and
	// offerElsewhere put a path of the core stand-in there instead of the
	// relay's client_path, reachable but past the relay, as a P-CSCF that
	// did not anchor passes rcs-as's on (code review on #553).
	keep                            bool
	answerSetup, offerSetup         sdp.Setup
	answerElsewhere, offerElsewhere bool
	// answerOffline has the core answer the client's INVITE to the peer
	// unregistered itself, and send what the client sends there on the
	// peer's earlier chat, as a network that keeps no message and uses a
	// chat the peer should have ended would (code review on #559).
	answerOffline bool
	// toPeer and toClient are what the forwarders do wrong on the way to
	// the peer and to the client.
	toPeer, toClient faults

	mu    sync.Mutex
	calls map[string]*anchoredCall // by Call-ID
	// toPeerLeg is the core leg toward the peer of the latest chat.
	toPeerLeg *msrp.Session
}

// faults are what a forwarder does wrong with what it sends on: it loses
// the notifications (dropNotifications), changes each message's text from
// one to another (change), writes another CPIM From in each message (from)
// or another recipient in each notification (recipient), or sends first, once,
// a message an earlier run left (leftover): with another Message-ID and,
// for "same token", this run's text. With cutOver it cuts what it sends to
// that many octets when it is longer: a large message arrives short. With
// dropNotificationsAfter it passes that many notifications on and loses
// the rest, and with failReportOver it sends a message longer than that
// on but reports its delivery failed.
type faults struct {
	dropNotifications      bool
	change                 [2]string
	from, recipient        string
	leftover               string
	cutOver                int
	dropNotificationsAfter int
	failReportOver         int
}

type anchoredCall struct {
	caller, callee anchor.Binding
	callerCore     msrp.URI
}

// anchorChats has core anchor every chat INVITE it forwards at the relay
// of cfg.Control, with its rcs-as legs on cfg's stand-in listener.
func anchorChats(t *testing.T, cfg scenario.Config, core *simtest.IMSCore) *chatAnchor {
	t.Helper()
	ln, err := cfg.CoreListener()
	if err != nil {
		t.Fatal(err)
	}
	a := &chatAnchor{t: t, ctrl: cfg.Control, core: chat.ServeCore(ln, "", cfg.MSRP), calls: map[string]*anchoredCall{}}
	t.Cleanup(func() { _ = a.core.Close() })
	// Forwarding may hold the request, as the relay calls do; the answer's
	// rewrite must not, so its one call goes on a goroutine of its own.
	core.Forwarding = a.forwarding
	core.RewriteResponse = a.answered
	core.AnswerOffline = a.offline
	return a
}

// offline answers the client's INVITE to the peer unregistered, with
// answerOffline: the client's binding as forwarding allocates it, and a
// core leg that sends on the peer's earlier chat.
func (a *chatAnchor) offline(req *sip.Request) []byte {
	if !a.answerOffline {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, m, err := msrpMedia(req.Body)
	if err != nil {
		return nil
	}
	path, err := mediaPath(m)
	if err != nil {
		return nil
	}
	callerCore, err := a.core.NewURI(nil)
	if err != nil {
		a.t.Error(err)
		return nil
	}
	caller, err := a.ctrl.Allocate(ctx, anchor.Paths{Client: path}, 10*time.Minute)
	if err != nil {
		a.t.Error(err)
		return nil
	}
	a.mu.Lock()
	leg := &forwarder{f: &a.toPeer, to: a.toPeerLeg}
	a.mu.Unlock()
	if _, err := a.core.Expect(callerCore, caller.CoreLocal, leg); err != nil {
		a.t.Error(err)
		return nil
	}
	if err := a.ctrl.Complete(ctx, caller.ID, anchor.Paths{Core: callerCore}, 0); err != nil {
		a.t.Error(err)
		return nil
	}
	if err := setMedia(s, m, caller.ClientPath, sdp.SetupPassive); err != nil {
		a.t.Error(err)
		return nil
	}
	body, err := s.Marshal()
	if err != nil {
		a.t.Error(err)
		return nil
	}
	return body
}

func (a *chatAnchor) forwarding(req *sip.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	to, _ := req.Header.To()
	callID := req.Header.Get("Call-ID")
	switch {
	case req.Method == "INVITE" && to.Tag() == "":
		s, m, err := msrpMedia(req.Body)
		if err != nil {
			return
		}
		path, err := mediaPath(m)
		if err != nil {
			return
		}
		// The caller's side: pcscf allocates with the client's path and
		// gives the relay rcs-as's (ADR 0004, the client originates).
		callerCore, err := a.core.NewURI(nil)
		if err != nil {
			a.t.Error(err)
			return
		}
		caller, err := a.ctrl.Allocate(ctx, anchor.Paths{Client: path}, 10*time.Minute)
		if err != nil {
			a.t.Error(err)
			return
		}
		// The callee's: rcs-as offers, so pcscf allocates with rcs-as's
		// path and gives the client the relay's (rcs-as originates).
		calleeCore, err := a.core.NewURI(nil)
		if err != nil {
			a.t.Error(err)
			return
		}
		callee, err := a.ctrl.Allocate(ctx, anchor.Paths{Core: calleeCore}, 10*time.Minute)
		if err != nil {
			a.t.Error(err)
			return
		}
		in, out := &forwarder{f: &a.toPeer}, &forwarder{f: &a.toClient}
		inbound, err := a.core.Expect(callerCore, caller.CoreLocal, in)
		if err != nil {
			a.t.Error(err)
			return
		}
		outbound, err := a.core.Expect(calleeCore, callee.CoreLocal, out)
		if err != nil {
			a.t.Error(err)
			return
		}
		in.to, out.to = outbound, inbound
		a.mu.Lock()
		a.toPeerLeg = outbound
		a.mu.Unlock()
		if err := a.ctrl.Complete(ctx, caller.ID, anchor.Paths{Core: callerCore}, 0); err != nil {
			a.t.Error(err)
			return
		}
		offerPath, offerSetup := callee.ClientPath, sdp.SetupActPass
		if a.offerElsewhere {
			offerPath = calleeCore
		}
		if a.offerSetup != "" {
			offerSetup = a.offerSetup
		}
		if err := setMedia(s, m, offerPath, offerSetup); err != nil {
			a.t.Error(err)
			return
		}
		if req.Body, err = s.Marshal(); err != nil {
			a.t.Error(err)
			return
		}
		a.mu.Lock()
		a.calls[callID] = &anchoredCall{caller: caller, callee: callee, callerCore: callerCore}
		a.mu.Unlock()
	case req.Method == "BYE" && !a.keep:
		a.mu.Lock()
		c := a.calls[callID]
		delete(a.calls, callID)
		a.mu.Unlock()
		if c != nil {
			_ = a.ctrl.Release(ctx, c.caller.ID)
			_ = a.ctrl.Release(ctx, c.callee.ID)
		}
	}
}

// answered gives the caller the relay's client_path in the callee's 2xx,
// and the relay the callee's path.
func (a *chatAnchor) answered(req *sip.Request, res *sip.Response) {
	if req.Method != "INVITE" || res.StatusCode < 200 || res.StatusCode >= 300 {
		return
	}
	a.mu.Lock()
	c := a.calls[req.Header.Get("Call-ID")]
	a.mu.Unlock()
	if c == nil {
		return
	}
	s, m, err := msrpMedia(res.Body)
	if err != nil {
		return
	}
	path, err := mediaPath(m)
	if err != nil {
		return
	}
	setup := sdp.SetupPassive
	if a.answerSetup != "" {
		setup = a.answerSetup
	}
	answerPath := c.caller.ClientPath
	if a.answerElsewhere {
		// The caller's core leg: a passive MSRP end that takes a client's
		// connection, as rcs-as's does.
		answerPath = c.callerCore
	}
	if err := setMedia(s, m, answerPath, setup); err != nil {
		a.t.Error(err)
		return
	}
	if res.Body, err = s.Marshal(); err != nil {
		a.t.Error(err)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// Not reported: a scenario that has ended released the binding
		// already, and one that goes on needs the path, without which the
		// peer is never bound and its step fails.
		_ = a.ctrl.Complete(ctx, c.callee.ID, anchor.Paths{Client: path}, 0)
	}()
}

// forwarder is one of the core stand-in's legs: what it receives is sent on
// the other leg, to, once that is bound, and acknowledged here, as rcs-as
// takes a message and delivers it in a session of its own.
type forwarder struct {
	f  *faults
	to *msrp.Session

	mu       sync.Mutex
	leftOver bool // the leftover has gone
	notes    int  // notifications seen
}

func (f *forwarder) HandleMessage(_ *msrp.Session, m *msrp.Message) error {
	body, contentType := m.Body.Bytes(), m.MediaType()
	notification := bytes.Contains(body, []byte(imdn.ContentType))
	if f.f.dropNotifications && notification {
		return nil
	}
	if n := f.f.dropNotificationsAfter; n > 0 && notification {
		f.mu.Lock()
		f.notes++
		drop := f.notes > n
		f.mu.Unlock()
		if drop {
			return nil
		}
	}
	// Sent on, but its success report fails (a REPORT with the error,
	// the transaction itself answered 200).
	var reportErr error
	if n := f.f.failReportOver; n > 0 && len(body) > n {
		reportErr = &msrp.StatusError{Code: msrp.StatusForbidden}
	}
	if f.f.change[0] != "" {
		body = bytes.ReplaceAll(body, []byte(f.f.change[0]), []byte(f.f.change[1]))
	}
	if n := f.f.cutOver; n > 0 && len(body) > n {
		body = body[:n]
	}
	if f.f.recipient != "" && notification {
		body = recipientRe.ReplaceAll(body, []byte("<recipient-uri>"+f.f.recipient+"</recipient-uri>"))
	}
	var first []byte
	if !notification {
		if f.f.from != "" {
			body = rewritten(body, func(h *cpim.Header) {
				if h.Name == cpim.HeaderFrom {
					h.Value = "<" + f.f.from + ">"
				}
			}, nil)
		}
		f.mu.Lock()
		if f.f.leftover != "" && !f.leftOver {
			f.leftOver = true
			var text []byte
			if f.f.leftover != "same token" {
				text = []byte("from an earlier run")
			}
			first = rewritten(body, func(h *cpim.Header) {
				if strings.HasSuffix(h.Name, "."+imdn.HeaderMessageID) {
					h.Value = "leftover0123456789"
				}
			}, text)
		}
		f.mu.Unlock()
	}
	// In order: a leftover is one the network had stored before this.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if first != nil {
			_, _ = f.to.Send(ctx, msrp.Outgoing{ContentType: contentType, Body: msrp.BodyOf(first), SuccessReport: true})
		}
		_, _ = f.to.Send(ctx, msrp.Outgoing{ContentType: contentType, Body: msrp.BodyOf(body), SuccessReport: true})
	}()
	return reportErr
}

var recipientRe = regexp.MustCompile(`<recipient-uri>[^<]*</recipient-uri>`)

// rewritten is the CPIM message body with edit applied to each of its
// headers, and its content text instead if that is not nil; body as it is
// if it does not parse.
func rewritten(body []byte, edit func(*cpim.Header), text []byte) []byte {
	c, err := cpim.Parse(body)
	if err != nil {
		return body
	}
	for i := range c.Headers {
		edit(&c.Headers[i])
	}
	if text != nil {
		c.Body = content.BodyOf(text)
	}
	out, err := c.Marshal()
	if err != nil {
		return body
	}
	return out
}

func (f *forwarder) HandleReport(*msrp.Session, msrp.Report) {}

func msrpMedia(body []byte) (*sdp.Session, *sdp.Media, error) {
	s, err := sdp.Parse(body)
	if err != nil {
		return nil, nil, err
	}
	for i := range s.Media {
		if s.Media[i].IsMSRP() {
			return s, &s.Media[i], nil
		}
	}
	return nil, nil, sdp.ErrNoAttribute
}

func mediaPath(m *sdp.Media) (msrp.URI, error) {
	p, err := m.Path()
	if err != nil {
		return msrp.URI{}, err
	}
	return msrp.ParseURI(p[len(p)-1])
}

func setMedia(s *sdp.Session, m *sdp.Media, path msrp.URI, setup sdp.Setup) error {
	if err := m.SetPath([]string{path.String()}); err != nil {
		return err
	}
	_ = s
	return m.SetSetup(setup)
}

func TestAChatOverSIPCarriesAMessageEachWayAndItsBYEReleasesIt(t *testing.T) {
	cfg, core := sipStack(t)
	anchorChats(t, cfg, core)
	ok, results := runAll(t, cfg, "chat-invite")
	if !ok {
		t.Fatalf("results %+v", results)
	}
	steps := byStep(results)
	for _, s := range []string{"register", "invite", "connect", "client-to-peer", "peer-to-client", "chunked-message", "bye", "released", "peer-offline", "clean"} {
		if !steps[s].OK {
			t.Fatalf("%s: %+v", s, steps[s])
		}
	}
	if steps["invite"].Detail["status"] != 200 || steps["client-to-peer"].Detail["skipped"] != 0 {
		t.Fatalf("invite %+v, client-to-peer %+v", steps["invite"], steps["client-to-peer"])
	}
	// Chunked: well over internal/msrp's 2 KiB chunks.
	if steps["chunked-message"].Detail["bytes"] < 100<<10 {
		t.Fatalf("chunked-message %+v", steps["chunked-message"])
	}
	// The stand-in core stores nothing for an unregistered peer: 480.
	if d := steps["peer-offline"].Detail; d["status"] != 480 || d["stored"] != 0 {
		t.Fatalf("peer-offline %+v", steps["peer-offline"])
	}
	if core.Registered(self.URI) || core.Registered(peer.URI) {
		t.Fatal("a binding outlived the scenario")
	}
}

func TestAChatAnsweredActiveFailsItsInvite(t *testing.T) {
	// The client is behind NAT and must connect (RFC 6135 §4.2.2): an
	// answer that has it wait for the network to connect fails the step.
	cfg, core := sipStack(t)
	anchorChats(t, cfg, core).answerSetup = sdp.SetupActive
	ok, results := runAll(t, cfg, "chat-invite")
	last := results[len(results)-1]
	if ok || last.Step != "invite" || !strings.Contains(last.Error, "want passive") {
		t.Fatalf("results %+v", results)
	}
}

func TestAChatWhoseBindingOutlivesItsBYEFailsReleased(t *testing.T) {
	// The relay still binds the session after the BYE: the released step
	// binds again until its timeout and fails.
	cfg, core := sipStack(t)
	cfg.StepTimeout = 3 * time.Second
	anchorChats(t, cfg, core).keep = true
	ok, results := runAll(t, cfg, "chat-invite")
	steps := byStep(results)
	if ok || steps["released"].OK || steps["released"].Error != "the relay still binds the session after the BYE" || steps["released"].Detail["binds"] < 2 {
		t.Fatalf("results %+v", results)
	}
}

func TestAChatThatLosesItsNotificationsFailsTheMessageStep(t *testing.T) {
	cfg, core := sipStack(t)
	cfg.StepTimeout = 3 * time.Second
	anchorChats(t, cfg, core).toClient.dropNotifications = true
	ok, results := runAll(t, cfg, "chat-invite")
	last := results[len(results)-1]
	if ok || last.Step != "client-to-peer" || last.Error != "2 notifications did not arrive" {
		t.Fatalf("results %+v", results)
	}
}

func TestAChatThatChangesTheTextFailsTheMessageStep(t *testing.T) {
	// The CPIM body is changed on the way, its Message-ID kept: the peer
	// gets the message, but not what was sent.
	cfg, core := sipStack(t)
	anchorChats(t, cfg, core).toPeer.change = [2]string{"hello over SIP", "hello over SIQ"}
	ok, results := runAll(t, cfg, "chat-invite")
	last := results[len(results)-1]
	if ok || last.Step != "client-to-peer" || last.Error != "the message arrived changed" {
		t.Fatalf("results %+v", results)
	}
}

// Code review on #553: what the network does wrong, each way, fails the
// step that sees it. The relay's own path must be what each client gets; a
// reachable end that is not it, as a P-CSCF that did not anchor passes on,
// fails.
func TestAChatTheNetworkGetsWrongFailsTheStepThatSeesIt(t *testing.T) {
	for name, tc := range map[string]struct {
		fault       func(*chatAnchor)
		step, err   string
		stepTimeout time.Duration
	}{
		"the answer's path past the relay": {func(a *chatAnchor) { a.answerElsewhere = true },
			"invite", "the answer's a=path is not msrp-relay's client_path (ADR 0004)", 0},
		// The stand-in core passes the INVITE on to the peer, so the
		// peer's refusal is the INVITE's answer; through rcs-as it comes
		// at client-to-peer.
		"the peer's offer past the relay": {func(a *chatAnchor) { a.offerElsewhere = true },
			"invite", "the network's offer to the peer has an a=path that is not msrp-relay's client_path (ADR 0004)", 0},
		"a passive offer to the peer": {func(a *chatAnchor) { a.offerSetup = sdp.SetupPassive },
			"invite", "the network's offer to the peer has a=setup:passive, not actpass (RFC 6135 §4.2.2)", 0},
		"another sender to the peer": {func(a *chatAnchor) { a.toPeer.from = "sip:+15550100003@" + imsDomain },
			"client-to-peer", "the message arrived changed", 0},
		"another sender to the client": {func(a *chatAnchor) { a.toClient.from = "sip:+15550100003@" + imsDomain },
			"peer-to-client", "the message arrived changed", 0},
		"the text changed to the client": {func(a *chatAnchor) { a.toClient.change = [2]string{"hello over SIP", "hello over SIQ"} },
			"peer-to-client", "the message arrived changed", 0},
		"the notifications lost to the peer": {func(a *chatAnchor) { a.toPeer.dropNotifications = true },
			"peer-to-client", "2 notifications did not arrive", 3 * time.Second},
		// Whichever of the two comes first.
		"a notification from another to the client": {func(a *chatAnchor) { a.toClient.recipient = "sip:+15550100003@" + imsDomain },
			"client-to-peer", " notification from someone the message was not sent to", 0},
		"an earlier run's message with this run's text": {func(a *chatAnchor) { a.toPeer.leftover = "same token" },
			"client-to-peer", "the message received is not the one sent", 0},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, core := sipStack(t)
			if tc.stepTimeout > 0 {
				cfg.StepTimeout = tc.stepTimeout
			}
			tc.fault(anchorChats(t, cfg, core))
			ok, results := runAll(t, cfg, "chat-invite")
			last := results[len(results)-1]
			if ok || last.Step != tc.step || !strings.HasSuffix(last.Error, tc.err) {
				t.Fatalf("results %+v", results)
			}
		})
	}
}

// An earlier run's message, another Message-ID and without this run's
// token, is skipped and counted, and the run passes; each way.
func TestAChatSkipsWhatAnEarlierRunLeft(t *testing.T) {
	cfg, core := sipStack(t)
	a := anchorChats(t, cfg, core)
	a.toPeer.leftover, a.toClient.leftover = "earlier", "earlier"
	ok, results := runAll(t, cfg, "chat-invite")
	if !ok {
		t.Fatalf("results %+v", results)
	}
	steps := byStep(results)
	if steps["client-to-peer"].Detail["skipped"] != 1 || steps["peer-to-client"].Detail["skipped"] != 1 {
		t.Fatalf("client-to-peer %+v, peer-to-client %+v", steps["client-to-peer"], steps["peer-to-client"])
	}
}

func TestAChatWithoutTheRelaysAddressFailsAtOnce(t *testing.T) {
	cfg, _ := sipStack(t)
	cfg.RelayPublic = ""
	ok, results := runAll(t, cfg, "chat-invite")
	if last := results[len(results)-1]; ok || last.Step != "register" || last.Error != "no relay address configured (-relay-public)" {
		t.Fatalf("results %+v", results)
	}
}

func TestAChatThatCutsALargeMessageFailsTheChunkedStep(t *testing.T) {
	// The short messages pass; the large one arrives cut, its CPIM
	// headers whole, and the step says it changed.
	cfg, core := sipStack(t)
	anchorChats(t, cfg, core).toPeer.cutOver = 64 << 10
	ok, results := runAll(t, cfg, "chat-invite")
	last := results[len(results)-1]
	if ok || last.Step != "chunked-message" || last.Error != "the message arrived changed" {
		t.Fatalf("results %+v", results)
	}
}

// Code review on #559: the chunked and peer-offline steps fail what they
// exist to see.
func TestAChatsChunkedAndOfflineStepsFailWhatTheyCheck(t *testing.T) {
	for name, tc := range map[string]struct {
		fault func(*chatAnchor, *simtest.IMSCore)
		step  string
		err   string
	}{
		// The first two notifications, client-to-peer's, pass; the large
		// message's are lost.
		"the large message's notifications lost": {func(a *chatAnchor, _ *simtest.IMSCore) { a.toClient.dropNotificationsAfter = 2 },
			"chunked-message", "2 notifications did not arrive"},
		"the large message's delivery reported failed": {func(a *chatAnchor, _ *simtest.IMSCore) { a.toPeer.failReportOver = 64 << 10 },
			"chunked-message", "delivery failed with 403"},
		// A refusal other than 480 for the peer unregistered.
		"the offline chat refused 404": {func(_ *chatAnchor, c *simtest.IMSCore) { c.Offline = simtest.RefuseNotFound },
			"peer-offline", "INVITE to the unregistered peer answered 404, want 480 or store-and-forward"},
		// Taken, kept nowhere, and sent on the peer's earlier chat, which
		// the peer has ended: the message never comes.
		"the offline chat sent on the peer's earlier chat": {func(a *chatAnchor, _ *simtest.IMSCore) { a.answerOffline = true },
			"peer-offline", "the message to the unregistered peer never arrived after it registered again"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, core := sipStack(t)
			cfg.StepTimeout = 3 * time.Second
			tc.fault(anchorChats(t, cfg, core), core)
			ok, results := runAll(t, cfg, "chat-invite")
			last := results[len(results)-1]
			if ok || last.Step != tc.step || !strings.HasPrefix(last.Error, tc.err) {
				t.Fatalf("results %+v", results)
			}
		})
	}
}
