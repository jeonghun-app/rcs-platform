package scenario_test

import (
	"bytes"
	"context"
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
	// keep leaves the bindings at the BYE; answerSetup, if set, is the
	// a=setup the client gets in the answer instead of passive; the
	// forwarders lose the notifications with dropNotifications, and change
	// every message's text from one to another with change.
	keep              bool
	answerSetup       sdp.Setup
	dropNotifications bool
	change            [2]string
	// cutOver, if set, cuts what the forwarders send to that many octets
	// when it is longer: a large message arrives short.
	cutOver int

	mu    sync.Mutex
	calls map[string]*anchoredCall // by Call-ID
}

type anchoredCall struct {
	caller, callee anchor.Binding
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
	return a
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
		in, out := &forwarder{a: a}, &forwarder{a: a}
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
		if err := a.ctrl.Complete(ctx, caller.ID, anchor.Paths{Core: callerCore}, 0); err != nil {
			a.t.Error(err)
			return
		}
		if err := setMedia(s, m, callee.ClientPath, sdp.SetupActPass); err != nil {
			a.t.Error(err)
			return
		}
		if req.Body, err = s.Marshal(); err != nil {
			a.t.Error(err)
			return
		}
		a.mu.Lock()
		a.calls[callID] = &anchoredCall{caller: caller, callee: callee}
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
	if err := setMedia(s, m, c.caller.ClientPath, setup); err != nil {
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
	a  *chatAnchor
	to *msrp.Session
}

func (f *forwarder) HandleMessage(_ *msrp.Session, m *msrp.Message) error {
	body, contentType := m.Body.Bytes(), m.MediaType()
	if f.a.dropNotifications && bytes.Contains(body, []byte(imdn.ContentType)) {
		return nil
	}
	if f.a.change[0] != "" {
		body = bytes.ReplaceAll(body, []byte(f.a.change[0]), []byte(f.a.change[1]))
	}
	if n := f.a.cutOver; n > 0 && len(body) > n {
		body = body[:n]
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = f.to.Send(ctx, msrp.Outgoing{ContentType: contentType, Body: msrp.BodyOf(body), SuccessReport: true})
	}()
	return nil
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
	anchorChats(t, cfg, core).dropNotifications = true
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
	anchorChats(t, cfg, core).change = [2]string{"hello over SIP", "hello over SIQ"}
	ok, results := runAll(t, cfg, "chat-invite")
	last := results[len(results)-1]
	if ok || last.Step != "client-to-peer" || last.Error != "the message arrived changed" {
		t.Fatalf("results %+v", results)
	}
}

func TestAChatThatCutsALargeMessageFailsTheChunkedStep(t *testing.T) {
	// The short messages pass; the large one arrives cut, its CPIM
	// headers whole, and the step says it changed.
	cfg, core := sipStack(t)
	anchorChats(t, cfg, core).cutOver = 64 << 10
	ok, results := runAll(t, cfg, "chat-invite")
	last := results[len(results)-1]
	if ok || last.Step != "chunked-message" || last.Error != "the message arrived changed" {
		t.Fatalf("results %+v", results)
	}
}
