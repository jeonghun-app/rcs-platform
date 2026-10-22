package scenario_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/conference"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/sdp"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/anchor"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/chat"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/scenario"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/simtest"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/sipua"
)

// otherConference is a conference URI the stand-in focus may name in a 200
// for another group than the client's (code review on #602).
const otherConference = "sip:+15550100004@" + imsDomain

// rejoinAnswer is how the stand-in focus answers a rejoin once its owner
// is lost: status 200 sets the session up; another is a refusal, with
// Retry-After when retry is set.
type rejoinAnswer struct {
	status int
	retry  bool
}

// groupFocus plays rcs-as's conference focus in the in-process stack for
// group-chat (#121 D4): a UA registered as the third test subscriber, which
// stands for both the factory and the group's conference URI. It answers
// the factory INVITE and each rejoin with a leg of its own through the
// relay, invites the peer, forwards each MSRP message from one leg to the
// other, serves the roster SUBSCRIBE with its NOTIFYs, and, at StopOwner,
// ends its sessions and the subscription as an owner that stops does (or
// nothing, as one that crashed), after which it invites the peer back for
// the client's next message, as the new owner does.
type groupFocus struct {
	t    *testing.T
	core *simtest.IMSCore
	ctrl *anchor.Control
	msrp *chat.Core
	ua   *sipua.UA
	cfg  scenario.Config

	// Faults: reinvite invites the peer again before every message from
	// the client, twiceAfterLoss twice when the owner is lost;
	// otherConference answers the first rejoin with another
	// group's conference URI; endReason, when set, ends the subscription at
	// the stop with that reason instead of deactivated; afterLoss answers
	// the rejoins once the owner is lost, in turn (default: 500 with
	// Retry-After, then 200); crash ends nothing at the stop.
	reinvite        bool
	twiceAfterLoss  bool
	otherConference bool
	endReason       string
	afterLoss       []rejoinAnswer
	crash           bool

	mu          sync.Mutex
	clientLeg   *msrp.Session
	peerLeg     *msrp.Session
	peerReady   chan struct{} // closed once peerLeg is up
	clientCall  *sipua.Dialog
	peerCall    *sipua.Dialog
	lost        bool
	rejoins     int
	answers     map[string]response // by Call-ID, for the core's rewrite
	sub         *rosterSub
	version     uint32
	inviting    bool
	peerInvites int
}

// response is what the core's rewrite puts in the focus's answer: its
// Contact's URI for a 2xx, Retry-After for a refusal.
type response struct {
	contact string
	retry   bool
}

// rosterSub is the client's roster subscription the focus serves.
type rosterSub struct {
	req  *sip.Request
	tag  string
	cseq int
}

func serveGroups(t *testing.T, cfg *scenario.Config, core *simtest.IMSCore) *groupFocus {
	t.Helper()
	ln, err := cfg.CoreListener()
	if err != nil {
		t.Fatal(err)
	}
	f := &groupFocus{t: t, core: core, ctrl: cfg.Control, msrp: chat.ServeCore(ln, "", cfg.MSRP), cfg: *cfg,
		answers: map[string]response{}, peerReady: make(chan struct{})}
	t.Cleanup(func() { _ = f.msrp.Close() })
	creds, err := sipua.DigestCredentials(thirdIMPI, []byte(thirdToken))
	if err != nil {
		t.Fatal(err)
	}
	u, err := sip.ParseURI(thirdIMPU)
	if err != nil {
		t.Fatal(err)
	}
	f.ua, err = sipua.Dial(context.Background(), sipua.Config{
		Network: transport.TCP, Proxy: core.Addr, Domain: imsDomain, IMPU: u,
		InstanceID: "urn:uuid:00000000-0000-4000-8000-000000000003", Credentials: creds,
		OnInvite: func(c *sipua.IncomingCall) { go f.invited(c) }, OnRequest: f.request,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.ua.Close() })
	if _, err := f.ua.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	core.RewriteResponse = f.rewrite
	// The focus takes the recipient list, as rcs-as does; sipua's UAS,
	// which plays it, would answer 420 to the Require that asks for it.
	core.Rewrite = func(req *sip.Request) {
		if req.Method == "INVITE" && strings.EqualFold(req.Header.Get("Require"), "recipient-list-invite") {
			req.Header.Del("Require")
		}
	}
	cfg.ConferenceFactory = u
	cfg.StopOwner = f.stopOwner
	return f
}

// rewrite gives the focus's answers what rcs-as's carry: a Contact that is
// the conference URI, marked isfocus, and Retry-After on a refusal to try
// again.
func (f *groupFocus) rewrite(req *sip.Request, res *sip.Response) {
	if req.Method != "INVITE" || req.URI.User != "+15550100003" {
		return
	}
	f.mu.Lock()
	a, ok := f.answers[req.Header.Get("Call-ID")]
	f.mu.Unlock()
	if !ok {
		return
	}
	switch {
	case res.StatusCode >= 200 && res.StatusCode < 300:
		res.Header.Del("Contact")
		_ = res.Header.Add("Contact", "<"+a.contact+";transport=tcp>;isfocus;+g.oma.sip-im")
	case a.retry:
		_ = res.Header.Add("Retry-After", "1")
	}
}

// invited answers an INVITE to the focus: the factory's, which makes the
// group, or a rejoin.
func (f *groupFocus) invited(c *sipua.IncomingCall) {
	req := c.Request()
	callID := req.Header.Get("Call-ID")
	f.mu.Lock()
	rejoin := !strings.HasPrefix(req.Header.Get("Content-Type"), "multipart/mixed")
	answer := rejoinAnswer{status: 200}
	contact := thirdIMPU
	switch {
	case rejoin && f.lost:
		queue := f.afterLoss
		if queue == nil {
			queue = []rejoinAnswer{{status: 500, retry: true}, {status: 200}}
		}
		if f.rejoins < len(queue) {
			answer = queue[f.rejoins]
		}
		f.rejoins++
	case rejoin && f.otherConference:
		f.otherConference = false
		contact = otherConference
	}
	f.answers[callID] = response{contact: contact, retry: answer.retry}
	f.mu.Unlock()
	if answer.status != 200 {
		_ = c.Reject(answer.status)
		return
	}
	clientPath, err := offeredPath(req)
	if err != nil {
		_ = c.Reject(488)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, s, err := f.leg(ctx, anchor.Paths{Client: clientPath}, false)
	if err != nil {
		_ = c.Reject(500)
		return
	}
	d, err := c.Accept(focusSDP(f.t, b.ClientPath, sdp.SetupPassive))
	if err != nil {
		return
	}
	f.mu.Lock()
	f.clientLeg, f.clientCall = s, d
	invite := !rejoin
	f.mu.Unlock()
	if invite {
		// Once the creator's session is up, the focus invites the peer.
		f.invitePeer()
	}
}

// leg allocates a relay binding for a leg of the focus, with its own MSRP
// session on the core stand-in: for the client's INVITE, the client's
// path known (paths.Client); for the peer's, rcs-as's offer.
func (f *groupFocus) leg(ctx context.Context, paths anchor.Paths, peer bool) (anchor.Binding, *msrp.Session, error) {
	local, err := f.msrp.NewURI(nil)
	if err != nil {
		return anchor.Binding{}, nil, err
	}
	if paths.Client.Host == "" {
		paths.Core = local
	}
	b, err := f.ctrl.Allocate(ctx, paths, 10*time.Minute)
	if err != nil {
		return anchor.Binding{}, nil, err
	}
	s, err := f.msrp.Expect(local, b.CoreLocal, &focusLeg{f: f, fromPeer: peer})
	if err != nil {
		return anchor.Binding{}, nil, err
	}
	if !peer {
		if err := f.ctrl.Complete(ctx, b.ID, anchor.Paths{Core: local}, 0); err != nil {
			return anchor.Binding{}, nil, err
		}
	}
	return b, s, nil
}

// invitePeer has the focus invite the peer, and keeps the session it
// answers as the peer's leg.
func (f *groupFocus) invitePeer() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, s, err := f.leg(ctx, anchor.Paths{}, true)
	if err != nil {
		f.t.Error(err)
		return
	}
	u, _ := sip.ParseURI(peer.URI)
	req, err := f.ua.NewInvite(u, focusSDP(f.t, b.ClientPath, sdp.SetupActPass))
	if err != nil {
		f.t.Error(err)
		return
	}
	f.mu.Lock()
	f.peerInvites++
	f.mu.Unlock()
	d, res, err := f.ua.Invite(ctx, req, nil)
	if err != nil || d == nil {
		return
	}
	s2, m, err := msrpMedia(res.Body)
	if err != nil {
		return
	}
	_ = s2
	path, err := mediaPath(m)
	if err != nil {
		return
	}
	if err := f.ctrl.Complete(ctx, b.ID, anchor.Paths{Client: path}, 0); err != nil {
		return
	}
	f.mu.Lock()
	f.peerLeg, f.peerCall = s, d
	select {
	case <-f.peerReady: // a second invitation, as twiceAfterLoss sends
	default:
		close(f.peerReady)
	}
	f.mu.Unlock()
}

// focusLeg forwards what one of the focus's legs receives to the other, as
// rcs-as fans a message out to the group and passes notifications back.
type focusLeg struct {
	f        *groupFocus
	fromPeer bool
}

func (l *focusLeg) HandleMessage(_ *msrp.Session, m *msrp.Message) error {
	body, contentType := m.Body.Bytes(), m.MediaType()
	notification := bytes.Contains(body, []byte(imdn.ContentType))
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		f := l.f
		if l.fromPeer {
			f.mu.Lock()
			to := f.clientLeg
			f.mu.Unlock()
			if to != nil {
				_, _ = to.Send(ctx, msrp.Outgoing{ContentType: contentType, Body: msrp.BodyOf(body), SuccessReport: true})
			}
			return
		}
		if !notification {
			f.mu.Lock()
			again := f.reinvite || f.peerLeg == nil && !f.inviting
			if again {
				f.inviting = true
				f.peerLeg, f.peerReady = nil, make(chan struct{})
			}
			f.mu.Unlock()
			if again {
				if f.twiceAfterLoss && f.lost {
					f.invitePeer()
				}
				f.invitePeer()
				f.mu.Lock()
				f.inviting = false
				f.mu.Unlock()
			}
		}
		f.mu.Lock()
		ready := f.peerReady
		f.mu.Unlock()
		select {
		case <-ready:
		case <-ctx.Done():
			return
		}
		f.mu.Lock()
		to := f.peerLeg
		f.mu.Unlock()
		_, _ = to.Send(ctx, msrp.Outgoing{ContentType: contentType, Body: msrp.BodyOf(body), SuccessReport: true})
	}()
	return nil
}

func (l *focusLeg) HandleReport(*msrp.Session, msrp.Report) {}

// request serves the roster SUBSCRIBE (RFC 4575): 200, then a NOTIFY with
// the full roster, both participants connected.
func (f *groupFocus) request(tx *transaction.ServerTransaction) {
	req := tx.Request()
	if req.Method != "SUBSCRIBE" {
		if res, err := sip.NewResponse(req, 405, "", "f1"); err == nil {
			_ = tx.Respond(res)
		}
		return
	}
	tag := "focus" + strconv.Itoa(int(time.Now().UnixNano()%1e6))
	res, err := sip.NewResponse(req, 200, "", tag)
	if err != nil {
		return
	}
	_ = res.Header.Add("Contact", "<"+thirdIMPU+";transport=tcp>")
	_ = res.Header.Add("Expires", "60")
	_ = tx.Respond(res)
	f.mu.Lock()
	f.sub = &rosterSub{req: req.Clone(), tag: tag}
	f.version++
	v := f.version
	f.mu.Unlock()
	go f.notify("active;expires=60", f.roster(v))
}

// roster is the full roster at version v, both participants connected.
func (f *groupFocus) roster(v uint32) []byte {
	info := &conference.Info{Entity: thirdIMPU, State: conference.Full, Version: v,
		Description: &conference.Description{Subject: "rcs-sim group"}, Users: &conference.Users{State: conference.Full}}
	for _, who := range []string{self.URI, peer.URI} {
		info.Users.List = append(info.Users.List, conference.User{Entity: who, State: conference.Full,
			Endpoints: []conference.Endpoint{{Entity: who, State: conference.Full, Status: conference.Connected}}})
	}
	b, err := info.Marshal()
	if err != nil {
		f.t.Error(err)
	}
	return b
}

// notify sends a NOTIFY in the client's roster subscription.
func (f *groupFocus) notify(state string, body []byte) {
	f.mu.Lock()
	s := f.sub
	if s == nil {
		f.mu.Unlock()
		return
	}
	s.cseq++
	cseq := s.cseq
	f.mu.Unlock()
	contacts, err := s.req.Header.Contact()
	if err != nil || len(contacts) == 0 {
		return
	}
	branch := make([]byte, 8)
	_, _ = io.ReadFull(rand.Reader, branch)
	req := &sip.Request{Method: "NOTIFY", URI: contacts[0].URI}
	for _, h := range [][2]string{
		{"Via", fmt.Sprintf("SIP/2.0/TCP focus.invalid;branch=z9hG4bK%x", branch)},
		{"Max-Forwards", "70"},
		{"From", s.req.Header.Get("To") + ";tag=" + s.tag},
		{"To", s.req.Header.Get("From")},
		{"Call-ID", s.req.Header.Get("Call-ID")},
		{"CSeq", strconv.Itoa(cseq) + " NOTIFY"},
		{"Contact", "<" + thirdIMPU + ";transport=tcp>"},
		{"Event", "conference"},
		{"Subscription-State", state},
	} {
		_ = req.Header.Add(h[0], h[1])
	}
	if len(body) > 0 {
		_ = req.Header.Add("Content-Type", conference.ContentType)
		req.Body = body
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = f.ua.Send(ctx, req)
}

// stopOwner is the scenario's StopOwner: the owner ends its sessions with a
// BYE and the roster subscription (deactivated, or endReason), unless it
// crashed; either way the next owner holds no session.
func (f *groupFocus) stopOwner(ctx context.Context, conf sip.URI) error {
	if conf.String() != thirdIMPU {
		return errors.New("asked to stop the owner of another group")
	}
	f.mu.Lock()
	f.lost = true
	calls := []*sipua.Dialog{f.clientCall, f.peerCall}
	f.clientLeg, f.peerLeg = nil, nil
	f.mu.Unlock()
	if f.crash {
		return nil
	}
	for _, d := range calls {
		if d != nil {
			_, _ = d.Bye(ctx)
		}
	}
	reason := f.endReason
	if reason == "" {
		reason = "deactivated"
	}
	f.notify("terminated;reason="+reason, nil)
	return nil
}

// offeredPath is the client's MSRP path in req's offer, its SDP or the SDP
// part of its multipart/mixed body.
func offeredPath(req *sip.Request) (msrp.URI, error) {
	body := req.Body
	if mt, params, err := mime.ParseMediaType(req.Header.Get("Content-Type")); err == nil && mt == "multipart/mixed" {
		r := multipart.NewReader(bytes.NewReader(req.Body), params["boundary"])
		for {
			p, err := r.NextPart()
			if err != nil {
				return msrp.URI{}, err
			}
			if strings.HasPrefix(p.Header.Get("Content-Type"), "application/sdp") {
				body, _ = io.ReadAll(p)
				break
			}
		}
	}
	_, m, err := msrpMedia(body)
	if err != nil {
		return msrp.URI{}, err
	}
	return mediaPath(m)
}

// focusSDP is a chat session description at path with setup.
func focusSDP(t *testing.T, path msrp.URI, setup sdp.Setup) []byte {
	s, err := sdp.Parse([]byte("v=0\r\no=- 1 1 IN IP4 192.0.2.3\r\ns=-\r\nc=IN IP4 192.0.2.3\r\nt=0 0\r\n" +
		"m=message 9 TCP/MSRP *\r\na=accept-types:message/cpim application/im-iscomposing+xml\r\n" +
		"a=accept-wrapped-types:text/plain message/imdn+xml\r\na=path:" + path.String() + "\r\na=setup:" + string(setup) + "\r\na=sendrecv\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// groupSteps are group-chat's steps, in order.
var groupSteps = []string{"register", "create", "invited", "message", "roster", "rejoin", "owner-stop", "owner-lost",
	"rejoin-after-loss", "roster-after-loss", "message-after-loss", "clean"}

func groupStack(t *testing.T) (scenario.Config, *groupFocus) {
	t.Helper()
	cfg, core := sipStack(t)
	cfg.GroupRejoins = 2
	return cfg, serveGroups(t, &cfg, core)
}

// #121 D4: group-chat against a focus that does what rcs-as does passes
// every step, the peer invited once at the start and once by the new owner.
func TestAGroupChatPassesAgainstAFocusThatServesIt(t *testing.T) {
	for _, crash := range []bool{false, true} {
		t.Run(fmt.Sprintf("crash=%v", crash), func(t *testing.T) {
			cfg, f := groupStack(t)
			cfg.OwnerCrash, f.crash = crash, crash
			ok, results := runAll(t, cfg, "group-chat")
			if !ok {
				t.Fatalf("results %+v", results)
			}
			steps := byStep(results)
			for _, s := range groupSteps {
				if !steps[s].OK {
					t.Fatalf("%s: %+v", s, steps[s])
				}
			}
			if steps["invited"].Detail["invites"] != 1 || steps["message"].Detail["invites"] != 0 ||
				steps["rejoin"].Detail["invites"] != 0 || steps["message-after-loss"].Detail["invites"] != 1 {
				t.Fatalf("invites: %+v", results)
			}
			if d := steps["rejoin-after-loss"].Detail; d["tries"] != 2 {
				t.Fatalf("rejoin-after-loss %+v", d)
			}
			if !crash && steps["owner-lost"].Detail["reason"] != 2 {
				t.Fatalf("owner-lost %+v", steps["owner-lost"])
			}
		})
	}
}

// Code review on #602: what a focus gets wrong fails the step that sees
// it, with a fixed text.
func TestAGroupChatTheFocusGetsWrongFailsTheStepThatSeesIt(t *testing.T) {
	for name, tc := range map[string]struct {
		fault     func(*groupFocus)
		step, err string
	}{
		// #121's fault: a task that does not hold the peer's session
		// invites it again for each message.
		"a re-invite for every message": {func(f *groupFocus) { f.reinvite = true },
			"message", "the focus invited the peer again, though its session with the group was open"},
		"the new owner invites the peer twice": {func(f *groupFocus) { f.twiceAfterLoss = true },
			"message-after-loss", "the new owner did not invite the peer back exactly once"},
		"a rejoin answered by another group": {func(f *groupFocus) { f.otherConference = true },
			"rejoin", "the rejoin was answered by another conference"},
		"the subscription ended noresource": {func(f *groupFocus) { f.endReason = "noresource" },
			"owner-lost", "the roster subscription ended for another reason than deactivated"},
		// A live group is never 404 (#121 D3): rcsjta takes it for the
		// group's end.
		"a 404 to the rejoin": {func(f *groupFocus) { f.afterLoss = []rejoinAnswer{{status: 404}} },
			"rejoin-after-loss", "the rejoin was answered 404"},
		"a 500 without Retry-After": {func(f *groupFocus) { f.afterLoss = []rejoinAnswer{{status: 500}} },
			"rejoin-after-loss", "a 500 without Retry-After"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, f := groupStack(t)
			tc.fault(f)
			ok, results := runAll(t, cfg, "group-chat")
			last := results[len(results)-1]
			if ok || last.Step != tc.step || last.Error != tc.err {
				t.Fatalf("results %+v", results)
			}
		})
	}
}

// The reason a subscription ended is numbered, never quoted: a reason the
// network wrote stays out of the result line (code review on #602).
func TestAGroupChatQuotesNoReasonTheNetworkWrote(t *testing.T) {
	cfg, f := groupStack(t)
	f.endReason = "sip-+15550100003"
	_, results := runAll(t, cfg, "group-chat")
	last := results[len(results)-1]
	if last.Step != "owner-lost" || strings.Contains(last.Error, "+1555") || last.Detail["reason"] != 0 {
		t.Fatalf("results %+v", results)
	}
}
