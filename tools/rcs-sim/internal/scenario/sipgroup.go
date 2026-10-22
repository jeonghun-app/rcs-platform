package scenario

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"mime/multipart"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/conference"
	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/resourcelists"
	"github.com/jeonghun-app/rcs-platform/internal/sdp"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/chat"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/sipua"
)

// omaIMTag is the OMA SIMPLE IM feature tag, by which rcsjta offers and
// takes a group chat session (RCC.07; rcs-as matches either it or the
// chat ICSI, docs/rcs-as.md, Feature tags).
const omaIMTag = "+g.oma.sip-im"

// rosterExpires is how long the scenario asks a roster subscription to
// last: rcs-as's least (docs/rcs-as.md, The roster), as the scenario ends
// long before.
const rosterExpires = 60

// groupInviteBody is the body of an INVITE to the conference factory
// (RFC 5366 §4, as rcsjta's OriginatingAdhocGroupChatSession sends it): a
// multipart/mixed of offer, the SDP, and a resource list naming invitees
// (RFC 4826), the part a recipient-list-invite reads. It returns the
// Content-Type with its boundary.
func groupInviteBody(offer []byte, invitees []sip.URI) (string, []byte, error) {
	if len(invitees) == 0 {
		return "", nil, errors.New("a group needs someone to invite")
	}
	var list bytes.Buffer
	list.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\r\n" +
		`<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists" xmlns:cp="urn:ietf:params:xml:ns:copycontrol"><list>`)
	for _, u := range invitees {
		list.WriteString(`<entry uri="`)
		if err := xml.EscapeText(&list, []byte(u.String())); err != nil {
			return "", nil, err
		}
		list.WriteString(`" cp:copyControl="to"/>`)
	}
	list.WriteString("</list></resource-lists>")

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	for _, part := range []struct {
		header textproto.MIMEHeader
		data   []byte
	}{
		{textproto.MIMEHeader{"Content-Type": {"application/sdp"}}, offer},
		{textproto.MIMEHeader{
			"Content-Type":        {resourcelists.ContentType},
			"Content-Disposition": {"recipient-list"},
		}, list.Bytes()},
	} {
		p, err := w.CreatePart(part.header)
		if err != nil {
			return "", nil, err
		}
		if _, err := p.Write(part.data); err != nil {
			return "", nil, err
		}
	}
	if err := w.Close(); err != nil {
		return "", nil, err
	}
	return `multipart/mixed;boundary="` + w.Boundary() + `"`, body.Bytes(), nil
}

// groupHeaders turns req, a chat INVITE from sipua's NewInvite, into one
// for a group chat as rcsjta sends it: the OMA IM tag in its Contact and
// an Accept-Contact for it, and the chat's Contribution-ID, which names the
// group (rcs-as refuses a group INVITE without one, 400).
func groupHeaders(req *sip.Request, contribution string) error {
	if contribution == "" {
		return errors.New("a group INVITE needs a Contribution-ID")
	}
	cs, err := req.Header.Contact()
	if err != nil || len(cs) != 1 {
		return errors.New("the INVITE has no Contact to tag")
	}
	c := cs[0]
	c.Params.SetFlag(omaIMTag)
	if err := req.Header.Set("Contact", c.String()); err != nil {
		return err
	}
	if err := req.Header.Add("Accept-Contact", "*;"+omaIMTag); err != nil {
		return err
	}
	return req.Header.Add("Contribution-ID", contribution)
}

// factoryInvite is the INVITE that creates a group at the conference
// factory: offer and the invitees' list as groupInviteBody makes them,
// Require: recipient-list-invite, as rcsjta's says, and the group's
// subject.
func factoryInvite(ua *sipua.UA, factory sip.URI, offer []byte, invitees []sip.URI, contribution, subject string) (*sip.Request, error) {
	req, err := ua.NewInvite(factory, offer)
	if err != nil {
		return nil, err
	}
	ct, body, err := groupInviteBody(offer, invitees)
	if err != nil {
		return nil, err
	}
	if err := groupHeaders(req, contribution); err != nil {
		return nil, err
	}
	for _, f := range [][2]string{{"Require", "recipient-list-invite"}, {"Subject", subject}} {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			return nil, err
		}
	}
	if err := req.Header.Set("Content-Type", ct); err != nil {
		return nil, err
	}
	req.Body = body
	return req, nil
}

// rejoinInvite is the INVITE that rejoins a group at its conference URI,
// with only an SDP body, as rcsjta's RejoinGroupChatSession sends it
// (RCC.07 rejoin).
func rejoinInvite(ua *sipua.UA, conf sip.URI, offer []byte, contribution string) (*sip.Request, error) {
	req, err := ua.NewInvite(conf, offer)
	if err != nil {
		return nil, err
	}
	if err := groupHeaders(req, contribution); err != nil {
		return nil, err
	}
	return req, nil
}

// conferenceOf is the conference URI a group's 200 names: its Contact,
// marked isfocus (RFC 4579 §5.2), which rcsjta keeps to rejoin by.
func conferenceOf(res *sip.Response) (sip.URI, error) {
	cs, err := res.Header.Contact()
	if err != nil || len(cs) != 1 || cs[0].Star {
		return sip.URI{}, errors.New("the answer has no single Contact")
	}
	if !cs[0].Params.Has("isfocus") {
		return sip.URI{}, errors.New("the answer's Contact is not marked isfocus")
	}
	return cs[0].URI, nil
}

// groupIdentity is the group a conference URI names: the URI without its
// parameters. rcs-as names its sessions' Contact with transport=tcp (#542),
// which RFC 3261 §19.1.4 leaves the same URI as the bare one the group is
// stored, listed in its roster and written in CPIM under. Requests go to
// the Contact as it came, as rcsjta's rejoin does.
func groupIdentity(u sip.URI) sip.URI {
	return sip.URI{Scheme: u.Scheme, User: u.User, Host: u.Host, Port: u.Port}
}

// roster is a group's roster as a subscriber builds it from its NOTIFYs
// (RFC 4575 §4.6): the first full, each partial one version up merged in.
type roster struct {
	info *conference.Info
}

// apply merges the document of n, a NOTIFY of the conference event
// package. A NOTIFY without a body changes nothing.
func (r *roster) apply(n sipua.Notification) error {
	if n.Err != nil {
		return n.Err
	}
	if len(n.Body) == 0 {
		return nil
	}
	if n.ContentType != conference.ContentType {
		return fmt.Errorf("the NOTIFY's body is %s, not a conference-info document", n.ContentType)
	}
	doc, err := conference.Parse(n.Body)
	if err != nil {
		return fmt.Errorf("the roster does not parse: %w", err)
	}
	merged, err := conference.Merge(r.info, doc)
	if err != nil {
		return fmt.Errorf("the roster does not merge: %w", err)
	}
	r.info = merged
	return nil
}

// version is the roster's version, 0 before any document.
func (r *roster) version() uint32 {
	if r.info == nil {
		return 0
	}
	return r.info.Version
}

// status is the endpoint status of the participant who is any of ids, and
// whether the roster lists it: rcs-as names a participant by the identity
// the network asserted, its tel URI when there is one (docs/rcs-as.md), so
// a client looks itself up by each of its IMPUs.
func (r *roster) status(ids ...string) (conference.EndpointStatus, bool) {
	if r.info == nil || r.info.Users == nil {
		return "", false
	}
	for _, u := range r.info.Users.List {
		if !slices.ContainsFunc(ids, func(id string) bool { return strings.EqualFold(id, u.Entity) }) {
			continue
		}
		if len(u.Endpoints) == 0 {
			return "", true
		}
		return u.Endpoints[0].Status, true
	}
	return "", false
}

// errNoFactory fails the group scenario without a conference factory URI.
var errNoFactory = errors.New("no conference factory configured (-sip-conference-factory)")

// groupSubject is the subject of the group the scenario makes.
const groupSubject = "rcs-sim group"

// maxRetryAfter bounds how long the scenario honours one Retry-After: rcs-as
// asks for 1 s (docs/rcs-as.md), and a longer one waits out the step's time.
const maxRetryAfter = 5 * time.Second

// groupLeg is one participant's session with the group: its dialog and its
// MSRP session through the relay.
type groupLeg struct {
	dialog *sipua.Dialog
	client *chat.Client
}

// close ends the leg as a client whose session ended does, closing its MSRP
// session, and with a BYE unless the dialog has ended. The BYE has no
// Reason: the participant stays in the group (docs/rcs-as.md, Leave).
func (r *run) closeLeg(l groupLeg) {
	_ = l.client.Close()
	r.hangUp(l.dialog)
}

// joinGroup sends req, an INVITE to the factory or a rejoin, from c, and
// sets up the session its 2xx answers: the answer names the relay's
// client_path, passive, and the client connects to it (RFC 6135). It returns
// the INVITE's final response, the conference URI its Contact names, and the
// leg; any status but 2xx returns no leg and no error, for the step to judge.
func (r *run) joinGroup(ctx context.Context, c *sipClient, req *sip.Request, local msrp.URI, end *chat.Endpoint) (*sip.Response, sip.URI, groupLeg, error) {
	d, res, err := c.ua.Invite(ctx, req, nil)
	if err != nil {
		return nil, sip.URI{}, groupLeg{}, sipError(err)
	}
	if d == nil {
		return res, sip.URI{}, groupLeg{}, nil
	}
	conf, err := conferenceOf(res)
	if err != nil {
		r.hangUp(d)
		return res, sip.URI{}, groupLeg{}, err
	}
	path, setup, err := chatAnswer(res.Body)
	switch {
	case err != nil:
	case !r.atRelay(path):
		// The session must be anchored at msrp-relay (ADR 0004).
		err = errNotRelay
	case setup != sdp.SetupPassive:
		err = fmt.Errorf("the answer's a=setup is %s, want passive: the client connects (RFC 6135)", setup)
	}
	if err != nil {
		r.hangUp(d)
		return res, conf, groupLeg{}, err
	}
	cl, err := chat.Dial(ctx, path, local, end, r.cfg.MSRP, r.cfg.TLS, nil)
	if err != nil {
		r.hangUp(d)
		return res, conf, groupLeg{}, err
	}
	return res, conf, groupLeg{dialog: d, client: cl}, nil
}

// rejoin rejoins the group at conf from c (RCC.07 rejoin), trying again
// after each 500 with Retry-After, as rcsjta does, until ctx ends: a task
// that cannot reach the group's owner answers so, never 404, while another
// takes the group over (docs/rcs-as.md, Which task serves a group). It
// returns the leg and how many INVITEs it took.
func (r *run) rejoin(ctx context.Context, c *sipClient, conf sip.URI, contribution string, end *chat.Endpoint) (groupLeg, int, error) {
	for tries := 1; ; tries++ {
		local, err := chat.LocalURI(r.cfg.Rand)
		if err != nil {
			return groupLeg{}, tries, err
		}
		offer, err := chatSDP(local, sdp.SetupActive)
		if err != nil {
			return groupLeg{}, tries, err
		}
		req, err := rejoinInvite(c.ua, conf, offer, contribution)
		if err != nil {
			return groupLeg{}, tries, err
		}
		res, got, leg, err := r.joinGroup(ctx, c, req, local, end)
		switch {
		case err != nil:
			return groupLeg{}, tries, err
		case leg.dialog != nil && !strings.EqualFold(groupIdentity(got).String(), groupIdentity(conf).String()):
			r.closeLeg(leg)
			return groupLeg{}, tries, errors.New("the rejoin was answered by another conference")
		case leg.dialog != nil:
			return leg, tries, nil
		case res.StatusCode != 500:
			return groupLeg{}, tries, fmt.Errorf("the rejoin was answered %d", res.StatusCode)
		}
		wait, err := retryAfter(res)
		if err != nil {
			return groupLeg{}, tries, err
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return groupLeg{}, tries, fmt.Errorf("the rejoin was still answered 500 after %d tries", tries)
		}
	}
}

// retryAfter is how long a 500 asks to wait (RFC 3261 §20.33), at most
// maxRetryAfter; a 500 without it is a failure, not a pause.
func retryAfter(res *sip.Response) (time.Duration, error) {
	v := strings.TrimSpace(res.Header.Get("Retry-After"))
	if i := strings.IndexAny(v, " ;("); i >= 0 {
		v = v[:i]
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, errors.New("a 500 without Retry-After")
	}
	return min(time.Duration(n)*time.Second, maxRetryAfter), nil
}

// identities are the IMPUs a roster may list a client by: its SIP URI, and
// the tel URI of its number, which the network asserts when it has one.
func identities(impu sip.URI) []string {
	ids := []string{impu.String()}
	if strings.HasPrefix(impu.User, "+") {
		ids = append(ids, "tel:"+impu.User)
	}
	return ids
}

// awaitRoster applies sub's NOTIFYs to ro until ready says it shows what the
// step waits for.
func awaitRoster(ctx context.Context, sub *sipua.Subscription, ro *roster, ready func() bool) (int, error) {
	n := 0
	for !ready() {
		select {
		case note := <-sub.Notifications():
			n++
			if err := ro.apply(note); err != nil {
				return n, err
			}
			if note.State == "terminated" && !ready() {
				return n, fmt.Errorf("the roster subscription ended (%s)", note.Reason)
			}
		case <-ctx.Done():
			return n, errors.New("the roster never showed the participants")
		}
	}
	return n, nil
}

// subscribeRoster subscribes from c to the group's roster (RFC 4575) and
// waits until it lists every one of who as connected.
func subscribeRoster(ctx context.Context, c *sipClient, conf sip.URI, who ...[]string) (*sipua.Subscription, *roster, map[string]int64, error) {
	sub, res, err := c.ua.Subscribe(ctx, conf, "conference", conference.ContentType, rosterExpires)
	if err != nil {
		detail := map[string]int64{}
		if res != nil {
			detail["status"] = int64(res.StatusCode)
		}
		return nil, nil, detail, sipError(err)
	}
	ro := &roster{}
	n, err := awaitRoster(ctx, sub, ro, func() bool {
		for _, ids := range who {
			if s, ok := ro.status(ids...); !ok || s != conference.Connected {
				return false
			}
		}
		return true
	})
	return sub, ro, map[string]int64{"status": int64(res.StatusCode), "notifies": int64(n), "version": int64(ro.version())}, err
}

// groupMessage sends a message from from on its leg to the group at conf,
// and waits for its success report, its arrival at to's endpoint, and the
// delivery and display notifications that come back from to. rcs-as
// rewrites the CPIM From, so only the text and the Message-ID are compared.
// A session the peer refused is reported as such (peerRefused).
func (r *run) groupMessage(ctx context.Context, from *chat.Endpoint, leg groupLeg, conf sip.URI, to *chat.Endpoint, text []byte, token string) (map[string]int64, error) {
	sent, err := from.Send(ctx, leg.client.Session, cpim.Address{URI: groupIdentity(conf).String()}, "text/plain;charset=UTF-8", text, imdn.PositiveDelivery|imdn.Display)
	if err != nil {
		return nil, err
	}
	if err := waitReport(ctx, from, sent.MSRP); err != nil {
		return nil, err
	}
	got, skipped, err := awaitChat(ctx, to, sent.IMDN, token)
	detail := map[string]int64{"skipped": int64(skipped)}
	if err != nil {
		return detail, r.peerRefused(err)
	}
	if !bytes.Equal(got.Body, text) {
		return detail, errors.New("the message arrived changed")
	}
	return detail, awaitNotifications(ctx, from, sent.IMDN, to.Self.URI)
}

// groupChat is the group-chat scenario (#121 D4): the client makes a group
// with the peer at the conference factory, through the P-CSCF, which anchors
// it at msrp-relay, and the S-CSCF, whose iFC take it to rcs-as. The focus
// invites the peer, who answers. A message goes through the group, the
// client's roster subscription shows them both, and the client rejoins
// (RCC.07 rejoin) GroupRejoins times: the core gives each request to any
// rcs-as task, and the one that does not own the group forwards it. Then
// the owner task stops (StopOwner): both sessions get its BYE and the
// roster subscription ends, the client rejoins once another task has taken
// the group over, its roster is back, and its next message reaches the
// peer, whom the new owner invites back for it.
func groupChat(r *run) error {
	switch {
	case r.cfg.SIP == nil:
		return r.step("register", func(context.Context) (map[string]int64, error) { return nil, errNoSIP })
	case r.cfg.SIPPeer == nil:
		return r.step("register", func(context.Context) (map[string]int64, error) { return nil, errNoPeer })
	case r.cfg.ConferenceFactory.Host == "":
		return r.step("register", func(context.Context) (map[string]int64, error) { return nil, errNoFactory })
	case r.cfg.RelayPublic == "":
		return r.step("register", func(context.Context) (map[string]int64, error) { return nil, errNoRelay })
	}
	calls := make(chan *sipua.IncomingCall, queueLength)
	var a *sipClient
	if err := r.step("register", func(ctx context.Context) (map[string]int64, error) {
		var err error
		if a, err = r.newSIPClient(ctx, *r.cfg.SIP, r.cfg.Self); err != nil {
			return nil, sipError(err)
		}
		peer := *r.cfg.SIPPeer
		peer.OnInvite = func(c *sipua.IncomingCall) {
			select {
			case calls <- c:
			default:
				_ = c.Reject(486)
			}
		}
		if _, err = r.newSIPClient(ctx, peer, r.cfg.Peer); err != nil {
			return nil, fmt.Errorf("peer: %w", sipError(err))
		}
		return nil, nil
	}); err != nil {
		return err
	}
	token, err := imdn.NewMessageID(r.cfg.Rand)
	if err != nil {
		return err
	}
	// The group's Contribution-ID, new for every run: rcs-as names a group
	// by it, and refuses an INVITE to the factory that names a live one.
	contribution, err := imdn.NewMessageID(r.cfg.Rand)
	if err != nil {
		return err
	}
	aEnd := r.endpoint(r.cfg.Self, false)
	bEnd := r.endpoint(r.cfg.Peer, true)
	sessions := make(chan peerSession, queueLength)
	answerer, stop := context.WithCancel(context.Background())
	answering := make(chan struct{})
	go func() {
		defer close(answering)
		r.answerCalls(answerer, calls, bEnd, sessions)
	}()
	r.onEnd(func() { stop(); <-answering })

	var conf sip.URI
	var aLeg groupLeg
	// Each leg the client opens ends with the scenario, unless it has.
	r.onEnd(func() {
		if aLeg.dialog != nil {
			r.closeLeg(aLeg)
		}
	})
	if err := r.step("create", func(ctx context.Context) (map[string]int64, error) {
		local, err := chat.LocalURI(r.cfg.Rand)
		if err != nil {
			return nil, err
		}
		offer, err := chatSDP(local, sdp.SetupActive)
		if err != nil {
			return nil, err
		}
		peer := r.cfg.SIPPeer.IMPU
		req, err := factoryInvite(a.ua, r.cfg.ConferenceFactory, offer, []sip.URI{peer}, contribution, groupSubject)
		if err != nil {
			return nil, err
		}
		res, got, leg, err := r.joinGroup(ctx, a, req, local, aEnd)
		if err != nil {
			return nil, err
		}
		detail := map[string]int64{"status": int64(res.StatusCode)}
		if leg.dialog == nil {
			return detail, fmt.Errorf("the factory's INVITE was answered %d", res.StatusCode)
		}
		conf, aLeg = got, leg
		return detail, nil
	}); err != nil {
		return err
	}
	var peerLeg peerSession
	if err := r.step("invited", func(ctx context.Context) (map[string]int64, error) {
		// The focus invites the peer once the creator's session is up.
		var err error
		peerLeg, err = latestSession(ctx, sessions, peerSession{})
		return nil, r.peerRefused(err)
	}); err != nil {
		return err
	}
	if err := r.step("message", func(ctx context.Context) (map[string]int64, error) {
		return r.groupMessage(ctx, aEnd, aLeg, conf, bEnd, []byte(sipChatText+" to the group "+token), token)
	}); err != nil {
		return err
	}
	self, peer := identities(r.cfg.SIP.IMPU), identities(r.cfg.SIPPeer.IMPU)
	var sub *sipua.Subscription
	if err := r.step("roster", func(ctx context.Context) (map[string]int64, error) {
		var detail map[string]int64
		var err error
		sub, _, detail, err = subscribeRoster(ctx, a, conf, self, peer)
		return detail, err
	}); err != nil {
		return err
	}
	if err := r.step("rejoin", func(ctx context.Context) (map[string]int64, error) {
		n := 0
		for range max(r.cfg.GroupRejoins, 1) {
			// The client's session ends without its leaving, as one idle
			// too long does, and it rejoins.
			r.closeLeg(aLeg)
			aLeg = groupLeg{}
			leg, _, err := r.rejoin(ctx, a, conf, contribution, aEnd)
			if err != nil {
				return map[string]int64{"rejoins": int64(n)}, err
			}
			aLeg = leg
			n++
		}
		detail, err := r.groupMessage(ctx, aEnd, aLeg, conf, bEnd, []byte(sipChatText+" after rejoining "+token), token)
		if detail == nil {
			detail = map[string]int64{}
		}
		detail["rejoins"] = int64(n)
		return detail, err
	}); err != nil {
		return err
	}
	if r.cfg.StopOwner == nil {
		return r.skip("owner-stop", "no way to stop the group's owner task (-group-owner-stop-dir)")
	}
	// A clean stop takes the task's shutdown, up to RCS_SHUTDOWN_TIMEOUT
	// and its grace, and the host's own time to act on it.
	if err := r.stepWithin("owner-stop", r.cfg.StepTimeout+2*time.Minute, func(ctx context.Context) (map[string]int64, error) {
		return nil, r.cfg.StopOwner(ctx, groupIdentity(conf))
	}); err != nil {
		return err
	}
	if err := r.step("owner-lost", func(ctx context.Context) (map[string]int64, error) {
		// The owner ended what it held of the group on its way out: both
		// sessions with a BYE, the roster subscription deactivated, so
		// that the client subscribes again at once (docs/rcs-as.md).
		for _, d := range []*sipua.Dialog{aLeg.dialog, peerLeg.dialog} {
			select {
			case <-d.Done():
			case <-ctx.Done():
				return nil, errors.New("a session with the group outlived its owner")
			}
		}
		for {
			select {
			case note := <-sub.Notifications():
				if note.State == "terminated" {
					if note.Reason != "deactivated" {
						return nil, fmt.Errorf("the roster subscription ended %s, want deactivated", note.Reason)
					}
					return nil, nil
				}
			case <-ctx.Done():
				return nil, errors.New("the roster subscription outlived the owner")
			}
		}
	}); err != nil {
		return err
	}
	_ = aLeg.client.Close()
	aLeg = groupLeg{}
	// Up to RCS_TASK_LEASE and RCS_TASK_SKEW, 22 s, after an owner that
	// crashed; 2 s after one that stopped cleanly.
	if err := r.stepWithin("rejoin-after-loss", r.cfg.StepTimeout+30*time.Second, func(ctx context.Context) (map[string]int64, error) {
		leg, tries, err := r.rejoin(ctx, a, conf, contribution, aEnd)
		aLeg = leg
		return map[string]int64{"tries": int64(tries)}, err
	}); err != nil {
		return err
	}
	if err := r.step("roster-after-loss", func(ctx context.Context) (map[string]int64, error) {
		// The peer has no session now, but is still a participant.
		_, ro, detail, err := subscribeRoster(ctx, a, conf, self)
		if err == nil {
			if _, ok := ro.status(peer...); !ok {
				err = errors.New("the roster no longer lists the peer")
			}
		}
		return detail, err
	}); err != nil {
		return err
	}
	if err := r.step("message-after-loss", func(ctx context.Context) (map[string]int64, error) {
		return r.groupMessage(ctx, aEnd, aLeg, conf, bEnd, []byte(sipChatText+" after the owner stopped "+token), token)
	}); err != nil {
		return err
	}
	return r.step("clean", func(context.Context) (map[string]int64, error) {
		for _, e := range []*chat.Endpoint{aEnd, bEnd} {
			e.Wait()
			if n := e.Malformed.Load(); n > 0 {
				return nil, fmt.Errorf("%d malformed messages received", n)
			}
			if n := e.Dropped.Load(); n > 0 {
				return nil, fmt.Errorf("%d events dropped", n)
			}
		}
		return nil, nil
	})
}
