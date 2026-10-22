package sipas

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/sdp"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/dialog"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// The OMA CPM ICSIs of a chat session and of a large-mode message (RCC.07
// §2.6.1): what an INVITE is for. Their feature tags go in the Contact of
// rcs-as's sessions and, for the INVITEs it sends, in Accept-Contact, so
// that scscf forks them to the contacts that take them (RFC 3841).
const (
	chatICSI  = "urn:urn-7:3gpp-service.ims.icsi.oma.cpm.session"
	largeICSI = "urn:urn-7:3gpp-service.ims.icsi.oma.cpm.largemsg"
	chatTag   = `+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"`
	largeTag  = `+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.largemsg"`
	sdpType   = "application/sdp"
)

// directionRefused is the Reason with which pcscf ends a session whose
// client answered rcs-as's offer passive (ADR 0004), and with which rcs-as
// ends one whose answer it finds passive itself.
const directionRefused = `SIP;cause=488;text="MSRP direction not supported"`

// minSessionExpires is the shortest session interval rcs-as takes, RFC
// 4028 §4's minimum; a request for less is answered 422 with Min-SE.
const minSessionExpires = 90

// dialogTimeout bounds the lookup of a dialog's next hop.
const dialogTimeout = 5 * time.Second

// session is one SIP session rcs-as is a party to and the MSRP leg it
// anchors in it: a client's INVITE it answered, or one it sent to deliver
// (inv). The fields below mu are guarded by it.
type session struct {
	s   *Server
	leg *messaging.Leg
	// user is the client's identity in the session, which
	// Config.MaxOutgoingPerUser bounds.
	user string
	// reserved is set while a session rcs-as started holds its place
	// before its 2xx (Server.reserve); guarded by the Server's mu.
	reserved bool
	// live is set once the session's first answer is on its way: rcs-as's
	// 2xx to a client's INVITE, or its ACK to the client's 2xx. A BYE
	// before it would end a dialog the other side does not have yet
	// (#270). Guarded by the Server's mu.
	live bool
	// confirmed is closed once the dialog is confirmed both ways (confirm);
	// addSession makes it.
	confirmed   chan struct{}
	confirmOnce sync.Once
	mode        store.Mode
	// inv is the invitation of a session rcs-as started; zero otherwise.
	inv messaging.Invitation
	// group is the conference URI of a session with a group chat, which
	// rcs-as is the focus of; empty otherwise. conversation is the
	// session's, whose Contribution-ID names the group chat to its clients.
	group        string
	conversation messaging.Conversation

	mu sync.Mutex
	d  *dialog.Dialog
	// remotePath is the a=path of the other side, which a re-INVITE or
	// UPDATE must keep.
	remotePath string
	// origin and sdp are the o= line and the body of the last SDP rcs-as
	// sent in the session, from which an answer to a refresh is made
	// (RFC 3264 §8).
	origin sdp.Origin
	sdp    []byte
	// interval is the session timer, zero for none (RFC 4028).
	interval time.Duration
	timer    msrp.Timer
	// ack is the ACK of the 2xx rcs-as's INVITE got, sent again for each
	// retransmission of it (RFC 3261 §13.2.2.4).
	ack *sip.Request
	// final is set once rcs-as's INVITE has a final answer, and noDialog
	// once a 2xx to it set up no dialog; dropped holds the To tags of the
	// other forks rcs-as ended.
	final, noDialog bool
	dropped         map[string]bool
	// acked is set once the client's ACK of rcs-as's 2xx came (watch).
	acked bool
	ended bool
}

// contactTag is the feature tag of the session's service.
func (ss *session) contactTag() string {
	if ss.mode == store.Standalone {
		return largeTag
	}
	return chatTag
}

// inviteTags are the feature tags of the INVITEs rcs-as sends for the
// session's service, in Contact and Accept-Contact: for a chat, with a
// group too, both the CPM chat ICSI and the OMA SIMPLE IM tag, by which
// rcsjta takes a chat session (ImsServiceDispatcher, ChatUtils).
func (ss *session) inviteTags() string {
	if ss.mode == store.Standalone {
		return largeTag
	}
	return chatTag + ";" + omaIMTag
}

// acceptTags are the feature tags of an INVITE's Accept-Contact values,
// one each (inviteTags).
func (ss *session) acceptTags() []string {
	if ss.mode == store.Standalone {
		return []string{largeTag}
	}
	return []string{chatTag, omaIMTag}
}

// contact is the Contact of rcs-as's side of the session: this task, where
// the requests in the dialog reach it, with the service's feature tag; or,
// in a session with a group, the conference URI marked as a focus (RFC
// 4579 §5.2), which is how rcsjta tells a group's INVITE from a 1-to-1
// one (ChatUtils.isGroupChatInvitation) and what it rejoins the group at.
func (ss *session) contact() string { return ss.contactWith(ss.contactTag()) }

// inviteContact is contact with the feature tags of an INVITE
// (inviteTags).
func (ss *session) inviteContact() string { return ss.contactWith(ss.inviteTags()) }

func (ss *session) contactWith(tags string) string {
	if ss.group != "" {
		return "<" + ss.group + ">;isfocus;" + tags
	}
	return sip.Address{URI: ss.s.cfg.Contact}.String() + ";" + tags
}

// Why addSession did not add a session.
var (
	errClosing         = errors.New("sipas: closing")
	errTooManySessions = errors.New("sipas: too many sessions on this task")
	errUserSessions    = errors.New("sipas: too many sessions for the user")
	errLargeBusy       = errors.New("sipas: a large-mode session from the sender to the recipient is open")
)

// addSession makes ss reachable by the requests in its dialog, unless s
// is closing or a bound on sessions is reached (threat model T9). A session
// rcs-as started holds its place already (reserve), which it takes over.
//
// The session it adds is being answered until answered is called, which
// the caller defers once addSession succeeds: once the session's first
// answer has gone (rcs-as's 2xx to a client's INVITE, or its ACK of the
// client's 2xx), or the session ended before. Until then Close sends it no
// BYE (#270). On an error, answered does nothing.
func (s *Server) addSession(ss *session) (answered func(), err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ss.reserved {
		ss.reserved = false
		s.pending--
		if s.closed {
			s.dropUser(ss)
			return func() {}, errClosing
		}
	} else {
		if err := s.roomFor(ss); err != nil {
			return func() {}, err
		}
		s.perUser[ss.budget()]++
	}
	s.sessions[ss.d.ID()] = ss
	ss.confirmed = make(chan struct{})
	s.answering.Add(1)
	var once sync.Once
	return func() { once.Do(func() { s.settle(ss) }) }, nil
}

// settle marks a session that addSession took as live, its first answer
// having gone, or as done with if it ended before. A session that becomes
// live while s is closing is ended now, once its dialog is confirmed or
// closeWait has passed: Close waited for it, up to its bound, and leaves
// the BYE of one it did not see live to this.
func (s *Server) settle(ss *session) {
	s.mu.Lock()
	ss.live = true
	// Before Close takes its sessions, this one is among them, and Close
	// ends it and waits for its BYE's answer; after, it is ended here, and
	// Close, while it still waits for its own BYEs, waits for this one
	// too (QA on #273).
	late, counted, by := s.swept, s.sweeping, s.closeBy
	if counted {
		s.lateByes.Add(1)
	}
	s.mu.Unlock()
	s.answering.Done()
	if late {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), s.closeWait())
			defer cancel()
			if counted {
				defer s.lateByes.Done()
				// Within Close's own bound, which waits for it.
				ctx, cancel = context.WithDeadline(ctx, by)
				defer cancel()
			}
			select {
			case <-ss.byeConfirmed(ctx):
			case <-ctx.Done():
			}
		}()
	}
}

// confirm records that the session's dialog is confirmed both ways: the
// client's ACK of rcs-as's 2xx came, or never will (proxy.ErrNoACK), or
// rcs-as sent its own ACK.
func (ss *session) confirm() { ss.confirmOnce.Do(func() { close(ss.confirmed) }) }

// acknowledged reports whether the client's ACK of rcs-as's 2xx came, once
// confirmed is closed.
func (ss *session) acknowledged() bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.acked
}

// byeConfirmed ends the session with a BYE once its dialog is confirmed,
// or once ctx ends: a callee must not send a BYE before the 2xx's ACK
// comes or its transaction times out (RFC 3261 §15), since the BYE could
// overtake the 2xx; a shutdown cannot wait as long. What it returns is
// bye's.
func (ss *session) byeConfirmed(ctx context.Context) <-chan struct{} {
	select {
	case <-ss.confirmed:
	case <-ctx.Done():
	}
	return ss.bye("")
}

// reserve holds a place for a session rcs-as is about to start for ss's
// user, so that INVITEs still waiting for their answer count against the
// bounds too; release gives it back if the session does not come about.
func (s *Server) reserve(ss *session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.roomFor(ss); err != nil {
		return err
	}
	if key := ss.largeKey(); key != "" {
		if s.large[key] {
			// One large-mode session at a time from one sender to one
			// recipient (security review on #252): the next message
			// waits for this one, rather than ringing the recipient's
			// client once for each.
			return errLargeBusy
		}
		s.large[key] = true
	}
	ss.reserved = true
	s.pending++
	s.perUser[ss.budget()]++
	return nil
}

func (s *Server) release(ss *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ss.reserved {
		return
	}
	ss.reserved = false
	s.pending--
	s.dropUser(ss)
}

// dropUser counts one session of ss's user fewer, and frees its sender and
// recipient for another large-mode session; it needs s.mu.
func (s *Server) dropUser(ss *session) {
	if b := ss.budget(); s.perUser[b] <= 1 {
		delete(s.perUser, b)
	} else {
		s.perUser[b]--
	}
	if key := ss.largeKey(); key != "" {
		delete(s.large, key)
	}
}

// budget names the count of ss's sessions that ss belongs to: those its
// user opens, or those rcs-as opens to its user.
func (ss *session) budget() string {
	if ss.inv.Recipient != "" {
		return ss.user + "\x00in"
	}
	return ss.user + "\x00out"
}

// largeKey names a large-mode session rcs-as opens by its recipient and
// sender; empty for any other session.
func (ss *session) largeKey() string {
	if ss.inv.Recipient == "" || ss.mode != store.Standalone {
		return ""
	}
	return ss.inv.Recipient + "\x00" + ss.inv.Peer
}

// roomFor reports whether ss may be added; it needs s.mu.
func (s *Server) roomFor(ss *session) error {
	limit := s.cfg.MaxOutgoingPerUser
	if ss.inv.Recipient != "" {
		limit = s.cfg.MaxIncomingPerUser
	}
	switch {
	case s.closed:
		return errClosing
	case len(s.sessions)+s.pending >= s.cfg.MaxSessions:
		s.cfg.Metrics.Count("sip.session.task_limit", 1)
		return errTooManySessions
	case s.perUser[ss.budget()] >= limit:
		s.cfg.Metrics.Count("sip.session.user_limit", 1)
		return errUserSessions
	}
	return nil
}

func (s *Server) removeSession(ss *session) {
	ss.mu.Lock()
	d := ss.d
	ss.mu.Unlock()
	if d == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions[d.ID()] != ss {
		return
	}
	delete(s.sessions, d.ID())
	s.dropUser(ss)
}

// sessionOf finds the session of a request the other side sent in it, by
// the dialog's identifier, rcs-as's tag being To's (dialog.Dialog.ID).
func (s *Server) sessionOf(req *sip.Request) *session {
	from, err1 := req.Header.From()
	to, err2 := req.Header.To()
	if err1 != nil || err2 != nil {
		return nil
	}
	id := req.Header.Get("Call-ID") + "\x00" + strings.ToLower(to.Tag()) + "\x00" + strings.ToLower(from.Tag())
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[id]
}

// closeWait bounds each of Close's two waits: for the sessions still being
// answered and their ACKs, and for the answers to its BYEs.
const closeWait = 2 * time.Second

// closeCtx is a context that ends after d: on the test's closeClock if it
// set one, in real time otherwise.
func (s *Server) closeCtx(d time.Duration) (context.Context, context.CancelFunc) {
	if s.cfg.closeClock == nil {
		return context.WithTimeout(context.Background(), d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t := s.cfg.closeClock.AfterFunc(d, cancel)
	return ctx, func() { t.Stop(); cancel() }
}

func (s *Server) closeWait() time.Duration {
	if s.cfg.closeWait > 0 {
		return s.cfg.closeWait
	}
	return closeWait
}

// Close ends every session with a BYE and every subscription with a last
// NOTIFY, before the transport closes, and takes no new one. A session
// still being answered is answered first, and a session's BYE waits for
// the 2xx's ACK (RFC 3261 §15), both up to closeWait. Then it waits for the
// answers to the BYEs and NOTIFYs, up to closeWait again: the transport
// writes a request after SendRequest returns, and closing it at once could
// drop it. So Close takes at most twice closeWait.
func (s *Server) Close() { s.closeOnce.Do(s.close) }

func (s *Server) close() {
	wait := s.closeWait()
	s.mu.Lock()
	s.closed = true
	s.closeBy = time.Now().Add(2 * wait)
	s.mu.Unlock()
	// One bound for every session's answer and ACK: a closed Done reaches
	// every waiter.
	answering, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	// A session whose first answer has not gone yet, as one whose first
	// message is being stored, gets it first: its BYE follows its 2xx
	// (#270), from settle if it comes too late for this.
	answered := make(chan struct{})
	go func() { s.answering.Wait(); close(answered) }()
	select {
	case <-answered:
	case <-answering.Done():
	}
	s.mu.Lock()
	all := make([]*session, 0, len(s.sessions))
	for _, ss := range s.sessions {
		if ss.live {
			all = append(all, ss)
		}
	}
	subs := make([]*subscription, 0, len(s.subs))
	for _, sub := range s.subs {
		subs = append(subs, sub)
	}
	s.swept, s.sweeping = true, true
	s.mu.Unlock()
	var wg sync.WaitGroup
	for _, ss := range all {
		wg.Go(func() {
			done := ss.byeConfirmed(answering)
			// The BYE's answer has a budget of its own, whatever the
			// answers above took.
			ctx, cancel := context.WithTimeout(context.Background(), wait)
			defer cancel()
			select {
			case <-done:
			case <-ctx.Done():
			}
		})
	}
	// A subscriber may subscribe again at once, which reaches another
	// task (RFC 6665 §4.1.3, deactivated).
	for _, sub := range subs {
		wg.Go(func() {
			ctx, cancel := s.closeCtx(wait)
			defer cancel()
			// The lock may be held by a SUBSCRIBE reading the roster from
			// a slow store: taking it counts against the bound too (QA
			// on #340).
			ended := make(chan (<-chan struct{}), 1)
			go func() {
				sub.mu.Lock()
				var done <-chan struct{} = closedChan
				if !sub.ended {
					done = sub.end(reasonDeactivated)
				}
				sub.mu.Unlock()
				ended <- done
			}()
			select {
			case done := <-ended:
				select {
				case <-done:
					return
				case <-ctx.Done():
				}
			case <-ctx.Done():
			}
			// Its last NOTIFY, or its lock, outlasted the bound.
			s.cfg.Metrics.Count("sip.subscription.unfinished_at_stop", 1)
		})
	}
	wg.Wait()
	// No settle counts a BYE once this is cleared, so that no Add races
	// the Wait below.
	s.mu.Lock()
	s.sweeping = false
	s.mu.Unlock()
	s.lateByes.Wait()
}

// msrpOffer reads the SDP offer in body: its first MSRP media line, with
// its path, or the status that refuses it. No offer (a late offer, RFC
// 3261 §13.2.1), no MSRP line, or an offer of passive, which only a
// connecting answerer could take and rcs-as never connects (RFC 6135
// §4.2.2, ADR 0004), is 488.
func msrpOffer(h *sip.Header, body []byte) (*sdp.Session, int, []msrp.URI, int) {
	offer, err := sdpBody(h, body)
	if err != nil {
		return nil, 0, nil, 488
	}
	return msrpOfferIn(offer)
}

// msrpOfferIn is msrpOffer for a session description already parsed.
func msrpOfferIn(offer *sdp.Session) (*sdp.Session, int, []msrp.URI, int) {
	// An offer without a=setup is active (RFC 4145 §4).
	i, path, setup, err := firstMSRP(offer, sdp.SetupActive)
	if err != nil || setup == sdp.SetupPassive {
		return nil, 0, nil, 488
	}
	return offer, i, path, 0
}

func sdpBody(h *sip.Header, body []byte) (*sdp.Session, error) {
	ct, err := h.ContentType()
	if err != nil || len(body) == 0 || !strings.EqualFold(ct.Type+"/"+ct.Subtype, sdpType) {
		return nil, errors.New("sipas: no SDP")
	}
	return sdp.Parse(body)
}

// firstMSRP is the first MSRP media line of s that is not disabled, its
// path, and its role, absent when it names none.
func firstMSRP(s *sdp.Session, absent sdp.Setup) (int, []msrp.URI, sdp.Setup, error) {
	for i := range s.Media {
		m := &s.Media[i]
		if !m.IsMSRP() || m.Port == 0 {
			continue
		}
		setup, err := s.MediaSetup(i)
		switch {
		case errors.Is(err, sdp.ErrNoAttribute):
			setup = absent
		case err != nil:
			return 0, nil, "", err
		}
		values, err := m.Path()
		if err != nil {
			return 0, nil, "", err
		}
		path := make([]msrp.URI, 0, len(values))
		for _, v := range values {
			u, err := msrp.ParseURI(v)
			if err != nil {
				return 0, nil, "", err
			}
			path = append(path, u)
		}
		return i, path, setup, nil
	}
	return 0, nil, "", errors.New("sipas: no MSRP media line")
}

func joinPath(path []msrp.URI) string {
	parts := make([]string, len(path))
	for i, u := range path {
		parts[i] = u.String()
	}
	return strings.Join(parts, " ")
}

// newOrigin is the o= line of a session rcs-as describes, at host, the
// leg's instance address (ADR 0005), numbered from the clock as RFC 8866
// §5.2 suggests.
func (s *Server) newOrigin(host string) sdp.Origin {
	const ntpEpoch = 2208988800 // 1900 to 1970, in seconds
	addrType := "IP4"
	if strings.Contains(host, ":") {
		addrType = "IP6"
	}
	now := s.cfg.Clock.Now()
	return sdp.Origin{
		Username: "-", SessionID: strconv.FormatInt(now.UnixNano(), 10),
		SessionVersion: strconv.FormatInt(now.Unix()+ntpEpoch, 10),
		NetType:        "IN", AddrType: addrType, Address: host,
	}
}

// answerSDP answers line i of offer with leg's path, passive, and origin.
func (s *Server) answerSDP(offer *sdp.Session, i int, leg *messaging.Leg, mode store.Mode, origin sdp.Origin) ([]byte, error) {
	local := leg.Local()
	m, err := sdp.NegotiateMSRP(offer, i, sdp.MSRPEndpoint{
		Port: local.Port, Path: []string{local.String()}, AcceptTypes: messaging.AcceptTypes(mode),
		MaxSize: int64(s.cfg.MaxMessageSize), PreferredSetup: sdp.SetupPassive,
	})
	if err != nil {
		return nil, err
	}
	answer := sdp.NewAnswer(offer, origin, sdp.Connection{NetType: "IN", AddrType: origin.AddrType, Address: origin.Address})
	answer.Media[i] = m
	return answer.Marshal()
}

// answerRefresh answers the offer of a re-INVITE or UPDATE in ss: the same
// answer as before, with the same o= version, unless what rcs-as describes
// has changed, which takes the next version (RFC 3264 §8).
func (ss *session) answerRefresh(offer *sdp.Session, i int) ([]byte, error) {
	ss.mu.Lock()
	origin, last := ss.origin, ss.sdp
	ss.mu.Unlock()
	body, err := ss.s.answerSDP(offer, i, ss.leg, ss.mode, origin)
	if err != nil || slices.Equal(body, last) {
		return body, err
	}
	n, err := strconv.ParseUint(origin.SessionVersion, 10, 63)
	if err != nil {
		return nil, err
	}
	origin.SessionVersion = strconv.FormatUint(n+1, 10)
	if body, err = ss.s.answerSDP(offer, i, ss.leg, ss.mode, origin); err != nil {
		return nil, err
	}
	ss.mu.Lock()
	ss.origin, ss.sdp = origin, body
	ss.mu.Unlock()
	return body, nil
}

// offerAgain is the offer in the 2xx to a re-INVITE without one: the
// session's last SDP, with every MSRP line actpass, since an offer is
// never passive (RFC 6135 §4.2.2) and rcs-as's last SDP in a session a
// client started is its passive answer. That SDP is the same, and keeps
// its o= version, unless the setup changed, which takes the next version
// (RFC 3264 §8).
func (ss *session) offerAgain() ([]byte, error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	last, err := sdp.Parse(ss.sdp)
	if err != nil {
		return nil, err
	}
	for i := range last.Media {
		if m := &last.Media[i]; m.IsMSRP() && m.Port != 0 {
			if err := m.SetSetup(sdp.SetupActPass); err != nil {
				return nil, err
			}
		}
	}
	body, err := last.Marshal()
	if err != nil || slices.Equal(body, ss.sdp) {
		return ss.sdp, err
	}
	n, err := strconv.ParseUint(ss.origin.SessionVersion, 10, 63)
	if err != nil {
		return nil, err
	}
	ss.origin.SessionVersion = strconv.FormatUint(n+1, 10)
	last.Origin = ss.origin
	if body, err = last.Marshal(); err != nil {
		return nil, err
	}
	ss.sdp = body
	return body, nil
}

// sessionHeaders adds the header fields of a 2xx in a session: contact,
// Allow, the SDP if any and, with a timer, the Session-Expires the UAC
// refreshes (RFC 4028 §9).
func (s *Server) sessionHeaders(res *sip.Response, contact string, body []byte, interval time.Duration) error {
	fields := [][2]string{
		{"Contact", contact},
		{"Allow", allowed},
		{"Supported", "timer"},
	}
	if interval > 0 {
		fields = append(fields, [2]string{"Require", "timer"},
			[2]string{"Session-Expires", strconv.Itoa(int(interval/time.Second)) + ";refresher=uac"})
	}
	if len(body) > 0 {
		fields = append(fields, [2]string{"Content-Type", sdpType})
	}
	for _, f := range fields {
		if err := res.Header.Add(f[0], f[1]); err != nil {
			return err
		}
	}
	res.Body = body
	return nil
}

// sessionInterval is the session timer a request asks for and rcs-as
// takes, zero for none, or the status that refuses it. rcs-as never
// refreshes a session itself. A UAC that supports the extension and lets
// the UAS choose, or chooses itself, refreshes (RFC 4028 §9, Table 2), and
// one asking for less than minSessionExpires gets 422. One that asks
// rcs-as to refresh (refresher=uas), which the UAS cannot change, or that
// does not support the extension, which leaves refreshing to the UAS,
// gets no timer, as from a UAS without the extension, and no 422 either:
// a UAC without the extension cannot act on one. Such a session ends with
// its MSRP connection or a BYE.
func sessionInterval(req *sip.Request) (time.Duration, int) {
	if !req.Header.Has("Session-Expires") {
		return 0, 0
	}
	se, err := req.Header.SessionExpires()
	if err != nil {
		return 0, 400
	}
	supported, err := req.Header.Supported()
	if err != nil {
		return 0, 400
	}
	if !containsFold(supported, "timer") || se.Refresher() == "uas" {
		return 0, 0
	}
	if se.Delta < minSessionExpires {
		return 0, 422
	}
	return time.Duration(se.Delta) * time.Second, 0
}

func containsFold(list []string, v string) bool {
	return slices.ContainsFunc(list, func(x string) bool { return strings.EqualFold(x, v) })
}

// watch ends the session from rcs-as's side when it must: a 2xx that got
// no ACK (RFC 3261 §13.3.1.4); a leg that ended on its own, as when
// msrp-relay dropped its connection; or a terminating large-mode leg that
// has made its delivery (messaging.Leg.Finished).
func (ss *session) watch(u *proxy.UAS) {
	if u != nil {
		_, err := u.ACK(context.Background())
		ss.mu.Lock()
		ss.acked = err == nil
		ss.mu.Unlock()
		ss.confirm()
		if errors.Is(err, proxy.ErrNoACK) {
			ss.s.cfg.Metrics.Count("sip.session.no_ack", 1)
			ss.bye("")
			return
		}
	}
	select {
	case <-ss.leg.Done():
	case <-ss.leg.Finished():
	}
	ss.bye("")
}

// arm starts the session timer again: without a refresh before the
// interval runs out less min(32 s, interval/3), rcs-as ends the session
// (RFC 4028 §10).
func (ss *session) arm() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.timer != nil {
		ss.timer.Stop()
		ss.timer = nil
	}
	if ss.interval <= 0 || ss.ended {
		return
	}
	ss.timer = ss.s.cfg.Clock.AfterFunc(ss.interval-min(32*time.Second, ss.interval/3), func() {
		ss.s.cfg.Metrics.Count("sip.session.expired", 1)
		ss.bye("")
	})
}

// end forgets the session and closes its leg; it reports whether it was
// the call that did.
func (ss *session) end() bool {
	ss.mu.Lock()
	if ss.ended {
		ss.mu.Unlock()
		return false
	}
	ss.ended = true
	if ss.timer != nil {
		ss.timer.Stop()
	}
	ss.mu.Unlock()
	ss.s.removeSession(ss)
	_ = ss.leg.Close()
	return true
}

// bye ends the session from rcs-as's side with a BYE in its dialog,
// carrying reason if it is not empty. What it returns is closed once the
// BYE is answered, or was not sent.
func (ss *session) bye(reason string) <-chan struct{} {
	if !ss.end() {
		return closedChan
	}
	ss.mu.Lock()
	var req *sip.Request
	var next sip.URI
	err := errors.New("sipas: no dialog")
	if ss.d != nil {
		req, err = ss.d.Request("BYE", ss.s.ids)
		next = ss.d.NextHop()
	}
	ss.mu.Unlock()
	if err != nil {
		return closedChan
	}
	if reason != "" && req.Header.Add("Reason", reason) != nil {
		return closedChan
	}
	ss.s.cfg.Metrics.Count("sip.bye.sent", 1)
	return ss.s.sendInDialog(req, next)
}

// closedChan is a channel closed already.
var closedChan = func() chan struct{} { c := make(chan struct{}); close(c); return c }()

// sendInDialog sends rcs-as's request in a dialog to next. Nothing is left
// to do with its answer; what it returns is closed when the answer, or the
// transaction's end, comes, or at once if the request was not sent.
func (s *Server) sendInDialog(req *sip.Request, next sip.URI) <-chan struct{} {
	return s.sendInDialogThen(req, next, nil)
}

// sendInDialogThen is sendInDialog, with then, if not nil, called with the
// final answer or the transaction's error, once; or with an error if the
// request was not sent.
func (s *Server) sendInDialogThen(req *sip.Request, next sip.URI, then func(*sip.Response, error)) <-chan struct{} {
	ctx, cancel := context.WithTimeout(context.Background(), dialogTimeout)
	defer cancel()
	if then == nil {
		then = func(*sip.Response, error) {}
	}
	dst, err := s.cfg.Resolver.Resolve(ctx, next)
	if err != nil {
		s.cfg.Metrics.Count("sip.dialog.unresolved", 1)
		then(nil, err)
		return closedChan
	}
	dst.Listener = s.cfg.Listener
	done := make(chan struct{})
	var once sync.Once
	if _, err := s.layer.Request(req, dst, func(res *sip.Response, err error) {
		if err != nil || res.StatusCode >= 200 {
			once.Do(func() {
				then(res, err)
				close(done)
			})
		}
	}); err != nil {
		s.cfg.Metrics.Count("sip.dialog.unsent", 1)
		then(nil, err)
		return closedChan
	}
	return done
}

// sendACK sends the ACK of a 2xx to next. It belongs to no transaction
// (RFC 3261 §13.2.2.4); each copy is a request of its own, since the
// transport writes its Via.
func (s *Server) sendACK(ack *sip.Request, next sip.URI) {
	ctx, cancel := context.WithTimeout(context.Background(), dialogTimeout)
	defer cancel()
	dst, err := s.cfg.Resolver.Resolve(ctx, next)
	if err != nil {
		s.cfg.Metrics.Count("sip.dialog.unresolved", 1)
		return
	}
	dst.Listener = s.cfg.Listener
	if _, err := s.sender.SendRequest(ack.Clone(), dst); err != nil {
		s.cfg.Metrics.Count("sip.dialog.unsent", 1)
	}
}

// inDialog serves a request the other side sent in a session: BYE ends
// it, a re-INVITE or UPDATE refreshes it (RFC 4028 §7), OPTIONS is
// answered, and nothing else is taken.
func (s *Server) inDialog(ctx context.Context, u *proxy.UAS) {
	req := u.Request().Message
	ss := s.sessionOf(req)
	if ss == nil {
		if sub := s.subscriptionOf(req); sub != nil {
			s.inSubscription(ctx, u, sub, req)
			return
		}
		s.respond(u, req, 481)
		return
	}
	ss.mu.Lock()
	err := ss.d.Accept(req)
	ended := ss.ended
	ss.mu.Unlock()
	switch {
	case ended || errors.Is(err, dialog.ErrNotInDialog):
		s.respond(u, req, 481)
		return
	case errors.Is(err, dialog.ErrOutOfOrder):
		s.respond(u, req, 500)
		return
	case err != nil:
		s.respond(u, req, 400)
		return
	}
	switch req.Method {
	case "BYE":
		s.cfg.Metrics.Count("sip.bye.received", 1)
		// Ended before the 200 leaves, so that what the other side does
		// next finds the session gone.
		carried := ss.leg.Carried()
		switch {
		case !ss.end():
		case ss.inv.Recipient != "" && !carried && directionRefusedBy(req):
			// The client answered passive and pcscf ended the session
			// before any MSRP traffic (ADR 0004): it takes no session
			// from the network. A session that carried messages was
			// served, whatever its BYE says.
			s.engine.InviteFailed(ss.inv, messaging.ErrNoSessions)
		case ss.group != "" && leaves(req):
			s.left(ctx, ss)
		}
		s.respond(u, req, 200)
	case "INVITE", "UPDATE":
		s.refresh(u, ss, req)
	case "OPTIONS":
		s.respond(u, req, 200)
	case "REFER":
		if ss.group == "" {
			// A 1-to-1 chat has nobody to add.
			s.respondWith(u, req, 405, [2]string{"Allow", allowed})
			return
		}
		s.refer(ctx, u, ss, req)
	default:
		s.respond(u, req, 405)
	}
}

// inSubscription serves a request in a subscription's dialog: a SUBSCRIBE
// that refreshes or ends it; nothing else is taken there.
func (s *Server) inSubscription(ctx context.Context, u *proxy.UAS, sub *subscription, req *sip.Request) {
	sub.mu.Lock()
	err := sub.d.Accept(req)
	ended := sub.ended
	sub.mu.Unlock()
	switch {
	case ended || errors.Is(err, dialog.ErrNotInDialog):
		s.respond(u, req, 481)
	case errors.Is(err, dialog.ErrOutOfOrder):
		s.respond(u, req, 500)
	case err != nil:
		s.respond(u, req, 400)
	case req.Method != "SUBSCRIBE":
		s.respondWith(u, req, 405, [2]string{"Allow", "SUBSCRIBE"})
	default:
		s.resubscribe(ctx, u, sub, req)
	}
}

// directionRefusedBy reports a BYE whose Reason is SIP cause 488, with
// which pcscf ends a session whose client answered passive (ADR 0004).
func directionRefusedBy(req *sip.Request) bool { return sipCause(req, 488) }

// sipCause reports a request whose Reason names SIP cause code (RFC 3326).
func sipCause(req *sip.Request, code int) bool {
	reasons, err := req.Header.Reason()
	if err != nil {
		return false
	}
	return slices.ContainsFunc(reasons, func(r sip.Reason) bool {
		cause, ok := r.Cause()
		return ok && cause == code && strings.EqualFold(r.Protocol, "SIP")
	})
}

// refresh answers a re-INVITE or UPDATE in ss. One whose offer keeps the
// MSRP path refreshes the session timer; one that moves it is refused
// (488), since a leg does not move. A re-INVITE without an offer gets the
// session's last SDP as the offer in its 2xx, with the same o= version, as
// nothing changed (RFC 3261 §14.2, RFC 3264 §8, RFC 4028 §7.4), and the
// answer in its ACK must keep the path. An UPDATE without an offer is a
// plain refresh, whose 2xx carries no SDP (RFC 3311 §5.2).
func (s *Server) refresh(u *proxy.UAS, ss *session, req *sip.Request) {
	if s.refuseUnsupported(u, req, "timer") {
		return
	}
	var body []byte
	offerless := req.Method == "INVITE" && len(req.Body) == 0
	switch {
	case offerless:
		var err error
		if body, err = ss.offerAgain(); err != nil {
			s.respond(u, req, 500)
			return
		}
	case len(req.Body) > 0:
		offer, i, path, code := msrpOffer(&req.Header, req.Body)
		ss.mu.Lock()
		moved := code == 0 && joinPath(path) != ss.remotePath
		ss.mu.Unlock()
		if code != 0 || moved {
			s.cfg.Metrics.Count("sip.refresh.refused", 1)
			s.respond(u, req, 488)
			return
		}
		var err error
		if body, err = ss.answerRefresh(offer, i); err != nil {
			s.respond(u, req, 488)
			return
		}
	}
	interval, code := sessionInterval(req)
	if code != 0 {
		s.respond(u, req, code)
		return
	}
	ss.mu.Lock()
	tag := ss.d.LocalTag()
	ss.mu.Unlock()
	res, err := sip.NewResponse(req, 200, "", tag)
	if err != nil || s.sessionHeaders(res, ss.contact(), body, interval) != nil {
		return // the proxy answers 500
	}
	ss.mu.Lock()
	ss.interval = interval
	ss.mu.Unlock()
	if err := u.Respond(res); err != nil {
		s.cfg.Metrics.Count("sip.respond_failed", 1)
		return
	}
	s.cfg.Metrics.Count("sip.refresh.answered", 1)
	ss.arm()
	if offerless {
		go ss.checkAnswer(u)
	}
}

// checkAnswer takes the ACK of an offerless re-INVITE's 2xx, whose answer
// must keep the session's MSRP path; a 2xx without its ACK, or an answer
// that moves the leg, ends the session (RFC 3261 §13.3.1.4).
func (ss *session) checkAnswer(u *proxy.UAS) {
	ack, err := u.ACK(context.Background())
	if err != nil {
		ss.s.cfg.Metrics.Count("sip.session.no_ack", 1)
		ss.bye("")
		return
	}
	answer, err := sdpBody(&ack.Header, ack.Body)
	if err != nil {
		return // no answer: the session goes on as it was
	}
	_, path, _, err := firstMSRP(answer, sdp.SetupActive)
	ss.mu.Lock()
	moved := err != nil || joinPath(path) != ss.remotePath
	ss.mu.Unlock()
	if moved {
		ss.s.cfg.Metrics.Count("sip.refresh.refused", 1)
		ss.bye("")
	}
}
