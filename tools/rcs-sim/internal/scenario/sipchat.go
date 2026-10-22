package scenario

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/sdp"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/chat"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/sipua"
)

// chatAcceptTypes are what a chat session carries (RCC.07): CPIM, and
// is-composing indications; CPIM wraps the text and the notifications.
var (
	chatAcceptTypes  = []string{cpim.ContentType, "application/im-iscomposing+xml"}
	chatWrappedTypes = []string{"text/plain", imdn.ContentType}
)

// errNoRelay fails chat-invite without the relay's address, and errNotRelay
// an answer whose a=path is not the relay's: a P-CSCF that did not anchor
// the chat passes rcs-as's own path on, which a client on the same network
// could connect to and chat through, the relay left out (code review on
// #553).
var (
	errNoRelay  = errors.New("no relay address configured (-relay-public)")
	errNotRelay = errors.New("the answer's a=path is not msrp-relay's client_path (ADR 0004)")
)

// atRelay reports whether u is msrp-relay's: its host and port those of
// Config.RelayPublic, over TCP, as every client_path is.
func (r *run) atRelay(u msrp.URI) bool {
	host, port, err := net.SplitHostPort(r.cfg.RelayPublic)
	return err == nil && strings.EqualFold(u.Host, host) && strconv.Itoa(u.Port) == port && u.Transport == "tcp"
}

// refuseCall answers call code and keeps why, which the step then waiting
// for the peer reports (peerRefused) instead of a time out.
func (r *run) refuseCall(call *sipua.IncomingCall, code int, why string) {
	r.refusalMu.Lock()
	r.refusal = why
	r.refusalMu.Unlock()
	_ = call.Reject(code)
}

// peerRefused is the reason the peer last refused an offer, as an error,
// or err if it refused none.
func (r *run) peerRefused(err error) error {
	r.refusalMu.Lock()
	defer r.refusalMu.Unlock()
	if r.refusal != "" {
		return errors.New(r.refusal)
	}
	return err
}

// releasePoll is how long the released step waits between binds, while
// pcscf's release of the binding is on its way.
const releasePoll = 50 * time.Millisecond

// sipChatText starts the text of each message this scenario sends; a token
// of the run follows, which tells its messages from an earlier run's.
const sipChatText = "hello over SIP"

// peerSession is a chat the network opened to the peer: the INVITE's
// dialog and the session the peer bound at the relay.
type peerSession struct {
	dialog *sipua.Dialog
	client *chat.Client
}

// chatInvite is the chat-invite scenario (#135 AC 4): the client sends an
// INVITE for a 1-to-1 chat with an MSRP offer to the peer's IMPU, through
// the P-CSCF, which anchors it at msrp-relay, and the S-CSCF, whose iFC
// take it to rcs-as. The answer names the relay's client_path, and the
// client connects to it actively (RFC 6135). The network opens a chat to
// the peer for what the client sends, by an INVITE of its own, which the
// peer answers and connects to the relay for. Then a message each way, each
// with its success report and its delivery and display notifications, and
// a BYE, after which the relay no longer binds the client's session.
func chatInvite(r *run) error {
	switch {
	case r.cfg.SIP == nil:
		return r.step("register", func(context.Context) (map[string]int64, error) { return nil, errNoSIP })
	case r.cfg.SIPPeer == nil:
		return r.step("register", func(context.Context) (map[string]int64, error) { return nil, errNoPeer })
	case r.cfg.RelayPublic == "":
		return r.step("register", func(context.Context) (map[string]int64, error) { return nil, errNoRelay })
	}
	calls := make(chan *sipua.IncomingCall, queueLength)
	var a, b *sipClient
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
		// The peer's chats come through OnInvite.
		if b, err = r.newSIPClient(ctx, peer, r.cfg.Peer); err != nil {
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
	aEnd := r.endpoint(r.cfg.Self, false)
	// The peer reads at once, so its display notifications go out without
	// a step for them.
	bEnd := r.endpoint(r.cfg.Peer, true)
	sessions := make(chan peerSession, queueLength)
	answerer, stop := context.WithCancel(context.Background())
	answering := make(chan struct{})
	go func() {
		defer close(answering)
		r.answerCalls(answerer, calls, bEnd, sessions)
	}()
	// The answerer ends what it opened once stopped; the scenario's end
	// waits for that.
	r.onEnd(func() { stop(); <-answering })

	local, err := chat.LocalURI(r.cfg.Rand)
	if err != nil {
		return err
	}
	var dialog *sipua.Dialog
	var relayPath msrp.URI
	if err := r.step("invite", func(ctx context.Context) (map[string]int64, error) {
		offer, err := chatSDP(local, sdp.SetupActive)
		if err != nil {
			return nil, err
		}
		req, err := a.ua.NewInvite(r.cfg.SIPPeer.IMPU, offer)
		if err != nil {
			return nil, err
		}
		d, res, err := a.ua.Invite(ctx, req, nil)
		if err != nil {
			return nil, sipError(err)
		}
		detail := map[string]int64{"status": int64(res.StatusCode)}
		if d == nil {
			// A network that passes the INVITE on to the peer, as the
			// unit tests' stand-in core does, answers with the peer's
			// refusal.
			return detail, r.peerRefused(fmt.Errorf("INVITE answered %d", res.StatusCode))
		}
		dialog = d
		r.onEnd(func() { r.hangUp(d) })
		path, setup, err := chatAnswer(res.Body)
		if err != nil {
			return detail, err
		}
		if setup != sdp.SetupPassive {
			return detail, fmt.Errorf("the answer's a=setup is %s, want passive: the client connects (RFC 6135)", setup)
		}
		if !r.atRelay(path) {
			return detail, errNotRelay
		}
		relayPath = path
		return detail, nil
	}); err != nil {
		return err
	}
	var aConn *chat.Client
	if err := r.step("connect", func(ctx context.Context) (map[string]int64, error) {
		c, err := chat.Dial(ctx, relayPath, local, aEnd, r.cfg.MSRP, r.cfg.TLS, nil)
		if err != nil {
			return nil, err
		}
		aConn = c
		r.onEnd(func() { _ = c.Close() })
		return nil, nil
	}); err != nil {
		return err
	}
	var peer peerSession
	if err := r.step("client-to-peer", func(ctx context.Context) (map[string]int64, error) {
		text := []byte(sipChatText + " " + token)
		sent, err := aEnd.Send(ctx, aConn.Session, bEnd.Self, "text/plain;charset=UTF-8", text, imdn.PositiveDelivery|imdn.Display)
		if err != nil {
			return nil, err
		}
		if err := waitReport(ctx, aEnd, sent.MSRP); err != nil {
			return nil, err
		}
		got, skipped, err := awaitChat(ctx, bEnd, sent.IMDN, token)
		detail := map[string]int64{"skipped": int64(skipped)}
		if err != nil {
			return detail, r.peerRefused(err)
		}
		if !bytes.Equal(got.Body, text) || got.From.URI != aEnd.Self.URI {
			return detail, errors.New("the message arrived changed")
		}
		// The session the network opened to the peer for it, the latest.
		if peer, err = latestSession(ctx, sessions, peer); err != nil {
			return detail, r.peerRefused(err)
		}
		return detail, awaitNotifications(ctx, aEnd, sent.IMDN, bEnd.Self.URI)
	}); err != nil {
		return err
	}
	if err := r.step("peer-to-client", func(ctx context.Context) (map[string]int64, error) {
		text := []byte(sipChatText + " back " + token)
		sent, err := bEnd.Send(ctx, peer.client.Session, aEnd.Self, "text/plain;charset=UTF-8", text, imdn.PositiveDelivery|imdn.Display)
		if err != nil {
			return nil, err
		}
		if err := waitReport(ctx, bEnd, sent.MSRP); err != nil {
			return nil, err
		}
		got, skipped, err := awaitChat(ctx, aEnd, sent.IMDN, token)
		detail := map[string]int64{"skipped": int64(skipped)}
		if err != nil {
			return detail, err
		}
		if !bytes.Equal(got.Body, text) || got.From.URI != bEnd.Self.URI {
			return detail, errors.New("the message arrived changed")
		}
		if err := aEnd.Display(ctx, aConn.Session, got); err != nil {
			return detail, fmt.Errorf("sending the display notification: %w", err)
		}
		return detail, awaitNotifications(ctx, bEnd, sent.IMDN, aEnd.Self.URI)
	}); err != nil {
		return err
	}
	if err := r.step("chunked-message", func(ctx context.Context) (map[string]int64, error) {
		// Large enough to travel in internal/msrp's 2 KiB chunks through
		// the relay and rcs-as, as text, which rcs-as stores and sends on.
		raw, err := r.content(largeMessage / 2)
		if err != nil {
			return nil, err
		}
		text := []byte(token + " " + hex.EncodeToString(raw))
		sent, err := aEnd.Send(ctx, aConn.Session, bEnd.Self, "text/plain;charset=UTF-8", text, imdn.PositiveDelivery|imdn.Display)
		if err != nil {
			return nil, err
		}
		detail := map[string]int64{"bytes": int64(len(text))}
		if err := waitReport(ctx, aEnd, sent.MSRP); err != nil {
			return detail, err
		}
		got, skipped, err := awaitChat(ctx, bEnd, sent.IMDN, token)
		detail["skipped"] = int64(skipped)
		if err != nil {
			return detail, err
		}
		if !bytes.Equal(got.Body, text) {
			return detail, errors.New("the message arrived changed")
		}
		return detail, awaitNotifications(ctx, aEnd, sent.IMDN, bEnd.Self.URI)
	}); err != nil {
		return err
	}
	if err := r.step("bye", func(ctx context.Context) (map[string]int64, error) {
		res, err := dialog.Bye(ctx)
		if err != nil {
			return nil, sipError(err)
		}
		if res.StatusCode != 200 {
			return map[string]int64{"status": int64(res.StatusCode)}, fmt.Errorf("BYE answered %d", res.StatusCode)
		}
		return nil, nil
	}); err != nil {
		return err
	}
	if err := r.step("released", func(ctx context.Context) (map[string]int64, error) {
		// The client ends its MSRP session with the SIP one, as a device
		// does: the relay does not cut a running bridge at a release
		// (docs/msrp-relay.md).
		_ = aConn.Close()
		// pcscf releases the binding on the BYE, but not before it passes
		// the 200 on: the release may still be on its way. So the client
		// binds again until the relay refuses it with 481 (#135 AC 4).
		// Until then the binding is there, claimed by the client's first
		// connection, and the relay answers another one 403
		// (docs/msrp-relay.md); a bind that succeeds is closed. Each try
		// is counted.
		attempts := int64(0)
		for {
			attempts++
			again, err := chat.LocalURI(r.cfg.Rand)
			if err != nil {
				return nil, err
			}
			c, err := chat.Dial(ctx, relayPath, again, r.endpoint(r.cfg.Self, false), r.cfg.MSRP, r.cfg.TLS, nil)
			var se *msrp.StatusError
			// A dial cut by the step's deadline can fail a moment before
			// ctx says so: the step's time ran out either way.
			late := ctx.Err() != nil
			if d, ok := ctx.Deadline(); ok && !time.Now().Before(d) {
				late = true
			}
			switch {
			case err == nil:
				_ = c.Close()
			case errors.As(err, &se) && se.Code == msrp.StatusNoSession:
				return map[string]int64{"binds": attempts}, nil
			case errors.As(err, &se) && se.Code == msrp.StatusForbidden:
			case late:
				return map[string]int64{"binds": attempts}, errors.New("the relay still binds the session after the BYE")
			default:
				return map[string]int64{"binds": attempts}, fmt.Errorf("binding the session after the BYE: %w, want 481", err)
			}
			select {
			case <-time.After(releasePoll):
			case <-ctx.Done():
				return map[string]int64{"binds": attempts}, errors.New("the relay still binds the session after the BYE")
			}
		}
	}); err != nil {
		return err
	}
	if err := r.step("peer-offline", func(ctx context.Context) (map[string]int64, error) {
		return r.chatToOfflinePeer(ctx, b, a, aEnd, bEnd, token)
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

// chatToOfflinePeer is the peer-offline step (#135 AC 4): the peer
// unregisters and the client opens a chat to it and sends a message. A
// network without store-and-forward, as the unit tests' stand-in core,
// answers the INVITE 480, which passes. One that answers it 2xx, as rcs-as
// does, must store the message: once the peer registers again the network
// opens a chat to it, and the message, its text and Message-ID intact,
// arrives there, and its notifications come back to the client (stored).
// One that accepts the chat and loses the message fails.
func (r *run) chatToOfflinePeer(ctx context.Context, b, a *sipClient, aEnd, bEnd *chat.Endpoint, token string) (map[string]int64, error) {
	if _, err := b.ua.Unregister(ctx); err != nil {
		return nil, fmt.Errorf("peer: %w", sipError(err))
	}
	local, err := chat.LocalURI(r.cfg.Rand)
	if err != nil {
		return nil, err
	}
	offer, err := chatSDP(local, sdp.SetupActive)
	if err != nil {
		return nil, err
	}
	req, err := a.ua.NewInvite(r.cfg.SIPPeer.IMPU, offer)
	if err != nil {
		return nil, err
	}
	d, res, err := a.ua.Invite(ctx, req, nil)
	if err != nil {
		return nil, sipError(err)
	}
	detail := map[string]int64{"status": int64(res.StatusCode)}
	switch {
	case res.StatusCode == 480:
		return detail, nil
	case d == nil:
		return detail, fmt.Errorf("INVITE to the unregistered peer answered %d, want 480 or store-and-forward", res.StatusCode)
	}
	defer r.hangUp(d)
	path, setup, err := chatAnswer(res.Body)
	if err != nil {
		return detail, err
	}
	if setup != sdp.SetupPassive {
		return detail, fmt.Errorf("the answer's a=setup is %s, want passive: the client connects (RFC 6135)", setup)
	}
	if !r.atRelay(path) {
		return detail, errNotRelay
	}
	c, err := chat.Dial(ctx, path, local, aEnd, r.cfg.MSRP, r.cfg.TLS, nil)
	if err != nil {
		return detail, err
	}
	defer c.Close()
	text := []byte(sipChatText + " kept " + token)
	sent, err := aEnd.Send(ctx, c.Session, bEnd.Self, "text/plain;charset=UTF-8", text, imdn.PositiveDelivery|imdn.Display)
	if err != nil {
		return detail, err
	}
	// The network took the message for the peer, unregistered.
	if err := waitReport(ctx, aEnd, sent.MSRP); err != nil {
		return detail, err
	}
	if _, err := b.ua.Register(ctx); err != nil {
		return detail, fmt.Errorf("peer: %w", sipError(err))
	}
	got, skipped, err := awaitChat(ctx, bEnd, sent.IMDN, token)
	detail["skipped"] = int64(skipped)
	if err != nil {
		return detail, fmt.Errorf("the message to the unregistered peer never arrived after it registered again: %w", r.peerRefused(err))
	}
	if !bytes.Equal(got.Body, text) {
		return detail, errors.New("the stored message changed on the way")
	}
	if err := awaitNotifications(ctx, aEnd, sent.IMDN, bEnd.Self.URI); err != nil {
		return detail, err
	}
	detail["stored"] = 1
	return detail, nil
}

// answerCalls answers each chat the network opens to the peer: an MSRP
// offer naming the relay, a=setup:actpass, answered with the peer's own
// path and a=setup:active, and the peer connecting to the relay at once, as
// a device behind NAT does. Each session goes to sessions; an offer the
// peer cannot take is refused 488, and why is kept for the step waiting on
// the peer (peerRefused). It runs on a goroutine of its own until ctx
// ends, and then closes the sessions it opened and hangs up their dialogs
// before it returns: the caller cancels ctx and waits for it at the
// scenario's end (onEnd is the scenario goroutine's alone).
func (r *run) answerCalls(ctx context.Context, calls <-chan *sipua.IncomingCall, end *chat.Endpoint, sessions chan<- peerSession) {
	var opened []peerSession
	defer func() {
		for _, s := range opened {
			_ = s.client.Close()
			r.hangUp(s.dialog)
		}
	}()
	for {
		var call *sipua.IncomingCall
		select {
		case call = <-calls:
		case <-ctx.Done():
			return
		}
		// The network offers actpass (RFC 6135 §4.2.2 forbids passive in
		// an offer) with the relay's client_path, as pcscf writes it.
		path, setup, err := chatAnswer(call.Request().Body)
		switch {
		case err != nil:
			r.refuseCall(call, 488, "the network's offer to the peer has no MSRP path it can take")
			continue
		case setup != sdp.SetupActPass:
			r.refuseCall(call, 488, "the network's offer to the peer has a=setup:"+string(setup)+", not actpass (RFC 6135 §4.2.2)")
			continue
		case !r.atRelay(path):
			r.refuseCall(call, 488, "the network's offer to the peer has an a=path that is not msrp-relay's client_path (ADR 0004)")
			continue
		}
		local, err := chat.LocalURI(r.cfg.Rand)
		if err != nil {
			_ = call.Reject(500)
			continue
		}
		answer, err := chatSDP(local, sdp.SetupActive)
		if err != nil {
			_ = call.Reject(500)
			continue
		}
		d, err := call.Accept(answer)
		if err != nil {
			continue
		}
		dctx, cancel := context.WithTimeout(ctx, r.cfg.StepTimeout)
		c, err := chat.Dial(dctx, path, local, end, r.cfg.MSRP, r.cfg.TLS, nil)
		cancel()
		if err != nil {
			r.hangUp(d)
			continue
		}
		s := peerSession{dialog: d, client: c}
		opened = append(opened, s)
		select {
		case sessions <- s:
		default:
		}
	}
}

// hangUp ends d with a BYE, unless it has ended.
func (r *run) hangUp(d *sipua.Dialog) {
	select {
	case <-d.Done():
		return
	default:
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.StepTimeout)
	defer cancel()
	_, _ = d.Bye(ctx)
}

// latestSession returns the newest session the network has opened to the
// peer, or prev if it has opened none since; it waits for one when there is
// none at all.
func latestSession(ctx context.Context, sessions <-chan peerSession, prev peerSession) (peerSession, error) {
	got := prev
	for {
		select {
		case s := <-sessions:
			got = s
			continue
		default:
		}
		if got.client != nil {
			return got, nil
		}
		select {
		case s := <-sessions:
			got = s
		case <-ctx.Done():
			return got, errors.New("the network opened no session to the peer")
		}
	}
}

// awaitChat waits for the chat message with the IMDN Message-ID id, and
// returns it with how many it skipped: a store-and-forward network may first
// deliver what an earlier run left, which another Message-ID and the lack of
// token tell apart. One of this run's (token) with another Message-ID is a
// fault.
func awaitChat(ctx context.Context, e *chat.Endpoint, id, token string) (chat.Received, int, error) {
	for skipped := 0; ; skipped++ {
		select {
		case got := <-e.Messages:
			if got.Request.MessageID == id {
				return got, skipped, nil
			}
			if strings.Contains(string(got.Body), token) {
				return got, skipped, errors.New("the message received is not the one sent")
			}
		case <-ctx.Done():
			return chat.Received{}, skipped, errors.New("the message did not arrive")
		}
	}
}

// awaitNotifications waits for the delivery and the display notification
// that each of recipients, by its URI, sends about the message with IMDN
// Message-ID id: a group's message gets one pair from every invitee (RFC
// 5438 §7.1.2, code review on #553). Each pair counts once; another from a
// recipient, or one from someone the message was not sent to, fails.
// Notifications about other messages, an earlier run's, are passed over.
func awaitNotifications(ctx context.Context, e *chat.Endpoint, id string, recipients ...string) error {
	type pair struct {
		recipient string
		status    imdn.Status
	}
	want := map[pair]bool{}
	for _, who := range recipients {
		want[pair{who, imdn.Delivered}], want[pair{who, imdn.Displayed}] = true, true
	}
	if len(want) == 0 {
		return errors.New("no recipient to wait for notifications from")
	}
	for len(want) > 0 {
		select {
		case n := <-e.Notifications:
			if n.MessageID != id {
				continue
			}
			p := pair{n.RecipientURI, n.Status}
			switch {
			case !slices.Contains(recipients, n.RecipientURI):
				return fmt.Errorf("a %s notification from someone the message was not sent to", n.Status)
			case !want[p]:
				return fmt.Errorf("unexpected %s notification", n.Status)
			}
			delete(want, p)
		case <-ctx.Done():
			return fmt.Errorf("%d notifications did not arrive", len(want))
		}
	}
	return nil
}

// chatSDP is an SDP offer or answer for a chat session from local: an MSRP
// media line with local as its a=path, the chat's accept types and setup.
// The port is 9, the discard port, as an active end that listens on none
// writes (RFC 4145 §4).
func chatSDP(local msrp.URI, setup sdp.Setup) ([]byte, error) {
	var b strings.Builder
	b.WriteString("v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n")
	b.WriteString("m=message " + strconv.Itoa(local.Port) + " TCP/MSRP *\r\n")
	b.WriteString("a=accept-types:" + strings.Join(chatAcceptTypes, " ") + "\r\n")
	b.WriteString("a=accept-wrapped-types:" + strings.Join(chatWrappedTypes, " ") + "\r\n")
	b.WriteString("a=path:" + local.String() + "\r\n")
	b.WriteString("a=setup:" + string(setup) + "\r\n")
	b.WriteString("a=sendrecv\r\n")
	s, err := sdp.Parse([]byte(b.String()))
	if err != nil {
		return nil, err
	}
	return s.Marshal()
}

// chatAnswer reads the MSRP media line of body: the one URI of its a=path,
// which is msrp-relay's client_path on this platform, and its a=setup.
func chatAnswer(body []byte) (msrp.URI, sdp.Setup, error) {
	s, err := sdp.Parse(body)
	if err != nil {
		return msrp.URI{}, "", errors.New("the SDP does not parse")
	}
	for i := range s.Media {
		m := &s.Media[i]
		if !m.IsMSRP() {
			continue
		}
		path, err := m.Path()
		if err != nil || len(path) != 1 {
			return msrp.URI{}, "", errors.New("the SDP's a=path is not one URI")
		}
		u, err := msrp.ParseURI(path[0])
		if err != nil {
			return msrp.URI{}, "", errors.New("the SDP's a=path does not parse")
		}
		setup, err := s.MediaSetup(i)
		if err != nil {
			return msrp.URI{}, "", errors.New("the SDP's a=setup does not parse")
		}
		return u, setup, nil
	}
	return msrp.URI{}, "", errors.New("the SDP has no MSRP media line")
}
