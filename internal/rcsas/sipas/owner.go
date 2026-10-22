package sipas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/group"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
)

// Each group is served by the task that owns it (#121, ADR 0005): its
// sessions, subscriptions and fan-out all live there. A request for a
// group that reaches another task, as the core may send one to any, goes
// on to the owner's SIP instance address, once.

// fwdParam is the URI parameter of the Route with which a task forwards a
// request to the task that owns its group, or wakes it (wakeType): the
// owner serves it, and a task that is not the owner refuses it rather than
// forward it again, so that two tasks whose views differ for a moment
// cannot pass a request between them.
const fwdParam = "rcsas-fwd"

// forwarded reports a request another task sent here for its group.
func forwarded(r *proxy.Request) bool {
	return slices.ContainsFunc(r.Routed, func(a sip.Address) bool { return a.URI.Params.Has(fwdParam) })
}

// toOwner decides a request for the group uri that this task may not
// serve: when it returns true, the Decision forwards the request to the
// group's owner, or answers it 500 with Retry-After when there is no owner
// to forward it to now (this task's heartbeat has lapsed, the store is
// busy, the request was forwarded here already, or the owner's address is
// not one rcs-as forwards to). It is never 404 for a group that exists,
// which rcsjta takes for the group's end and restarts at the factory as a
// group of its own (#121). False leaves the request to this task: the
// group is its own, or there is none, which serving it answers.
func (s *Server) toOwner(ctx context.Context, r *proxy.Request, uri string) (proxy.Decision, bool) {
	if s.groups == nil {
		return proxy.Decision{}, false
	}
	ctx, cancel := context.WithTimeout(ctx, groupTimeout)
	defer cancel()
	mine, at, err := s.groups.Place(ctx, uri)
	switch {
	case errors.Is(err, group.ErrNoGroup), err == nil && mine:
		return proxy.Decision{}, false
	case err == nil && !forwarded(r):
		if next, ok := s.peer(at.SIP); ok {
			s.cfg.Metrics.Count("group.forwarded", 1)
			// No Record-Route: the dialog's requests go to the conference
			// URI, and from wherever they reach, to the owner.
			return proxy.Decision{
				Targets: []proxy.Target{{URI: r.Message.URI, Routes: []sip.Address{{URI: next}}, Timeout: s.forwardWait()}},
				OnFinal: unreached, OnResponse: retryUnreached,
			}, true
		}
	}
	s.cfg.Metrics.Count("group.forward_refused", 1)
	return s.retryDecision(r), true
}

// forwardWait bounds a forward the owner does not answer: half of Timer
// B, so that the client hears 500 with Retry-After before its own
// transaction gives up (RFC 3261 §17.1.1.2); the proxy ends the branch as
// a 504 then (unreached).
const forwardWait = 32 * transaction.DefaultT1

func (s *Server) forwardWait() time.Duration {
	if s.cfg.forwardWait > 0 {
		return s.cfg.forwardWait
	}
	return forwardWait
}

// unreached makes the final response of a forward that never reached the
// owner, a 408, 430 or 504, a 500, which retryUnreached gives a
// Retry-After as it does the proxy's own 500 for a next hop it could not
// reach (§16.7, the transport's 503): a failure to try again, as for any group
// this task cannot serve now: a closed port, or a dial that timed out
// (QA on #464). The owner's own answers, its 404 for a group that has
// ended among them, go as they are.
func unreached(_ context.Context, res *sip.Response) {
	switch res.StatusCode {
	case 408, 430, 504:
		res.StatusCode, res.Reason = 500, sip.DefaultReason(500)
	}
}

// retryUnreached gives the 500 of an unreached forward (unreached) its
// Retry-After.
func retryUnreached(_ context.Context, res *sip.Response) {
	if res.StatusCode == 500 && res.Header.Get("Retry-After") == "" {
		_ = res.Header.Set("Retry-After", busyRetryAfter)
	}
}

// peer is the Route to the task at the SIP instance address at, which the
// store holds for a group's owner, if rcs-as forwards there: a private
// address (RFC 1918, or an IPv6 unique local one) on rcs-as's own SIP port,
// and not this task's. Only tasks write the address, but it is checked all
// the same before anything is sent to it (#121 design, security review).
func (s *Server) peer(at string) (sip.URI, bool) {
	ap, err := netip.ParseAddrPort(at)
	if err != nil || ap.Addr().Zone() != "" {
		// A zone names an interface of the writer's, and no URI host
		// (security review and QA on #464).
		return sip.URI{}, false
	}
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	var ok bool
	if s.cfg.peers != nil {
		ok = s.cfg.peers(ap)
	} else {
		own, err := netip.ParseAddr(strings.Trim(s.cfg.Contact.Host, "[]"))
		ok = ap.Addr().IsPrivate() && int(ap.Port()) == s.cfg.Contact.Port && (err != nil || ap.Addr() != own.Unmap())
	}
	if !ok {
		s.cfg.Metrics.Count("group.forward_refused.address", 1)
		return sip.URI{}, false
	}
	host := ap.Addr().String()
	if ap.Addr().Is6() {
		host = "[" + host + "]"
	}
	u := sip.URI{Scheme: "sip", Host: host, Port: int(ap.Port())}
	u.Params.Set("transport", "tcp")
	u.Params.SetFlag("lr")
	u.Params.SetFlag(fwdParam)
	return u, true
}

// retryDecision answers r 500 with Retry-After, which scscf passes on as it
// is, and which rcsjta takes for a failure to try again (submit).
func (s *Server) retryDecision(r *proxy.Request) proxy.Decision {
	tag, err := s.ids.Tag()
	if err != nil {
		return proxy.Decision{Status: 500}
	}
	res, err := sip.NewResponse(r.Message, 500, "", tag)
	if err != nil || res.Header.Set("Retry-After", busyRetryAfter) != nil {
		return proxy.Decision{Status: 500}
	}
	return proxy.Decision{Response: res}
}

// groupOf is the conference URI of the group req is for: the one its
// Request-URI names, or for the factory, the one its Contribution-ID makes
// or takes up (group.Service.URIFor). False when it names none, which
// serving the request answers.
// A creator over its rate for new groups is left to Create, which refuses
// it before any store read: looking its group up first would cost a read
// for each such INVITE (security review on #464).
func (s *Server) groupOf(req *sip.Request) (string, bool) {
	if !s.isFactory(req.URI) {
		return s.conferenceURI(req.URI)
	}
	c := req.Header.Get("Contribution-ID")
	if c == "" || s.groups == nil {
		return "", false
	}
	if creator, _, ok := s.assertedUser(req); ok && !s.groups.CanCreate(creator) {
		return "", false
	}
	return s.groups.URIFor(c), true
}

// inDialogElsewhere decides an in-dialog request, an ACK included, to a
// conference URI whose dialog this task does not hold: the Contact of a
// group's sessions and subscriptions is the conference URI (RFC 4579), so
// the core may send their requests to any task, and the owner holds them.
// False leaves the request to this task.
func (s *Server) inDialogElsewhere(ctx context.Context, r *proxy.Request) (proxy.Decision, bool) {
	if !s.cfg.GroupChat || !s.atConference(r.Message.URI) {
		return proxy.Decision{}, false
	}
	uri, ok := s.conferenceURI(r.Message.URI)
	if !ok || s.sessionOf(r.Message) != nil || s.subscriptionOf(r.Message) != nil {
		return proxy.Decision{}, false
	}
	return s.toOwner(ctx, r, uri)
}

// wakeType is the content type of the MESSAGE with which a task asks the
// owner of a group to read a participant's queue again (WakeOwner).
const wakeType = "application/vnd.rcsplatform.group-wake+json"

// wake is the body of a wake MESSAGE; the group is its Request-URI.
// Registered says the user registered on a new flow at the sender since
// its last wake for the group (messaging.Engine.Wake).
type wake struct {
	User       string `json:"user"`
	Registered bool   `json:"registered,omitempty"`
}

// maxWakeUser bounds the identity a wake names, as long as any a queue is
// kept for.
const maxWakeUser = 256

// WakeOwner implements group.Notifier: it sends the task at at, which owns
// the group uri, a MESSAGE that has it read user's queue again (#121 T8).
// It goes to the owner directly, as a forwarded request does, without
// waiting for the answer: a wake lost costs the copy its wait for the
// owner's own retry.
func (s *Server) WakeOwner(ctx context.Context, at, uri, user string, registered bool) error {
	next, ok := s.peer(at)
	if !ok {
		return errors.New("sipas: no route to the group's owner")
	}
	target, err := sip.ParseURI(uri)
	if err != nil {
		return err
	}
	body, err := json.Marshal(wake{User: user, Registered: registered})
	if err != nil {
		return err
	}
	// Not ownTag: the request is for a conference URI rcs-as hosts, which
	// must not be taken for one of its own come back (looped, #242).
	tag, err := s.ids.Tag()
	if err != nil {
		return err
	}
	callID, err := s.ids.CallID(s.cfg.Host)
	if err != nil {
		return err
	}
	from := sip.Address{URI: s.cfg.Contact}
	from.Params.Set("tag", tag)
	req := &sip.Request{Method: "MESSAGE", URI: target, Body: body}
	for _, f := range [][2]string{
		{"Max-Forwards", "70"},
		{"Route", "<" + next.String() + ">"},
		{"From", from.String()},
		{"To", "<" + uri + ">"},
		{"Call-ID", callID},
		{"CSeq", "1 MESSAGE"},
		{"Content-Type", wakeType},
	} {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			return err
		}
	}
	dst, err := s.cfg.Resolver.Resolve(ctx, next)
	if err != nil {
		return err
	}
	dst.Listener = s.cfg.Listener
	branch, err := s.ids.Branch()
	if err != nil {
		return err
	}
	v := sip.Via{Transport: string(networkOf(dst)), Host: viaPlaceholderHost}
	v.Params.Set("branch", branch)
	if err := req.Header.Prepend("Via", v.String()); err != nil {
		return err
	}
	_, err = s.layer.Request(req, dst, func(res *sip.Response, err error) {
		switch {
		case err != nil:
			s.cfg.Metrics.Count("sip.group.wake.timeout", 1)
		case res.StatusCode >= 200:
			s.cfg.Metrics.Count(fmt.Sprintf("sip.group.wake.%d", res.StatusCode), 1)
		}
	})
	return err
}

// isWake reports a wake MESSAGE another task sent (WakeOwner).
func isWake(r *proxy.Request) bool {
	ct, err := r.Message.Header.ContentType()
	return err == nil && forwarded(r) && strings.EqualFold(ct.Type+"/"+ct.Subtype, wakeType)
}

// groupWake serves a wake MESSAGE: if this task owns the group, its engine
// reads the user's queue again (messaging.Engine.Wake). It is answered 200
// either way, once it reads: a task that does not own the group has
// nothing to do for it.
func (s *Server) groupWake(ctx context.Context, u *proxy.UAS) {
	req := u.Request().Message
	uri, ok := s.conferenceURI(req.URI)
	var w wake
	if !ok || json.Unmarshal(req.Body, &w) != nil || w.User == "" || len(w.User) > maxWakeUser {
		s.respond(u, req, 400)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, groupTimeout)
	defer cancel()
	if mine, _, err := s.groups.Place(ctx, uri); err == nil && mine {
		s.cfg.Metrics.Count("sip.group.woken", 1)
		s.engine.Wake(w.User, uri, w.Registered)
	}
	s.respond(u, req, 200)
}

// ackWait bounds how long a session Disowned ends waits for its 2xx's ACK:
// Timer H, 64*T1, after which the server transaction gives up on it (RFC
// 3261 §17.2.1).
const ackWait = 64 * transaction.DefaultT1

// Disowned implements group.Notifier: this task no longer owns the group
// uri, so the sessions and subscriptions it holds of it end, the sessions
// with a BYE, the subscriptions with reason=deactivated, which lets the
// subscriber subscribe again at once (RFC 6665 §4.2.2). The participants
// rejoin through the group's owner (the lead's decision on #121, Q4). A
// session whose 2xx is not acknowledged yet gets its BYE once the ACK
// comes, or Timer H runs out (RFC 3261 §15; code review on #464), each on
// a goroutine of its own, so that neither the request nor the heartbeat
// that found the group lost waits for it.
func (s *Server) Disowned(uri string) {
	s.mu.Lock()
	var ended []*session
	for _, ss := range s.sessions {
		if ss.group == uri {
			ended = append(ended, ss)
		}
	}
	subs := slices.Collect(maps.Keys(s.groupSubs[uri]))
	s.mu.Unlock()
	for _, sub := range subs {
		sub.mu.Lock()
		if !sub.ended {
			sub.end(reasonDeactivated)
		}
		sub.mu.Unlock()
	}
	for _, ss := range ended {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), ackWait)
			defer cancel()
			ss.byeConfirmed(ctx)
		}()
	}
	s.cfg.Metrics.Count("sip.group.disowned.sessions", int64(len(ended)))
}
