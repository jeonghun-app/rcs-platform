package sipas

import (
	"context"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// maxRegistrations bounds the registrations rcs-as remembers; past it, one
// is forgotten, and its next refresh is taken for a new registration.
const maxRegistrations = 100_000

// register takes scscf's third-party REGISTER (TS 24.229 §5.4.1.7) for the
// user in To: what is queued for the user may go now.
//
// A registration rcs-as has not heard of, or whose last one has run out,
// counts as one on a new flow (messaging.Engine.UserRegistered), which
// lets a client that once answered passive be offered sessions again (ADR
// 0004); a refresh does not. The third-party REGISTER does not say which
// flow the client registered on, so a client that moves to a new flow
// before its registration runs out is taken as refreshing. A
// de-registration (Expires: 0) only forgets the user: delivery then finds
// it offline.
func (s *Server) register(_ context.Context, u *proxy.UAS) {
	req := u.Request().Message
	to, err := req.Header.To()
	if err != nil {
		s.respond(u, req, 400)
		return
	}
	user, ok := messaging.UserOf(to.URI.String(), s.cfg.HomeDomain)
	if !ok {
		s.respond(u, req, 400)
		return
	}
	// RFC 3261 §10.2.1 lets a REGISTER give the expiry in Expires or in
	// each Contact; the third-party REGISTER uses Expires.
	expires, err := req.Header.Expires()
	if err != nil {
		s.respond(u, req, 400)
		return
	}
	// Taken before the 200 leaves, so that the next REGISTER for the user
	// finds this one.
	now := s.cfg.Clock.Now()
	s.mu.Lock()
	until, known := s.registered[user]
	fresh := !known || !now.Before(until)
	if expires == 0 {
		delete(s.registered, user)
	} else {
		if !known && len(s.registered) >= maxRegistrations {
			for k := range s.registered {
				delete(s.registered, k)
				break
			}
		}
		s.registered[user] = now.Add(time.Duration(expires) * time.Second)
	}
	s.mu.Unlock()
	if expires == 0 {
		s.cfg.Metrics.Count("sip.register.ended", 1)
	} else {
		s.cfg.Metrics.Count("sip.register.taken", 1)
		s.engine.UserRegistered(user, fresh)
	}
	s.respond(u, req, 200)
}
