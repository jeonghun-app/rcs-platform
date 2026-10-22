package routing

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// addressedSender sends to the destination it is given, as scscf's sender
// does: one at deadAS cannot be connected to, and fail says how a send to
// another address ends.
type addressedSender struct {
	mu   sync.Mutex
	to   []netip.AddrPort
	fail error
}

func (s *addressedSender) Send(context.Context, *sip.Request) (*sip.Response, error) {
	return nil, errors.New("sent without an address")
}

func (s *addressedSender) SendTo(_ context.Context, req *sip.Request, dst transport.Destination) (*sip.Response, error) {
	s.mu.Lock()
	s.to = append(s.to, dst.Addr)
	fail := s.fail
	s.mu.Unlock()
	switch {
	case dst.Addr == deadAS:
		return nil, fmt.Errorf("%w: dial tcp %v: connection refused", ErrNotSent, dst.Addr)
	case fail != nil:
		return nil, fail
	}
	return sip.NewResponse(req, 200, "", "as")
}

func (s *addressedSender) sentTo() []netip.AddrPort {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]netip.AddrPort(nil), s.to...)
}

// TestAThirdPartyREGISTERGoesOnToTheNextAddress (#580): the server's name
// resolves to a stopped task and a live one; the REGISTER, which could
// not be sent to the stopped one, goes to the live one and is answered,
// and the stopped task is tried last for the DNS TTL.
func TestAThirdPartyREGISTERGoesOnToTheNextAddress(t *testing.T) {
	e := newEnv(t)
	e.profile(t0, criterion(40, rcsAS, registerTrigger(), ifc.SessionContinued))
	s := &addressedSender{}
	rt := e.router(nil, withSender(s), withResolver(fixedAddresses{deadAS, liveAS}))
	rt.Registered(bg, registration(t, ifc.InitialRegistration, time.Hour))
	deadline := time.Now().Add(10 * time.Second)
	for e.metrics.get("routing.third_party.registered") < 1 {
		if time.Now().After(deadline) {
			t.Fatal("the REGISTER was not answered")
		}
		time.Sleep(time.Millisecond)
	}
	if got := s.sentTo(); len(got) != 2 || got[0] != deadAS || got[1] != liveAS {
		t.Fatalf("sent to %v, want the stopped task and then the live one", got)
	}
	if e.metrics.get("routing.as_failover") != 1 || e.metrics.get("routing.third_party.unanswered") != 0 {
		t.Errorf("failovers %d, unanswered %d", e.metrics.get("routing.as_failover"), e.metrics.get("routing.third_party.unanswered"))
	}
	rt.Registered(bg, registration(t, ifc.ReRegistration, time.Hour))
	rt.Stop()
	if got := s.sentTo(); len(got) != 3 || got[2] != liveAS {
		t.Errorf("the next REGISTER went to %v, want the live task first", got[2:])
	}
}

// TestAThirdPartyREGISTERThatMayHaveArrivedIsNotFailedOver (#580): once a
// REGISTER was written, a timeout or a lost connection may come after the
// server had it, so it does not go to another address.
func TestAThirdPartyREGISTERThatMayHaveArrivedIsNotFailedOver(t *testing.T) {
	for name, fail := range map[string]error{
		"timer F":              transaction.ErrTimeout,
		"reset":                errors.New("connection reset by peer"),
		"its time":             context.DeadlineExceeded,
		"too many connections": fmt.Errorf("%w: %w", ErrNotSent, transport.ErrTooManyConnections),
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.profile(t0, criterion(40, rcsAS, registerTrigger(), ifc.SessionContinued))
			s := &addressedSender{fail: fail}
			rt := e.router(nil, withSender(s), withResolver(fixedAddresses{liveAS, otherLiveAS}))
			rt.Registered(bg, registration(t, ifc.InitialRegistration, time.Hour))
			rt.Stop()
			if got := s.sentTo(); len(got) != 1 {
				t.Errorf("sent to %v, want the first address only", got)
			}
			if e.metrics.get("routing.as_failover") != 0 || e.metrics.get("routing.third_party.unanswered") != 1 {
				t.Errorf("failovers %d, unanswered %d", e.metrics.get("routing.as_failover"), e.metrics.get("routing.third_party.unanswered"))
			}
		})
	}
}
