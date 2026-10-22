package scscf

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/regevent"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/registrar"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// resolverFunc is a proxy.Resolver from a function.
type resolverFunc func(sip.URI) (transport.Destination, error)

func (f resolverFunc) Resolve(_ context.Context, u sip.URI) (transport.Destination, error) {
	return f(u)
}

func request(t *testing.T, text string) *sip.Request {
	t.Helper()
	m, err := sip.ParseMessage([]byte(strings.ReplaceAll(text, "\n", "\r\n") + "\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	return m.(*sip.Request)
}

// TestASendThatCannotGoSaysWhy: before the proxy is up, without a next hop,
// or with a Route that does not parse, Send fails without sending; it
// resolves the first Route, not the Request-URI.
func TestASendThatCannotGoSaysWhy(t *testing.T) {
	req := func() *sip.Request {
		return request(t, "NOTIFY sip:ue1@192.0.2.11:5060 SIP/2.0\nRoute: <sip:pcscf.rcs.local;lr>\nFrom: <sip:scscf.rcs.local>;tag=a\nTo: <sip:ue1@192.0.2.11>;tag=b\nCall-ID: c\nCSeq: 2 NOTIFY\nMax-Forwards: 70\nContent-Length: 0")
	}
	noHop := errors.New("no next hop")
	var resolved []string
	s := &sender{
		layer: func() *transaction.Layer { return nil },
		resolver: resolverFunc(func(u sip.URI) (transport.Destination, error) {
			resolved = append(resolved, u.Host)
			return transport.Destination{}, noHop
		}),
		branch: func() (string, error) { return "z9hG4bK-test", nil },
	}
	if _, err := s.Send(bg, req()); !errors.Is(err, errNoLayer) {
		t.Errorf("before the proxy: %v", err)
	}
	s.layer = func() *transaction.Layer { return &transaction.Layer{} }
	if _, err := s.Send(bg, req()); !errors.Is(err, noHop) || len(resolved) != 1 || resolved[0] != "pcscf.rcs.local" {
		t.Errorf("without a next hop: %v, resolved %v", err, resolved)
	}
	bad := req()
	_ = bad.Header.Set("Route", "<sip:")
	if _, err := s.Send(bg, bad); err == nil {
		t.Error("a Route that does not parse was sent")
	}
}

var bg = context.Background()

// TestTheRegistrarTellsNoServerUntilTheRouterIsSet: what the registrar
// tells before the router is made is dropped, not a nil call.
func TestTheRegistrarTellsNoServerUntilTheRouterIsSet(t *testing.T) {
	var l lateThirdParty
	l.Registered(bg, registrar.ThirdPartyRegistration{})
}

// TestTheSubscriptionSweepsRunUntilTheirContextEnds: each interval sweeps
// the notifier's subscriptions, and the loop returns when ctx ends.
func TestTheSubscriptionSweepsRunUntilTheirContextEnds(t *testing.T) {
	store := state.NewMemory()
	n, err := regevent.New(regevent.Config{Store: store, Sender: &sender{layer: func() *transaction.Layer { return nil }}, Contact: mustURI("sip:scscf.rcs.local")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runSubscriptionSweeps(ctx, n, time.Millisecond, 10, slog.New(slog.DiscardHandler))
	}()
	time.Sleep(5 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(realWait):
		t.Fatal("the sweeps did not stop")
	}
}

// TestTheMemoryStoreNeedsNoAWS: SCSCF_STORE=memory opens a store of the
// task's own.
func TestTheMemoryStoreNeedsNoAWS(t *testing.T) {
	cfg := testConfig()
	s, err := openStore(bg, cfg, deps{})
	if err != nil || s == nil {
		t.Fatalf("store %v, %v", s, err)
	}
}
