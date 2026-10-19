package cxclient

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

func TestTheClientConnectsToEveryHSSTaskInDNS(t *testing.T) {
	e := newEnv(t, nil)
	startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	startHSS(t, e.net, "192.0.2.2", "hss-b.rcs.local")
	e.refresh("192.0.2.1", "192.0.2.2")
	ps := e.client.Peers()
	if ps[0].Host != "hss-a.rcs.local" || ps[1].Host != "hss-b.rcs.local" {
		t.Errorf("peers %+v", ps)
	}
	if n := e.metrics.count("cxclient.peer.added"); n != 2 {
		t.Errorf("peer.added = %d", n)
	}
}

func TestATaskThatLeavesDNSIsDisconnectedAndANewOneConnected(t *testing.T) {
	e := newEnv(t, nil)
	a := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	startHSS(t, e.net, "192.0.2.2", "hss-b.rcs.local")
	startHSS(t, e.net, "192.0.2.3", "hss-c.rcs.local")
	e.refresh("192.0.2.1", "192.0.2.2")
	e.refresh("192.0.2.2", "192.0.2.3")
	// The dropped task sees its peer go: the node was shut down, not left to
	// reconnect.
	eventually(t, "hss-a to lose the peer", func() bool { return len(a.node.Peers()) == 0 })
	dials := e.net.dialsTo("192.0.2.1")
	time.Sleep(100 * time.Millisecond)
	if e.net.dialsTo("192.0.2.1") != dials {
		t.Error("the client keeps redialling an address that left DNS")
	}
	if n := e.metrics.count("cxclient.peer.removed"); n != 1 {
		t.Errorf("peer.removed = %d", n)
	}
}

func TestAFailedOrEmptyResolutionKeepsThePeers(t *testing.T) {
	e := newEnv(t, nil)
	startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	e.refresh("192.0.2.1")
	e.dns.set(errors.New("SERVFAIL"))
	if err := e.client.Refresh(context.Background()); err == nil {
		t.Error("a failed resolution was not reported")
	}
	e.dns.set(nil)
	if err := e.client.Refresh(context.Background()); err == nil {
		t.Error("an empty answer was not reported")
	}
	e.waitAvailable("192.0.2.1")
	// One for the first resolution, which found no address.
	if n := e.metrics.count("cxclient.resolve.error"); n != 3 {
		t.Errorf("resolve.error = %d", n)
	}
}

func TestPeersAreBoundedByMaxPeers(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.MaxPeers = 2 })
	for _, a := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		startHSS(t, e.net, a, "hss-"+strings.ReplaceAll(a, ".", "-")+".rcs.local")
	}
	e.dns.set(nil, "192.0.2.3", "192.0.2.1", "192.0.2.2")
	if err := e.client.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.waitAvailable("192.0.2.1", "192.0.2.2")
}

func TestARequestCarriesTheInstancesIdentityAndTheSharedServerName(t *testing.T) {
	e := newEnv(t, nil)
	h := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	e.refresh("192.0.2.1")
	if _, err := e.client.SAR(ctx(t), &cx.SAR{UserName: impi1, PublicIdentities: []string{impu1}, AssignmentType: cx.Registration}); err != nil {
		t.Fatal(err)
	}
	got := h.requests()
	if len(got) != 1 {
		t.Fatalf("%d requests", len(got))
	}
	sar, err := cx.ParseSAR(got[0].msg)
	if err != nil {
		t.Fatal(err)
	}
	if sar.OriginHost != thisHost || sar.DestinationRealm != realm || sar.ServerName != scscfName {
		t.Errorf("Origin-Host %q, Destination-Realm %q, Server-Name %q", sar.OriginHost, sar.DestinationRealm, sar.ServerName)
	}
	if !strings.HasPrefix(got[0].sessionID, thisHost+";") {
		t.Errorf("Session-Id %q is not this instance's", got[0].sessionID)
	}
}

func TestEveryCommandReturnsItsAnswer(t *testing.T) {
	e := newEnv(t, nil)
	startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	e.refresh("192.0.2.1")
	uaa, err := e.client.UAR(ctx(t), uar())
	if err != nil || uaa.ServerName != scscfName || Classify(uaa.Result) != Success {
		t.Fatalf("UAR: %+v, %v", uaa, err)
	}
	lia, err := e.client.LIR(ctx(t), &cx.LIR{PublicIdentity: impu1})
	if err != nil || lia.ServerName != scscfName {
		t.Fatalf("LIR: %+v, %v", lia, err)
	}
	maa, err := e.client.MAR(ctx(t), &cx.MAR{UserName: impi1, PublicIdentity: impu1, NumberAuthItems: 1,
		AuthDataItem: cx.AuthDataItem{Scheme: cx.SchemeSIPDigest}})
	if err != nil || len(maa.AuthDataItems) != 1 || maa.AuthDataItems[0].Scheme != cx.SchemeSIPDigest {
		t.Fatalf("MAR: %+v, %v", maa, err)
	}
	saa, err := e.client.SAR(ctx(t), &cx.SAR{UserName: impi1, PublicIdentities: []string{impu1}, AssignmentType: cx.Registration})
	if err != nil || string(saa.UserData) != "<IMSSubscription/>" {
		t.Fatalf("SAR: %+v, %v", saa, err)
	}
	if n := e.metrics.count("cxclient.UAR.exp.2001"); n != 1 {
		t.Errorf("cxclient.UAR.exp.2001 = %d", n)
	}
}

// TestABusyTaskIsRetriedOnceOnAnotherWithTheSameIdentifiers checks RFC 6733
// §5.5.4: the retry keeps Session-Id and End-to-End Identifier and sets T.
func TestABusyTaskIsRetriedOnceOnAnotherWithTheSameIdentifiers(t *testing.T) {
	e := newEnv(t, nil)
	a := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	b := startHSS(t, e.net, "192.0.2.2", "hss-b.rcs.local")
	a.setAnswer(busy)
	b.setAnswer(busy)
	e.refresh("192.0.2.1", "192.0.2.2")
	// Whichever task is first, the other gets the retry.
	var first, second *fakeHSS
	_, err := e.client.UAR(ctx(t), uar())
	var pe *ProtocolError
	if !errors.As(err, &pe) || pe.Result.Code != diameter.ResultTooBusy {
		t.Fatalf("error = %v, want TOO_BUSY after one retry", err)
	}
	if len(a.requests()) == 1 && len(b.requests()) == 1 {
		first, second = a, b
		if a.requests()[0].flags&diameter.FlagRetransmit != 0 {
			first, second = b, a
		}
	} else {
		t.Fatalf("requests: %d on a, %d on b; want one each", len(a.requests()), len(b.requests()))
	}
	f, s := first.requests()[0], second.requests()[0]
	if f.sessionID != s.sessionID || f.endToEnd != s.endToEnd {
		t.Error("the retry changed Session-Id or End-to-End Identifier")
	}
	if f.flags&diameter.FlagRetransmit != 0 || s.flags&diameter.FlagRetransmit == 0 {
		t.Error("only the retry must carry the T flag")
	}
	if n := e.metrics.count("cxclient.UAR.retry"); n != 1 {
		t.Errorf("retry = %d", n)
	}

	// One busy task: the retry succeeds.
	b.setAnswer(nil)
	a.setAnswer(nil)
	first.setAnswer(busy)
	for range 2 {
		uaa, err := e.client.UAR(ctx(t), uar())
		if err != nil || Classify(uaa.Result) != Success {
			t.Fatalf("with one task busy: %v", err)
		}
	}
}

func TestATaskShuttingDownIsRetriedOnAnother(t *testing.T) {
	e := newEnv(t, nil)
	a := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	b := startHSS(t, e.net, "192.0.2.2", "hss-b.rcs.local")
	unable := func(uint32, *diameter.Message) (*diameter.Message, error) {
		return nil, &diameter.Error{ResultCode: diameter.ResultUnableToDeliver}
	}
	a.setAnswer(unable)
	b.setAnswer(unable)
	e.refresh("192.0.2.1", "192.0.2.2")
	b.setAnswer(nil)
	a.setAnswer(unable)
	for range 4 {
		if _, err := e.client.UAR(ctx(t), uar()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestALostTaskIsFailedOverAndDroppedFromTheRotation(t *testing.T) {
	e := newEnv(t, nil)
	a := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	startHSS(t, e.net, "192.0.2.2", "hss-b.rcs.local")
	e.refresh("192.0.2.1", "192.0.2.2")
	// The task hangs: its requests time out, and each is retried on the other.
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	a.setAnswer(func(uint32, *diameter.Message) (*diameter.Message, error) {
		<-hang
		return nil, errors.New("gone")
	})
	for range 3 {
		if _, err := e.client.UAR(ctx(t), uar()); err != nil {
			t.Fatalf("with a hung task: %v", err)
		}
	}
	// It dies: its connection closes and requests go to the other only.
	a.kill()
	eventually(t, "the dead task to be unavailable", func() bool {
		for _, p := range e.client.Peers() {
			if p.Address == netip.MustParseAddr("192.0.2.1") && p.Available {
				return false
			}
		}
		return true
	})
	for range 3 {
		if _, err := e.client.UAR(ctx(t), uar()); err != nil {
			t.Fatalf("with a dead task: %v", err)
		}
	}
}

func TestNoRetryOnceTheCallerHasGivenUp(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.RequestTimeout = time.Minute })
	a := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	b := startHSS(t, e.net, "192.0.2.2", "hss-b.rcs.local")
	e.refresh("192.0.2.1", "192.0.2.2")
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	hung := func(uint32, *diameter.Message) (*diameter.Message, error) {
		<-hang
		return nil, errors.New("gone")
	}
	a.setAnswer(hung)
	b.setAnswer(hung)
	c, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := e.client.UAR(c, uar()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want the caller's deadline", err)
	}
	if n := len(a.requests()) + len(b.requests()); n != 1 {
		t.Errorf("%d attempts after the caller gave up, want 1", n)
	}
}

func TestWithoutAnHSSTaskARequestFailsAtOnce(t *testing.T) {
	e := newEnv(t, nil)
	if _, err := e.client.UAR(ctx(t), uar()); !errors.Is(err, ErrNoPeer) {
		t.Fatalf("error = %v, want ErrNoPeer", err)
	}
	if ErrorOutcome(ErrNoPeer) != Unavailable {
		t.Error("ErrNoPeer is not Unavailable")
	}
}

func TestRequestsAreSpreadOverTheTasks(t *testing.T) {
	e := newEnv(t, nil)
	a := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	b := startHSS(t, e.net, "192.0.2.2", "hss-b.rcs.local")
	e.refresh("192.0.2.1", "192.0.2.2")
	for range 10 {
		if _, err := e.client.UAR(ctx(t), uar()); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.requests()) != 5 || len(b.requests()) != 5 {
		t.Errorf("requests %d and %d, want 5 each", len(a.requests()), len(b.requests()))
	}
}

// pushTo sends an HSS-initiated request to the client over the task's
// connection, as hss.Pusher does.
func pushTo(t *testing.T, h *fakeHSS, build func(n *diameter.Node) (*diameter.Message, error)) *diameter.Message {
	t.Helper()
	var peer *diameter.Peer
	eventually(t, "the HSS to see the client", func() bool {
		for _, p := range h.node.Peers() {
			if p.Available() {
				peer = p
				return true
			}
		}
		return false
	})
	m, err := build(h.node)
	if err != nil {
		t.Fatal(err)
	}
	ans, err := peer.Send(ctx(t), m)
	if err != nil {
		t.Fatal(err)
	}
	return ans
}

func TestRTRAndPPRReachTheCallbacksAndAreAnsweredWithTheirResult(t *testing.T) {
	var mu sync.Mutex
	var rtrs []*cx.RTR
	var pprs []*cx.PPR
	e := newEnv(t, func(c *Config) {
		c.OnRTR = func(_ context.Context, r *cx.RTR) cx.Result {
			mu.Lock()
			rtrs = append(rtrs, r)
			mu.Unlock()
			return cx.ResultCode(diameter.ResultSuccess)
		}
		c.OnPPR = func(_ context.Context, r *cx.PPR) cx.Result {
			mu.Lock()
			pprs = append(pprs, r)
			mu.Unlock()
			return cx.ExperimentalResult(cx.ErrorUserUnknown)
		}
	})
	h := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	e.refresh("192.0.2.1")
	ans := pushTo(t, h, (&cx.RTR{
		Request:              cx.Request{DestinationHost: thisHost, DestinationRealm: realm},
		UserName:             impi1,
		DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination},
	}).Message)
	rta, err := cx.ParseRTA(ans)
	if err != nil || rta.Result != cx.ResultCode(diameter.ResultSuccess) {
		t.Fatalf("RTA %+v, %v", rta, err)
	}
	ans = pushTo(t, h, (&cx.PPR{
		Request:  cx.Request{DestinationHost: thisHost, DestinationRealm: realm},
		UserName: impi1, UserData: []byte("<IMSSubscription/>"),
	}).Message)
	ppa, err := cx.ParsePPA(ans)
	if err != nil || ppa.Result != cx.ExperimentalResult(cx.ErrorUserUnknown) {
		t.Fatalf("PPA %+v, %v", ppa, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(rtrs) != 1 || rtrs[0].UserName != impi1 || len(pprs) != 1 || string(pprs[0].UserData) != "<IMSSubscription/>" {
		t.Errorf("callbacks got %d RTRs and %d PPRs", len(rtrs), len(pprs))
	}
	if e.metrics.count("cxclient.RTR.2001") != 1 || e.metrics.count("cxclient.PPR.exp.5001") != 1 {
		t.Error("the answers were not counted")
	}
}

func TestWithoutCallbacksRTRIsAnsweredUnableToComply(t *testing.T) {
	e := newEnv(t, nil)
	h := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	e.refresh("192.0.2.1")
	ans := pushTo(t, h, (&cx.RTR{
		Request:  cx.Request{DestinationHost: thisHost, DestinationRealm: realm},
		UserName: impi1,
	}).Message)
	rta, err := cx.ParseRTA(ans)
	if err != nil || rta.Result != cx.ResultCode(diameter.ResultUnableToComply) {
		t.Fatalf("RTA %+v, %v", rta, err)
	}
}

func TestAMalformedAnswerIsAnError(t *testing.T) {
	e := newEnv(t, nil)
	h := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	e.refresh("192.0.2.1")
	h.setAnswer(func(_ uint32, req *diameter.Message) (*diameter.Message, error) {
		// Both Result-Code and Experimental-Result: which one did it mean?
		ans := h.node.NewAnswer(req, diameter.ResultSuccess)
		ans.Add(diameter.NewGrouped(diameter.AVPExperimentalResult, diameter.FlagMandatory, 0,
			diameter.NewAVP(diameter.AVPVendorID, diameter.FlagMandatory, 0, diameter.Unsigned32(cx.Vendor3GPP)),
			diameter.NewAVP(diameter.AVPExperimentalResultCode, diameter.FlagMandatory, 0, diameter.Unsigned32(cx.FirstRegistration))))
		return ans, nil
	})
	if _, err := e.client.UAR(ctx(t), uar()); err == nil {
		t.Fatal("an ambiguous answer was accepted")
	}
	if n := e.metrics.count("cxclient.UAR.error.malformed"); n != 1 {
		t.Errorf("malformed = %d", n)
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		r    cx.Result
		want Outcome
	}{
		{cx.ResultCode(diameter.ResultSuccess), Success},
		{cx.ExperimentalResult(cx.FirstRegistration), Success},
		{cx.ExperimentalResult(cx.ErrorUserUnknown), UserUnknown},
		{cx.ExperimentalResult(cx.ErrorIdentitiesDontMatch), IdentitiesDontMatch},
		{cx.ExperimentalResult(cx.ErrorIdentityNotRegistered), NotRegistered},
		{cx.ExperimentalResult(cx.ErrorRoamingNotAllowed), RoamingNotAllowed},
		{cx.ExperimentalResult(cx.ErrorIdentityAlreadyRegistered), ServedElsewhere},
		{cx.ExperimentalResult(cx.ErrorAuthSchemeNotSupported), SchemeNotSupported},
		{cx.ExperimentalResult(cx.ErrorInAssignmentType), Rejected},
		{cx.ResultCode(diameter.ResultAuthorizationRejected), Rejected},
		{cx.ResultCode(diameter.ResultAuthenticationRejected), Rejected},
		{cx.ResultCode(diameter.ResultTooBusy), Unavailable},
		{cx.ResultCode(diameter.ResultOutOfSpace), Unavailable},
		{cx.ResultCode(diameter.ResultUnableToComply), Failure},
	}
	for _, tt := range tests {
		if got := Classify(tt.r); got != tt.want {
			t.Errorf("Classify(%v) = %v, want %v", tt.r, got, tt.want)
		}
	}
	if Outcome(99).String() != "Outcome(99)" || Success.String() != "Success" {
		t.Error("Outcome names")
	}
	if ErrorOutcome(&ProtocolError{Result: cx.ResultCode(diameter.ResultTooBusy)}) != Unavailable ||
		ErrorOutcome(errors.New("x")) != Failure {
		t.Error("ErrorOutcome")
	}
}

func TestOriginHostFor(t *testing.T) {
	if h, err := OriginHostFor("scscf", "0a1b2c", "rcs.local"); err != nil || h != "scscf-0a1b2c.rcs.local" {
		t.Errorf("OriginHostFor = %q, %v", h, err)
	}
	for _, bad := range [][3]string{{"", "1", "rcs.local"}, {"scscf", "", "rcs.local"}, {"scscf", "a b", "rcs.local"}, {"scscf", "1", "-bad"}} {
		if _, err := OriginHostFor(bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("OriginHostFor%q accepted", bad)
		}
	}
}

func TestNewRefusesAnIncompleteConfig(t *testing.T) {
	for _, cfg := range []Config{
		{OriginHost: thisHost, OriginRealm: realm, DestinationRealm: realm},
		{OriginHost: thisHost, OriginRealm: realm, HSS: hssName},
		{OriginHost: "not a host", OriginRealm: realm, DestinationRealm: realm, HSS: hssName},
	} {
		if c, err := New(cfg); err == nil {
			_ = c.Close(context.Background())
			t.Errorf("New(%+v) accepted", cfg)
		}
	}
}

func TestCloseDisconnectsAndRefusesRefresh(t *testing.T) {
	e := newEnv(t, nil)
	h := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	e.refresh("192.0.2.1")
	if err := e.client.Close(ctx(t)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the HSS to lose the peer", func() bool { return len(h.node.Peers()) == 0 })
	if err := e.client.Refresh(context.Background()); !errors.Is(err, ErrClosed) {
		t.Errorf("Refresh after Close = %v", err)
	}
	if _, err := e.client.UAR(ctx(t), uar()); !errors.Is(err, ErrNoPeer) {
		t.Errorf("UAR after Close = %v", err)
	}
}
