package cxclient

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
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

// TestATaskIsDroppedOnlyOnceGoneFromDNSAndDown: a task a DNS answer leaves out
// keeps its connection while it answers; once it has stopped, having been left
// out of three answers in a row, it is dropped, its node shut down.
func TestATaskIsDroppedOnlyOnceGoneFromDNSAndDown(t *testing.T) {
	e := newEnv(t, nil)
	a := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	startHSS(t, e.net, "192.0.2.2", "hss-b.rcs.local")
	startHSS(t, e.net, "192.0.2.3", "hss-c.rcs.local")
	e.refresh("192.0.2.1", "192.0.2.2")
	for range 5 {
		e.dns.set(nil, "192.0.2.2", "192.0.2.3")
		if err := e.client.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	e.waitAvailable("192.0.2.1", "192.0.2.2", "192.0.2.3")
	if n := e.metrics.count("cxclient.peer.removed"); n != 0 {
		t.Fatalf("a live task left out of DNS was dropped (%d)", n)
	}
	a.kill()
	eventually(t, "task A to be unavailable", func() bool {
		for _, p := range e.client.Peers() {
			if p.Address == netip.MustParseAddr("192.0.2.1") && p.Available {
				return false
			}
		}
		return true
	})
	// Left out of five answers already, it goes at the next one.
	if err := e.client.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.waitAvailable("192.0.2.2", "192.0.2.3")
	// Count once the dropped node has shut down: until then its reconnect
	// loop may still be dialling.
	eventually(t, "the dropped node to shut down", func() bool { return e.client.shuttingDown.Load() == 0 })
	dials := e.net.dialsTo("192.0.2.1")
	time.Sleep(100 * time.Millisecond)
	if e.net.dialsTo("192.0.2.1") != dials {
		t.Error("the client keeps redialling a task it dropped")
	}
	if n := e.metrics.count("cxclient.peer.removed"); n != 1 {
		t.Errorf("peer.removed = %d", n)
	}
}

// TestTenTasksBehindEightRecordAnswersStayConnected is Cloud Map MULTIVALUE
// DNS with more tasks than records: each answer names a different eight.
func TestTenTasksBehindEightRecordAnswersStayConnected(t *testing.T) {
	e := newEnv(t, nil)
	var all []string
	for i := 1; i <= 10; i++ {
		a := "192.0.2." + itoa(i)
		all = append(all, a)
		startHSS(t, e.net, a, "hss-"+itoa(i)+".rcs.local")
	}
	sortAddrs(all)
	for round := range 12 {
		answer := make([]string, 0, 8)
		for j := range 8 {
			answer = append(answer, all[(round*3+j)%10])
		}
		e.dns.set(nil, answer...)
		if err := e.client.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	e.waitAvailable(all...)
	if n := e.metrics.count("cxclient.peer.removed"); n != 0 {
		t.Errorf("peer.removed = %d with every task alive", n)
	}
	if n := e.metrics.count("cxclient.peer.added"); n != 10 {
		t.Errorf("peer.added = %d, want each task once", n)
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

func sortAddrs(as []string) {
	slices.SortFunc(as, func(a, b string) int { return netip.MustParseAddr(a).Compare(netip.MustParseAddr(b)) })
}

func itoa(i int) string { return strconv.Itoa(i) }

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
	// The hung task's requests fail over when their timer runs out, which
	// the test fires once they have arrived: no wall-clock bound applies
	// to the healthy task's answers (#195).
	clock := newHeldTimers(heldTimeout)
	e := newEnv(t, func(c *Config) { c.Node.Clock, c.Node.RequestTimeout = clock, heldTimeout })
	a := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	startHSS(t, e.net, "192.0.2.2", "hss-b.rcs.local")
	e.refresh("192.0.2.1", "192.0.2.2")
	// The task hangs: its requests time out, and each is retried on the other.
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	arrived := make(chan struct{}, 16)
	a.setAnswer(func(uint32, *diameter.Message) (*diameter.Message, error) {
		arrived <- struct{}{}
		<-hang
		return nil, errors.New("gone")
	})
	var allowed atomic.Int32
	allowed.Store(3)
	timeOutArrivals(t, clock, arrived, &allowed)
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

// expiring is a caller's context that runs out of time when the test says
// so, rather than after a fixed delay: its Err is then
// context.DeadlineExceeded, as a deadline's is, which is what the client
// must tell apart from an attempt's own RequestTimeout. Deadline reports a
// time already past once it has expired, as a real deadline would.
type expiring struct {
	context.Context
	done    chan struct{}
	once    sync.Once
	mu      sync.Mutex
	expired time.Time
}

func newExpiring(parent context.Context) *expiring {
	return &expiring{Context: parent, done: make(chan struct{})}
}

func (e *expiring) Done() <-chan struct{} { return e.done }

func (e *expiring) Err() error {
	select {
	case <-e.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func (e *expiring) Deadline() (time.Time, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.expired.IsZero() {
		return e.expired, true
	}
	return e.Context.Deadline()
}

func (e *expiring) expire() {
	e.once.Do(func() {
		e.mu.Lock()
		e.expired = time.Now()
		e.mu.Unlock()
		close(e.done)
	})
}

// Once the caller's deadline has passed, a request that has not been
// answered is not tried on another task. The deadline passes as soon as the
// first attempt has reached its task: a fixed 100 ms could pass, on a loaded
// host, before the first request was even written (#167).
func TestNoRetryOnceTheCallerHasGivenUp(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.RequestTimeout = time.Minute })
	a := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	b := startHSS(t, e.net, "192.0.2.2", "hss-b.rcs.local")
	e.refresh("192.0.2.1", "192.0.2.2")
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	arrived := make(chan struct{}, 2)
	hung := func(uint32, *diameter.Message) (*diameter.Message, error) {
		arrived <- struct{}{}
		<-hang
		return nil, errors.New("gone")
	}
	a.setAnswer(hung)
	b.setAnswer(hung)
	c := newExpiring(ctx(t))
	go func() {
		select {
		case <-arrived:
		case <-time.After(realWait):
			// Nothing arrived: the count below fails the test.
		}
		c.expire()
	}()
	if _, err := e.client.UAR(c, uar()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want the caller's deadline", err)
	}
	// A retry with the caller's context gone may never leave the node, so
	// the tasks' count alone would not show one; the client's own count
	// does.
	if n := len(a.requests()) + len(b.requests()); n != 1 || e.metrics.count("cxclient.UAR.retry") != 0 {
		t.Errorf("%d attempts, %d retries after the caller gave up, want 1 and 0", n, e.metrics.count("cxclient.UAR.retry"))
	}
	// Nor is the task that was still answering taken out of the rotation:
	// the caller ran out of time, not the task (QA, #175).
	if n := e.metrics.count("cxclient.peer.excluded"); n != 0 {
		t.Errorf("peer.excluded = %d after the caller's own deadline, want 0", n)
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

func TestADownTaskStillInDNSIsKept(t *testing.T) {
	e := newEnv(t, nil)
	a := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	startHSS(t, e.net, "192.0.2.2", "hss-b.rcs.local")
	e.refresh("192.0.2.1", "192.0.2.2")
	a.kill()
	for range 4 {
		if err := e.client.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.client.Peers()) != 2 {
		t.Error("a task still in DNS was dropped while it restarts")
	}
}

// TestABusyTaskGetsOnlyItsShareOfFirstAttempts: the retry does not move the
// turn, so a task that keeps failing gets half of the first attempts, not all.
func TestABusyTaskGetsOnlyItsShareOfFirstAttempts(t *testing.T) {
	e := newEnv(t, nil)
	a := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	startHSS(t, e.net, "192.0.2.2", "hss-b.rcs.local")
	e.refresh("192.0.2.1", "192.0.2.2")
	a.setAnswer(busy)
	for range 20 {
		if _, err := e.client.UAR(ctx(t), uar()); err != nil {
			t.Fatal(err)
		}
	}
	first := 0
	for _, r := range a.requests() {
		if r.flags&diameter.FlagRetransmit == 0 {
			first++
		}
	}
	if first > 11 {
		t.Fatalf("the busy task got %d of 20 first attempts, want about half", first)
	}
}

// heldTimeout is the node's request timeout where a test holds it
// (heldTimers): a duration no other timer has.
const heldTimeout = 777 * time.Millisecond

// heldTimers is a diameter.Clock that holds the timers of one duration,
// the node's request timeout, until the test fires them; every other
// timer runs on real time. It lets a request to a hung task time out
// exactly when the test says, without a short timeout that a slow but
// healthy answer could also run out of (#189). Its Now stands still
// unless the test advances it, so that a test can put the client just
// before or just after a TimeoutExclusion ends.
type heldTimers struct {
	d    time.Duration
	mu   sync.Mutex
	now  time.Time
	held []*heldTimer
}

func newHeldTimers(d time.Duration) *heldTimers {
	return &heldTimers{d: d, now: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)}
}

type heldTimer struct {
	c    *heldTimers
	f    func()
	done bool
}

func (c *heldTimers) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// advance moves Now on by d; it fires no timer.
func (c *heldTimers) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *heldTimers) AfterFunc(d time.Duration, f func()) diameter.Timer {
	if d != c.d {
		return time.AfterFunc(d, f)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &heldTimer{c: c, f: f}
	c.held = append(c.held, t)
	return t
}

func (t *heldTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := !t.done
	t.done = true
	return was
}

// pending reports whether a held timer is still to fire.
func (c *heldTimers) pending() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, t := range c.held {
		if !t.done {
			return true
		}
	}
	return false
}

// fire runs the held timers not yet stopped or fired, and reports how
// many it ran.
func (c *heldTimers) fire() int {
	c.mu.Lock()
	var due []func()
	for _, t := range c.held {
		if !t.done {
			t.done = true
			due = append(due, t.f)
		}
	}
	c.held = nil
	c.mu.Unlock()
	for _, f := range due {
		f()
	}
	return len(due)
}

// timeOutArrivals times out every request that reaches a hung task, as
// its arrivals say: it fires the request's held timer, and only that one.
// A request that arrives beyond allowed is an error, and so is one whose
// timer is never held, which is not fired by real time instead.
func timeOutArrivals(t *testing.T, clock *heldTimers, arrived <-chan struct{}, allowed *atomic.Int32) {
	stop, done := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(stop); <-done })
	go func() {
		defer close(done)
		for n := int32(1); ; n++ {
			select {
			case <-arrived:
			case <-stop:
				return
			}
			if most := allowed.Load(); n > most {
				t.Errorf("the hung task got attempt %d, want %d at most", n, most)
			}
			// The client sets the timer before it writes the request, so
			// it is held by now; the wait only guards against a hang.
			held := false
			for deadline := time.Now().Add(realWait); !held && time.Now().Before(deadline); {
				if held = clock.pending(); !held {
					time.Sleep(time.Millisecond)
				}
			}
			if !held {
				t.Errorf("no request timer was held for attempt %d", n)
				continue
			}
			if fired := clock.fire(); fired != 1 {
				t.Errorf("attempt %d fired %d request timers, want 1", n, fired)
			}
		}
	}()
}

// A task whose attempt timed out gets no first attempts for
// TimeoutExclusion: of ten requests, the hung task sees only the one that
// timed out, and every request is answered by the other. Just before the
// exclusion ends it still gets none; just after, it gets a first attempt
// again. The hung request times out when the test fires its timer, once
// it has arrived, and the client's clock moves only when the test moves
// it: no wall-clock bound is involved, so neither a slow healthy answer
// nor a slow test can fail it (#189).
func TestATaskThatTimedOutGetsNoFirstAttemptsForAWhile(t *testing.T) {
	const exclusion = time.Minute
	clock := newHeldTimers(heldTimeout)
	e := newEnv(t, func(c *Config) {
		c.Node.Clock, c.Node.RequestTimeout, c.TimeoutExclusion = clock, heldTimeout, exclusion
	})
	a := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	startHSS(t, e.net, "192.0.2.2", "hss-b.rcs.local")
	e.refresh("192.0.2.1", "192.0.2.2")
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	arrived := make(chan struct{}, 16)
	a.setAnswer(func(uint32, *diameter.Message) (*diameter.Message, error) {
		arrived <- struct{}{}
		<-hang
		return nil, errors.New("gone")
	})
	// The first request to reach the hung task times out; any later one
	// is a first attempt it should not have had.
	var allowed atomic.Int32
	allowed.Store(1)
	timeOutArrivals(t, clock, arrived, &allowed)
	uars := func(n int) {
		t.Helper()
		for range n {
			if _, err := e.client.UAR(ctx(t), uar()); err != nil {
				t.Fatal(err)
			}
		}
	}
	uars(10)
	if n := len(a.requests()); n != 1 {
		t.Errorf("the hung task got %d attempts, want only the one that timed out", n)
	}
	if e.metrics.count("cxclient.peer.excluded") != 1 {
		t.Error("the exclusion was not counted")
	}
	clock.advance(exclusion - time.Millisecond)
	uars(4)
	if n := len(a.requests()); n != 1 {
		t.Errorf("the hung task got %d attempts before its exclusion ended", n)
	}
	// Two requests in turn: one is the hung task's first attempt again.
	clock.advance(2 * time.Millisecond)
	allowed.Store(2)
	uars(2)
	if n := len(a.requests()); n != 2 {
		t.Errorf("the hung task got %d attempts after its exclusion ended, want 2", n)
	}
	if e.metrics.count("cxclient.peer.excluded") != 2 {
		t.Error("the second exclusion was not counted")
	}
}

// An attempt that ran out of time counts as the task's timeout whichever
// timer ended it: the node's (ErrTimeout) or the attempt context's
// (DeadlineExceeded), which with the default wiring, both RequestTimeout,
// is about a third of them. Once the caller has given up, neither does.
func TestAnAttemptTimesOutByEitherTimerWhileTheCallerWaits(t *testing.T) {
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tt := range []struct {
		ctx  context.Context
		err  error
		want bool
	}{
		{context.Background(), diameter.ErrTimeout, true},
		{context.Background(), fmt.Errorf("send: %w", context.DeadlineExceeded), true},
		{context.Background(), diameter.ErrConnectionClosed, false},
		{context.Background(), nil, false},
		{gone, diameter.ErrTimeout, false},
		{gone, context.DeadlineExceeded, false},
	} {
		if got := timedOut(tt.ctx, tt.err); got != tt.want {
			t.Errorf("timedOut(caller err %v, %v) = %v, want %v", tt.ctx.Err(), tt.err, got, tt.want)
		}
	}
}

// A failed attempt is repeated on another task when the task was busy or
// shutting down or the request did not get through, by either timer, and
// only while the caller still waits.
func TestWhatIsRetriedOnAnotherTask(t *testing.T) {
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	answer := func(rc uint32) *diameter.Message {
		m := &diameter.Message{}
		m.Add(diameter.NewAVP(diameter.AVPResultCode, diameter.FlagMandatory, 0, diameter.Unsigned32(rc)))
		return m
	}
	for _, tt := range []struct {
		ctx  context.Context
		ans  *diameter.Message
		err  error
		want bool
	}{
		{context.Background(), nil, diameter.ErrPeerUnavailable, true},
		{context.Background(), nil, diameter.ErrConnectionClosed, true},
		{context.Background(), nil, diameter.ErrTimeout, true},
		{context.Background(), nil, fmt.Errorf("send: %w", context.DeadlineExceeded), true},
		{context.Background(), nil, diameter.ErrApplicationNotNegotiated, true},
		{context.Background(), nil, errors.New("other"), false},
		{context.Background(), answer(diameter.ResultTooBusy), nil, true},
		{context.Background(), answer(diameter.ResultUnableToDeliver), nil, true},
		{context.Background(), answer(diameter.ResultSuccess), nil, false},
		{context.Background(), &diameter.Message{}, nil, false},
		{gone, nil, diameter.ErrTimeout, false},
		{gone, answer(diameter.ResultTooBusy), nil, false},
	} {
		if got := retryable(tt.ctx, tt.ans, tt.err); got != tt.want {
			t.Errorf("retryable(caller err %v, answer %v, %v) = %v, want %v", tt.ctx.Err(), tt.ans, tt.err, got, tt.want)
		}
	}
}

func TestReadyNeedsAnAvailableTask(t *testing.T) {
	e := newEnv(t, nil)
	if err := e.client.Ready(); !errors.Is(err, ErrNoPeer) {
		t.Errorf("Ready without tasks = %v", err)
	}
	startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	e.refresh("192.0.2.1")
	if err := e.client.Ready(); err != nil {
		t.Errorf("Ready = %v", err)
	}
}

func TestAPeerWhoseOriginHostIsNotAnHSSIsNotUsedOrBelieved(t *testing.T) {
	var rtrs int
	e := newEnv(t, func(c *Config) {
		c.HSSHostPattern = "hss-*.rcs.local"
		c.OnRTR = func(context.Context, *cx.RTR) cx.Result { rtrs++; return cx.ResultCode(diameter.ResultSuccess) }
	})
	impostor := startHSS(t, e.net, "192.0.2.1", "evil.rcs.local")
	startHSS(t, e.net, "192.0.2.2", "hss-b.rcs.local")
	e.refresh("192.0.2.1", "192.0.2.2")
	for range 4 {
		if _, err := e.client.UAR(ctx(t), uar()); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(impostor.requests()); n != 0 {
		t.Errorf("the impostor got %d requests", n)
	}
	ans := pushTo(t, impostor, (&cx.RTR{
		Request:  cx.Request{DestinationHost: thisHost, DestinationRealm: realm},
		UserName: impi1,
	}).Message)
	rta, err := cx.ParseRTA(ans)
	if err != nil || rta.Result != cx.ResultCode(diameter.ResultUnableToComply) || rtrs != 0 {
		t.Fatalf("RTA %+v, %v; callback called %d times", rta, err, rtrs)
	}
	if e.metrics.count("cxclient.RTR.refused") != 1 {
		t.Error("the refusal was not counted")
	}
}

func TestMatchHost(t *testing.T) {
	for _, tt := range []struct {
		pattern, host string
		want          bool
	}{
		{"hss-*.rcs.local", "hss-1a2b.rcs.local", true},
		{"hss-*.rcs.local", "HSS-1A.RCS.local", true},
		{"hss-*.rcs.local", "hss-.rcs.local", true},
		{"hss-*.rcs.local", "hss-a.evil.rcs.local", false},
		{"hss-*.rcs.local", "evil.rcs.local", false},
		{"hss.rcs.local", "hss.rcs.local", true},
		{"*-hss.rcs.local", "a-hss.rcs.local", true},
	} {
		if got := matchHost(tt.pattern, tt.host); got != tt.want {
			t.Errorf("matchHost(%q, %q) = %v", tt.pattern, tt.host, got)
		}
	}
}

// stuckDiscovery never answers until its ctx ends.
type stuckDiscovery struct{ entered chan struct{} }

func (s stuckDiscovery) HSSAddresses(ctx context.Context) ([]netip.Addr, error) {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestCloseEndsADiscoveryInProgress(t *testing.T) {
	d := stuckDiscovery{entered: make(chan struct{}, 1)}
	c, err := New(Config{OriginHost: thisHost, OriginRealm: realm, DestinationRealm: realm, Discovery: d})
	if err != nil {
		t.Fatal(err)
	}
	<-d.entered
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if err := c.Close(ctx); err != nil {
		t.Errorf("Close = %v", err)
	}
	if time.Since(start) > time.Second {
		t.Error("Close waited for the stuck discovery")
	}
}

func TestLatencyAndPeerGaugesAreRecorded(t *testing.T) {
	e := newEnv(t, nil)
	startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	e.refresh("192.0.2.1")
	if _, err := e.client.SAR(ctx(t), &cx.SAR{UserName: impi1, PublicIdentities: []string{impu1}, AssignmentType: cx.Registration}); err != nil {
		t.Fatal(err)
	}
	if err := e.client.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.metrics.mu.Lock()
	defer e.metrics.mu.Unlock()
	if e.metrics.timed["cxclient.SAR.latency"] != 1 {
		t.Error("SAR latency not recorded")
	}
	if e.metrics.gauges["cxclient.peers"] != 1 || e.metrics.gauges["cxclient.peers.known"] != 1 {
		t.Errorf("gauges %d available, %d known; want 1 and 1", e.metrics.gauges["cxclient.peers"], e.metrics.gauges["cxclient.peers.known"])
	}
	if _, summed := e.metrics.counts["cxclient.peers"]; summed {
		t.Error("cxclient.peers is recorded as a count")
	}
}

// The services pass their *runtime.Metrics.
var _ Metrics = (*runtime.Metrics)(nil)

// unavailableFrom makes every send from the k-th on (1-based) fail as one
// to a task that became unavailable after it was picked, the race #261 is
// about, and counts the sends; the first fails with first instead, if set,
// rather than going to its task.
func unavailableFrom(c *Client, k int, first ...error) *atomic.Int32 {
	return failFrom(c, k, diameter.ErrPeerUnavailable, first...)
}

// failFrom is unavailableFrom with err for the attempts from the k-th.
func failFrom(c *Client, k int, err error, first ...error) *atomic.Int32 {
	var n atomic.Int32
	real := c.send
	c.send = func(ctx context.Context, p *diameter.Peer, m *diameter.Message) (*diameter.Message, error) {
		i := int(n.Add(1))
		switch {
		case i >= k:
			return nil, err
		case i == 1 && len(first) > 0:
			return nil, first[0]
		}
		return real(ctx, p, m)
	}
	return &n
}

// unableToDeliver is the answer of an HSS task that is draining.
func unableToDeliver(uint32, *diameter.Message) (*diameter.Message, error) {
	return nil, &diameter.Error{ResultCode: diameter.ResultUnableToDeliver}
}

// TestAnErrorSaysWhetherAnyAttemptWasSent: a first attempt answered busy,
// or by a task draining (3002), or that timed out or lost its connection,
// may have been served, though its retry then found its task unavailable
// and the error is the retry's; only one whose every attempt never left,
// unavailable or not speaking Cx in either order, is NeverSent (#261).
func TestAnErrorSaysWhetherAnyAttemptWasSent(t *testing.T) {
	for _, c := range []struct {
		name string
		// tasks is the number of HSS tasks, 2 when 0; answer is theirs,
		// busy when nil.
		tasks  int
		answer func(uint32, *diameter.Message) (*diameter.Message, error)
		// From the from-th attempt on, each fails with retry, unavailable
		// when nil; the first, before that, with first if given.
		from      int
		retry     error
		first     []error
		neverSent bool
	}{
		{name: "first busy, retry unavailable", from: 2},
		{name: "first draining, retry unavailable", answer: unableToDeliver, from: 2},
		{name: "first timed out, retry unavailable", from: 2, first: []error{diameter.ErrTimeout}},
		{name: "first's deadline passed, retry unavailable", from: 2, first: []error{context.DeadlineExceeded}},
		{name: "first's connection closed, retry unavailable", from: 2, first: []error{diameter.ErrConnectionClosed}},
		{name: "first not negotiated, retry unavailable", from: 2, first: []error{diameter.ErrApplicationNotNegotiated}, neverSent: true},
		{name: "first unavailable, retry not negotiated", from: 2, retry: diameter.ErrApplicationNotNegotiated, first: []error{diameter.ErrPeerUnavailable}, neverSent: true},
		{name: "the one task not negotiated", tasks: 1, from: 1, retry: diameter.ErrApplicationNotNegotiated, neverSent: true},
		{name: "both unavailable", from: 1, neverSent: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, nil)
			answer, retry, tasks := c.answer, c.retry, c.tasks
			if answer == nil {
				answer = busy
			}
			if retry == nil {
				retry = diameter.ErrPeerUnavailable
			}
			if tasks == 0 {
				tasks = 2
			}
			addrs := []string{"192.0.2.1", "192.0.2.2"}[:tasks]
			for i, a := range addrs {
				startHSS(t, e.net, a, []string{"hss-a.rcs.local", "hss-b.rcs.local"}[i]).setAnswer(answer)
			}
			e.refresh(addrs...)
			sends := failFrom(e.client, c.from, retry, c.first...)
			_, err := e.client.MAR(ctx(t), &cx.MAR{UserName: impi1, PublicIdentity: impu1, NumberAuthItems: 1})
			if int(sends.Load()) != tasks || !errors.Is(err, retry) {
				t.Fatalf("%d sends, error %v; want %d and the last attempt's %v", sends.Load(), err, tasks, retry)
			}
			if NeverSent(err) != c.neverSent || ErrorOutcome(err) != Unavailable {
				t.Errorf("NeverSent = %v, outcome %v; want %v, Unavailable", NeverSent(err), ErrorOutcome(err), c.neverSent)
			}
		})
	}
	for _, err := range []error{ErrNoPeer, diameter.ErrPeerUnavailable, diameter.ErrApplicationNotNegotiated} {
		if !NeverSent(err) {
			t.Errorf("NeverSent(%v) is false", err)
		}
	}
	// A caller that gave up, as when the REGISTER's flow closed, may have
	// done so after the send.
	for _, err := range []error{diameter.ErrTimeout, diameter.ErrConnectionClosed, context.DeadlineExceeded, context.Canceled} {
		if NeverSent(err) {
			t.Errorf("NeverSent(%v) is true", err)
		}
	}
}

// TestAnAuthenticationWhoseFirstSchemeWasAnsweredWasSent: the AKA MAR got
// 5006 from the HSS and the SIP Digest one found no task: the HSS saw the
// first (#261).
func TestAnAuthenticationWhoseFirstSchemeWasAnsweredWasSent(t *testing.T) {
	e := newEnv(t, nil)
	h := startHSS(t, e.net, "192.0.2.1", "hss-a.rcs.local")
	e.refresh("192.0.2.1")
	h.setAnswer(func(code uint32, req *diameter.Message) (*diameter.Message, error) {
		return h.result(code, req, cx.ExperimentalResult(cx.ErrorAuthSchemeNotSupported))
	})
	unavailableFrom(e.client, 2)
	schemes, _ := Schemes("", nil)
	_, err := e.client.Authenticate(ctx(t), &cx.MAR{UserName: impi1, PublicIdentity: impu1, NumberAuthItems: 1}, schemes)
	if !errors.Is(err, diameter.ErrPeerUnavailable) || NeverSent(err) {
		t.Errorf("error %v, NeverSent %v; want the second MAR's unavailable peer, sent", err, NeverSent(err))
	}
}
