package diameter

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestNodeConfigurationIsValidated(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"no Origin-Host", func(c *Config) { c.OriginHost = "" }, "OriginHost"},
		{"invalid Origin-Realm", func(c *Config) { c.OriginRealm = "rcs test" }, "OriginRealm"},
		{"no application", func(c *Config) { c.Applications = nil }, "application"},
		{"invalid address", func(c *Config) { c.HostIPAddresses = []netip.Addr{{}} }, "HostIPAddress"},
		{"rule without identity", func(c *Config) { c.Accept = []PeerRule{{}} }, "peer rule"},
		{"watchdog below the RFC 3539 minimum", func(c *Config) { c.WatchdogInterval = 5 * time.Second }, "minimum"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig(newFakeClock(), hssHost)
			tt.edit(&cfg)
			_, err := NewNode(cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestNodeConfigurationDefaults(t *testing.T) {
	clock := newFakeClock()
	n, err := NewNode(Config{OriginHost: hssHost, OriginRealm: testRealm, Applications: []Application{{ID: appCx}},
		Clock: clock, ReconnectMin: time.Minute, ReconnectMax: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c := n.cfg
	if c.ProductName != "rcs-platform" || c.WatchdogInterval != DefaultWatchdogInterval ||
		c.RequestTimeout != DefaultRequestTimeout || c.CapabilitiesTimeout != DefaultCapabilitiesTimeout ||
		c.MaxInFlight != DefaultMaxInFlight || c.Dictionary == nil || c.Random == nil || c.Dial == nil || c.Logger == nil {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if c.ReconnectMax != time.Minute {
		t.Fatalf("ReconnectMax %s below ReconnectMin must be raised to it", c.ReconnectMax)
	}
	if c.OriginStateID != uint32(clock.Now().Unix()) {
		t.Fatalf("OriginStateID = %d, want the start-up time", c.OriginStateID)
	}
	if c.Limits.MaxMessageSize != DefaultMaxMessageSize || c.Limits.MaxDepth != DefaultMaxDepth {
		t.Fatalf("limits = %+v", c.Limits)
	}
	var system Clock = systemClock{}
	if !system.AfterFunc(time.Hour, func() {}).Stop() {
		t.Fatal("system clock timer cannot be stopped")
	}
	if system.Now().IsZero() {
		t.Fatal("system clock has no time")
	}
}

func TestHandlerRegistrationMistakesPanic(t *testing.T) {
	n := newTestNode(t, testConfig(newFakeClock(), hssHost))
	h := HandlerFunc(func(context.Context, *Peer, *Message) (*Message, error) { return nil, nil })
	n.Handle(appCx, cmdTest, h)
	for name, f := range map[string]func(){
		"nil handler":       func() { n.Handle(appCx, cmdTest+1, nil) },
		"base protocol":     func() { n.Handle(AppCommon, CodeDeviceWatchdog, h) },
		"duplicate handler": func() { n.Handle(appCx, cmdTest, h) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("no panic")
				}
			}()
			f()
		})
	}
}

func TestRequestBuilderPutsSessionIDFirst(t *testing.T) {
	n := newTestNode(t, testConfig(newFakeClock(), scscfHost))
	sid := n.NewSessionID("x")
	if !strings.HasPrefix(sid, scscfHost+";") || !strings.HasSuffix(sid, ";x") {
		t.Fatalf("Session-Id = %q", sid)
	}
	m := n.NewRequest(cmdTest, appCx, sid, NewAVP(AVPUserName, FlagMandatory, 0, []byte("u")))
	codes := []uint32{}
	for _, a := range m.AVPs {
		codes = append(codes, a.Code)
	}
	want := []uint32{AVPSessionID, AVPOriginHost, AVPOriginRealm, AVPUserName}
	if len(codes) != len(want) {
		t.Fatalf("AVP order %v, want %v", codes, want)
	}
	for i := range want {
		if codes[i] != want[i] {
			t.Fatalf("AVP order %v, want %v", codes, want)
		}
	}
	if !m.IsRequest() || m.ApplicationID != appCx || m.Code != cmdTest {
		t.Fatalf("header %+v", m)
	}
	if n.NewRequest(cmdTest, appCx, "").Find(AVPSessionID, 0) != nil {
		t.Fatal("empty session id added a Session-Id")
	}
}

func TestExperimentalAnswerCarriesTheVendorResult(t *testing.T) {
	n := newTestNode(t, testConfig(newFakeClock(), hssHost))
	req := n.NewRequest(cmdTest, appCx, "scscf.rcs.test;1;2")
	req.Flags |= FlagProxiable
	req.HopByHop, req.EndToEnd = 5, 6
	a := n.NewExperimentalAnswer(req, vendor3GPP, 2001)
	if a.IsRequest() || a.Flags != FlagProxiable || a.HopByHop != 5 || a.EndToEnd != 6 {
		t.Fatalf("header %+v", a)
	}
	if a.Find(AVPResultCode, 0) != nil {
		t.Fatal("an experimental answer has no Result-Code")
	}
	children, err := a.Find(AVPExperimentalResult, 0).Grouped()
	if err != nil || len(children) != 2 {
		t.Fatalf("Experimental-Result = %+v, %v", children, err)
	}
	if v, _ := children[0].Unsigned32(); children[0].Code != AVPVendorID || v != vendor3GPP {
		t.Fatalf("Vendor-Id = %+v", children[0])
	}
	if v, _ := children[1].Unsigned32(); children[1].Code != AVPExperimentalResultCode || v != 2001 {
		t.Fatalf("Experimental-Result-Code = %+v", children[1])
	}
}

func TestReconnectionBacksOffExponentiallyToTheCeiling(t *testing.T) {
	clock := newFakeClock()
	dialer := newPipeDialer()
	dialer.fail = errors.New("connection refused")
	cfg := testConfig(clock, scscfHost)
	cfg.Dial = dialer.Dial
	cfg.Random = func() uint64 { return 0 } // lower edge of the jitter
	// The dial timer must not share a duration with any backoff step, or
	// waitForTimer could find it instead of the sleep.
	cfg.CapabilitiesTimeout = 11 * time.Second
	n := newTestNode(t, cfg)
	if _, err := n.Connect(PeerConfig{Address: "hss:3868"}); err != nil {
		t.Fatal(err)
	}
	// Exponential from 1 s to 20 s, each halved by the zero jitter.
	for i, d := range []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second,
		8 * time.Second, 10 * time.Second, 10 * time.Second} {
		clock.waitForTimer(t, d)
		if got := dialer.count(); got != i+1 {
			t.Fatalf("after %d waits, %d dials", i, got)
		}
		clock.Advance(d)
	}
}

func TestBackoffJitterStaysInTheUpperHalf(t *testing.T) {
	cfg := testConfig(newFakeClock(), scscfHost)
	cfg.Random = func() uint64 { return ^uint64(0) }
	n := newTestNode(t, cfg)
	for attempt := range 10 {
		d := n.backoff(attempt)
		ceiling := min(testReconnectMin<<attempt, testReconnectMax)
		if d < ceiling/2 || d > ceiling {
			t.Errorf("attempt %d: %s outside [%s, %s]", attempt, d, ceiling/2, ceiling)
		}
	}
}

func TestPeerSendingDPRIsAnsweredAndReconnectedAfterTheLongestDelay(t *testing.T) {
	_, peer, dialer, clock := startInitiator(t, nil)
	s := dialer.next(t)
	acceptCER(t, s)
	waitFor(t, "peer to open", peer.Available)

	dpa := s.roundTrip(&Message{Code: CodeDisconnectPeer, AVPs: append(s.origin(),
		NewAVP(AVPDisconnectCause, FlagMandatory, 0, Enumerated(DisconnectBusy)))})
	if rc, _ := dpa.ResultCode(); rc != ResultSuccess {
		t.Fatalf("DPA result %d", rc)
	}
	if peer.Available() {
		t.Fatal("a disconnecting peer must not take new requests")
	}
	_ = s.nc.Close()
	clock.waitForTimer(t, testReconnectMax)
	clock.Advance(testReconnectMax)
	acceptCER(t, dialer.next(t))
}

func TestPeerRebootingIsReconnectedWithTheShortDelay(t *testing.T) {
	n, peer, dialer, clock := startInitiator(t, nil)
	s := dialer.next(t)
	acceptCER(t, s)
	waitFor(t, "peer to open", peer.Available)
	s.roundTrip(&Message{Code: CodeDisconnectPeer, AVPs: append(s.origin(),
		NewAVP(AVPDisconnectCause, FlagMandatory, 0, Enumerated(DisconnectRebooting)))})
	_ = s.nc.Close()
	clock.waitForTimer(t, n.backoff(0))
	clock.Advance(n.backoff(0))
	acceptCER(t, dialer.next(t))
}

func TestRequestsAfterDPRAreRefused(t *testing.T) {
	hss, ln, _ := startResponder(t, nil)
	hss.Handle(appCx, cmdTest, echoHandler(hss))
	s := openScript(t, ln, scscfHost)
	s.roundTrip(&Message{Code: CodeDisconnectPeer, AVPs: s.origin()})
	ans := s.roundTrip(&Message{Code: cmdTest, ApplicationID: appCx, AVPs: s.origin()})
	if rc, _ := ans.ResultCode(); rc != ResultUnableToDeliver {
		t.Fatalf("request after DPR answered %d", rc)
	}
}

func TestDPRSenderThatKeepsTheConnectionIsClosedAfterAGracePeriod(t *testing.T) {
	_, ln, clock := startResponder(t, nil)
	s := openScript(t, ln, scscfHost)
	s.roundTrip(&Message{Code: CodeDisconnectPeer, AVPs: s.origin()})
	clock.waitForTimer(t, disconnectWaitForPeerToDrop)
	clock.Advance(disconnectWaitForPeerToDrop)
	s.expectClosed()
}

func TestShutdownSendsDPRAndClosesOnTheAnswer(t *testing.T) {
	hss, ln, _ := startResponder(t, nil)
	s := openScript(t, ln, scscfHost)
	s.sync() // the connection is running
	errc := make(chan error, 1)
	go func() { errc <- hss.Shutdown(context.Background()) }()
	dpr := s.read()
	if !dpr.IsRequest() || dpr.Code != CodeDisconnectPeer {
		t.Fatalf("expected DPR, got %+v", dpr)
	}
	if cause, _ := dpr.Find(AVPDisconnectCause, 0).Enumerated(); cause != DisconnectRebooting {
		t.Fatalf("Disconnect-Cause = %d", cause)
	}
	s.write(s.answer(dpr, ResultSuccess))
	s.expectClosed()
	if err := <-errc; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := hss.Shutdown(context.Background()); !errors.Is(err, ErrNodeClosed) {
		t.Fatalf("second Shutdown: %v", err)
	}
	if _, err := hss.Connect(PeerConfig{Address: "x:1"}); !errors.Is(err, ErrNodeClosed) {
		t.Fatalf("Connect after Shutdown: %v", err)
	}
	if err := hss.Serve(newPipeListener()); !errors.Is(err, ErrNodeClosed) {
		t.Fatalf("Serve after Shutdown: %v", err)
	}
}

func TestShutdownStopsWaitingForDPAAfterTheRequestTimeout(t *testing.T) {
	hss, ln, clock := startResponder(t, nil)
	s := openScript(t, ln, scscfHost)
	s.sync()
	errc := make(chan error, 1)
	go func() { errc <- hss.Shutdown(context.Background()) }()
	s.read() // DPR, unanswered
	clock.waitForTimer(t, testRequestWait)
	clock.Advance(testRequestWait)
	s.expectClosed()
	if err := <-errc; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestShutdownReturnsTheContextErrorWhenItEndsFirst(t *testing.T) {
	hss, ln, _ := startResponder(t, nil)
	s := openScript(t, ln, scscfHost)
	s.sync()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- hss.Shutdown(ctx) }()
	s.read()
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) && err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	s.expectClosed()
}

func TestShutdownStopsReconnecting(t *testing.T) {
	clock := newFakeClock()
	dialer := newPipeDialer()
	dialer.fail = errors.New("refused")
	cfg := testConfig(clock, scscfHost)
	cfg.Dial = dialer.Dial
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Connect(PeerConfig{Address: "hss:3868"}); err != nil {
		t.Fatal(err)
	}
	clock.waitForTimer(t, n.backoff(0))
	if err := n.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := dialer.count(); got != 1 {
		t.Fatalf("%d dials, want 1", got)
	}
}

func TestServeReturnsTheAcceptError(t *testing.T) {
	n := newTestNode(t, testConfig(newFakeClock(), hssHost))
	ln := newPipeListener()
	_ = ln.Close()
	if err := n.Serve(failingListener{ln}); err == nil || errors.Is(err, ErrNodeClosed) {
		t.Fatalf("Serve = %v, want the listener's error", err)
	}
}

type failingListener struct{ *pipeListener }

func (failingListener) Accept() (net.Conn, error) { return nil, errors.New("too many open files") }
