package diameter

import (
	"testing"
	"time"
)

func isDWR(m *Message) bool {
	return m.IsRequest() && m.ApplicationID == AppCommon && m.Code == CodeDeviceWatchdog
}

func (s *script) expectDWR() *Message {
	s.t.Helper()
	m := s.read()
	if !isDWR(m) {
		s.t.Fatalf("expected DWR, got command %d (request %v)", m.Code, m.IsRequest())
	}
	return m
}

func TestWatchdogRequestIsSentAfterTwOfSilence(t *testing.T) {
	hss, ln, clock := startResponder(t, nil)
	s := openScript(t, ln, scscfHost)
	clock.waitForTimer(t, testWatchdog)
	clock.Advance(testWatchdog)
	dwr := s.expectDWR()
	if h, _ := dwr.Find(AVPOriginHost, 0).DiameterIdentity(); h != hssHost {
		t.Fatalf("DWR Origin-Host = %q", h)
	}
	if dwr.Find(AVPOriginStateID, 0) == nil {
		t.Fatal("DWR without Origin-State-Id")
	}
	s.write(s.answer(dwr, ResultSuccess))
	s.sync()
	clock.waitForTimer(t, testWatchdog)
	clock.Advance(testWatchdog)
	s.expectDWR()
	if !hss.Peer(scscfHost).Available() {
		t.Fatal("an answered watchdog must leave the peer available")
	}
}

func TestReceivedTrafficPostponesTheWatchdog(t *testing.T) {
	_, ln, clock := startResponder(t, nil)
	s := openScript(t, ln, scscfHost)
	clock.waitForTimer(t, testWatchdog)
	clock.Advance(20 * time.Second)
	s.sync() // traffic at 20 s moves the deadline to 50 s
	clock.Advance(10 * time.Second)
	// The timer fired at 30 s, found the deadline later and re-armed for the
	// remaining 20 s. Had it sent a DWR, it would have re-armed for a full
	// Tw instead.
	clock.waitForTimer(t, 20*time.Second)
	clock.Advance(20 * time.Second)
	s.expectDWR()
}

func TestUnansweredWatchdogMakesThePeerSuspectAndThenClosesIt(t *testing.T) {
	hss, ln, clock := startResponder(t, nil)
	s := openScript(t, ln, scscfHost)
	peer := hss.Peer(scscfHost)
	clock.waitForTimer(t, testWatchdog)
	clock.Advance(testWatchdog)
	s.expectDWR()

	clock.waitForTimer(t, testWatchdog)
	clock.Advance(testWatchdog)
	waitFor(t, "the peer to become suspect", func() bool { return !peer.Available() })
	if hss.Peer(scscfHost) == nil {
		t.Fatal("a suspect peer keeps its connection until the next expiry")
	}

	clock.waitForTimer(t, testWatchdog)
	clock.Advance(testWatchdog)
	s.expectClosed()
	waitFor(t, "the peer to be forgotten", func() bool { return hss.Peer(scscfHost) == nil })
}

func TestSuspectPeerRecoversOnAnyReceivedMessage(t *testing.T) {
	hss, ln, clock := startResponder(t, nil)
	s := openScript(t, ln, scscfHost)
	peer := hss.Peer(scscfHost)
	clock.waitForTimer(t, testWatchdog)
	clock.Advance(testWatchdog)
	s.expectDWR()
	clock.waitForTimer(t, testWatchdog)
	clock.Advance(testWatchdog)
	waitFor(t, "the peer to become suspect", func() bool { return !peer.Available() })

	s.sync()
	if !peer.Available() {
		t.Fatal("a message from a suspect peer must bring it back")
	}
}

func TestWatchdogIntervalIsJitteredByUpToTwoSeconds(t *testing.T) {
	for _, tt := range []struct {
		random uint64
		want   time.Duration
	}{
		{0, testWatchdog - 2*time.Second},
		{2000, testWatchdog},
		{4000, testWatchdog + 2*time.Second},
		{4001, testWatchdog - 2*time.Second},
	} {
		cfg := testConfig(newFakeClock(), hssHost)
		cfg.Random = func() uint64 { return tt.random }
		n := newTestNode(t, cfg)
		if got := n.watchdogInterval(); got != tt.want {
			t.Errorf("random %d: Tw = %s, want %s", tt.random, got, tt.want)
		}
	}
}

func TestDWRIsAnsweredWithSuccessAndTheOriginStateID(t *testing.T) {
	_, ln, _ := startResponder(t, func(c *Config) { c.OriginStateID = 1234 })
	s := openScript(t, ln, scscfHost)
	dwa := s.roundTrip(&Message{Code: CodeDeviceWatchdog, AVPs: s.origin()})
	if rc, _ := dwa.ResultCode(); rc != ResultSuccess {
		t.Fatalf("DWA result %d", rc)
	}
	if v, _ := dwa.Find(AVPOriginStateID, 0).Unsigned32(); v != 1234 {
		t.Fatalf("Origin-State-Id = %d", v)
	}
}

func TestReconnectedPeerCarriesTrafficOnlyAfterThreeWatchdogAnswers(t *testing.T) {
	n, peer, dialer, clock := startInitiator(t, nil)
	first := dialer.next(t)
	acceptCER(t, first)
	waitFor(t, "the first connection to open", peer.Available)

	_ = first.nc.Close()
	clock.waitForTimer(t, n.backoff(0))
	clock.Advance(n.backoff(0))

	s := dialer.next(t)
	acceptCER(t, s)
	// REOPEN starts with a DWR right away (RFC 3539 §3.4.1).
	for i := 1; i <= 3; i++ {
		dwr := s.expectDWR()
		if peer.Available() {
			t.Fatalf("available after %d watchdog answers", i-1)
		}
		if i == 1 {
			ans := s.roundTrip(&Message{Code: cmdTest, ApplicationID: appCx, AVPs: s.origin()})
			if rc, _ := ans.ResultCode(); rc != ResultUnableToDeliver || ans.Flags&FlagError == 0 {
				t.Fatalf("request while reopening answered %d (flags %#x), want DIAMETER_UNABLE_TO_DELIVER", rc, ans.Flags)
			}
		}
		s.write(s.answer(dwr, ResultSuccess))
		s.sync()
		if i < 3 {
			clock.waitForTimer(t, testWatchdog)
			clock.Advance(testWatchdog)
		}
	}
	if !peer.Available() {
		t.Fatal("not available after three watchdog answers")
	}
}

func TestReopeningConnectionToleratesOneMissedWatchdogAnswer(t *testing.T) {
	n, peer, dialer, clock := startInitiator(t, nil)
	first := dialer.next(t)
	acceptCER(t, first)
	waitFor(t, "the first connection to open", peer.Available)
	_ = first.nc.Close()
	clock.waitForTimer(t, n.backoff(0))
	clock.Advance(n.backoff(0))

	s := dialer.next(t)
	acceptCER(t, s)
	s.expectDWR() // left unanswered
	clock.waitForTimer(t, testWatchdog)
	clock.Advance(testWatchdog) // first miss: NumDWA becomes -1
	s.sync()
	clock.waitForTimer(t, testWatchdog)
	clock.Advance(testWatchdog) // second miss: close
	s.expectClosed()
}
