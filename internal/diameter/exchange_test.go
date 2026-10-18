package diameter

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestTwoNodesExchangeCapabilitiesAndKeepTheCommonApplications(t *testing.T) {
	hss, ln, _ := startResponder(t, func(c *Config) {
		c.Applications = []Application{{ID: appCx, VendorID: vendor3GPP}, {ID: appSh, VendorID: vendor3GPP}}
	})
	clock := newFakeClock()
	cfg := testConfig(clock, scscfHost)
	cfg.Applications = []Application{{ID: appCx, VendorID: vendor3GPP}, {ID: 4}}
	cfg.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return addrConn{Conn: ln.connect(t, "10.0.7.7:41000"), local: tcpAddr("10.0.7.7:41000"), remote: tcpAddr("10.0.0.1:3868")}, nil
	}
	scscf := newTestNode(t, cfg)
	peer, err := scscf.Connect(PeerConfig{Address: "hss.rcs.test:3868", Host: hssHost, Realm: testRealm})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "scscf to see the hss available", peer.Available)
	waitFor(t, "hss to register the scscf", func() bool { return hss.Peer(scscfHost) != nil })

	if got := peer.Applications(); !slices.Equal(got, []uint32{appCx}) {
		t.Errorf("initiator applications = %v, want only Cx", got)
	}
	back := hss.Peer(strings.ToUpper(scscfHost))
	if back == nil || !slices.Equal(back.Applications(), []uint32{appCx}) {
		t.Fatalf("responder peer = %+v", back)
	}
	if peer.Host() != hssHost || peer.Realm() != testRealm || back.Host() != scscfHost || back.Realm() != testRealm {
		t.Errorf("identities: %s/%s and %s/%s", peer.Host(), peer.Realm(), back.Host(), back.Realm())
	}
	if len(hss.Peers()) != 1 || len(scscf.Peers()) != 1 {
		t.Errorf("peer tables: hss %d, scscf %d", len(hss.Peers()), len(scscf.Peers()))
	}
}

func TestCERAdvertisesTheNodeCapabilities(t *testing.T) {
	_, _, dialer, _ := startInitiator(t, func(c *Config) {
		c.Applications = []Application{{ID: appCx, VendorID: vendor3GPP}, {ID: 4}}
		c.FirmwareRevision = 3
		c.OriginStateID = 99
	})
	s := dialer.next(t)
	cer := s.read()
	d := testDictionary(t)
	caps, err := parseCapabilities(cer, d)
	if err != nil {
		t.Fatal(err)
	}
	if caps.host != scscfHost || caps.realm != testRealm || caps.originStateID != 99 {
		t.Fatalf("caps = %+v", caps)
	}
	if !slices.Equal(caps.authApps, []uint32{4, appCx}) {
		t.Fatalf("applications = %v", caps.authApps)
	}
	// With no configured address, the connection's local address is used.
	if a, _ := cer.Find(AVPHostIPAddress, 0).Address(); a != netip.MustParseAddr("10.0.1.5") {
		t.Fatalf("Host-IP-Address = %v", a)
	}
	if v, _ := cer.Find(AVPSupportedVendorID, 0).Unsigned32(); v != vendor3GPP {
		t.Fatalf("Supported-Vendor-Id = %d", v)
	}
	if v, _ := cer.Find(AVPFirmwareRevision, 0).Unsigned32(); v != 3 {
		t.Fatalf("Firmware-Revision = %d", v)
	}
	if name, _ := cer.Find(AVPProductName, 0).UTF8String(); name != "rcs-platform" || cer.Find(AVPProductName, 0).Mandatory() {
		t.Fatalf("Product-Name = %q, M bit %v", name, cer.Find(AVPProductName, 0).Mandatory())
	}
}

func TestConfiguredHostIPAddressesAreAdvertised(t *testing.T) {
	_, ln, _ := startResponder(t, func(c *Config) {
		c.HostIPAddresses = []netip.Addr{netip.MustParseAddr("10.0.0.9"), netip.MustParseAddr("2001:db8::9")}
	})
	s := newScript(t, ln.connect(t, "10.0.1.5:40000"), scscfHost)
	s.write(testCER(scscfHost, testRealm, cxVSA()))
	cea := s.read()
	var got []netip.Addr
	for _, a := range cea.FindAll(AVPHostIPAddress, 0) {
		addr, _ := a.Address()
		got = append(got, addr)
	}
	if len(got) != 2 || got[0] != netip.MustParseAddr("10.0.0.9") || got[1] != netip.MustParseAddr("2001:db8::9") {
		t.Fatalf("Host-IP-Address = %v", got)
	}
}

func TestResponderRefusesAPeerNoRuleAccepts(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		realm  string
		remote string
		want   uint32
	}{
		{"task identity from the VPC", "scscf-77ff.rcs.test", testRealm, "10.0.3.3:5000", ResultSuccess},
		{"task identity from outside the VPC", "scscf-77ff.rcs.test", testRealm, "192.0.2.50:5000", ResultUnknownPeer},
		{"unknown host", "rogue.rcs.test", testRealm, "10.0.3.3:5000", ResultUnknownPeer},
		{"wildcard spanning a label", "scscf-x.evil.rcs.test", testRealm, "10.0.3.3:5000", ResultUnknownPeer},
		{"other realm", "scscf-77ff.rcs.test", "other.test", "10.0.3.3:5000", ResultUnknownPeer},
		{"exact host rule", "icscf.rcs.test", testRealm, "192.0.2.60:5000", ResultSuccess},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ln, _ := startResponder(t, func(c *Config) {
				c.Accept = append(c.Accept, PeerRule{Host: "icscf.rcs.test"})
			})
			s := newScript(t, ln.connect(t, tt.remote), tt.host)
			s.write(testCER(tt.host, tt.realm, cxVSA()))
			cea := s.read()
			rc, _ := cea.ResultCode()
			if rc != tt.want {
				t.Fatalf("CEA result %d, want %d", rc, tt.want)
			}
			if tt.want == ResultSuccess {
				return
			}
			if cea.Flags&FlagError == 0 {
				t.Error("DIAMETER_UNKNOWN_PEER is a protocol error and needs the E bit")
			}
			if cea.Find(AVPOriginHost, 0) == nil || cea.Find(AVPHostIPAddress, 0) == nil {
				t.Error("a refusing CEA still identifies the responder")
			}
			s.expectClosed()
		})
	}
}

func TestResponderWithoutRulesRefusesEveryone(t *testing.T) {
	_, ln, _ := startResponder(t, func(c *Config) { c.Accept = nil })
	s := newScript(t, ln.connect(t, "10.0.1.5:40000"), scscfHost)
	s.write(testCER(scscfHost, testRealm, cxVSA()))
	if rc, _ := s.read().ResultCode(); rc != ResultUnknownPeer {
		t.Fatalf("result %d", rc)
	}
	s.expectClosed()
}

func TestResponderRefusesUnacceptableCapabilities(t *testing.T) {
	tests := []struct {
		name   string
		cer    func() *Message
		want   uint32
		failed uint32
	}{
		{"no common application", func() *Message {
			return testCER(scscfHost, testRealm, NewAVP(AVPAuthApplicationID, FlagMandatory, 0, Unsigned32(4)))
		}, ResultNoCommonApplication, 0},
		{"in-band TLS only", func() *Message {
			return testCER(scscfHost, testRealm, cxVSA(), NewAVP(AVPInbandSecurityID, FlagMandatory, 0, Unsigned32(InbandSecurityTLS)))
		}, ResultNoCommonSecurity, 0},
		{"missing Host-IP-Address", func() *Message {
			m := testCER(scscfHost, testRealm, cxVSA())
			m.AVPs = slices.DeleteFunc(m.AVPs, func(a *AVP) bool { return a.Code == AVPHostIPAddress })
			return m
		}, ResultMissingAVP, AVPHostIPAddress},
		{"malformed AVP", func() *Message {
			return testCER(scscfHost, testRealm, cxVSA(), NewAVP(AVPOriginStateID, FlagMandatory, 0, []byte{1}))
		}, ResultInvalidAVPLength, AVPOriginStateID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ln, _ := startResponder(t, nil)
			s := newScript(t, ln.connect(t, "10.0.1.5:40000"), scscfHost)
			s.write(tt.cer())
			cea := s.read()
			if rc, _ := cea.ResultCode(); rc != tt.want {
				t.Fatalf("result %d, want %d", rc, tt.want)
			}
			if tt.failed != 0 {
				fa := cea.Find(AVPFailedAVP, 0)
				if fa == nil {
					t.Fatal("no Failed-AVP")
				}
				inner, _ := fa.Grouped()
				if len(inner) != 1 || inner[0].Code != tt.failed {
					t.Fatalf("Failed-AVP holds %+v, want code %d", inner, tt.failed)
				}
			}
			s.expectClosed()
		})
	}
}

func TestSecondConnectionFromAnOpenIdentityIsRefused(t *testing.T) {
	hss, ln, _ := startResponder(t, nil)
	first := openScript(t, ln, scscfHost)
	s := newScript(t, ln.connect(t, "10.0.1.6:40000"), scscfHost)
	s.write(testCER(scscfHost, testRealm, cxVSA()))
	if rc, _ := s.read().ResultCode(); rc != ResultUnableToComply {
		t.Fatalf("result %d, want DIAMETER_UNABLE_TO_COMPLY", rc)
	}
	s.expectClosed()
	first.sync()
	if hss.Peer(scscfHost) == nil {
		t.Fatal("the refused duplicate removed the open peer")
	}
}

func TestFirstMessageOtherThanCERClosesTheConnection(t *testing.T) {
	_, ln, _ := startResponder(t, nil)
	s := newScript(t, ln.connect(t, "10.0.1.5:40000"), scscfHost)
	s.write(&Message{Flags: FlagRequest, Code: CodeDeviceWatchdog, AVPs: s.origin()})
	s.expectClosed()
}

func TestGarbageBeforeCERClosesTheConnection(t *testing.T) {
	_, ln, _ := startResponder(t, nil)
	s := newScript(t, ln.connect(t, "10.0.1.5:40000"), scscfHost)
	s.writeRaw([]byte{1, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	s.expectClosed()
}

func TestConnectionThatNeverSendsCERIsClosedAfterTheTimeout(t *testing.T) {
	_, ln, clock := startResponder(t, nil)
	s := newScript(t, ln.connect(t, "10.0.1.5:40000"), scscfHost)
	clock.waitForTimer(t, testCapabilities)
	clock.Advance(testCapabilities)
	s.expectClosed()
}

func TestInitiatorRefusesAnUnacceptableCEA(t *testing.T) {
	tests := []struct {
		name string
		cea  func(cer *Message) *Message
	}{
		{"refusal", func(cer *Message) *Message { return testCEA(cer, ResultUnknownPeer, hssHost) }},
		{"no Result-Code", func(cer *Message) *Message {
			m := testCEA(cer, ResultSuccess, hssHost, cxVSA())
			m.AVPs = m.AVPs[1:]
			return m
		}},
		{"unexpected host", func(cer *Message) *Message { return testCEA(cer, ResultSuccess, "hss-other.rcs.test", cxVSA()) }},
		{"no common application", func(cer *Message) *Message {
			return testCEA(cer, ResultSuccess, hssHost, NewAVP(AVPAuthApplicationID, FlagMandatory, 0, Unsigned32(4)))
		}},
		{"in-band TLS only", func(cer *Message) *Message {
			return testCEA(cer, ResultSuccess, hssHost, cxVSA(), NewAVP(AVPInbandSecurityID, FlagMandatory, 0, Unsigned32(InbandSecurityTLS)))
		}},
		{"missing Product-Name", func(cer *Message) *Message {
			m := testCEA(cer, ResultSuccess, hssHost, cxVSA())
			m.AVPs = slices.DeleteFunc(m.AVPs, func(a *AVP) bool { return a.Code == AVPProductName })
			return m
		}},
		{"wrong Hop-by-Hop Identifier", func(cer *Message) *Message {
			m := testCEA(cer, ResultSuccess, hssHost, cxVSA())
			m.HopByHop++
			return m
		}},
		{"a request instead", func(cer *Message) *Message {
			m := testCER(hssHost, testRealm, cxVSA())
			return m
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, peer, dialer, _ := startInitiator(t, nil)
			s := dialer.next(t)
			s.write(tt.cea(s.read()))
			s.expectClosed()
			if peer.Available() {
				t.Fatal("peer available after a refused exchange")
			}
		})
	}
}

func TestInitiatorRefusesAPeerInAnotherRealm(t *testing.T) {
	clock := newFakeClock()
	dialer := newPipeDialer()
	cfg := testConfig(clock, scscfHost)
	cfg.Dial = dialer.Dial
	n := newTestNode(t, cfg)
	if _, err := n.Connect(PeerConfig{Address: "hss:3868", Realm: "other.test"}); err != nil {
		t.Fatal(err)
	}
	s := dialer.next(t)
	acceptCER(t, s)
	s.expectClosed()
}

func TestInitiatorWithoutExpectationsAcceptsAnyIdentity(t *testing.T) {
	clock := newFakeClock()
	dialer := newPipeDialer()
	cfg := testConfig(clock, scscfHost)
	cfg.Dial = dialer.Dial
	n := newTestNode(t, cfg)
	p, err := n.Connect(PeerConfig{Address: "hss:3868"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Host() != "" || p.Available() {
		t.Fatalf("peer before the exchange: host %q, available %v", p.Host(), p.Available())
	}
	s := dialer.next(t)
	acceptCER(t, s)
	waitFor(t, "peer to open", p.Available)
	if p.Host() != hssHost || n.Peer(hssHost) != p {
		t.Fatalf("peer host %q, table entry %v", p.Host(), n.Peer(hssHost))
	}
}

func TestNodesTalkOverLoopbackTCPWithTheDefaultDialerAndClock(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	quiet := slog.New(slog.DiscardHandler)
	hss, err := NewNode(Config{OriginHost: hssHost, OriginRealm: testRealm, Logger: quiet,
		Applications: []Application{{ID: appCx, VendorID: vendor3GPP}},
		Accept:       []PeerRule{{HostPattern: "scscf-*.rcs.test", Networks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}})
	if err != nil {
		t.Fatal(err)
	}
	hss.HandleFunc(appCx, cmdTest, func(ctx context.Context, p *Peer, req *Message) (*Message, error) {
		return hss.NewAnswer(req, ResultSuccess), nil
	})
	served := make(chan error, 1)
	go func() { served <- hss.Serve(ln) }()

	scscf, err := NewNode(Config{OriginHost: scscfHost, OriginRealm: testRealm, Logger: quiet,
		Applications: []Application{{ID: appCx, VendorID: vendor3GPP}}})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := scscf.Connect(PeerConfig{Address: ln.Addr().String(), Host: hssHost})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the loopback connection to open", peer.Available)
	ans, err := peer.Send(context.Background(), scscf.NewRequest(cmdTest, appCx, scscf.NewSessionID("")))
	if err != nil {
		t.Fatal(err)
	}
	if rc, _ := ans.ResultCode(); rc != ResultSuccess {
		t.Fatalf("result %d", rc)
	}

	ctx, cancel := context.WithTimeout(context.Background(), realWait)
	defer cancel()
	if err := scscf.Shutdown(ctx); err != nil {
		t.Fatalf("scscf Shutdown: %v", err)
	}
	waitFor(t, "the hss to see the DPR", func() bool { return hss.Peer(scscfHost) == nil })
	if err := hss.Shutdown(ctx); err != nil {
		t.Fatalf("hss Shutdown: %v", err)
	}
	if err := <-served; !errors.Is(err, ErrNodeClosed) {
		t.Fatalf("Serve = %v", err)
	}
}

func TestConnectionsBeyondThePendingExchangeLimitAreClosedAtOnce(t *testing.T) {
	hss, ln, _ := startResponder(t, func(c *Config) { c.MaxPendingConnections = 1 })
	silent := newScript(t, ln.connect(t, "10.0.1.5:40000"), scscfHost)

	refused := newScript(t, ln.connect(t, "10.0.1.6:40000"), "scscf-2.rcs.test")
	refused.expectClosed()

	// Once the first connection finishes its exchange there is room again.
	silent.write(testCER(scscfHost, testRealm, cxVSA()))
	if rc, _ := silent.read().ResultCode(); rc != ResultSuccess {
		t.Fatalf("CEA result %d", rc)
	}
	waitFor(t, "the exchange to be counted as finished", func() bool {
		hss.mu.Lock()
		defer hss.mu.Unlock()
		return hss.exchanging == 0
	})
	openScript(t, ln, "scscf-3.rcs.test")
}
