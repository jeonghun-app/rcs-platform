package diameter

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
)

func echoHandler(n *Node) HandlerFunc {
	return func(ctx context.Context, peer *Peer, req *Message) (*Message, error) {
		return n.NewAnswer(req, ResultSuccess, NewAVP(AVPUserName, FlagMandatory, 0, []byte("answered-by-"+n.cfg.OriginHost))), nil
	}
}

// connectedPair returns an `scscf` node connected to an `hss` node over a
// pipe, both with fake clocks.
func connectedPair(t *testing.T) (scscf, hss *Node, toHSS, toSCSCF *Peer) {
	t.Helper()
	hss, ln, _ := startResponder(t, nil)
	cfg := testConfig(newFakeClock(), scscfHost)
	cfg.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return addrConn{Conn: ln.connect(t, "10.0.7.7:41000"), local: tcpAddr("10.0.7.7:41000"), remote: tcpAddr("10.0.0.1:3868")}, nil
	}
	scscf = newTestNode(t, cfg)
	toHSS, err := scscf.Connect(PeerConfig{Address: "hss:3868", Host: hssHost})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the connection to open", func() bool { return toHSS.Available() && hss.Peer(scscfHost) != nil })
	return scscf, hss, toHSS, hss.Peer(scscfHost)
}

func TestRequestIsAnsweredByTheHandlerForItsApplicationAndCommand(t *testing.T) {
	scscf, hss, toHSS, toSCSCF := connectedPair(t)
	hss.Handle(appCx, cmdTest, echoHandler(hss))
	scscf.Handle(appCx, cmdTest+1, echoHandler(scscf))

	sid := scscf.NewSessionID("")
	req := scscf.NewRequest(cmdTest, appCx, sid, NewAVP(AVPDestinationRealm, FlagMandatory, 0, []byte(testRealm)))
	ans, err := toHSS.Send(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if ans.IsRequest() || ans.HopByHop != req.HopByHop || ans.EndToEnd != req.EndToEnd || ans.Code != cmdTest {
		t.Fatalf("answer header %+v does not match request %+v", ans, req)
	}
	if got, _ := ans.SessionID(); got != sid || ans.AVPs[0].Code != AVPSessionID {
		t.Fatalf("Session-Id = %q at position 0? %v", got, ans.AVPs[0].Code == AVPSessionID)
	}
	if h, _ := ans.Find(AVPOriginHost, 0).DiameterIdentity(); h != hssHost {
		t.Fatalf("Origin-Host = %q", h)
	}
	if rc, _ := ans.ResultCode(); rc != ResultSuccess {
		t.Fatalf("Result-Code = %d", rc)
	}
	if u, _ := ans.Find(AVPUserName, 0).UTF8String(); u != "answered-by-"+hssHost {
		t.Fatalf("User-Name = %q", u)
	}

	// The responder can send requests too (HSS-initiated Cx, ADR 0005).
	back, err := toSCSCF.Send(context.Background(), hss.NewRequest(cmdTest+1, appCx, hss.NewSessionID("")))
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := back.Find(AVPUserName, 0).UTF8String(); u != "answered-by-"+scscfHost {
		t.Fatalf("User-Name = %q", u)
	}
}

func TestConcurrentRequestsAreMatchedByHopByHopIdentifier(t *testing.T) {
	scscf, hss, toHSS, _ := connectedPair(t)
	hss.HandleFunc(appCx, cmdTest, func(ctx context.Context, peer *Peer, req *Message) (*Message, error) {
		return hss.NewAnswer(req, ResultSuccess, req.Find(AVPUserName, 0)), nil
	})
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := []byte{'u', byte('a' + i%26), byte('a' + i/26)}
			ans, err := toHSS.Send(context.Background(),
				scscf.NewRequest(cmdTest, appCx, scscf.NewSessionID(""), NewAVP(AVPUserName, FlagMandatory, 0, name)))
			if err != nil {
				t.Error(err)
				return
			}
			if got := ans.Find(AVPUserName, 0); got == nil || !bytes.Equal(got.Data, name) {
				t.Errorf("request %s got the answer for %v", name, got)
			}
		}()
	}
	wg.Wait()
}

func TestRequestErrorsAreAnsweredPerRFC6733Section7(t *testing.T) {
	missing := NewAVP(AVPUserName, FlagMandatory, 0, nil)
	tests := []struct {
		name    string
		handler HandlerFunc
		app     uint32
		code    uint32
		want    uint32
		eBit    bool
		failed  uint32
	}{
		{"unknown command of a known application", nil, appCx, cmdTest + 9, ResultCommandUnsupported, true, 0},
		{"application not negotiated", nil, appSh, cmdTest, ResultApplicationUnsupported, true, 0},
		{"handler reports a missing AVP", func(ctx context.Context, p *Peer, r *Message) (*Message, error) {
			return nil, &Error{ResultCode: ResultMissingAVP, FailedAVP: missing, Message: "missing User-Name"}
		}, appCx, cmdTest, ResultMissingAVP, false, AVPUserName},
		{"handler reports a protocol error", func(ctx context.Context, p *Peer, r *Message) (*Message, error) {
			return nil, &Error{ResultCode: ResultRealmNotServed}
		}, appCx, cmdTest, ResultRealmNotServed, true, 0},
		{"handler fails", func(ctx context.Context, p *Peer, r *Message) (*Message, error) {
			return nil, errors.New("store unavailable")
		}, appCx, cmdTest, ResultUnableToComply, false, 0},
		{"handler returns nothing", func(ctx context.Context, p *Peer, r *Message) (*Message, error) {
			return nil, nil
		}, appCx, cmdTest, ResultUnableToComply, false, 0},
		{"handler panics", func(ctx context.Context, p *Peer, r *Message) (*Message, error) {
			panic("bug")
		}, appCx, cmdTest, ResultUnableToComply, false, 0},
		{"handler answer too large to encode", func(ctx context.Context, p *Peer, r *Message) (*Message, error) {
			return &Message{AVPs: []*AVP{NewAVP(AVPClass, 0, 0, make([]byte, maxAVPLength))}}, nil
		}, appCx, cmdTest, ResultUnableToComply, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hss, ln, _ := startResponder(t, func(c *Config) {
				c.Applications = append(c.Applications, Application{ID: appSh, VendorID: vendor3GPP})
			})
			h := tt.handler
			if h == nil {
				h = echoHandler(hss)
			}
			hss.Handle(appCx, cmdTest, h)
			s := openScript(t, ln, scscfHost)
			sid := NewAVP(AVPSessionID, FlagMandatory, 0, []byte(scscfHost+";1;1"))
			ans := s.roundTrip(&Message{Code: tt.code, ApplicationID: tt.app, AVPs: append([]*AVP{sid}, s.origin()...)})
			if rc, _ := ans.ResultCode(); rc != tt.want {
				t.Fatalf("result %d, want %d", rc, tt.want)
			}
			if got := ans.Flags&FlagError != 0; got != tt.eBit {
				t.Fatalf("E bit %v, want %v", got, tt.eBit)
			}
			if got, _ := ans.SessionID(); got != scscfHost+";1;1" {
				t.Fatalf("error answer Session-Id = %q", got)
			}
			fa := ans.Find(AVPFailedAVP, 0)
			if tt.failed == 0 {
				if fa != nil {
					t.Fatal("unexpected Failed-AVP")
				}
				return
			}
			inner, _ := fa.Grouped()
			if len(inner) != 1 || inner[0].Code != tt.failed {
				t.Fatalf("Failed-AVP holds %+v", inner)
			}
			if msg, _ := ans.Find(AVPErrorMessage, 0).UTF8String(); msg != "missing User-Name" {
				t.Fatalf("Error-Message = %q", msg)
			}
		})
	}
}

func TestMalformedRequestsAreAnsweredAndTheConnectionStays(t *testing.T) {
	tests := []struct {
		name string
		edit func(b []byte) []byte
		want uint32
	}{
		{"invalid AVP length", func(b []byte) []byte {
			return append(b, rawAVP(AVPOriginStateID, FlagMandatory, 9, 1, 0, 0, 0)...)
		}, ResultInvalidAVPLength},
		{"E bit on a request", func(b []byte) []byte { b[4] |= byte(FlagError); return b }, ResultInvalidHdrBits},
		{"unsupported version", func(b []byte) []byte { b[0] = 2; return b }, ResultUnsupportedVersion},
		{"unsupported mandatory AVP", func(b []byte) []byte {
			return append(b, NewAVP(4242, FlagMandatory, 0, Unsigned32(1)).appendTo(nil)...)
		}, ResultAVPUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hss, ln, _ := startResponder(t, nil)
			hss.Handle(appCx, cmdTest, echoHandler(hss))
			s := openScript(t, ln, scscfHost)
			req := &Message{Flags: FlagRequest, Code: cmdTest, ApplicationID: appCx, HopByHop: 77, EndToEnd: 88, AVPs: s.origin()}
			b, _ := req.Encode()
			b = tt.edit(b)
			b[1], b[2], b[3] = byte(len(b)>>16), byte(len(b)>>8), byte(len(b))
			s.writeRaw(b)
			ans := s.read()
			if rc, _ := ans.ResultCode(); rc != tt.want || ans.HopByHop != 77 || ans.EndToEnd != 88 {
				t.Fatalf("answer result %d hop %d end %d, want %d for 77/88", rc, ans.HopByHop, ans.EndToEnd, tt.want)
			}
			if got := ans.Flags&FlagError != 0; got != IsProtocolError(tt.want) {
				t.Fatalf("E bit %v for result %d", got, tt.want)
			}
			s.sync()
		})
	}
}

func TestAnswerCopiesProxyInfoAndMirrorsTheProxiableBit(t *testing.T) {
	hss, ln, _ := startResponder(t, nil)
	hss.HandleFunc(appCx, cmdTest, func(ctx context.Context, p *Peer, req *Message) (*Message, error) {
		a := hss.NewAnswer(req, ResultSuccess)
		// Identifiers set wrongly by a handler are corrected by the node.
		a.HopByHop, a.EndToEnd, a.Code, a.Flags = 1, 2, 3, FlagRequest|FlagRetransmit
		return a, nil
	})
	s := openScript(t, ln, scscfHost)
	p1 := NewGrouped(AVPProxyInfo, FlagMandatory, 0, NewAVP(AVPProxyHost, FlagMandatory, 0, []byte("dra-1.rcs.test")), NewAVP(AVPProxyState, FlagMandatory, 0, []byte{1}))
	p2 := NewGrouped(AVPProxyInfo, FlagMandatory, 0, NewAVP(AVPProxyHost, FlagMandatory, 0, []byte("dra-2.rcs.test")), NewAVP(AVPProxyState, FlagMandatory, 0, []byte{2}))
	req := &Message{Flags: FlagProxiable, Code: cmdTest, ApplicationID: appCx, AVPs: append(s.origin(), p1, p2)}
	ans := s.roundTrip(req)
	if ans.Flags != FlagProxiable {
		t.Fatalf("answer flags %#x, want only P", ans.Flags)
	}
	got := ans.FindAll(AVPProxyInfo, 0)
	if len(got) != 2 || !bytes.Equal(got[0].Data, p1.Data) || !bytes.Equal(got[1].Data, p2.Data) {
		t.Fatalf("Proxy-Info = %+v", got)
	}
}

func TestBaseProtocolRequestsTheNodeDoesNotImplementAreRefused(t *testing.T) {
	_, ln, _ := startResponder(t, nil)
	s := openScript(t, ln, scscfHost)
	if rc, _ := s.roundTrip(testCER(scscfHost, testRealm, cxVSA())).ResultCode(); rc != ResultUnableToComply {
		t.Fatalf("CER on an open connection answered %d", rc)
	}
	ans := s.roundTrip(&Message{Code: 271, AVPs: s.origin()})
	if rc, _ := ans.ResultCode(); rc != ResultCommandUnsupported || ans.Flags&FlagError == 0 {
		t.Fatalf("accounting request answered %d (flags %#x)", rc, ans.Flags)
	}
}

func TestRequestsBeyondTheInFlightLimitAreAnsweredTooBusy(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	hss, ln, _ := startResponder(t, func(c *Config) { c.MaxInFlight = 1 })
	hss.HandleFunc(appCx, cmdTest, func(ctx context.Context, p *Peer, req *Message) (*Message, error) {
		started <- struct{}{}
		<-release
		return hss.NewAnswer(req, ResultSuccess), nil
	})
	s := openScript(t, ln, scscfHost)
	first := s.request(&Message{Code: cmdTest, ApplicationID: appCx, AVPs: s.origin()})
	<-started
	busy := s.roundTrip(&Message{Code: cmdTest, ApplicationID: appCx, AVPs: s.origin()})
	if rc, _ := busy.ResultCode(); rc != ResultTooBusy || busy.Flags&FlagError == 0 {
		t.Fatalf("second request answered %d (flags %#x), want DIAMETER_TOO_BUSY", rc, busy.Flags)
	}
	close(release)
	ans := s.read()
	if rc, _ := ans.ResultCode(); rc != ResultSuccess || ans.HopByHop != first.HopByHop {
		t.Fatalf("first request answered %d on %d", rc, ans.HopByHop)
	}
}

func TestHandlerContextEndsWhenTheConnectionCloses(t *testing.T) {
	hss, ln, _ := startResponder(t, nil)
	ended := make(chan struct{})
	hss.HandleFunc(appCx, cmdTest, func(ctx context.Context, p *Peer, req *Message) (*Message, error) {
		<-ctx.Done()
		close(ended)
		return nil, ctx.Err()
	})
	s := openScript(t, ln, scscfHost)
	s.request(&Message{Code: cmdTest, ApplicationID: appCx, AVPs: s.origin()})
	s.sync()
	_ = s.nc.Close()
	<-ended
}

func TestSendTimesOutOnTheInjectedClock(t *testing.T) {
	n, peer, dialer, clock := startInitiator(t, nil)
	s := dialer.next(t)
	acceptCER(t, s)
	waitFor(t, "peer to open", peer.Available)

	errc := make(chan error, 1)
	go func() {
		_, err := peer.Send(context.Background(), n.NewRequest(cmdTest, appCx, n.NewSessionID("")))
		errc <- err
	}()
	req := s.read()
	clock.waitForTimer(t, testRequestWait)
	clock.Advance(testRequestWait)
	if err := <-errc; !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	// A late answer is dropped without disturbing the connection.
	s.write(s.answer(req, ResultSuccess))
	s.sync()
}

func TestSendEndsWithTheContext(t *testing.T) {
	n, peer, dialer, _ := startInitiator(t, nil)
	s := dialer.next(t)
	acceptCER(t, s)
	waitFor(t, "peer to open", peer.Available)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := peer.Send(ctx, n.NewRequest(cmdTest, appCx, n.NewSessionID("")))
		errc <- err
	}()
	s.read()
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestPendingRequestsFailWhenTheConnectionCloses(t *testing.T) {
	n, peer, dialer, _ := startInitiator(t, nil)
	s := dialer.next(t)
	acceptCER(t, s)
	waitFor(t, "peer to open", peer.Available)
	errc := make(chan error, 1)
	go func() {
		_, err := peer.Send(context.Background(), n.NewRequest(cmdTest, appCx, n.NewSessionID("")))
		errc <- err
	}()
	s.read()
	_ = s.nc.Close()
	if err := <-errc; !errors.Is(err, ErrConnectionClosed) {
		t.Fatalf("err = %v, want ErrConnectionClosed", err)
	}
}

func TestAnswerForAnotherCommandIsNotTakenAsTheAnswer(t *testing.T) {
	n, peer, dialer, _ := startInitiator(t, nil)
	s := dialer.next(t)
	acceptCER(t, s)
	waitFor(t, "peer to open", peer.Available)
	type res struct {
		m   *Message
		err error
	}
	done := make(chan res, 1)
	go func() {
		m, err := peer.Send(context.Background(), n.NewRequest(cmdTest, appCx, n.NewSessionID("")))
		done <- res{m, err}
	}()
	req := s.read()
	wrong := s.answer(req, ResultSuccess)
	wrong.Code = cmdTest + 1
	s.write(wrong)
	s.write(s.answer(req, ResultMissingAVP))
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	if rc, _ := r.m.ResultCode(); rc != ResultMissingAVP || r.m.Code != cmdTest {
		t.Fatalf("delivered answer %d for command %d", rc, r.m.Code)
	}
}

func TestMalformedAnswerIsReportedToTheWaitingCaller(t *testing.T) {
	n, peer, dialer, _ := startInitiator(t, nil)
	s := dialer.next(t)
	acceptCER(t, s)
	waitFor(t, "peer to open", peer.Available)
	errc := make(chan error, 1)
	go func() {
		_, err := peer.Send(context.Background(), n.NewRequest(cmdTest, appCx, n.NewSessionID("")))
		errc <- err
	}()
	req := s.read()
	bad := s.answer(req, ResultSuccess, NewAVP(4242, FlagMandatory, 0, nil))
	s.write(bad)
	var derr *Error
	if err := <-errc; !errors.As(err, &derr) || derr.ResultCode != ResultAVPUnsupported {
		t.Fatalf("err = %v, want DIAMETER_AVP_UNSUPPORTED", err)
	}
}

func TestSendRefusesWhatThePeerCannotTake(t *testing.T) {
	n, peer, dialer, _ := startInitiator(t, nil)
	if _, err := peer.Send(context.Background(), n.NewRequest(cmdTest, appCx, "")); !errors.Is(err, ErrPeerUnavailable) {
		t.Fatalf("before the exchange: %v", err)
	}
	s := dialer.next(t)
	acceptCER(t, s)
	waitFor(t, "peer to open", peer.Available)
	if _, err := peer.Send(context.Background(), n.NewRequest(cmdTest, appSh, "")); !errors.Is(err, ErrApplicationNotNegotiated) {
		t.Fatalf("application not negotiated: %v", err)
	}
	if _, err := peer.Send(context.Background(), n.NewRequest(CodeDeviceWatchdog, AppCommon, "")); !errors.Is(err, ErrApplicationNotNegotiated) {
		t.Fatalf("base protocol command: %v", err)
	}
	big := n.NewRequest(cmdTest, appCx, "", NewAVP(AVPClass, 0, 0, make([]byte, maxAVPLength)))
	if _, err := peer.Send(context.Background(), big); !errors.Is(err, ErrMessageTooLong) {
		t.Fatalf("oversized request: %v", err)
	}
	s.sync()
}

func TestOversizedMessageClosesTheConnection(t *testing.T) {
	_, ln, _ := startResponder(t, func(c *Config) { c.Limits.MaxMessageSize = 512 })
	s := openScript(t, ln, scscfHost)
	s.write(&Message{Flags: FlagRequest, Code: cmdTest, ApplicationID: appCx,
		AVPs: append(s.origin(), NewAVP(AVPClass, 0, 0, make([]byte, 600)))})
	s.expectClosed()
}

func TestUnmatchedAnswerIsIgnored(t *testing.T) {
	_, ln, _ := startResponder(t, nil)
	s := openScript(t, ln, scscfHost)
	s.write(&Message{Code: cmdTest, ApplicationID: appCx, HopByHop: 12345, AVPs: s.origin()})
	s.sync()
}
