package scscf

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/milenage"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/routing"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// These tests run scscf as runtime.Main would, against a Diameter HSS on
// loopback, with the memory store, and a REGISTER sent over the core
// listener as pcscf would.

const (
	realm    = "ims.mnc001.mcc001.3gppnetwork.org"
	impi     = "001010000000001@" + realm
	impu     = "sip:+15550100001@" + realm
	realWait = 10 * time.Second
)

var password = []byte("test-password")

// diameterHSS is an HSS task that answers MAR with a SIP Digest vector for
// impi, or an IMS AKA one once aka is set, and SAR with impi's User-Data,
// and records the SARs. With asURI set, the User-Data sends that server a
// third-party REGISTER.
type diameterHSS struct {
	addr  string
	node  *diameter.Node
	asURI atomic.Pointer[string]
	mu    sync.Mutex
	sars  []*cx.SAR
	aka   *milenage.Milenage
	sqn   milenage.SQN
	rands uint64
}

// startHSS starts an HSS whose subscriber registers with SIP Digest.
func startHSS(t *testing.T) *diameterHSS { return startHSSOf(t, nil) }

// startHSSOf starts an HSS whose subscriber registers with IMS AKA, with
// aka as the keys its card holds, or with SIP Digest when aka is nil.
func startHSSOf(t *testing.T, aka *milenage.Milenage) *diameterHSS {
	t.Helper()
	dict, err := diameter.NewDictionary(cx.AVPs...)
	if err != nil {
		t.Fatal(err)
	}
	n, err := diameter.NewNode(diameter.Config{
		OriginHost: "hss-0a1b2c.rcs.local", OriginRealm: realm,
		HostIPAddresses:    []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		Applications:       []diameter.Application{cx.Application},
		SupportedVendorIDs: []uint32{cx.Vendor3GPP, cx.VendorETSI},
		Dictionary:         dict,
		Accept:             []diameter.PeerRule{{HostPattern: "scscf-*.rcs.local"}},
		Logger:             slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	n.SetErrorAVPs(cx.ApplicationID, cx.ErrorAVPs)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &diameterHSS{addr: l.Addr().String(), node: n, aka: aka}
	if aka != nil {
		if h.sqn, err = milenage.NewSQN(32, 0); err != nil {
			t.Fatal(err)
		}
	}
	n.HandleFunc(cx.ApplicationID, cx.CodeMultimediaAuth, func(_ context.Context, _ *diameter.Peer, req *diameter.Message) (*diameter.Message, error) {
		if h.aka != nil {
			item, err := h.akaVector()
			if err != nil {
				return nil, err
			}
			return (&cx.MAA{Answer: cx.Answer{Result: cx.ResultCode(2001)}, UserName: impi, AuthDataItems: []cx.AuthDataItem{item}}).Message(n, req)
		}
		ha1, err := digest.ComputeHA1(digest.MD5, impi, realm, password)
		if err != nil {
			return nil, err
		}
		return (&cx.MAA{Answer: cx.Answer{Result: cx.ResultCode(2001)}, UserName: impi, AuthDataItems: []cx.AuthDataItem{{
			Scheme: cx.SchemeSIPDigest, Digest: &cx.DigestAuthenticate{Realm: realm, Algorithm: "MD5", QoP: "auth", HA1: ha1},
		}}}).Message(n, req)
	})
	n.HandleFunc(cx.ApplicationID, cx.CodeServerAssignment, func(_ context.Context, _ *diameter.Peer, req *diameter.Message) (*diameter.Message, error) {
		sar, err := cx.ParseSAR(req)
		if err != nil {
			return nil, err
		}
		h.mu.Lock()
		h.sars = append(h.sars, sar)
		h.mu.Unlock()
		sp := ifc.ServiceProfile{PublicIdentities: []ifc.PublicIdentity{{Identity: impu}}}
		if as := h.asURI.Load(); as != nil {
			sp.InitialFilterCriteria = []ifc.FilterCriteria{{
				Priority:          40,
				TriggerPoint:      &ifc.TriggerPoint{ConditionTypeCNF: true, SPTs: []ifc.SPT{{Condition: ifc.Method("REGISTER"), Groups: []int{0}}}},
				ApplicationServer: ifc.ApplicationServer{ServerName: *as, DefaultHandling: ifc.SessionContinued},
			}}
		}
		data, err := (&ifc.Subscription{PrivateID: impi, ServiceProfiles: []ifc.ServiceProfile{sp}}).Marshal()
		if err != nil {
			return nil, err
		}
		return (&cx.SAA{Answer: cx.Answer{Result: cx.ResultCode(2001)}, UserName: impi, UserData: data}).Message(n, req)
	})
	go func() { _ = n.Serve(l) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), realWait)
		defer cancel()
		_ = n.Shutdown(ctx)
	})
	return h
}

// akaVector is the next IMS AKA vector for impi (TS 33.203): RAND‖AUTN,
// XRES and the keys, under the next sequence number.
func (h *diameterHSS) akaVector() (cx.AuthDataItem, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rands++
	var rnd [16]byte
	binary.BigEndian.PutUint64(rnd[8:], h.rands)
	var err error
	if h.sqn, err = h.sqn.Next(); err != nil {
		return cx.AuthDataItem{}, err
	}
	v := h.aka.Vector(rnd, h.sqn, [2]byte{0x80, 0})
	autn, xres, ck, ik := v.AUTN(), v.XRES(), v.CK(), v.IK()
	return cx.AuthDataItem{
		Scheme: cx.SchemeDigestAKAv1MD5, Authenticate: append(rnd[:], autn[:]...),
		Authorization: xres[:], ConfidentialityKey: ck[:], IntegrityKey: ik[:],
	}, nil
}

func (h *diameterHSS) sarsOf() []*cx.SAR {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*cx.SAR(nil), h.sars...)
}

type staticDiscovery []netip.Addr

func (s staticDiscovery) HSSAddresses(context.Context) ([]netip.Addr, error) { return s, nil }

// seededRand is a reproducible random source the service's goroutines can
// share. Unlike one byte over and over, it gives each nonce, branch and tag
// a value of its own, so that a test of more than one request does not
// meet a repeated one (#439 QA).
type seededRand struct {
	mu sync.Mutex
	c  *rand.ChaCha8
}

func newSeededRand(seed byte) *seededRand {
	var s [32]byte
	s[0] = seed
	return &seededRand{c: rand.NewChaCha8(s)}
}

func (r *seededRand) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.c.Read(p)
}

// running is scscf started by startSCSCF.
type running struct {
	core netip.AddrPort
	stop func() error
	h    *runtimetest.Harness
}

// testConfig is a configuration as Configure would give it, with the
// memory store.
func testConfig() ServiceConfig {
	return ServiceConfig{
		HomeDomain: realm, Namespace: "rcs.local",
		CoreAddr: "127.0.0.1:0", CoreHost: netip.MustParseAddr("127.0.0.2"),
		OriginRealm: realm, HSSRealm: realm, HSSDiscovery: DiscoveryDNS,
		HSSHostPattern: "hss-*.rcs.local", CxTimeout: 2 * time.Second,
		Store:         StoreMemory,
		NonceKey:      []byte("0123456789abcdef0123456789abcdef"),
		DialogKeys:    []routing.DialogKey{{ID: "k1", Key: []byte("fedcba9876543210fedcba9876543210")}},
		ICSCF:         mustURI("sip:icscf.rcs.local:5060;transport=tcp;lr"),
		PCSCFCorePort: DefaultPCSCFCorePort,
		ASTimeout:     routing.DefaultASTimeout, ThirdPartyTimeout: routing.DefaultThirdPartyTimeout,
		MaxThirdParty: routing.DefaultMaxThirdParty, NotifyTimeout: time.Second,
		SweepInterval: time.Hour, SweepLimit: DefaultSweepLimit,
		DrainTimeout:          time.Second,
		MaxServerTransactions: 1000, MaxServerTransactionBytes: 64 << 20,
	}
}

func mustURI(s string) sip.URI {
	u, err := sip.ParseURI(s)
	if err != nil {
		panic(err)
	}
	return u
}

// stopWait bounds a test's wait for a stop, which takes up to
// DrainTimeout plus stopMargin.
const stopWait = 30 * time.Second

// startSCSCF runs scscf until the test ends, with its HSS at hss.
func startSCSCF(t *testing.T, hss *diameterHSS, store state.Store) *running {
	t.Helper()
	return startSCSCFWith(t, hss, store, 1, nil)
}

// startSCSCFWith is startSCSCF with seed for its random source, which two
// instances must not share, and tweak applied to its configuration and
// deps.
func startSCSCFWith(t *testing.T, hss *diameterHSS, store state.Store, seed byte, tweak func(*ServiceConfig, *deps)) *running {
	t.Helper()
	h := runtimetest.New(t, "scscf")
	listening := make(chan netip.AddrPort, 1)
	cfg := testConfig()
	d := deps{
		rand:      newSeededRand(seed),
		store:     store,
		discovery: staticDiscovery{netip.MustParseAddr("127.0.0.1")},
		dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dl net.Dialer
			return dl.DialContext(ctx, network, hss.addr)
		},
		listening: func(a netip.AddrPort) { listening <- a },
		allow:     func(a netip.Addr) bool { return a.IsLoopback() },
	}
	if tweak != nil {
		tweak(&cfg, &d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, h.Runtime, cfg, d) }()
	r := &running{h: h}
	select {
	case r.core = <-listening:
	case err := <-done:
		cancel()
		t.Fatalf("run ended: %v", err)
	case <-time.After(realWait):
		cancel()
		t.Fatal("scscf did not start")
	}
	var once sync.Once
	var stopErr error
	r.stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case stopErr = <-done:
			case <-time.After(stopWait):
				stopErr = fmt.Errorf("scscf did not stop in %v", stopWait)
			}
		})
		return stopErr
	}
	t.Cleanup(func() {
		if err := r.stop(); err != nil {
			t.Errorf("stop: %v", err)
		}
	})
	// /readyz says scscf can take work once the HSS is connected: a
	// REGISTER before is answered 480. The harness clock is advanced past
	// the readiness cache at every look.
	deadline := time.Now().Add(realWait)
	for {
		h.Advance(2 * time.Second)
		if code, _ := h.Get("/readyz"); code == 200 {
			break
		}
		if time.Now().After(deadline) {
			_, body := h.Get("/readyz")
			t.Fatalf("scscf did not get ready: %s", body)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return r
}

// pcscfConn is a connection from the pcscf side to scscf's core listener.
type pcscfConn struct {
	c    net.Conn
	r    *sip.Reader
	cseq int
}

func dialSCSCF(t *testing.T, r *running) *pcscfConn {
	t.Helper()
	c, err := net.DialTimeout("tcp", r.core.String(), realWait)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &pcscfConn{c: c, r: sip.NewReader(bufio.NewReader(c), sip.Limits{})}
}

// register sends a REGISTER for impu as pcscf forwards it, with auth as
// its Authorization, and returns the final response.
func (p *pcscfConn) register(t *testing.T, auth string) *sip.Response {
	t.Helper()
	return p.registerVia(t, auth, "sip:flow-token@127.0.0.1:5070;transport=tcp;lr;ob")
}

// registerVia is register with path as the REGISTER's Path.
func (p *pcscfConn) registerVia(t *testing.T, auth, path string) *sip.Response {
	t.Helper()
	p.cseq++
	lines := []string{
		"REGISTER sip:" + realm + " SIP/2.0",
		fmt.Sprintf("Via: SIP/2.0/TCP 127.0.0.1:5070;branch=z9hG4bK-reg%d", p.cseq),
		"Max-Forwards: 69",
		"From: <" + impu + ">;tag=ue1",
		"To: <" + impu + ">",
		"Call-ID: reg-call-1",
		fmt.Sprintf("CSeq: %d REGISTER", p.cseq),
		`Contact: <sip:ue1@192.0.2.11:5060;transport=tcp>;expires=600;+sip.instance="<urn:uuid:00000000-0000-0000-0000-0000000000aa>";reg-id=1`,
		"Path: <" + path + ">",
		"Supported: path",
		"Authorization: " + auth,
		"Content-Length: 0",
	}
	if _, err := p.c.Write([]byte(strings.Join(lines, "\r\n") + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	return p.final(t)
}

// final reads the next final response on the connection.
func (p *pcscfConn) final(t *testing.T) *sip.Response {
	t.Helper()
	_ = p.c.SetReadDeadline(time.Now().Add(realWait))
	for {
		m, err := p.r.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		if res, ok := m.(*sip.Response); ok && res.StatusCode >= 200 {
			return res
		}
	}
}

// TestARegistrationRunsThroughTheWiredService: a REGISTER through the core
// listener is challenged with the HSS's vector, the answer is registered,
// and the HSS is told of the S-CSCF by its service name (#274 review), with
// the Service-Route naming the service, not the task.
func TestARegistrationRunsThroughTheWiredService(t *testing.T) {
	hss := startHSS(t)
	r := startSCSCF(t, hss, state.NewMemory())
	p := dialSCSCF(t, r)
	first := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="", uri="sip:%s", response=""`, impi, realm, realm)
	res := p.register(t, first)
	if res.StatusCode != 401 {
		t.Fatalf("first REGISTER: %d %s", res.StatusCode, res.Reason)
	}
	ch, err := digest.ParseChallenge(res.Header.Get("WWW-Authenticate"))
	if err != nil {
		t.Fatal(err)
	}
	creds, err := digest.Respond(ch, digest.ClientParams{Username: impi, Password: password, Method: "REGISTER", URI: "sip:" + realm, CNonce: "0a4f113b", NC: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res = p.register(t, creds.Header()); res.StatusCode != 200 {
		t.Fatalf("second REGISTER: %d %s", res.StatusCode, res.Reason)
	}
	routes := res.Header.Values("Service-Route")
	if len(routes) != 1 || !strings.Contains(routes[0], "scscf.rcs.local") || !strings.Contains(routes[0], "orig") {
		t.Errorf("Service-Route %q, want the service name with orig", routes)
	}
	sars := hss.sarsOf()
	if len(sars) == 0 {
		t.Fatal("no SAR reached the HSS")
	}
	for _, s := range sars {
		if s.ServerName != "sip:scscf.rcs.local" {
			t.Errorf("SAR Server-Name %q, want the service name", s.ServerName)
		}
	}
}

// TestTheServiceStopsWithinItsBudget: a stop drains, stops the sweeps and
// the router, and returns.
func TestTheServiceStopsWithinItsBudget(t *testing.T) {
	r := startSCSCF(t, startHSS(t), state.NewMemory())
	start := time.Now()
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > testConfig().DrainTimeout+stopMargin {
		t.Errorf("the stop took %v", took)
	}
}

// registered runs both REGISTERs of impu's registration over p, with path
// as its Path.
func registered(t *testing.T, p *pcscfConn, path string) {
	t.Helper()
	first := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="", uri="sip:%s", response=""`, impi, realm, realm)
	res := p.registerVia(t, first, path)
	if res.StatusCode != 401 {
		t.Fatalf("first REGISTER: %d %s", res.StatusCode, res.Reason)
	}
	ch, err := digest.ParseChallenge(res.Header.Get("WWW-Authenticate"))
	if err != nil {
		t.Fatal(err)
	}
	creds, err := digest.Respond(ch, digest.ClientParams{Username: impi, Password: password, Method: "REGISTER", URI: "sip:" + realm, CNonce: "0a4f113b", NC: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res = p.registerVia(t, creds.Header(), path); res.StatusCode != 200 {
		t.Fatalf("second REGISTER: %d %s", res.StatusCode, res.Reason)
	}
}

// pcscfCore is the core listener of a P-CSCF task, which answers each
// request it gets 200 and records it.
type pcscfCore struct {
	ln  net.Listener
	got chan *sip.Request
}

func startPCSCFCore(t *testing.T) *pcscfCore {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	p := &pcscfCore{ln: ln, got: make(chan *sip.Request, 16)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := sip.NewReader(bufio.NewReader(c), sip.Limits{})
				for {
					m, err := r.ReadMessage()
					if err != nil {
						return
					}
					req, ok := m.(*sip.Request)
					if !ok {
						continue
					}
					p.got <- req
					res, err := sip.NewResponse(req, 200, "", "pcscf1")
					if err != nil {
						return
					}
					b, err := res.Bytes()
					if err != nil {
						return
					}
					_, _ = c.Write(b)
				}
			}()
		}
	}()
	return p
}

func (p *pcscfCore) next(t *testing.T) *sip.Request {
	t.Helper()
	select {
	case req := <-p.got:
		return req
	case <-time.After(realWait):
		t.Fatal("the P-CSCF got nothing")
		return nil
	}
}

// TestAPCSCFsRegEventSubscriptionGetsItsNOTIFY: the dispatcher hands a
// SUBSCRIBE for the reg event to the notifier, and the NOTIFY goes, in a
// client transaction of scscf's own, to the P-CSCF the binding came over.
func TestAPCSCFsRegEventSubscriptionGetsItsNOTIFY(t *testing.T) {
	core := startPCSCFCore(t)
	r := startSCSCF(t, startHSS(t), state.NewMemory())
	p := dialSCSCF(t, r)
	path := "sip:flow-token@" + core.ln.Addr().String() + ";transport=tcp;lr;ob"
	registered(t, p, path)
	lines := []string{
		"SUBSCRIBE " + impu + " SIP/2.0",
		"Via: SIP/2.0/TCP 127.0.0.1:5070;branch=z9hG4bK-sub1",
		"Max-Forwards: 69",
		"From: <sip:pcscf.rcs.local>;tag=p1",
		"To: <" + impu + ">",
		"Call-ID: sub-call-1",
		"CSeq: 1 SUBSCRIBE",
		"Contact: <sip:sub1@" + core.ln.Addr().String() + ";transport=tcp>",
		"Event: reg",
		"Expires: 600",
		"Accept: application/reginfo+xml",
		"P-Asserted-Identity: <" + path + ">",
		"Content-Length: 0",
	}
	if _, err := p.c.Write([]byte(strings.Join(lines, "\r\n") + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if res := p.final(t); res.StatusCode != 200 {
		t.Fatalf("SUBSCRIBE: %d %s", res.StatusCode, res.Reason)
	}
	notify := core.next(t)
	if notify.Method != "NOTIFY" || notify.Header.Get("Event") != "reg" || !strings.Contains(string(notify.Body), impu) {
		t.Errorf("%s with Event %q and %d bytes", notify.Method, notify.Header.Get("Event"), len(notify.Body))
	}
}
