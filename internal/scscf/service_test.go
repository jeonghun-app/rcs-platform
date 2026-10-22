package scscf

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
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
	"github.com/jeonghun-app/rcs-platform/internal/scscf/registrar"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// These tests are #439 QA's probes of the wired service: the Cx push
// requests, the stop with work left toward a peer that does not answer,
// and a registration across two instances.

// device is one UE behind a P-CSCF path.
type device struct {
	path, contact, callID string
}

// deviceAt is the n-th UE, behind the P-CSCF core listener at core.
func deviceAt(core string, n int) device {
	return device{
		path:    fmt.Sprintf("sip:flow-%d@%s;transport=tcp;lr;ob", n, core),
		contact: fmt.Sprintf(`<sip:ue%d@192.0.2.%d:5060;transport=tcp>;+sip.instance="<urn:uuid:00000000-0000-0000-0000-0000000000a%d>";reg-id=1`, n, 10+n, n),
		callID:  fmt.Sprintf("reg-device-%d", n),
	}
}

// send writes a request and returns its final response.
func (p *pcscfConn) send(t *testing.T, lines []string) *sip.Response {
	t.Helper()
	if _, err := p.c.Write([]byte(strings.Join(lines, "\r\n") + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	return p.final(t)
}

// registerDevice sends dv's REGISTER with expires and auth.
func (p *pcscfConn) registerDevice(t *testing.T, dv device, expires int, auth string) *sip.Response {
	t.Helper()
	p.cseq++
	return p.send(t, []string{
		"REGISTER sip:" + realm + " SIP/2.0",
		fmt.Sprintf("Via: SIP/2.0/TCP 127.0.0.1:5070;branch=z9hG4bK-dev%d", p.cseq),
		"Max-Forwards: 69",
		"From: <" + impu + ">;tag=ue-" + dv.callID, "To: <" + impu + ">",
		"Call-ID: " + dv.callID, fmt.Sprintf("CSeq: %d REGISTER", p.cseq),
		"Contact: " + dv.contact + fmt.Sprintf(";expires=%d", expires),
		"Path: <" + dv.path + ">", "Supported: path",
		"Authorization: " + auth, "Content-Length: 0",
	})
}

// firstAuthorization is the Authorization of a REGISTER before the
// challenge, which names no algorithm.
var firstAuthorization = fmt.Sprintf(`Digest username="%s", realm="%s", nonce="", uri="sip:%s", response=""`, impi, realm, realm)

// answer is the Authorization that answers res's challenge: with the
// password, or for AKA with the RES the card computes from the RAND, once
// it has checked the network's AUTN (RFC 3310 §3.2).
func answer(t *testing.T, res *sip.Response, card *milenage.Milenage) string {
	t.Helper()
	if res.StatusCode != 401 {
		t.Fatalf("got %d %s, want a 401", res.StatusCode, res.Reason)
	}
	ch, err := digest.ParseChallenge(res.Header.Get("WWW-Authenticate"))
	if err != nil {
		t.Fatal(err)
	}
	p := digest.ClientParams{Username: impi, Password: password, Method: "REGISTER", URI: "sip:" + realm, CNonce: "0a4f113b", NC: 1}
	if card != nil {
		if ch.Algorithm != digest.AKAv1MD5 {
			t.Fatalf("challenged with %q, want AKAv1-MD5", ch.Algorithm)
		}
		rnd, autn, err := digest.ParseAKANonce(ch.Nonce)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := card.CheckAUTN(rnd, autn); err != nil {
			t.Fatalf("the card refused the network: %v", err)
		}
		r := card.F2(rnd)
		p.Password = r[:]
	}
	creds, err := digest.Respond(ch, p)
	if err != nil {
		t.Fatal(err)
	}
	return creds.Header()
}

// registerFully runs dv's two REGISTERs with SIP Digest.
func (p *pcscfConn) registerFully(t *testing.T, dv device, expires int) {
	t.Helper()
	res := p.registerDevice(t, dv, expires, firstAuthorization)
	if res = p.registerDevice(t, dv, expires, answer(t, res, nil)); res.StatusCode != 200 {
		t.Fatalf("second REGISTER: %d %s", res.StatusCode, res.Reason)
	}
}

// subscribeReg subscribes, as the P-CSCF of path, to impu's reg event,
// with its Contact at contact.
func (p *pcscfConn) subscribeReg(t *testing.T, path, contact, callID string) {
	t.Helper()
	res := p.send(t, []string{
		"SUBSCRIBE " + impu + " SIP/2.0",
		"Via: SIP/2.0/TCP 127.0.0.1:5070;branch=z9hG4bK-sub-" + callID,
		"Max-Forwards: 69",
		"From: <sip:pcscf.rcs.local>;tag=p-" + callID, "To: <" + impu + ">",
		"Call-ID: " + callID, "CSeq: 1 SUBSCRIBE",
		"Contact: <sip:sub@" + contact + ";transport=tcp>",
		"Event: reg", "Expires: 600", "Accept: application/reginfo+xml",
		"P-Asserted-Identity: <" + path + ">", "Content-Length: 0",
	})
	if res.StatusCode != 200 {
		t.Fatalf("SUBSCRIBE: %d %s", res.StatusCode, res.Reason)
	}
}

// silentPeer is a SIP peer that reads what it is sent and never answers,
// keeping the first request.
type silentPeer struct {
	addr  string
	got   atomic.Int64
	first atomic.Pointer[sip.Request]
}

func startSilentPeer(t *testing.T) *silentPeer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &silentPeer{addr: ln.Addr().String()}
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
					if req, ok := m.(*sip.Request); ok {
						s.first.CompareAndSwap(nil, req)
					}
					s.got.Add(1)
				}
			}()
		}
	}()
	return s
}

// waitFor polls cond until it holds, or fails the test.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(realWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("no %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// peer is the S-CSCF's connection to the HSS, once it is up.
func (h *diameterHSS) peer(t *testing.T) *diameter.Peer {
	t.Helper()
	var up *diameter.Peer
	waitFor(t, "S-CSCF connected to the HSS", func() bool {
		for _, p := range h.node.Peers() {
			if p.Available() {
				up = p
				return true
			}
		}
		return false
	})
	return up
}

// push sends the S-CSCF an RTR, or a PPR when ppr, for impi, and returns
// the answer's Result-Code and whether its E bit is set.
func (h *diameterHSS) push(t *testing.T, ppr bool) (uint32, bool) {
	t.Helper()
	p := h.peer(t)
	req := cx.Request{SessionID: h.node.NewSessionID(""), DestinationHost: p.Host(), DestinationRealm: p.Realm()}
	var m *diameter.Message
	var err error
	if ppr {
		data, merr := (&ifc.Subscription{PrivateID: impi, ServiceProfiles: []ifc.ServiceProfile{{PublicIdentities: []ifc.PublicIdentity{{Identity: impu}}}}}).Marshal()
		if merr != nil {
			t.Fatal(merr)
		}
		m, err = (&cx.PPR{Request: req, UserName: impi, UserData: data}).Message(h.node)
	} else {
		m, err = (&cx.RTR{Request: req, UserName: impi, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}).Message(h.node)
	}
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), realWait)
	defer cancel()
	ans, err := p.Send(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	rc, ok := ans.ResultCode()
	if !ok {
		t.Fatal("an answer without a Result-Code")
	}
	return rc, ans.Flags&diameter.FlagError != 0
}

// TestTheHSSsPushRequestsAreRefusedUntilTheRegistrarIsWired: an RTR or a
// PPR that comes before the registrar is set is answered 3004 with the E
// bit, so that the HSS tries another S-CSCF task (RFC 6733 §7.1.3).
func TestTheHSSsPushRequestsAreRefusedUntilTheRegistrarIsWired(t *testing.T) {
	hss := startHSS(t)
	h := runtimetest.New(t, "scscf")
	var reg atomic.Pointer[registrar.Registrar]
	d := deps{rand: newSeededRand(2), discovery: staticDiscovery{netip.MustParseAddr("127.0.0.1")}, dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dl net.Dialer
		return dl.DialContext(ctx, network, hss.addr)
	}}
	c, _, err := newCxClient(context.Background(), h.Runtime, testConfig(), d, &reg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	for _, ppr := range []bool{false, true} {
		if rc, e := hss.push(t, ppr); rc != diameter.ResultTooBusy || !e {
			t.Errorf("PPR %v before the wiring: %d with the E bit %v, want 3004 with it", ppr, rc, e)
		}
	}
}

// TestAnRTREndsTheRegistrationOnceWired: once the service runs, the HSS's
// RTR is the registrar's, which ends the set and tells the subscribed
// P-CSCF. A full-state NOTIFY of the active registration may still come
// before that one, the registration's own change catching up with the
// subscription on a loaded host (#544: CSeq 2 active, then CSeq 3
// terminated, on the same dialog); the test reads past those, a few at
// most, to the terminated one.
func TestAnRTREndsTheRegistrationOnceWired(t *testing.T) {
	hss := startHSS(t)
	core := startPCSCFCore(t)
	r := startSCSCF(t, hss, state.NewMemory())
	p := dialSCSCF(t, r)
	dv := deviceAt(core.ln.Addr().String(), 1)
	p.registerFully(t, dv, 600)
	p.subscribeReg(t, dv.path, core.ln.Addr().String(), "sub-rtr")
	core.next(t)
	if rc, _ := hss.push(t, false); rc != diameter.ResultSuccess {
		t.Fatalf("RTR answered %d, want 2001", rc)
	}
	for i := 0; ; i++ {
		n := core.next(t)
		body := string(n.Body)
		if strings.Contains(body, `state="terminated"`) {
			return
		}
		if i == 2 || n.Method != "NOTIFY" || !strings.Contains(body, `state="active"`) {
			t.Fatalf("NOTIFY %d after the RTR: %s with %q, want the registration terminated", i+1, n.Method, body)
		}
	}
}

// TestAStopLeavesNOTIFYsToAPCSCFThatDoesNotAnswer: NOTIFYs queued toward
// a P-CSCF that never answers hold the stop no longer than its budget,
// though each may wait a minute; the sweeps of the other tasks send them.
func TestAStopLeavesNOTIFYsToAPCSCFThatDoesNotAnswer(t *testing.T) {
	hss := startHSS(t)
	silent := startSilentPeer(t)
	r := startSCSCFWith(t, hss, state.NewMemory(), 1, func(c *ServiceConfig, _ *deps) { c.NotifyTimeout = time.Minute })
	p := dialSCSCF(t, r)
	dv := deviceAt(silent.addr, 1)
	p.registerFully(t, dv, 600)
	p.subscribeReg(t, dv.path, silent.addr, "sub-silent")
	waitFor(t, "NOTIFY at the P-CSCF", func() bool { return silent.got.Load() > 0 })
	for n := 2; n <= 4; n++ {
		p.registerFully(t, deviceAt(silent.addr, n), 600)
	}
	start := time.Now()
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	checkStopTook(t, time.Since(start))
}

// stopSlack is what a loaded host may add to a stop measured from outside
// run: the stop itself ends returnMargin before its budget.
const stopSlack = 500 * time.Millisecond

// checkStopTook fails the test if a stop took past its budget,
// DrainTimeout plus stopMargin, by more than stopSlack (#439 QA).
func checkStopTook(t *testing.T, took time.Duration) {
	t.Helper()
	if budget := testConfig().DrainTimeout + stopMargin; took > budget+stopSlack {
		t.Errorf("the stop took %v, past its budget of %v", took, budget)
	}
}

// TestAStopGivesUpOnAThirdPartyREGISTERToAServerThatDoesNotAnswer: a
// third-party REGISTER at a server that does not answer, and may wait a
// minute, holds the stop no longer than its budget, and is counted; the
// Cx client still has time for its DPR (#439 QA). The REGISTER has the one
// Via its sender gave it (RFC 3261 §8.1.1.7, #439 code review).
func TestAStopGivesUpOnAThirdPartyREGISTERToAServerThatDoesNotAnswer(t *testing.T) {
	hss := startHSS(t)
	as := startSilentPeer(t)
	uri := "sip:" + as.addr + ";transport=tcp"
	hss.asURI.Store(&uri)
	var dprs atomic.Int64
	r := startSCSCFWith(t, hss, state.NewMemory(), 1, func(c *ServiceConfig, d *deps) {
		c.ThirdPartyTimeout = time.Minute
		d.dial = dprDial(hss, false, &dprs)
	})
	p := dialSCSCF(t, r)
	p.registerFully(t, deviceAt("127.0.0.1:5070", 1), 600)
	waitFor(t, "third-party REGISTER at the server", func() bool { return as.got.Load() > 0 })
	start := time.Now()
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	checkStopTook(t, time.Since(start))
	if got, _ := r.h.Metric("routing.third_party.dropped_at_stop"); got != 1 {
		t.Errorf("%v dropped at the stop, want the one at the server", got)
	}
	if dprs.Load() == 0 {
		t.Error("no DPR went to the HSS: the Cx client was closed with no time left")
	}
	if vias := as.first.Load().Header.Values("Via"); len(vias) != 1 {
		t.Errorf("the third-party REGISTER has %d Vias", len(vias))
	}
}

// TestAChallengeOnOneInstanceIsAnsweredOnAnother: two instances share the
// store, and the answer to one's challenge registers on the other, with
// SIP Digest and with IMS AKA.
func TestAChallengeOnOneInstanceIsAnsweredOnAnother(t *testing.T) {
	var k, opc [milenage.KeySize]byte
	k[0], opc[0] = 0x11, 0x22
	card := milenage.New(k, opc)
	for _, c := range []struct {
		name string
		card *milenage.Milenage
	}{{"digest", nil}, {"aka", &card}} {
		t.Run(c.name, func(t *testing.T) {
			hss := startHSSOf(t, c.card)
			store := state.NewMemory()
			a := dialSCSCF(t, startSCSCFWith(t, hss, store, 1, nil))
			b := dialSCSCF(t, startSCSCFWith(t, hss, store, 2, nil))
			dv := deviceAt("127.0.0.1:5070", 1)
			res := a.registerDevice(t, dv, 600, firstAuthorization)
			b.cseq = a.cseq
			if res = b.registerDevice(t, dv, 600, answer(t, res, c.card)); res.StatusCode != 200 {
				t.Fatalf("the answer on the other instance: %d %s", res.StatusCode, res.Reason)
			}
			if got := len(res.Header.Values("Service-Route")); got != 1 {
				t.Errorf("%d Service-Routes", got)
			}
		})
	}
}

// holdingCore is a P-CSCF core listener that answers each request 200
// once release is closed, and records whether the S-CSCF was still
// connected to hss when it answered.
type holdingCore struct {
	ln      net.Listener
	got     chan *sip.Request
	release chan struct{}
	hssUp   atomic.Bool
	mu      sync.Mutex
	all     []*sip.Request
}

// received is every request the core got.
func (p *holdingCore) received() []*sip.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.all)
}

func startHoldingCore(t *testing.T, hss *diameterHSS) *holdingCore {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	p := &holdingCore{ln: ln, got: make(chan *sip.Request, 16), release: make(chan struct{})}
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
					p.mu.Lock()
					p.all = append(p.all, req)
					p.mu.Unlock()
					p.got <- req
					<-p.release
					p.hssUp.Store(hss.connected())
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

// connected reports whether an S-CSCF is connected to the HSS.
func (h *diameterHSS) connected() bool {
	for _, p := range h.node.Peers() {
		if p.Available() {
			return true
		}
	}
	return false
}

// TestAStopAnswersItsWorkBeforeItClosesTheTransportAndTheCxClient (#439
// code review): a stop with a SUBSCRIBE's first NOTIFY at a P-CSCF that
// holds its answer waits for the answer, which still comes over the open
// transport, with the HSS still connected, and only then closes the
// transport and says goodbye to the HSS.
func TestAStopAnswersItsWorkBeforeItClosesTheTransportAndTheCxClient(t *testing.T) {
	hss := startHSS(t)
	core := startHoldingCore(t, hss)
	r := startSCSCFWith(t, hss, state.NewMemory(), 1, func(c *ServiceConfig, _ *deps) { c.NotifyTimeout = 30 * time.Second })
	p := dialSCSCF(t, r)
	dv := deviceAt(core.ln.Addr().String(), 1)
	p.registerFully(t, dv, 600)
	p.subscribeReg(t, dv.path, core.ln.Addr().String(), "sub-order")
	if n := recv(t, core.got); n.Method != "NOTIFY" {
		t.Fatalf("the P-CSCF got a %s", n.Method)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- r.stop() }()
	// Long enough for a stop that did not wait to have closed what it
	// closes; the stop that waits has its budget, over five seconds.
	time.Sleep(500 * time.Millisecond)
	close(core.release)
	if err := recv(t, stopped); err != nil {
		t.Fatal(err)
	}
	// A change NOTIFY may follow the first, from the registration's own
	// work still under way when the SUBSCRIBE came; it is held and
	// answered the same way. Every one the P-CSCF got was answered over
	// the open transport, none of them twice (#479).
	got := core.received()
	if n, _ := r.h.Metric("regevent.notified"); n < 1 || int(n) != len(got) {
		t.Errorf("%v NOTIFYs answered of %d the P-CSCF got, want every one, the held one first", n, len(got))
	}
	checkNotifySequence(t, got)
	if !core.hssUp.Load() {
		t.Error("the Cx client closed before the NOTIFY was answered")
	}
	waitFor(t, "goodbye to the HSS", func() bool { return !hss.connected() })
}

// slowReads is the memory store, whose registration reads take delay once
// it is set, as DynamoDB's may.
type slowReads struct {
	*state.Memory
	delay atomic.Int64
}

func (s *slowReads) Registration(ctx context.Context, k state.SetKey) (*state.Registration, error) {
	time.Sleep(time.Duration(s.delay.Load()))
	return s.Memory.Registration(ctx, k)
}

// TestAStopRightAfterASUBSCRIBEStillSendsItsFirstNOTIFY (#439 code
// review): the SUBSCRIBE is done for the drain once its 200 is written, and
// its NOTIFY, which reads the set again first, goes after; the stop waits
// for it.
func TestAStopRightAfterASUBSCRIBEStillSendsItsFirstNOTIFY(t *testing.T) {
	hss := startHSS(t)
	core := startPCSCFCore(t)
	store := &slowReads{Memory: state.NewMemory()}
	r := startSCSCF(t, hss, store)
	p := dialSCSCF(t, r)
	dv := deviceAt(core.ln.Addr().String(), 1)
	p.registerFully(t, dv, 600)
	store.delay.Store(int64(300 * time.Millisecond))
	p.subscribeReg(t, dv.path, core.ln.Addr().String(), "sub-at-stop")
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-core.got:
		if n.Method != "NOTIFY" {
			t.Errorf("the P-CSCF got a %s", n.Method)
		}
	default:
		t.Error("the stop returned before the SUBSCRIBE's first NOTIFY went")
	}
}

// TestTheProxyAllowsAsManyContextsAsServerTransactions: as icscf's (#311
// code review), so that a burst meets the configured count first.
func TestTheProxyAllowsAsManyContextsAsServerTransactions(t *testing.T) {
	tcfg, contexts, bytes := proxyLimits(ServiceConfig{MaxServerTransactions: 30000, MaxServerTransactionBytes: 1 << 30})
	if tcfg.MaxServerTransactions != 30000 || tcfg.MaxServerTransactionBytes != 1<<30 || contexts != 30000 || bytes != 1<<30 {
		t.Fatalf("limits = %+v, %d contexts, %d bytes", tcfg, contexts, bytes)
	}
}

// recv is the next value of ch, or fails the test.
func recv[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(stopWait):
		t.Fatal("nothing came")
	}
	panic("unreachable")
}

// TestAStopDoesNotWaitOnAPeerThatStoppedReading (#439 code review and QA,
// after pcscf's for #366): a core peer stops reading while the S-CSCF's
// own handlers answer its SUBSCRIBEs, which wait for room in its
// connection's queue. Closing the transport first releases them; the
// proxy's Close would otherwise wait for them, up to WriteTimeout, which
// is long here so that filling the queue on a loaded host cannot trip it.
// The queue is small, so that it fills fast, and the wait for it to fill
// fails only when it stops filling.
func TestAStopDoesNotWaitOnAPeerThatStoppedReading(t *testing.T) {
	const writeTimeout = time.Minute
	const queueBytes = 256 << 10
	var tr *transport.Transport
	r := startSCSCFWith(t, startHSS(t), state.NewMemory(), 1, func(c *ServiceConfig, d *deps) {
		d.writeTimeout = writeTimeout
		d.sendQueueBytes = queueBytes
		d.transportMade = func(made *transport.Transport) { tr = made }
	})
	c, err := net.DialTimeout("tcp", r.core.String(), realWait)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(4096)
	}
	// A reg event SUBSCRIBE for a user with no registration is refused by
	// the notifier, on a handler goroutine, whose answer waits for room;
	// its long Via makes the answer large. They are sent until the stop
	// closes the connection, so the queue stays full.
	pad := strings.Repeat("z", 3000)
	_ = c.SetWriteDeadline(time.Now().Add(writeTimeout))
	go func() {
		for i := 0; ; i++ {
			text := strings.Join([]string{
				"SUBSCRIBE " + impu + " SIP/2.0",
				fmt.Sprintf("Via: SIP/2.0/TCP 127.0.0.1:5070;branch=z9hG4bK-stall%d;p=%s", i, pad),
				"Max-Forwards: 69",
				fmt.Sprintf("From: <sip:pcscf.rcs.local>;tag=stall%d", i), "To: <" + impu + ">",
				fmt.Sprintf("Call-ID: stall-%d", i), "CSeq: 1 SUBSCRIBE",
				"Contact: <sip:sub@127.0.0.1:5070;transport=tcp>",
				"Event: reg", "Expires: 600", "Content-Length: 0",
			}, "\r\n") + "\r\n\r\n"
			if _, err := io.WriteString(c, text); err != nil {
				return
			}
		}
	}()
	full := int64(queueBytes - 16<<10)
	waitForProgress(t, "the send queue to fill", func() int64 { return int64(tr.Stats().QueuedBytes) }, func(v int64) bool { return v >= full })
	// More answers pile up behind the full queue, waiting for room.
	time.Sleep(200 * time.Millisecond)
	failed := tr.Stats().WriteErrors
	start := time.Now()
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	checkStopTook(t, time.Since(start))
	if n := tr.Stats().WriteErrors - failed; n != 0 {
		t.Errorf("%d writes to the peer failed on their deadline during the stop, which waited for them", n)
	}
}

// waitForProgress polls value until done holds, and fails the test only
// when value has not changed for realWait: a loaded host is slow, not
// stuck.
func waitForProgress(t *testing.T, what string, value func() int64, done func(int64) bool) {
	t.Helper()
	last, since := value(), time.Now()
	for !done(last) {
		time.Sleep(10 * time.Millisecond)
		if v := value(); v != last {
			last, since = v, time.Now()
		} else if time.Since(since) > realWait {
			t.Fatalf("waited for %s, with no progress for %v at %d", what, realWait, v)
		}
	}
}

// panicOnceRouter panics on its first request, quoting the message, and
// refuses the next ones with 403.
type panicOnceRouter struct{ n atomic.Int64 }

func (r *panicOnceRouter) Route(_ context.Context, req *proxy.Request) proxy.Decision {
	if r.n.Add(1) == 1 {
		panic("hook-secret " + req.Message.Header.Get("From"))
	}
	return proxy.Decision{Status: 403}
}

// TestAHookPanicIsCountedInScscfsMetrics: scscf gives its proxy its
// metrics, as the other services do (#428): a Router that panics gets the
// request a 500, the next request is served, and proxy.hook_panics reaches
// the service's metrics, without the message in the output.
func TestAHookPanicIsCountedInScscfsMetrics(t *testing.T) {
	r := startSCSCFWith(t, startHSS(t), state.NewMemory(), 1, func(_ *ServiceConfig, d *deps) { d.router = &panicOnceRouter{} })
	p := dialSCSCF(t, r)
	options := func(n int) *sip.Response {
		return p.send(t, []string{
			"OPTIONS " + impu + " SIP/2.0",
			fmt.Sprintf("Via: SIP/2.0/TCP 127.0.0.1:5070;branch=z9hG4bK-panic%d", n),
			"Max-Forwards: 69",
			"From: <" + impu + ">;tag=panic", "To: <" + impu + ">",
			fmt.Sprintf("Call-ID: panic-%d", n), "CSeq: 1 OPTIONS", "Content-Length: 0",
		})
	}
	if res := options(1); res.StatusCode != 500 {
		t.Fatalf("first request: %d, want 500", res.StatusCode)
	}
	if res := options(2); res.StatusCode != 403 {
		t.Fatalf("next request: %d, want the Router's 403", res.StatusCode)
	}
	if v, _ := r.h.Metric(proxy.MetricHookPanics); v != 1 {
		t.Errorf("%s = %v, want 1", proxy.MetricHookPanics, v)
	}
	// The realm is in scscf's own Diameter logs, so the From's number
	// stands for the message here.
	for _, secret := range []string{"hook-secret", "15550100001"} {
		if strings.Contains(r.h.Output(), secret) {
			t.Errorf("the output holds %q", secret)
		}
	}
}

// reginfoVersion reads the version of a NOTIFY's reginfo document.
var reginfoVersion = regexp.MustCompile(`<reginfo[^>]*\sversion="(\d+)"`)

// checkNotifySequence fails the test if the NOTIFYs of one subscription
// repeat a CSeq or do not raise the reginfo version each time (RFC 3680
// §5.2): a NOTIFY sent twice would do either.
func checkNotifySequence(t *testing.T, notifies []*sip.Request) {
	t.Helper()
	seen := map[string]bool{}
	last := -1
	for _, n := range notifies {
		cseq := n.Header.Get("CSeq")
		if seen[cseq] {
			t.Errorf("two NOTIFYs with CSeq %q", cseq)
		}
		seen[cseq] = true
		m := reginfoVersion.FindSubmatch(n.Body)
		if m == nil {
			t.Errorf("a NOTIFY without a reginfo version")
			continue
		}
		v, _ := strconv.Atoi(string(m[1]))
		if v <= last {
			t.Errorf("reginfo version %d after %d", v, last)
		}
		last = v
	}
}

// TestASubscribesFirstNOTIFYIsCountedBeforeIts200 (#479): the stop runs
// to its end while the dispatcher is held just after the SUBSCRIBE's 200,
// before the NOTIFY goes. The NOTIFY was counted before the 200, so the
// stop waits for it, and the P-CSCF gets it.
func TestASubscribesFirstNOTIFYIsCountedBeforeIts200(t *testing.T) {
	hss := startHSS(t)
	core := startPCSCFCore(t)
	var r *running
	var once sync.Once
	stopped := make(chan error, 1)
	r = startSCSCFWith(t, hss, state.NewMemory(), 1, func(c *ServiceConfig, d *deps) {
		// The NOTIFY's transaction outlasts a loaded host's delay in
		// reading it: at testConfig's 1 s it could end unanswered, and
		// the stop with it, before the P-CSCF had the NOTIFY.
		c.NotifyTimeout = stopWait
		d.subscribeAnswered = func() {
			once.Do(func() {
				go func() { stopped <- r.stop() }()
				// Long enough for a stop that did not count the NOTIFY to
				// have closed the transport.
				time.Sleep(500 * time.Millisecond)
			})
		}
	})
	p := dialSCSCF(t, r)
	dv := deviceAt(core.ln.Addr().String(), 1)
	p.registerFully(t, dv, 600)
	p.subscribeReg(t, dv.path, core.ln.Addr().String(), "sub-held")
	if err := recv(t, stopped); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-core.got:
		if n.Method != "NOTIFY" {
			t.Errorf("the P-CSCF got a %s", n.Method)
		}
	default:
		t.Error("the stop ended before the SUBSCRIBE's first NOTIFY went")
	}
}
