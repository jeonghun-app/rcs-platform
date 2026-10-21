package scscf

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
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

// silentPeer is a SIP peer that reads what it is sent and never answers.
type silentPeer struct {
	addr string
	got  atomic.Int64
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
					if _, err := r.ReadMessage(); err != nil {
						return
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
// P-CSCF.
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
	n := core.next(t)
	if !strings.Contains(string(n.Body), `state="terminated"`) {
		t.Errorf("the NOTIFY after the RTR: %s with %q", n.Method, n.Body)
	}
}

// TestAStopLeavesNOTIFYsToAPCSCFThatDoesNotAnswer: NOTIFYs queued toward
// a P-CSCF that never answers hold the stop no longer than its budget,
// though each may wait a minute; the sweeps of the other tasks send them.
func TestAStopLeavesNOTIFYsToAPCSCFThatDoesNotAnswer(t *testing.T) {
	hss := startHSS(t)
	silent := startSilentPeer(t)
	r := startSCSCFWith(t, hss, state.NewMemory(), 1, func(c *ServiceConfig) { c.NotifyTimeout = time.Minute })
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

// checkStopTook fails the test if a stop took past its budget, with room
// for a loaded host, but far from the minute a peer could hold it.
func checkStopTook(t *testing.T, took time.Duration) {
	t.Helper()
	if budget := testConfig().DrainTimeout + stopMargin; took > 2*budget {
		t.Errorf("the stop took %v, past twice its budget of %v", took, budget)
	}
}

// TestAStopGivesUpOnAThirdPartyREGISTERToAServerThatDoesNotAnswer: a
// third-party REGISTER at a server that does not answer, and may wait a
// minute, holds the stop no longer than its budget, and is counted.
func TestAStopGivesUpOnAThirdPartyREGISTERToAServerThatDoesNotAnswer(t *testing.T) {
	hss := startHSS(t)
	as := startSilentPeer(t)
	uri := "sip:" + as.addr + ";transport=tcp"
	hss.asURI.Store(&uri)
	r := startSCSCFWith(t, hss, state.NewMemory(), 1, func(c *ServiceConfig) { c.ThirdPartyTimeout = time.Minute })
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
