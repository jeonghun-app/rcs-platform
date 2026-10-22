package pcscf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// relayStack is pcscf run as it is deployed, with msrp-relay's control API
// scripted, alice registered over a connection, and scscf a fake core node
// (QA of #248).
type relayStack struct {
	pc    *pcscf
	c     *peer
	scscf *fakeCoreNode
	relay *scriptedRelay
	// posted hears each POST; while block is set a POST waits for release.
	posted  chan struct{}
	release chan struct{}
	block   atomic.Bool
	// svc is the running pcscf, and icscf the node alice registered
	// through.
	svc   *service
	icscf *fakeCoreNode
}

func startRelayStack(t *testing.T, scscfAnswer func(*sip.Request) string, relayTimeout time.Duration, d deps) *relayStack {
	t.Helper()
	return startRelayStackAt(t, scscfAnswer, relayTimeout, d, nil)
}

// startRelayStackAt is startRelayStack with the control API at relayURL,
// or scripted if it is nil.
func startRelayStackAt(t *testing.T, scscfAnswer func(*sip.Request) string, relayTimeout time.Duration, d deps, relayURL *url.URL) *relayStack {
	t.Helper()
	st := &relayStack{posted: make(chan struct{}, 16), release: make(chan struct{})}
	st.relay = &scriptedRelay{bodies: map[int]map[string]any{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			st.posted <- struct{}{}
			if st.block.Load() {
				<-st.release
			}
		}
		st.relay.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	scscf := startCoreNode(t, scscfAnswer)
	scscfPort := scscf.ln.Addr().(*net.TCPAddr).Port
	scscfURI := fmt.Sprintf("sip:orig@scscf.rcs.internal:%d;transport=tcp;lr", scscfPort)
	icscf := startCoreNode(t, func(req *sip.Request) string {
		return strings.Replace(echo200(req), "<sip:orig@10.0.4.4;lr>", "<"+scscfURI+">", 1)
	})
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	cfg.SCSCFPort = scscfPort
	cfg.RelayURL, _ = url.Parse(srv.URL)
	if relayURL != nil {
		cfg.RelayURL = relayURL
	}
	cfg.RelayToken = relayToken{testRelayToken}
	cfg.RelayTimeout = relayTimeout
	d.lookup = icscfLookup("127.0.0.1")
	d.started = func(p *pcscf) { st.pc = p }
	s := start(t, cfg, d)
	st.svc, st.icscf = s, icscf
	st.c = dial(t, s.client, nil)
	_ = st.c.nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := io.WriteString(st.c.nc, registerText(outboundContact, "Supported: outbound")); err != nil {
		t.Fatal(err)
	}
	if res := st.c.final(); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	st.scscf = scscf
	return st
}

// invite has alice send method in call, with body as its offer if any.
func (st *relayStack) invite(t *testing.T, call, method string, body string) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s SIP/2.0\r\n", method, bobIMPU)
	fmt.Fprintf(&b, "Via: SIP/2.0/TCP 192.0.2.10:40000;branch=z9hG4bK-e2e-%s\r\n", call)
	b.WriteString("Max-Forwards: 70\r\n")
	b.WriteString("From: <" + aliceIMPU + ">;tag=a1\r\n")
	b.WriteString("To: <" + bobIMPU + ">\r\n")
	fmt.Fprintf(&b, "Call-ID: %s\r\nCSeq: 1 %s\r\n", call, method)
	b.WriteString("Contact: <" + clientContact + ">\r\n")
	if body != "" {
		b.WriteString("Content-Type: application/sdp\r\n")
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n%s", len(body), body)
	_ = st.c.nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := io.WriteString(st.c.nc, b.String()); err != nil {
		t.Fatal(err)
	}
}

// answerWithSDP is rcs-as answering an INVITE with rcsAsAnswer.
func answerWithSDP(req *sip.Request) string {
	a := answerAsUAS(req)
	if req.Method != "INVITE" {
		return a
	}
	return strings.Replace(a, "Content-Length: 0\r\n\r\n", fmt.Sprintf("Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", len(rcsAsAnswer), rcsAsAnswer), 1)
}

// waitHeld waits until the stack holds want bindings and no session.
func (st *relayStack) waitHeld(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	for time.Now().Before(deadline) {
		st.pc.msrp.wait()
		if st.pc.msrp.limit.held() == want && len(st.pc.msrp.all()) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("held %d, %d sessions, want %d: relay %q", st.pc.msrp.limit.held(), len(st.pc.msrp.all()), want, st.relay.log())
}

// A CANCEL while the relay is allocating ends the INVITE with 487 and
// releases what was allocated.
func TestACancelDuringAllocationReleasesTheBinding(t *testing.T) {
	st := startRelayStack(t, func(*sip.Request) string { return "" }, 2*time.Second, deps{})
	st.block.Store(true)
	st.invite(t, "e2e-cancel", "INVITE", clientChatOffer)
	<-st.posted
	st.invite(t, "e2e-cancel", "CANCEL", "")
	if res := st.c.final(); res.StatusCode != 200 {
		t.Errorf("CANCEL: %d", res.StatusCode)
	}
	close(st.release)
	if res := st.c.final(); res.StatusCode != 487 {
		t.Errorf("INVITE: %d", res.StatusCode)
	}
	st.waitHeld(t, 0)
	if st.relay.count(http.MethodDelete) != 1 {
		t.Errorf("relay %q", st.relay.log())
	}
}

// A CANCEL does not wait for a relay call that does not answer: the 487
// comes while the relay still holds the POST, with an hour of relay timeout,
// because the CANCEL ends the context the INVITE's Prepare runs under
// (#382). The call runs on, keeping its share of the flow's binding limit
// meanwhile (QA of #442), and once the relay answers, the binding it made is
// released, and counted.
func TestACancelDoesNotWaitForAStalledRelayCall(t *testing.T) {
	st := startRelayStack(t, func(*sip.Request) string { return "" }, time.Hour, deps{})
	st.block.Store(true)
	st.invite(t, "e2e-cancel-stall", "INVITE", clientChatOffer)
	<-st.posted
	st.invite(t, "e2e-cancel-stall", "CANCEL", "")
	if res := st.c.final(); res.StatusCode != 200 {
		t.Errorf("CANCEL: %d", res.StatusCode)
	}
	if res := st.c.final(); res.StatusCode != 487 {
		t.Errorf("INVITE: %d before the relay answered, want 487", res.StatusCode)
	}
	// The 487 came once Prepare had given up, and with it what the INVITE
	// took but the create still running.
	if n := st.pc.msrp.limit.held(); n != 1 {
		t.Errorf("held %d while the abandoned create runs, want its share, 1", n)
	}
	close(st.release)
	st.waitHeld(t, 0)
	if st.relay.count(http.MethodDelete) != 1 {
		t.Errorf("relay %q, want the binding made after the CANCEL released", st.relay.log())
	}
	if n, _ := st.svc.h.Metric(metricReleasedCancel); n != 1 {
		t.Errorf("%s = %v, want 1", metricReleasedCancel, n)
	}
	// Cancelled, not refused: no relay refusal is counted.
	if n, _ := st.svc.h.Metric(metricRefusedRelay); n != 0 {
		t.Errorf("%s = %v, want 0", metricRefusedRelay, n)
	}
}

// A create still running when pcscf stops, after its CANCEL, is cut by the
// stop: counted as such, not as a relay error, and not logged as one; the
// binding the relay may have made is left to expire (#382 review).
func TestACreateTheStopCutsIsNotARelayError(t *testing.T) {
	st := startRelayStack(t, func(*sip.Request) string { return "" }, time.Hour, deps{})
	st.block.Store(true)
	st.invite(t, "e2e-cut", "INVITE", clientChatOffer)
	<-st.posted
	st.invite(t, "e2e-cut", "CANCEL", "")
	if res := st.c.final(); res.StatusCode != 200 {
		t.Errorf("CANCEL: %d", res.StatusCode)
	}
	if res := st.c.final(); res.StatusCode != 487 {
		t.Errorf("INVITE: %d", res.StatusCode)
	}
	st.svc.stop() // the relay still holds the POST
	close(st.release)
	h := st.svc.h
	if n, _ := h.Metric(metricCreateCutAtStop); n != 1 {
		t.Errorf("%s = %v, want 1", metricCreateCutAtStop, n)
	}
	if n, _ := h.Metric(metricRelayErrors); n != 0 {
		t.Errorf("%s = %v, want 0", metricRelayErrors, n)
	}
	if logs := h.Logs("msrp-relay call failed"); len(logs) != 0 {
		t.Errorf("logged %v", logs)
	}
}

// A CANCEL after the INVITE has reached scscf, the order #361 left to
// chance, ends it with scscf's 487 at once, as scscf answers the INVITE
// 100 Trying and the CANCEL as a UAS does (RFC 3261 §9.2), and releases the
// binding; not at Timer B.
func TestACancelAfterTheInviteReachedTheCoreReleasesTheBinding(t *testing.T) {
	st := startRelayStack(t, func(*sip.Request) string { return "" }, 2*time.Second, deps{})
	st.invite(t, "e2e-cancel-sent", "INVITE", clientChatOffer)
	if inv := st.scscf.receive(t); inv.Method != "INVITE" {
		t.Fatalf("scscf got %s", inv.Method)
	}
	st.invite(t, "e2e-cancel-sent", "CANCEL", "")
	got := map[string]int{}
	for range 2 {
		res := st.c.final()
		cseq, _ := res.Header.CSeq()
		got[cseq.Method] = res.StatusCode
	}
	if got["CANCEL"] != 200 || got["INVITE"] != 487 {
		t.Errorf("finals %v", got)
	}
	st.waitHeld(t, 0)
}

// A relay that does not answer within PCSCF_RELAY_TIMEOUT has the INVITE
// answered 503 with Retry-After, and nothing held.
func TestARelayTimeoutIs503(t *testing.T) {
	st := startRelayStack(t, answerWithSDP, 300*time.Millisecond, deps{})
	st.block.Store(true)
	defer close(st.release)
	st.invite(t, "e2e-timeout", "INVITE", clientChatOffer)
	<-st.posted
	res := st.c.final()
	if res.StatusCode != 503 || res.Header.Get("Retry-After") != "1" {
		t.Errorf("%d, Retry-After %q", res.StatusCode, res.Header.Get("Retry-After"))
	}
	st.waitHeld(t, 0)
}

// A confirmed session's bindings go when its client's connection does:
// run wires the transport's flow closing to the anchoring (RFC 5626 §5.3).
func TestAClientsConnectionLostReleasesItsSessions(t *testing.T) {
	st := startRelayStack(t, answerWithSDP, 2*time.Second, deps{})
	st.invite(t, "e2e-flow", "INVITE", clientChatOffer)
	inv := st.scscf.receive(t)
	if !strings.Contains(string(inv.Body), "a=setup:active") || strings.Contains(string(inv.Body), "192.0.2.10:9/") {
		t.Errorf("offer to the core:\n%s", inv.Body)
	}
	if res := st.c.final(); res.StatusCode != 200 || !strings.Contains(string(res.Body), clientPathFor(1)) {
		t.Fatalf("200: %d\n%s", res.StatusCode, res.Body)
	}
	if st.pc.msrp.limit.held() != 1 {
		t.Fatalf("held %d", st.pc.msrp.limit.held())
	}
	_ = st.c.nc.Close()
	st.waitHeld(t, 0)
}

// run's sweep extends a confirmed session's bindings.
func TestRunsSweepExtendsTheBindings(t *testing.T) {
	clock := &syncClock{t: time.Unix(1_800_000_000, 0)}
	st := startRelayStack(t, answerWithSDP, 2*time.Second, deps{now: clock.now, sweep: 5 * time.Millisecond})
	st.invite(t, "e2e-sweep", "INVITE", clientChatOffer)
	if res := st.c.final(); res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	clock.add(15 * time.Minute)
	deadline := time.Now().Add(waitFor)
	for st.relay.count(http.MethodPatch) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("not extended: %q", st.relay.log())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Outside dev the relay is dialled only at a private address, whatever its
// name resolves to, so the token goes nowhere else (ADR 0007 §5); dev may
// reach one on loopback.
func TestTheRelayIsDialledOnlyAtAPrivateAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	cfg := Config{RelayTimeout: time.Second}
	if _, err := relayDialer(cfg)(context.Background(), "tcp", ln.Addr().String()); !errors.Is(err, runtime.ErrAddressNotPrivate) {
		t.Errorf("staging and prod dialled loopback: %v", err)
	}
	cfg.AllowLoopback = true
	c, err := relayDialer(cfg)(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dev: %v", err)
	}
	_ = c.Close()
}

// The relay token prints as "[redacted]" however the settings are printed
// or logged.
func TestTheRelayTokenNeverPrints(t *testing.T) {
	cfg := testConfig()
	cfg.RelayToken = relayToken{testRelayToken}
	var out bytes.Buffer
	slog.New(slog.NewTextHandler(&out, nil)).Info("settings", slog.Any("cfg", cfg))
	slog.New(slog.NewJSONHandler(&out, nil)).Info("settings", slog.Any("cfg", cfg))
	fmt.Fprintf(&out, "%v %+v %#v %s", cfg, cfg, cfg, cfg.RelayToken)
	if strings.Contains(out.String(), testRelayToken) || !strings.Contains(out.String(), "[redacted]") {
		t.Errorf("the token printed:\n%s", out.String())
	}
}
