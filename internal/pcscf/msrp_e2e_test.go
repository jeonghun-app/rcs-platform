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
}

func startRelayStack(t *testing.T, scscfAnswer func(*sip.Request) string, relayTimeout time.Duration, d deps) *relayStack {
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
	cfg.RelayToken = relayToken{testRelayToken}
	cfg.RelayTimeout = relayTimeout
	d.lookup = icscfLookup("127.0.0.1")
	d.started = func(p *pcscf) { st.pc = p }
	s := start(t, cfg, d)
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
