package icscf

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// Tests from the reviews of #276.

// QA [major] 1: a stop (Run's ctx ends, as on SIGTERM) while a REGISTER and
// a ringing INVITE are at the S-CSCF lets both final responses reach the
// sender.
func TestAStopLetsTheTransactionsInFlightFinish(t *testing.T) {
	scscf := startSlowSCSCF(t, 500*time.Millisecond)
	hss := startHSS(t)
	hss.answer = func(code uint32) (cx.Result, string) {
		if code == cx.CodeUserAuthorization {
			return cx.ExperimentalResult(cx.SubsequentRegistration), scscf.uri()
		}
		return cx.ResultCode(diameter.ResultSuccess), scscf.uri()
	}
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI(scscf.uri())}}, func(c *ServiceConfig, _ *deps) {
		c.DrainTimeout = 3 * time.Second
	})
	r.waitReady(t)
	reg := r.sendAsync(t, "REGISTER", "sip:"+home, "From: <"+impu1+">;tag=f1", "To: <"+impu1+">",
		"Contact: <sip:127.0.0.1:5070;transport=tcp>;expires=600")
	inv := r.sendAsync(t, "INVITE", tel1, "From: <sip:+15550100002@"+home+">;tag=f1", "To: <"+tel1+">",
		"Contact: <sip:127.0.0.1:5071;transport=tcp>")
	<-scscf.got
	<-scscf.got
	stopped := make(chan struct{})
	go func() { r.stop(); close(stopped) }()
	if got := <-reg; got != "200" {
		t.Errorf("REGISTER in flight at the stop: %s, want 200", got)
	}
	if got := <-inv; got != "200" {
		t.Errorf("INVITE ringing at the stop: %s, want 200", got)
	}
	select {
	case <-stopped:
	case <-time.After(realWait):
		t.Fatal("Run did not return after the drain timeout")
	}
}

// QA [minor] 2: the settings reach what they configure.
func TestTheSettingsReachTheServiceTheyConfigure(t *testing.T) {
	t.Run("ICSCF_RETRY_AFTER", func(t *testing.T) {
		hss := startHSS(t)
		_ = hss.node.Shutdown(context.Background())
		r := startICSCF(t, hss, []SCSCF{{URI: mustURI("sip:scscf.rcs.local;transport=tcp")}}, func(c *ServiceConfig, _ *deps) {
			c.RetryAfter = 30 * time.Second
		})
		res := r.send(t, "MESSAGE", tel1, "From: <sip:+15550100002@"+home+">;tag=f1", "To: <"+tel1+">")
		if res.StatusCode != 480 || res.Header.Get("Retry-After") != "30" {
			t.Fatalf("answered %d with Retry-After %q, want 480 and 30", res.StatusCode, res.Header.Get("Retry-After"))
		}
	})
	t.Run("ICSCF_REGISTER_TIMEOUT", func(t *testing.T) {
		silent := startSilentSCSCF(t)
		hss := startHSS(t)
		hss.answer = func(uint32) (cx.Result, string) {
			return cx.ExperimentalResult(cx.SubsequentRegistration), silent.uri()
		}
		r := startICSCF(t, hss, []SCSCF{{URI: mustURI(silent.uri())}}, func(c *ServiceConfig, _ *deps) {
			c.RegisterTimeout = 300 * time.Millisecond
		})
		r.waitReady(t)
		start := time.Now()
		res := r.send(t, "REGISTER", "sip:"+home, "From: <"+impu1+">;tag=f1", "To: <"+impu1+">")
		if res.StatusCode != 504 || time.Since(start) > 3*time.Second {
			t.Fatalf("answered %d after %v, want 504 after about 300ms", res.StatusCode, time.Since(start))
		}
	})
	t.Run("ICSCF_CX_TIMEOUT", func(t *testing.T) {
		hss := startHSS(t)
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		hss.answer = func(uint32) (cx.Result, string) { <-release; return cx.ResultCode(diameter.ResultSuccess), "" }
		r := startICSCF(t, hss, []SCSCF{{URI: mustURI("sip:scscf.rcs.local;transport=tcp")}}, func(c *ServiceConfig, _ *deps) {
			c.CxTimeout = 300 * time.Millisecond
		})
		r.waitReady(t)
		start := time.Now()
		res := r.send(t, "MESSAGE", tel1, "From: <sip:+15550100002@"+home+">;tag=f1", "To: <"+tel1+">")
		// An attempt and its retry of 300 ms each, not the default 2 s.
		if res.StatusCode != 480 || time.Since(start) > 3*time.Second {
			t.Fatalf("answered %d after %v, want 480 after about 600ms", res.StatusCode, time.Since(start))
		}
	})
	t.Run("the HSS name of DNS discovery", func(t *testing.T) {
		hss := startHSS(t)
		hss.answer = func(uint32) (cx.Result, string) { return cx.ResultCode(diameter.ResultSuccess), "" }
		lookups := &recordingResolver{addr: netip.MustParseAddr("127.0.0.1")}
		r := startICSCF(t, hss, []SCSCF{{URI: mustURI("sip:scscf.rcs.local;transport=tcp")}}, func(_ *ServiceConfig, d *deps) {
			d.discovery, d.hssResolver = nil, lookups
		})
		r.waitReady(t)
		if got := lookups.names(); len(got) == 0 || got[0] != "hss.rcs.local" {
			t.Fatalf("looked up %v, want hss.rcs.local", got)
		}
	})
	t.Run("ICSCF_CORE_HOST", func(t *testing.T) {
		hss := startHSS(t)
		scscf := startSCSCF(t)
		hss.answer = func(uint32) (cx.Result, string) { return cx.ResultCode(diameter.ResultSuccess), scscf.uri() }
		r := startICSCF(t, hss, []SCSCF{{URI: mustURI(scscf.uri())}})
		r.waitReady(t)
		r.send(t, "MESSAGE", tel1, "From: <sip:+15550100002@"+home+">;tag=f1", "To: <"+tel1+">")
		vias, err := scscf.next(t).Header.Via()
		if err != nil || len(vias) == 0 || vias[0].Host != "127.0.0.2" {
			t.Fatalf("top Via %v (%v), want icscf's advertised 127.0.0.2", vias, err)
		}
	})
}

// QA [minor] 4: ready, then the HSS stops (with a DPR), then it is back:
// /readyz follows, and requests in between get the 480.
func TestReadinessFollowsTheHSSGoingAndComing(t *testing.T) {
	hss := startHSS(t)
	hss.answer = func(uint32) (cx.Result, string) { return cx.ResultCode(diameter.ResultSuccess), "" }
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI("sip:scscf.rcs.local;transport=tcp")}})
	r.waitReady(t)
	_ = hss.node.Shutdown(context.Background())
	r.waitReadiness(t, 503)
	res := r.send(t, "MESSAGE", tel1, "From: <sip:+15550100002@"+home+">;tag=f1", "To: <"+tel1+">")
	if res.StatusCode != 480 {
		t.Fatalf("answered %d without an HSS, want 480", res.StatusCode)
	}
	again := startHSSAt(t, "hss-0a1b2c.rcs.local", hss.addr)
	again.answer = hss.answer
	r.waitReadiness(t, 200)
}

// waitReadiness waits until /readyz answers code.
func (r *running) waitReadiness(t *testing.T, code int) {
	t.Helper()
	deadline := time.Now().Add(realWait)
	for {
		r.h.Advance(2 * time.Second)
		if got, _ := r.h.Get("/readyz"); got == code {
			return
		}
		if time.Now().After(deadline) {
			_, body := r.h.Get("/readyz")
			t.Fatalf("/readyz did not become %d: %s", code, body)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// QA [minor] 5: a REGISTER whose S-CSCF cannot be sent to gets 500 with
// Retry-After, as a terminating request does.
func TestARegisterToAnUnreachableSCSCFGets500WithRetryAfter(t *testing.T) {
	hss := startHSS(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gone := "sip:" + ln.Addr().String() + ";transport=tcp"
	_ = ln.Close() // refuses connections from here on
	hss.answer = func(uint32) (cx.Result, string) { return cx.ExperimentalResult(cx.SubsequentRegistration), gone }
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI(gone)}})
	r.waitReady(t)
	res := r.send(t, "REGISTER", "sip:"+home, "From: <"+impu1+">;tag=f1", "To: <"+impu1+">")
	if res.StatusCode != 500 || res.Header.Get("Retry-After") != "10" {
		t.Fatalf("answered %d with Retry-After %q, want 500 and 10", res.StatusCode, res.Header.Get("Retry-After"))
	}
}

type recordingResolver struct {
	addr netip.Addr
	mu   sync.Mutex
	got  []string
}

func (r *recordingResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, host)
	return []netip.Addr{r.addr}, nil
}

func (r *recordingResolver) names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.got...)
}

// startSilentSCSCF accepts connections and answers nothing.
func startSilentSCSCF(t *testing.T) *sipPeer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	return &sipPeer{ln: ln}
}

// slowSCSCF answers every request 200 after delay; an INVITE gets 180 at
// once (QA's, from the review).
type slowSCSCF struct {
	ln    net.Listener
	delay time.Duration
	got   chan *sip.Request
}

func startSlowSCSCF(t *testing.T, delay time.Duration) *slowSCSCF {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &slowSCSCF{ln: ln, delay: delay, got: make(chan *sip.Request, 16)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				rd := sip.NewReader(bufio.NewReader(c), sip.Limits{})
				var mu sync.Mutex
				write := func(req *sip.Request, code int) {
					if res, err := sip.NewResponse(req, code, "", "scscf1"); err == nil {
						b, _ := res.Bytes()
						mu.Lock()
						_, _ = c.Write(b)
						mu.Unlock()
					}
				}
				for {
					m, err := rd.ReadMessage()
					if err != nil {
						return
					}
					req, ok := m.(*sip.Request)
					if !ok || req.Method == "ACK" {
						continue
					}
					s.got <- req
					if req.Method == "INVITE" {
						write(req, 180)
					}
					go func() { time.Sleep(s.delay); write(req, 200) }()
				}
			}()
		}
	}()
	return s
}

func (s *slowSCSCF) uri() string { return "sip:" + s.ln.Addr().String() + ";transport=tcp" }

// sendAsync is send without waiting: the final status, or why there was
// none (QA's, from the review).
func (r *running) sendAsync(t *testing.T, method, uri string, fields ...string) chan string {
	t.Helper()
	out := make(chan string, 1)
	nc, err := net.Dial("tcp", r.core.String())
	if err != nil {
		t.Fatal(err)
	}
	n := sends.Add(1)
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s SIP/2.0\r\n", method, uri)
	fmt.Fprintf(&b, "Via: SIP/2.0/TCP 127.0.0.1:%d;branch=z9hG4bK-qa-%d\r\n", nc.LocalAddr().(*net.TCPAddr).Port, n)
	fmt.Fprintf(&b, "Max-Forwards: 70\r\nCall-ID: qa-%d\r\nCSeq: 1 %s\r\n", n, method)
	for _, f := range fields {
		b.WriteString(f + "\r\n")
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	_ = nc.SetDeadline(time.Now().Add(realWait))
	if _, err := io.WriteString(nc, b.String()); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer nc.Close()
		rd := sip.NewReader(bufio.NewReader(nc), sip.Limits{})
		for {
			m, err := rd.ReadMessage()
			if err != nil {
				out <- "no final response: " + err.Error()
				return
			}
			if res, ok := m.(*sip.Response); ok && res.StatusCode >= 200 {
				out <- fmt.Sprint(res.StatusCode)
				return
			}
		}
	}()
	return out
}

// #198 is in: icscf resolves the S-CSCF's Cloud Map name, and the HSS's
// production form of it (sip:scscf.<namespace>) reaches the S-CSCF.
func TestTheSCSCFIsReachedByItsServiceName(t *testing.T) {
	hss := startHSS(t)
	scscf := startSCSCF(t)
	port := scscf.ln.Addr().(*net.TCPAddr).Port
	hss.answer = func(uint32) (cx.Result, string) {
		return cx.ExperimentalResult(cx.SubsequentRegistration), "sip:scscf.rcs.local"
	}
	lookups := &recordingResolver{addr: netip.MustParseAddr("127.0.0.1")}
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI(fmt.Sprintf("sip:scscf.rcs.local:%d;transport=tcp", port))}}, func(_ *ServiceConfig, d *deps) {
		d.lookup = lookups.LookupNetIP
	})
	r.waitReady(t)
	res := r.send(t, "REGISTER", "sip:"+home, "From: <"+impu1+">;tag=f1", "To: <"+impu1+">")
	if res.StatusCode != 200 {
		t.Fatalf("REGISTER answered %d", res.StatusCode)
	}
	scscf.next(t)
	if got := lookups.names(); len(got) == 0 || got[0] != "scscf.rcs.local" {
		t.Errorf("looked up %v, want scscf.rcs.local", got)
	}
}

// A task of the S-CSCF that is gone (its address refuses connections) does
// not fail the request: the next address of the name takes it.
func TestARequestGoesToTheNextAddressWhenOneRefuses(t *testing.T) {
	hss := startHSS(t)
	scscf := startSCSCF(t)
	port := scscf.ln.Addr().(*net.TCPAddr).Port
	hss.answer = func(uint32) (cx.Result, string) { return cx.ResultCode(diameter.ResultSuccess), "sip:scscf.rcs.local" }
	// Nothing listens on 127.0.0.3 at the S-CSCF's port: it refuses.
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.3"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI(fmt.Sprintf("sip:scscf.rcs.local:%d;transport=tcp", port))}}, func(_ *ServiceConfig, d *deps) {
		d.lookup = lookup
		d.shuffle = func(int, func(i, j int)) {} // the order as answered
	})
	r.waitReady(t)
	res := r.send(t, "MESSAGE", tel1, "From: <sip:+15550100002@"+home+">;tag=f1", "To: <"+tel1+">")
	if res.StatusCode != 200 {
		t.Fatalf("MESSAGE answered %d, want 200 from the second address", res.StatusCode)
	}
	scscf.next(t)
}

// A name that resolves to nothing is an S-CSCF that cannot be reached: 500
// with Retry-After.
func TestAnSCSCFNameWithoutAddressesGets500WithRetryAfter(t *testing.T) {
	hss := startHSS(t)
	hss.answer = func(uint32) (cx.Result, string) {
		return cx.ExperimentalResult(cx.SubsequentRegistration), "sip:scscf.rcs.local"
	}
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI("sip:scscf.rcs.local:5060;transport=tcp")}}, func(_ *ServiceConfig, d *deps) {
		d.lookup = func(context.Context, string, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }
	})
	r.waitReady(t)
	res := r.send(t, "REGISTER", "sip:"+home, "From: <"+impu1+">;tag=f1", "To: <"+impu1+">")
	if res.StatusCode != 500 || res.Header.Get("Retry-After") != "10" {
		t.Fatalf("answered %d with Retry-After %q, want 500 and 10", res.StatusCode, res.Header.Get("Retry-After"))
	}
}

// QA of #276: the drain also waits for a single request in progress.
func TestAStopLetsASingleRequestInFlightFinish(t *testing.T) {
	scscf := startSlowSCSCF(t, 500*time.Millisecond)
	hss := startHSS(t)
	hss.answer = func(uint32) (cx.Result, string) { return cx.ResultCode(diameter.ResultSuccess), scscf.uri() }
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI(scscf.uri())}}, func(c *ServiceConfig, _ *deps) {
		c.DrainTimeout = 3 * time.Second
	})
	r.waitReady(t)
	msg := r.sendAsync(t, "MESSAGE", tel1, "From: <sip:+15550100002@"+home+">;tag=f1", "To: <"+tel1+">")
	<-scscf.got
	go r.stop()
	if got := <-msg; got != "200" {
		t.Errorf("MESSAGE in flight at the stop: %s, want 200", got)
	}
}

// QA of #276: past two refusing addresses, the third takes the request.
func TestARequestGoesPastEveryRefusingAddress(t *testing.T) {
	hss := startHSS(t)
	scscf := startSCSCF(t)
	port := scscf.ln.Addr().(*net.TCPAddr).Port
	hss.answer = func(uint32) (cx.Result, string) { return cx.ResultCode(diameter.ResultSuccess), "sip:scscf.rcs.local" }
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.3"), netip.MustParseAddr("127.0.0.4"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI(fmt.Sprintf("sip:scscf.rcs.local:%d;transport=tcp", port))}}, func(_ *ServiceConfig, d *deps) {
		d.lookup = lookup
		d.shuffle = func(int, func(i, j int)) {}
	})
	r.waitReady(t)
	if res := r.send(t, "MESSAGE", tel1, "From: <sip:+15550100002@"+home+">;tag=f1", "To: <"+tel1+">"); res.StatusCode != 200 {
		t.Fatalf("MESSAGE answered %d, want 200 from the third address", res.StatusCode)
	}
}

// blackholeDialer never completes a connection to hole, as the address of a
// stopped task in a VPC drops the SYN, and dials anything else.
type blackholeDialer struct{ hole string }

func (b blackholeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if host, _, _ := net.SplitHostPort(address); host == b.hole {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// QA of #276: a blackholed address costs the 2 s connection timeout, not
// the transport's 5 s, and only once: the next request goes to another
// address first.
func TestABlackholedAddressCostsOneShortTimeoutOnce(t *testing.T) {
	hss := startHSS(t)
	scscf := startSCSCF(t)
	port := scscf.ln.Addr().(*net.TCPAddr).Port
	hss.answer = func(uint32) (cx.Result, string) { return cx.ResultCode(diameter.ResultSuccess), "sip:scscf.rcs.local" }
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.9"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI(fmt.Sprintf("sip:scscf.rcs.local:%d;transport=tcp", port))}}, func(_ *ServiceConfig, d *deps) {
		d.lookup = lookup
		d.shuffle = func(int, func(i, j int)) {}
		d.sipDialer = blackholeDialer{hole: "127.0.0.9"}
	})
	r.waitReady(t)
	send := func() (int, time.Duration) {
		start := time.Now()
		res := r.send(t, "MESSAGE", tel1, "From: <sip:+15550100002@"+home+">;tag=f1", "To: <"+tel1+">")
		return res.StatusCode, time.Since(start)
	}
	if code, took := send(); code != 200 || took > 4*time.Second {
		t.Fatalf("first: %d after %v, want 200 after about 2s", code, took)
	}
	if code, took := send(); code != 200 || took > 500*time.Millisecond {
		t.Fatalf("second: %d after %v, want 200 at once from the good address", code, took)
	}
}

// #281: a request still in progress when ICSCF_DRAIN_TIMEOUT runs out is
// answered 500 with Retry-After, so the sender tries another task at once.
func TestAStopAnswersARequestLeftInProgress500(t *testing.T) {
	scscf := startSlowSCSCF(t, 20*time.Second)
	hss := startHSS(t)
	hss.answer = func(uint32) (cx.Result, string) { return cx.ResultCode(diameter.ResultSuccess), scscf.uri() }
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI(scscf.uri())}}, func(c *ServiceConfig, _ *deps) {
		c.DrainTimeout = 300 * time.Millisecond
	})
	r.waitReady(t)
	msg := r.sendAsync(t, "MESSAGE", tel1, "From: <sip:+15550100002@"+home+">;tag=f1", "To: <"+tel1+">")
	<-scscf.got
	go r.stop()
	if got := <-msg; got != "500" {
		t.Errorf("MESSAGE left at the stop: %s, want 500", got)
	}
}

// #310: a REGISTER left at the stop gets 503 with Retry-After instead, which
// pcscf retries on another icscf at once.
func TestAStopAnswersARegisterLeftInProgress503(t *testing.T) {
	scscf := startSlowSCSCF(t, 20*time.Second)
	hss := startHSS(t)
	hss.answer = func(uint32) (cx.Result, string) {
		return cx.ExperimentalResult(cx.SubsequentRegistration), scscf.uri()
	}
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI(scscf.uri())}}, func(c *ServiceConfig, _ *deps) {
		c.DrainTimeout = 300 * time.Millisecond
	})
	r.waitReady(t)
	reg := r.sendAsync(t, "REGISTER", "sip:"+home, "From: <"+impu1+">;tag=f1", "To: <"+impu1+">",
		"Contact: <sip:127.0.0.1:5070;transport=tcp>;expires=600")
	<-scscf.got
	go r.stop()
	if got := <-reg; got != "503" {
		t.Errorf("REGISTER left at the stop: %s, want 503", got)
	}
}
