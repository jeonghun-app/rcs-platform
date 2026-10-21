package pcscf

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// #281: a request of the core still in progress when pcscf stops gets a
// final response by the end of the drain: 500 with Retry-After, so scscf
// tries elsewhere at once, or 430 when the client's flow closed under it
// (#234). Before, the core got nothing until its own Timer F.
func TestAStopAnswersTheCoreRequestsLeftInProgress(t *testing.T) {
	icscf := startCoreNode(t, echo200)
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	cfg.DrainTimeout = time.Second
	s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1")})
	c, path := registered(t, s, icscf)
	core := dial(t, s.core, nil)
	core.write(coreRequest("MESSAGE", "sip:alice@192.0.2.10:40000;transport=tcp", fmt.Sprintf("stop-%d", requests.Add(1)), "", 1, "Route: <"+path+">"))
	_ = c.nextRequest() // and never answered
	go s.stop()
	start := time.Now()
	_ = core.nc.SetDeadline(time.Now().Add(10 * time.Second))
	for {
		m, err := core.r.ReadMessage()
		if err != nil {
			t.Fatalf("no final response after %v: %v", time.Since(start), err)
		}
		res, ok := m.(*sip.Response)
		if !ok || res.StatusCode < 200 {
			continue
		}
		switch {
		case res.StatusCode == 500 && res.Header.Get("Retry-After") != "":
		case res.StatusCode == 430:
		default:
			t.Fatalf("core got %d (Retry-After %q), want 500 with Retry-After or 430", res.StatusCode, res.Header.Get("Retry-After"))
		}
		if took := time.Since(start); took > 5*time.Second {
			t.Fatalf("answered after %v, want by the 1 s drain", took)
		}
		return
	}
}

// #310: a REGISTER that a stopping icscf answers 503 with Retry-After, as
// its drain does, is sent on to another icscf at once, and the client gets
// the 200 from there. The fake answers the first copy as the draining
// task and the second as a healthy one.
func TestARegisterADrainingICSCFRefusesGoesToAnotherOne(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}
	// Every loopback address, so both icscf addresses reach it.
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	icscf := &fakeCoreNode{ln: ln, got: make(chan *sip.Request, 16), answer: func(req *sip.Request) string {
		key := req.Header.Get("Call-ID") + " " + req.Header.Get("CSeq")
		mu.Lock()
		again := seen[key]
		seen[key] = true
		mu.Unlock()
		if !again {
			return strings.Replace(echo200(req), "200 OK", "503 Service Unavailable\r\nRetry-After: 5", 1)
		}
		return echo200(req)
	}}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go icscf.serve(t, nc)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, fmt.Sprintf("sip:icscf.rcs.internal:%d;transport=tcp;lr", port))
	s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1", "127.0.0.6")})
	if res := registerOver(t, dial(t, s.client, nil)); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d, want the 200 of the second icscf", res.StatusCode)
	}
	if n := len(icscf.got); n != 2 {
		t.Fatalf("the icscf tasks got %d REGISTERs, want 2", n)
	}
}

// QA of #310: with only one icscf, a REGISTER it refuses while draining
// (503 with Retry-After) reaches the client as 500 with that Retry-After,
// so the client knows when to try again; a 504 would not tell it.
func TestARegisterTheOnlyICSCFRefusesKeepsItsRetryAfter(t *testing.T) {
	icscf := startCoreNode(t, func(req *sip.Request) string {
		return strings.Replace(echo200(req), "200 OK", "503 Service Unavailable\r\nRetry-After: 5", 1)
	})
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1")})
	res := registerOver(t, dial(t, s.client, nil))
	if res.StatusCode != 500 || res.Header.Get("Retry-After") != "5" {
		t.Fatalf("REGISTER: %d with Retry-After %q, want 500 with 5", res.StatusCode, res.Header.Get("Retry-After"))
	}
}

// The wait after the flow drain and the proxy's wait for its answers to go
// out fit in the stop margin together (QA of #310).
func TestTheStopWaitsFitTheMargin(t *testing.T) {
	if answersWait+proxy.DrainSendWait >= stopMargin {
		t.Fatalf("answersWait %v and the proxy's %v leave nothing of the %v stop margin", answersWait, proxy.DrainSendWait, stopMargin)
	}
}
