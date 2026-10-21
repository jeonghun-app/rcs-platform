package routing

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/registrar"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// Application servers of the tests: rcs-as, and an operator's server that
// sees every request before it.
const (
	rcsAS      = "sip:rcs-as.rcs.local"
	operatorAS = "sip:operator-as.rcs.local"
	thirdAS    = "sip:third-as.rcs.local"
)

// method is a trigger point matching requests of method m.
func method(m string) *ifc.TriggerPoint {
	return &ifc.TriggerPoint{ConditionTypeCNF: true, SPTs: []ifc.SPT{{Condition: ifc.Method(m), Groups: []int{0}}}}
}

// notServed is method m without a P-Served-User, as the default profile's
// rcs-as triggers are (docs/hss.md).
func notServed(m string) *ifc.TriggerPoint {
	tp := method(m)
	tp.SPTs = append(tp.SPTs, ifc.SPT{ConditionNegated: true, Condition: ifc.SIPHeader{Header: "P-Served-User"}, Groups: []int{1}})
	return tp
}

// criterion is a filter criterion sending what tp matches to server.
func criterion(priority int, server string, tp *ifc.TriggerPoint, handling ifc.DefaultHandling) ifc.FilterCriteria {
	return ifc.FilterCriteria{Priority: priority, TriggerPoint: tp, ApplicationServer: ifc.ApplicationServer{ServerName: server, DefaultHandling: handling}}
}

// profile stores the profile of set1, received at received, with criteria
// for impu1 and tel1.
func (e *env) profile(received time.Time, criteria ...ifc.FilterCriteria) {
	e.t.Helper()
	sub := ifc.Subscription{PrivateID: impi1, ServiceProfiles: []ifc.ServiceProfile{{
		PublicIdentities:      []ifc.PublicIdentity{{Identity: impu1}, {Identity: tel1}, {Identity: impu2, BarringIndication: true}},
		InitialFilterCriteria: criteria,
	}}}
	data, err := sub.Marshal()
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.store.SaveProfile(bg, &state.Profile{Key: set1, UserData: data, Received: received, KeepUntil: t0.Add(48 * time.Hour)}); err != nil {
		e.t.Fatal(err)
	}
}

// fromUser is a request impu1 sends to target along its Service-Route, as
// its P-CSCF forwards it: P-Asserted-Identity set, the Route with orig
// consumed.
func fromUser(t *testing.T, method, target string, extra ...string) *proxy.Request {
	t.Helper()
	r := request(t, method, target, append([]string{"P-Asserted-Identity: <" + impu1 + ">"}, extra...)...)
	orig, _ := sip.ParseAddress("<sip:scscf.rcs.local;lr;orig>")
	r.Routed = []sip.Address{orig}
	return r
}

// backFrom is the request the server of d's target i sends back, as a
// server that proxies it does: the branch's copy, with what Prepare put
// in, the server's own Route used and the S-CSCF's consumed.
func backFrom(t *testing.T, r *proxy.Request, d proxy.Decision, i int) *proxy.Request {
	t.Helper()
	if i >= len(d.Targets) || len(d.Targets[i].Routes) != 2 {
		t.Fatalf("no target %d toward a server: %+v (status %d)", i, d.Targets, d.Status)
	}
	tg := d.Targets[i]
	b := branchOf(t, r, d, tg)
	b.Header.Del("Route")
	return &proxy.Request{Message: b, Routed: []sip.Address{tg.Routes[1]}}
}

// branchOf is the copy of r the proxy sends to tg.
func branchOf(t *testing.T, r *proxy.Request, d proxy.Decision, tg proxy.Target) *sip.Request {
	t.Helper()
	b := r.Message.Clone()
	b.URI = tg.URI
	if err := d.Prepare(bg, tg, b); err != nil {
		t.Fatal(err)
	}
	return b
}

// serverOf is the host of the server d's only target goes to.
func serverOf(t *testing.T, d proxy.Decision) string {
	t.Helper()
	if len(d.Targets) != 1 || len(d.Targets[0].Routes) == 0 {
		t.Fatalf("targets %+v, status %d %s", d.Targets, d.Status, d.Reason)
	}
	return d.Targets[0].Routes[0].URI.Host
}

// TestAnOriginatingRequestGoesToTheServerOfItsFirstCriterion (TS 24.229
// §5.4.3.2): its Request-URI unchanged, along the server and back to the
// S-CSCF with the position signed in odi, the S-CSCF recording the route,
// and P-Served-User naming the user with the session case.
func TestAnOriginatingRequestGoesToTheServerOfItsFirstCriterion(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(10, rcsAS, method("INVITE"), ifc.SessionTerminated))
	r := fromUser(t, "INVITE", impu2)
	d := e.router(nil).Initial(bg, r)
	if host := serverOf(t, d); host != "rcs-as.rcs.local" {
		t.Fatalf("sent to %s", host)
	}
	tg := d.Targets[0]
	if tg.URI.String() != impu2 || !tg.Routes[0].URI.Params.Has("lr") {
		t.Errorf("Request-URI %s, route %s", tg.URI.String(), tg.Routes[0].URI.String())
	}
	if v, ok := tg.Routes[1].URI.Param(odiParam); !ok || v == "" || tg.Routes[1].URI.Host != "scscf.rcs.local" {
		t.Errorf("the route back is %s", tg.Routes[1].URI.String())
	}
	if tg.Timeout != 0 {
		t.Errorf("an INVITE's branch to a server is bounded by %v: it would be cancelled while it rings", tg.Timeout)
	}
	if len(d.RecordRoute) != 1 {
		t.Errorf("Record-Route %v", d.RecordRoute)
	}
	if got := branchOf(t, r, d, tg).Header.Get("P-Served-User"); got != "<"+impu1+">;sescase=orig;regstate=reg" {
		t.Errorf("P-Served-User %q", got)
	}
	if r.Message.Header.Has("P-Served-User") {
		t.Error("Prepare changed the shared request")
	}
}

// TestARequestOtherThanINVITEWaitsForTheServerOnlyASTimeout: its default
// handling applies in time for the client's Timer F.
func TestARequestOtherThanINVITEWaitsForTheServerOnlyASTimeout(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(10, rcsAS, method("MESSAGE"), ifc.SessionTerminated))
	d := e.router(nil, func(c *Config) { c.ASTimeout = 3 * time.Second }).Initial(bg, fromUser(t, "MESSAGE", impu2))
	if serverOf(t, d); d.Targets[0].Timeout != 3*time.Second {
		t.Errorf("timeout %v", d.Targets[0].Timeout)
	}
	if d := e.router(nil).Initial(bg, fromUser(t, "MESSAGE", impu2)); d.Targets[0].Timeout != DefaultASTimeout {
		t.Errorf("default timeout %v", d.Targets[0].Timeout)
	}
}

// TestTheChainGoesOnOnAnyInstanceFromWhereItLeft: the request back from
// the first server goes to the next criterion's, on another scscf
// instance, without a second Record-Route, and then, the chain done, to the
// I-CSCF without the P-Served-User the S-CSCF put in.
func TestTheChainGoesOnOnAnyInstanceFromWhereItLeft(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0,
		criterion(10, rcsAS, method("INVITE"), ifc.SessionTerminated),
		criterion(20, thirdAS, method("INVITE"), ifc.SessionContinued),
		criterion(30, operatorAS, method("MESSAGE"), ifc.SessionContinued))
	r := fromUser(t, "INVITE", impu2)
	first := e.router(nil).Initial(bg, r)
	back := backFrom(t, r, first, 0)
	second := e.router(nil).Initial(bg, back)
	if host := serverOf(t, second); host != "third-as.rcs.local" || len(second.RecordRoute) != 0 {
		t.Fatalf("then to %s, Record-Route %v", host, second.RecordRoute)
	}
	again := backFrom(t, back, second, 0)
	last := e.router(nil).Initial(bg, again)
	if host := serverOf(t, last); host != "icscf.rcs.local" || last.Targets[0].URI.String() != impu2 {
		t.Fatalf("at the end to %s for %s", host, last.Targets[0].URI.String())
	}
	if b := branchOf(t, again, last, last.Targets[0]); b.Header.Has("P-Served-User") {
		t.Error("the P-Served-User toward the servers went on to the terminating side")
	}
}

// TestAPositionTheSCSCFDidNotSignForTheRequestIsRefused with 403 (ADR
// 0005): changed, made for another Call-ID, expired, or empty.
func TestAPositionTheSCSCFDidNotSignForTheRequestIsRefused(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(10, rcsAS, method("INVITE"), ifc.SessionTerminated), criterion(20, thirdAS, method("INVITE"), ifc.SessionTerminated))
	r := fromUser(t, "INVITE", impu2)
	d := e.router(nil).Initial(bg, r)
	for name, change := range map[string]func(*proxy.Request){
		"as signed": func(*proxy.Request) {},
		"changed": func(b *proxy.Request) {
			// The priority raised past the next criterion, the MAC kept.
			v, _ := b.Routed[0].URI.Param(odiParam)
			parts := strings.Split(v, ".")
			payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
			payload[13] = 25
			b.Routed[0].URI.Params.Set(odiParam, parts[0]+"."+base64.RawURLEncoding.EncodeToString(payload)+"."+parts[2])
		},
		"another Call-ID": func(b *proxy.Request) { _ = b.Message.Header.Set("Call-ID", "term-call-2") },
		"expired":         func(*proxy.Request) { e.clock.advance(DefaultODILifetime + time.Second) },
		"just in time":    func(*proxy.Request) { e.clock.advance(DefaultODILifetime) },
		"empty":           func(b *proxy.Request) { b.Routed[0].URI.Params.SetFlag(odiParam) },
		"a key not kept": func(b *proxy.Request) {
			v, _ := b.Routed[0].URI.Param(odiParam)
			b.Routed[0].URI.Params.Set(odiParam, "k9"+strings.TrimPrefix(v, "k2"))
		},
		"from another key": func(b *proxy.Request) {
			v, _ := b.Routed[0].URI.Param(odiParam)
			pos, err := e.router(nil).openODI(v, "term-call-1", t0)
			if err != nil {
				t.Fatal(err)
			}
			other := e.router(nil, func(c *Config) {
				c.DialogKeys = []DialogKey{{ID: "k2", Key: bytes.Repeat([]byte{1}, MinDialogKeyBytes)}}
			})
			b.Routed[0].URI.Params.Set(odiParam, other.signODI(pos, "term-call-1", t0.Add(time.Minute)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			e.clock = &clock{now: t0}
			b := backFrom(t, r, d, 0)
			b.Routed[0].URI.Params = append(sip.Params(nil), b.Routed[0].URI.Params...)
			change(b)
			// Each case is its own return, with no claim on its position.
			got := e.router(claimsApart(e.store)).Initial(bg, b)
			switch {
			case name == "as signed" || name == "just in time":
				if serverOf(t, got) != "third-as.rcs.local" {
					t.Errorf("resumed to %v", got.Targets)
				}
			case got.Status != 403 || len(got.Targets) != 0:
				t.Errorf("status %d, %d targets", got.Status, len(got.Targets))
			}
		})
	}
	if e.metrics.get("routing.odi.refused") != 6 || e.metrics.get("routing.odi.resumed") != 2 {
		t.Errorf("refused %d", e.metrics.get("routing.odi.refused"))
	}
}

// TestTheEndOfAnOriginatingChainIsTheICSCFOfTheHomeDomain: a tel URI of a
// global number is sent as its SIP URI in the home domain, as no ENUM is
// asked; another domain, or a local number, is 404.
func TestTheEndOfAnOriginatingChainIsTheICSCFOfTheHomeDomain(t *testing.T) {
	for target, want := range map[string]string{
		impu2:                                   impu2,
		"tel:+1-555-010-0002":                   "sip:+15550100002@" + realm + ";user=phone",
		"sip:+15550100002@example.com":          "",
		"tel:5550100;phone-context=example.com": "",
	} {
		e := newEnv(t)
		e.registered(binding(1, 0, time.Hour))
		d := e.router(nil).Originating(bg, fromUser(t, "MESSAGE", target))
		if want == "" {
			if d.Status != 404 {
				t.Errorf("%s: status %d, targets %v", target, d.Status, uris(d.Targets))
			}
			continue
		}
		if serverOf(t, d) != "icscf.rcs.local" || d.Targets[0].URI.String() != want || len(d.RecordRoute) != 1 {
			t.Errorf("%s: to %v, Record-Route %v", target, uris(d.Targets), d.RecordRoute)
		}
	}
}

// TestAnOriginatingRequestNeedsARegisteredAssertedUser: 403 for a request
// asserting no public identity, for an unregistered or barred user, 500
// with Retry-After for a store that cannot be read; the first asserted
// public identity is the served user.
func TestAnOriginatingRequestNeedsARegisteredAssertedUser(t *testing.T) {
	for name, c := range map[string]struct {
		setUp  func(e *env)
		pai    string
		status int
	}{
		"no identity":         {func(e *env) { e.registered(binding(1, 0, time.Hour)) }, "", 403},
		"no public identity":  {func(e *env) { e.registered(binding(1, 0, time.Hour)) }, "<sip:" + realm + ">", 403},
		"barred":              {func(e *env) { e.registered(binding(1, 0, time.Hour)) }, "<" + impu2 + ">", 403},
		"not registered":      {func(*env) {}, "<" + impu1 + ">", 403},
		"every binding gone":  {func(e *env) { e.registered(binding(1, 0, -time.Second)) }, "<" + impu1 + ">", 403},
		"unregistered record": {func(e *env) { e.unregistered() }, "<" + impu1 + ">", 403},
		"the tel one first":   {func(e *env) { e.registered(binding(1, 0, time.Hour)) }, "<" + tel1 + ">, <" + impu1 + ">", 0},
		"malformed":           {func(e *env) { e.registered(binding(1, 0, time.Hour)) }, "<" + impu1, 403},
		"a public one second": {func(e *env) { e.registered(binding(1, 0, time.Hour)) }, "<sip:" + realm + ">, <" + impu1 + ">", 0},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			c.setUp(e)
			r := request(t, "MESSAGE", impu2)
			if c.pai != "" {
				_ = r.Message.Header.Set("P-Asserted-Identity", c.pai)
			}
			d := e.router(nil).Originating(bg, r)
			if d.Status != c.status {
				t.Errorf("status %d, want %d", d.Status, c.status)
			}
			if e.hss.calls() != 0 {
				t.Error("the HSS was asked for an originating user")
			}
		})
	}
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	d := e.router(failingStore{e.store}).Originating(bg, fromUser(t, "MESSAGE", impu2))
	if d.Response == nil || d.Response.StatusCode != 500 || d.Response.Header.Get("Retry-After") == "" {
		t.Errorf("a store failure is answered %+v", d)
	}
}

// registrarErr is the registrar's error for what the HSS said.
func registrarErr(what string) error {
	switch what {
	case "unknown":
		return registrar.ErrUnknownUser
	case "elsewhere":
		return registrar.ErrServedElsewhere
	}
	return registrar.ErrHSSUnavailable
}

// unregistered stores the record of impi1's set as an unregistered user's,
// as registrar.Unregistered does, its state ending an hour after t0.
func (e *env) unregistered() *state.Registration {
	e.t.Helper()
	r := &state.Registration{
		Key: set1, Incarnation: 8, Unregistered: t0.Add(time.Hour),
		Identities: []state.SetIdentity{{IMPU: impu1}, {IMPU: tel1}, {IMPU: impu2, Barred: true}},
	}
	saved, err := e.store.SaveRegistration(bg, r)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, id := range r.Identities {
		if _, err := e.store.SaveIdentity(bg, &state.Identity{IMPU: id.IMPU, Set: set1, Incarnation: 8, Barred: id.Barred, KeepUntil: t0.Add(48 * time.Hour)}, t0); err != nil {
			e.t.Fatal(err)
		}
	}
	return saved
}

// TestDefaultHandlingAppliesOnlyToAServerThatDoesNotAnswer (TS 24.229
// §5.4.3.2, §5.4.3.3): with its session continued, a server's silence, a
// failure to reach it, a 408 or a 5xx, without a provisional response from
// it first, sends the request on as if the criterion had not matched; any
// other answer, one after a provisional, or a session terminated, ends the
// request with the server's answer.
func TestDefaultHandlingAppliesOnlyToAServerThatDoesNotAnswer(t *testing.T) {
	for name, c := range map[string]struct {
		handling ifc.DefaultHandling
		failure  func(proxy.Target) proxy.BranchFailure
		next     string
	}{
		"timeout": {ifc.SessionContinued, func(tg proxy.Target) proxy.BranchFailure {
			return proxy.BranchFailure{Target: tg, Response: &sip.Response{StatusCode: 408}, Err: proxy.ErrTargetTimeout}
		}, "third-as.rcs.local"},
		"a 408": {ifc.SessionContinued, func(tg proxy.Target) proxy.BranchFailure {
			return proxy.BranchFailure{Target: tg, Response: &sip.Response{StatusCode: 408}}
		}, "third-as.rcs.local"},
		"unreachable": {ifc.SessionContinued, func(tg proxy.Target) proxy.BranchFailure {
			return proxy.BranchFailure{Target: tg, Response: &sip.Response{StatusCode: 503}, Err: errors.New("connection refused")}
		}, "third-as.rcs.local"},
		"its own 500": {ifc.SessionContinued, func(tg proxy.Target) proxy.BranchFailure {
			return proxy.BranchFailure{Target: tg, Response: &sip.Response{StatusCode: 500}}
		}, "third-as.rcs.local"},
		"its own 500, terminated": {ifc.SessionTerminated, func(tg proxy.Target) proxy.BranchFailure {
			return proxy.BranchFailure{Target: tg, Response: &sip.Response{StatusCode: 500}}
		}, ""},
		"its own 486": {ifc.SessionContinued, func(tg proxy.Target) proxy.BranchFailure {
			return proxy.BranchFailure{Target: tg, Response: &sip.Response{StatusCode: 486}}
		}, ""},
		"a 408 after a 180": {ifc.SessionContinued, func(tg proxy.Target) proxy.BranchFailure {
			return proxy.BranchFailure{Target: tg, Response: &sip.Response{StatusCode: 408}, Provisional: true, Progress: true}
		}, ""},
		"closed after a 180": {ifc.SessionContinued, func(tg proxy.Target) proxy.BranchFailure {
			return proxy.BranchFailure{Target: tg, Response: &sip.Response{StatusCode: 503}, Err: errors.New("connection closed"), Provisional: true, Progress: true}
		}, ""},
		"a 408 after only a 100": {ifc.SessionContinued, func(tg proxy.Target) proxy.BranchFailure {
			return proxy.BranchFailure{Target: tg, Response: &sip.Response{StatusCode: 408}, Provisional: true}
		}, "third-as.rcs.local"},
		"terminated": {ifc.SessionTerminated, func(tg proxy.Target) proxy.BranchFailure {
			return proxy.BranchFailure{Target: tg, Response: &sip.Response{StatusCode: 408}, Err: proxy.ErrTargetTimeout}
		}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.registered(binding(1, 0, time.Hour))
			e.profile(t0, criterion(10, rcsAS, method("MESSAGE"), c.handling), criterion(20, thirdAS, method("MESSAGE"), ifc.SessionTerminated))
			r := fromUser(t, "MESSAGE", impu2)
			d := e.router(nil).Initial(bg, r)
			serverOf(t, d)
			more := d.OnBranchFailure(bg, c.failure(d.Targets[0]))
			if c.next == "" {
				if len(more) != 0 {
					t.Errorf("went on to %v", more)
				}
				res := &sip.Response{StatusCode: 500, Reason: "Server Internal Error"}
				if err := res.Header.Set("Retry-After", "5"); err != nil {
					t.Fatal(err)
				}
				d.OnFinal(bg, res)
				if res.StatusCode != 500 || res.Header.Get("Retry-After") != "5" {
					t.Errorf("the server's answer became %d", res.StatusCode)
				}
				return
			}
			if len(more) != 1 || more[0].Routes[0].URI.Host != c.next {
				t.Fatalf("then %+v", more)
			}
			// The next server's branch is prepared as the first one was.
			if got := branchOf(t, r, d, more[0]).Header.Get("P-Served-User"); !strings.Contains(got, "sescase=orig") {
				t.Errorf("P-Served-User toward the next server %q", got)
			}
		})
	}
}

// TestAChainThatEndsAfterAServerFailedAnswersAsItsEndWould: a request to an
// unregistered user whose only server does not answer is 480, not the 504
// the proxy made of the timeout.
func TestAChainThatEndsAfterAServerFailedAnswersAsItsEndWould(t *testing.T) {
	e := newEnv(t)
	e.unregistered()
	e.profile(t0, criterion(10, rcsAS, method("OPTIONS"), ifc.SessionContinued))
	d := e.router(nil).Initial(bg, request(t, "OPTIONS", impu1))
	serverOf(t, d)
	if more := d.OnBranchFailure(bg, proxy.BranchFailure{Target: d.Targets[0], Response: &sip.Response{StatusCode: 408}, Err: proxy.ErrTargetTimeout}); len(more) != 0 {
		t.Fatalf("then %v", more)
	}
	res := &sip.Response{StatusCode: 504, Reason: "Server Time-out"}
	d.OnFinal(bg, res)
	if res.StatusCode != 480 {
		t.Errorf("answered %d", res.StatusCode)
	}
	// A 2xx another branch got stays one.
	ok := &sip.Response{StatusCode: 200, Reason: "OK"}
	if d.OnFinal(bg, ok); ok.StatusCode != 200 {
		t.Errorf("a 200 became %d", ok.StatusCode)
	}
}

// TestA430IsNotSentUpstream: the chain's OnFinal does what the proxy does
// without one (RFC 5626 §11.5).
func TestA430IsNotSentUpstream(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	d := e.router(nil).Terminating(bg, request(t, "MESSAGE", impu1))
	res := &sip.Response{StatusCode: 430, Reason: "Flow Failed"}
	d.OnFinal(bg, res)
	ok := &sip.Response{StatusCode: 200, Reason: "OK"}
	d.OnFinal(bg, ok)
	if res.StatusCode != 480 || ok.StatusCode != 200 {
		t.Errorf("430 became %d, 200 became %d", res.StatusCode, ok.StatusCode)
	}
}

// TestAnOperatorServerBeforeRcsAsDoesNotMakeRcsAsTriggersMiss (#14): the
// P-Served-User the S-CSCF put in toward the operator's server comes back
// with the request, and is not what rcs-as's triggers exclude.
func TestAnOperatorServerBeforeRcsAsDoesNotMakeRcsAsTriggersMiss(t *testing.T) {
	for name, r := range map[string]func(t *testing.T) *proxy.Request{
		"originating": func(t *testing.T) *proxy.Request { return fromUser(t, "MESSAGE", impu2) },
		"terminating": func(t *testing.T) *proxy.Request { return request(t, "MESSAGE", impu1) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.registered(binding(1, 0, time.Hour))
			e.profile(t0, criterion(5, operatorAS, method("MESSAGE"), ifc.SessionContinued), criterion(10, rcsAS, notServed("MESSAGE"), ifc.SessionTerminated))
			req := r(t)
			d := e.router(nil).Initial(bg, req)
			if serverOf(t, d) != "operator-as.rcs.local" {
				t.Fatal("not to the operator's server first")
			}
			back := backFrom(t, req, d, 0)
			if !back.Message.Header.Has("P-Served-User") {
				t.Fatal("the request came back without the P-Served-User")
			}
			if host := serverOf(t, e.router(nil).Initial(bg, back)); host != "rcs-as.rcs.local" {
				t.Errorf("then to %s", host)
			}
		})
	}
}

// TestARequestAServerSentForItsUserPassesItsTriggers (#137): one without
// orig and with a P-Served-User of its own is terminating, rcs-as's
// triggers miss it, before another server and after, and it reaches the
// user's contacts.
func TestARequestAServerSentForItsUserPassesItsTriggers(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(5, operatorAS, method("MESSAGE"), ifc.SessionContinued), criterion(10, rcsAS, notServed("MESSAGE"), ifc.SessionTerminated))
	r := request(t, "MESSAGE", impu1, "P-Served-User: <"+impu1+">;sescase=term")
	d := e.router(nil).Initial(bg, r)
	if serverOf(t, d) != "operator-as.rcs.local" {
		t.Fatal("not to the operator's server")
	}
	d = e.router(nil).Initial(bg, backFrom(t, r, d, 0))
	if got := uris(d.Targets); !slices.Equal(got, []string{binding(1, 0, 0).URI}) {
		t.Fatalf("then to %v, status %d", got, d.Status)
	}
	if b := branchOf(t, r, d, d.Targets[0]); b.Header.Has("P-Served-User") || b.Header.Get("P-Called-Party-ID") != "<"+impu1+">" {
		t.Errorf("toward the contact: P-Served-User %q, P-Called-Party-ID %q", b.Header.Get("P-Served-User"), b.Header.Get("P-Called-Party-ID"))
	}
}

// TestAPServedUserFromAnEdgeProxyIsNotTrusted (#137): a request a P-CSCF
// sends never names a served user, and rcs-as's triggers see past one.
func TestAPServedUserFromAnEdgeProxyIsNotTrusted(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(10, rcsAS, notServed("MESSAGE"), ifc.SessionTerminated))
	r := request(t, "MESSAGE", impu1, "P-Served-User: <"+impu1+">;sescase=term")
	if err := r.Message.Header.Set("Via", "SIP/2.0/TCP 198.51.100.5:5070;branch=z9hG4bK-edge"); err != nil {
		t.Fatal(err)
	}
	if host := serverOf(t, e.router(nil).Initial(bg, r)); host != "rcs-as.rcs.local" {
		t.Errorf("sent to %s", host)
	}
}

// TestAnUnregisteredUserIsServedByItsUnregisteredCriteria (§5.4.3.3): the
// HSS makes the user one this S-CSCF serves, once; the criteria for the
// unregistered state apply, with regstate=unreg toward the server; without
// one the request is 480.
func TestAnUnregisteredUserIsServedByItsUnregisteredCriteria(t *testing.T) {
	t.Run("ending", func(t *testing.T) {
		// One a sweep holds is neither, and gets no SAR of its own.
		e := newEnv(t)
		r := e.unregistered()
		r.Deregistering = t0.Add(time.Minute)
		if _, err := e.store.SaveRegistration(bg, r); err != nil {
			t.Fatal(err)
		}
		e.profile(t0, criterion(10, rcsAS, method("MESSAGE"), ifc.SessionTerminated))
		if d := e.router(nil).Initial(bg, request(t, "MESSAGE", impu1)); d.Status != 480 || e.hss.calls() != 0 {
			t.Errorf("status %d after %d SARs", d.Status, e.hss.calls())
		}
	})
	e := newEnv(t)
	e.hss.serve = func(string) (*state.Registration, error) { return e.unregistered(), nil }
	registeredOnly := criterion(5, operatorAS, method("MESSAGE"), ifc.SessionContinued)
	registeredOnly.ProfilePart = ifc.ProfilePartRegistered
	unreg := criterion(10, rcsAS, &ifc.TriggerPoint{ConditionTypeCNF: true, SPTs: []ifc.SPT{
		{Condition: ifc.Method("MESSAGE"), Groups: []int{0}},
		{Condition: ifc.TerminatingUnregistered, Groups: []int{1}},
	}}, ifc.SessionTerminated)
	e.profile(t0, registeredOnly, unreg)
	rt := e.router(nil)
	r := request(t, "MESSAGE", tel1)
	d := rt.Initial(bg, r)
	if serverOf(t, d) != "rcs-as.rcs.local" {
		t.Fatal("not to rcs-as")
	}
	if got := branchOf(t, r, d, d.Targets[0]).Header.Get("P-Served-User"); got != "<"+tel1+">;sescase=term;regstate=unreg" {
		t.Errorf("P-Served-User %q", got)
	}
	if d := rt.Initial(bg, request(t, "MESSAGE", impu1)); serverOf(t, d) != "rcs-as.rcs.local" {
		t.Error("the second request is not served")
	}
	if e.hss.calls() != 1 {
		t.Errorf("the HSS was asked %d times", e.hss.calls())
	}
	if d := rt.Initial(bg, request(t, "OPTIONS", impu1)); d.Status != 480 {
		t.Errorf("a request no criterion takes is %d", d.Status)
	}
}

// TestWhatTheHSSSaysOfAUserWithoutARecordIsAnswered: 404 for one it does
// not know, 480 for one another S-CSCF serves, 500 with Retry-After when it
// cannot be asked, and 404 for a barred identity.
func TestWhatTheHSSSaysOfAUserWithoutARecordIsAnswered(t *testing.T) {
	for name, c := range map[string]struct {
		serve  func(e *env) (*state.Registration, error)
		target string
		status int
	}{
		"unknown":          {func(*env) (*state.Registration, error) { return nil, registrarErr("unknown") }, impu1, 404},
		"served elsewhere": {func(*env) (*state.Registration, error) { return nil, registrarErr("elsewhere") }, impu1, 480},
		"unavailable":      {func(*env) (*state.Registration, error) { return nil, registrarErr("unavailable") }, impu1, 500},
		"barred":           {func(e *env) (*state.Registration, error) { return e.unregistered(), nil }, impu2, 404},
		"not in the set": {func(e *env) (*state.Registration, error) {
			// Its profile would send the request to rcs-as.
			e.profile(t0, criterion(10, rcsAS, method("MESSAGE"), ifc.SessionTerminated))
			r := e.unregistered()
			r.Identities = r.Identities[:1]
			return r, nil
		}, tel1, 480},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.hss.serve = func(string) (*state.Registration, error) { return c.serve(e) }
			d := e.router(nil).Terminating(bg, request(t, "MESSAGE", c.target))
			status := d.Status
			if d.Response != nil {
				status = d.Response.StatusCode
				if d.Response.Header.Get("Retry-After") == "" {
					t.Error("500 without Retry-After")
				}
			}
			if status != c.status {
				t.Errorf("status %d, want %d", status, c.status)
			}
		})
	}
}

// TestARetargetedRequestGoesToItsNewUsersSide (§5.4.3.3): a server that
// sent the request on to another user ends the served user's chain; one
// that only wrote another identity of the user's set does not.
func TestARetargetedRequestGoesToItsNewUsersSide(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(10, rcsAS, method("MESSAGE"), ifc.SessionContinued), criterion(20, thirdAS, method("MESSAGE"), ifc.SessionContinued))
	r := request(t, "MESSAGE", impu1)
	d := e.router(nil).Initial(bg, r)
	for target, want := range map[string]string{
		"sip:+15550100004@" + realm: "icscf.rcs.local",
		"sip:" + realm:              "icscf.rcs.local",
		tel1:                        "third-as.rcs.local",
	} {
		back := backFrom(t, r, d, 0)
		back.Message.URI, _ = sip.ParseURI(target)
		if host := serverOf(t, e.router(claimsApart(e.store)).Initial(bg, back)); host != want {
			t.Errorf("%s: to %s", target, host)
		}
	}
}

// TestARequestTooLargeToEvaluateIsRefused with 500 and no Retry-After (#14):
// a condition left unexamined could let it pass a server it must not.
func TestARequestTooLargeToEvaluateIsRefused(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(10, rcsAS, &ifc.TriggerPoint{SPTs: []ifc.SPT{{Condition: ifc.SIPHeader{Header: "Subject", Content: "chat"}, Groups: []int{0}}}}, ifc.SessionTerminated))
	d := e.router(nil).Initial(bg, fromUser(t, "MESSAGE", impu2, "Subject: "+strings.Repeat("x", ifc.MaxHeaderLength+1)))
	if d.Status != 500 || d.Response != nil || e.metrics.get("ifc.budget_exceeded") != 1 {
		t.Errorf("status %d, response %v", d.Status, d.Response)
	}
}

// TestAServerNameThatIsNoSIPURIIsPassedOver as an unreachable server with
// its session continued would be.
func TestAServerNameThatIsNoSIPURIIsPassedOver(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(10, "tel:+15550100005", method("MESSAGE"), ifc.SessionTerminated), criterion(20, thirdAS, method("MESSAGE"), ifc.SessionTerminated))
	if host := serverOf(t, e.router(nil).Initial(bg, fromUser(t, "MESSAGE", impu2))); host != "third-as.rcs.local" || e.metrics.get("routing.ifc.bad_server") != 1 {
		t.Errorf("to %s", host)
	}
}

// TestAProfileThatCannotBeReadIsAnInternalError: 500 without Retry-After,
// since asking again gets the same profile; a store failure has one.
func TestAProfileThatCannotBeReadIsAnInternalError(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	if err := e.store.SaveProfile(bg, &state.Profile{Key: set1, UserData: []byte("<not/>"), Received: t0, KeepUntil: t0.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if d := e.router(nil).Initial(bg, fromUser(t, "MESSAGE", impu2)); d.Status != 500 || d.Response != nil {
		t.Errorf("status %d, response %v", d.Status, d.Response)
	}
	d := e.router(profileFailing{e.store}).Initial(bg, fromUser(t, "MESSAGE", impu2))
	if d.Response == nil || d.Response.Header.Get("Retry-After") == "" {
		t.Errorf("a store failure is answered %+v", d)
	}
}

type profileFailing struct{ *state.Memory }

func (profileFailing) Profile(context.Context, state.SetKey, time.Time) (*state.Profile, error) {
	return nil, errors.New("throttled")
}

// TestAChangedProfileIsEvaluatedAfresh: the compiled criteria are kept per
// profile as received, so a PPR's takes effect at once.
func TestAChangedProfileIsEvaluatedAfresh(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(10, rcsAS, method("MESSAGE"), ifc.SessionTerminated))
	rt := e.router(nil)
	if serverOf(t, rt.Initial(bg, fromUser(t, "MESSAGE", impu2))) != "rcs-as.rcs.local" {
		t.Fatal("not to rcs-as")
	}
	e.profile(t0.Add(time.Minute), criterion(10, thirdAS, method("MESSAGE"), ifc.SessionTerminated))
	if host := serverOf(t, rt.Initial(bg, fromUser(t, "MESSAGE", impu2))); host != "third-as.rcs.local" {
		t.Errorf("after the change to %s", host)
	}
}

// TestNewRefusesAnIncompleteConfig: each E2 setting is required.
func TestNewRefusesAnIncompleteConfig(t *testing.T) {
	for name, tweak := range map[string]func(*Config){
		"no registrar":      func(c *Config) { c.Registrar = nil },
		"I-CSCF without lr": func(c *Config) { c.ICSCF.Params = nil },
		"I-CSCF not SIP":    func(c *Config) { c.ICSCF, _ = sip.ParseURI("tel:+15550100005") },
		"no home domain":    func(c *Config) { c.HomeDomain = "" },
	} {
		e := newEnv(t)
		self, _ := sip.ParseURI("sip:scscf.rcs.local")
		rr, _ := sip.ParseAddress("<sip:scscf.rcs.local;transport=tcp;lr>")
		icscf, _ := sip.ParseURI("sip:icscf.rcs.local;lr")
		cfg := Config{Store: e.store, RecordRoute: rr, Self: []sip.URI{self}, Registrar: e.hss, DialogKeys: []DialogKey{{ID: "k2", Key: dialogKey}}, ICSCF: icscf, HomeDomain: realm}
		if _, err := New(cfg); err != nil {
			t.Fatalf("the complete config: %v", err)
		}
		tweak(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestAChainGoesOnWithWhatTheUserIsNow: a request back from a server whose
// user deregistered meanwhile ends its chain, originating at the I-CSCF,
// terminating with 480; one whose identity was barred meanwhile is refused;
// and a store that cannot be read is 500 with Retry-After.
func TestAChainGoesOnWithWhatTheUserIsNow(t *testing.T) {
	for name, c := range map[string]struct {
		orig   bool
		change func(e *env)
		status int
		to     string
	}{
		"originating, deregistered": {true, func(e *env) { e.change(deregister) }, 0, "icscf.rcs.local"},
		"terminating, deregistered": {false, func(e *env) { e.change(deregister) }, 480, ""},
		"terminating, record gone":  {false, func(e *env) { e.change(nil) }, 480, ""},
		"originating, barred":       {true, func(e *env) { e.change(barImpu1) }, 403, ""},
		"terminating, barred":       {false, func(e *env) { e.change(barImpu1) }, 404, ""},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.registered(binding(1, 0, time.Hour))
			e.profile(t0, criterion(10, rcsAS, method("MESSAGE"), ifc.SessionContinued), criterion(20, thirdAS, method("MESSAGE"), ifc.SessionContinued))
			r := request(t, "MESSAGE", impu1)
			if c.orig {
				r = fromUser(t, "MESSAGE", impu2)
			}
			d := e.router(nil).Initial(bg, r)
			c.change(e)
			got := e.router(nil).Initial(bg, backFrom(t, r, d, 0))
			if c.to != "" {
				if host := serverOf(t, got); host != c.to {
					t.Errorf("to %s", host)
				}
				return
			}
			if got.Status != c.status || len(got.Targets) != 0 {
				t.Errorf("status %d, targets %v", got.Status, uris(got.Targets))
			}
		})
	}
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(10, rcsAS, method("MESSAGE"), ifc.SessionContinued))
	r := fromUser(t, "MESSAGE", impu2)
	d := e.router(nil).Initial(bg, r)
	got := e.router(failingStore{e.store}).Initial(bg, backFrom(t, r, d, 0))
	if got.Response == nil || got.Response.StatusCode != 500 || got.Response.Header.Get("Retry-After") == "" {
		t.Errorf("a store failure is answered %+v", got)
	}
}

// change applies f to the record of set1, or deletes it for a nil f.
func (e *env) change(f func(*state.Registration)) {
	e.t.Helper()
	r, err := e.store.Registration(bg, set1)
	if err != nil {
		e.t.Fatal(err)
	}
	if f == nil {
		err = e.store.DeleteRegistration(bg, r)
	} else {
		f(r)
		_, err = e.store.SaveRegistration(bg, r)
	}
	if err != nil {
		e.t.Fatal(err)
	}
}

func deregister(r *state.Registration) { r.Deregistering, r.Contacts = t0.Add(time.Minute), nil }

func barImpu1(r *state.Registration) { r.Identities[0].Barred = true }

// TestADefaultHandlingThatCannotGoOnAnswersAsTheChainWould: the profile
// cannot be read for the next criterion, and the request is 500 rather
// than the proxy's 504; the end of the chain, the I-CSCF, is tried once.
func TestADefaultHandlingThatCannotGoOnAnswersAsTheChainWould(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(10, rcsAS, method("MESSAGE"), ifc.SessionContinued))
	st := &profileOnce{Memory: e.store}
	d := e.router(st).Initial(bg, fromUser(t, "MESSAGE", impu2))
	timeout := func(tg proxy.Target) proxy.BranchFailure {
		return proxy.BranchFailure{Target: tg, Response: &sip.Response{StatusCode: 408}, Err: proxy.ErrTargetTimeout}
	}
	if more := d.OnBranchFailure(bg, timeout(d.Targets[0])); len(more) != 0 {
		t.Fatalf("then %v", uris(more))
	}
	res := &sip.Response{StatusCode: 504, Reason: "Server Time-out"}
	d.OnFinal(bg, res)
	if res.StatusCode != 500 {
		t.Errorf("answered %d", res.StatusCode)
	}

	st.reads = -1 << 30
	second := fromUser(t, "MESSAGE", impu2)
	_ = second.Message.Header.Set("Call-ID", "term-call-2")
	d = e.router(st).Initial(bg, second)
	more := d.OnBranchFailure(bg, timeout(d.Targets[0]))
	if len(more) != 1 || more[0].Routes[0].URI.Host != "icscf.rcs.local" {
		t.Fatalf("then %v", uris(more))
	}
	if again := d.OnBranchFailure(bg, proxy.BranchFailure{Target: more[0], Response: &sip.Response{StatusCode: 404}}); len(again) != 0 {
		t.Errorf("after the I-CSCF %v", uris(again))
	}
	if err := d.Prepare(bg, proxy.Target{URI: more[0].URI}, r0(t)); err == nil {
		t.Error("a target the plan does not hold was prepared")
	}
}

// r0 is a request to prepare.
func r0(t *testing.T) *sip.Request { return request(t, "MESSAGE", impu2).Message }

// profileOnce reads the profile once, and fails after.
type profileOnce struct {
	*state.Memory
	mu    sync.Mutex
	reads int
}

func (s *profileOnce) Profile(ctx context.Context, k state.SetKey, now time.Time) (*state.Profile, error) {
	s.mu.Lock()
	s.reads++
	n := s.reads
	s.mu.Unlock()
	if n > 1 {
		return nil, errors.New("throttled")
	}
	return s.Memory.Profile(ctx, k, now)
}

// TestCriteriaThatDoNotCompileAreAnInternalError: 500 without Retry-After.
func TestCriteriaThatDoNotCompileAreAnInternalError(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(10, rcsAS, &ifc.TriggerPoint{SPTs: []ifc.SPT{{Condition: ifc.RequestURI("(("), Groups: []int{0}}}}, ifc.SessionTerminated))
	if d := e.router(nil).Initial(bg, fromUser(t, "MESSAGE", impu2)); d.Status != 500 || d.Response != nil {
		t.Errorf("status %d, response %v", d.Status, d.Response)
	}
}

// TestEachIdentityHasTheCriteriaOfItsServiceProfile (TS 29.228 Annex E):
// identities of one set may have profiles of their own.
func TestEachIdentityHasTheCriteriaOfItsServiceProfile(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	sub := ifc.Subscription{PrivateID: impi1, ServiceProfiles: []ifc.ServiceProfile{
		{PublicIdentities: []ifc.PublicIdentity{{Identity: impu1}}, InitialFilterCriteria: []ifc.FilterCriteria{criterion(10, rcsAS, method("MESSAGE"), ifc.SessionTerminated)}},
		{PublicIdentities: []ifc.PublicIdentity{{Identity: "tel:+1-555-010-0001"}}, InitialFilterCriteria: []ifc.FilterCriteria{criterion(10, thirdAS, method("MESSAGE"), ifc.SessionTerminated)}},
	}}
	data, err := sub.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.SaveProfile(bg, &state.Profile{Key: set1, UserData: data, Received: t0, KeepUntil: t0.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	rt := e.router(nil)
	for target, want := range map[string]string{impu1: "rcs-as.rcs.local", tel1: "third-as.rcs.local"} {
		if host := serverOf(t, rt.Initial(bg, request(t, "MESSAGE", target))); host != want {
			t.Errorf("%s: to %s", target, host)
		}
	}
}

// TestAPositionTooShortIsRefusedEvenWithItsMAC: only a key holder can make
// one, and it must not take the router down.
func TestAPositionTooShortIsRefusedEvenWithItsMAC(t *testing.T) {
	rt := newEnv(t).router(nil)
	payload := []byte{0, 0, 0, 0}
	k := DialogKey{ID: "k2", Key: dialogKey}
	v := "k2." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(odiMAC(k, payload, "c"))
	if _, err := rt.openODI(v, "c", t0); err == nil {
		t.Error("opened")
	}
}

// TestTheFirstStepOfAChainSignsTheDialogsRoute (#322): the S-CSCF's
// Record-Route value in the branch toward the server is signed for the hop
// toward the caller, and responses are signed again; a step back from a
// server records nothing.
func TestTheFirstStepOfAChainSignsTheDialogsRoute(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(10, rcsAS, method("INVITE"), ifc.SessionContinued))
	caller := "<sip:" + flow(7) + "@198.51.100.7:5070;transport=tcp;lr>"
	r := fromUser(t, "INVITE", impu2, "Record-Route: "+caller)
	d := e.router(nil).Initial(bg, r)
	if d.OnResponse == nil || len(d.RecordRoute) != 1 {
		t.Fatal("the first step records no route")
	}
	b := r.Message.Clone()
	b.URI = d.Targets[0].URI
	if err := b.Header.Prepend("Record-Route", d.RecordRoute[0].String()); err != nil {
		t.Fatal(err)
	}
	if err := d.Prepare(bg, d.Targets[0], b); err != nil {
		t.Fatal(err)
	}
	rr, _ := b.Header.RecordRoute()
	v, ok := rr[0].URI.Param(dlgParam)
	if !ok || !e.router(nil).signedHop(v, "term-call-1", hopKey(mustURI(strings.Trim(caller, "<>")))) {
		t.Errorf("Record-Route %s is not signed for the caller's hop", rr[0].String())
	}
	back := backFrom(t, r, d, 0)
	if d := e.router(nil).Initial(bg, back); d.OnResponse != nil || len(d.RecordRoute) != 0 {
		t.Error("the step back from the server records the route again")
	}
}

// claimsApart is st with the claims of iFC positions (state.AttemptODI)
// kept apart, in a store of their own, as a test that resumes one position
// in several cases needs.
func claimsApart(st *state.Memory) state.Store {
	return &apartClaims{Memory: st, claims: state.NewMemory()}
}

type apartClaims struct {
	*state.Memory
	claims *state.Memory
}

func (s *apartClaims) CountAttempt(ctx context.Context, a state.Attempt, n int64, expires time.Time) (int64, error) {
	if a.Kind == state.AttemptODI {
		return s.claims.CountAttempt(ctx, a, n, expires)
	}
	return s.Memory.CountAttempt(ctx, a, n, expires)
}

// TestAServerThatSentTheRequestBackIsNotPassedOver (code review on #359):
// an OPTIONS rcs-as sent on, whose callee is slow, times out on the branch
// toward rcs-as; the default handling does not send a second copy, as the
// copy rcs-as sent back goes on, on any instance. A copy back after the
// default handling went on is refused.
func TestAServerThatSentTheRequestBackIsNotPassedOver(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(30, rcsAS, method("OPTIONS"), ifc.SessionContinued))
	r := fromUser(t, "OPTIONS", impu2)
	d := e.router(nil).Initial(bg, r)
	back := backFrom(t, r, d, 0)
	if host := serverOf(t, e.router(nil).Initial(bg, back)); host != "icscf.rcs.local" {
		t.Fatalf("the copy back went to %s", host)
	}
	timeout := proxy.BranchFailure{Target: d.Targets[0], Response: &sip.Response{StatusCode: 408}, Err: proxy.ErrTargetTimeout}
	if more := d.OnBranchFailure(bg, timeout); len(more) != 0 {
		t.Errorf("a second copy went to %v", uris(more))
	}
	// The other way round: the default handling first.
	r2 := fromUser(t, "OPTIONS", impu2)
	_ = r2.Message.Header.Set("Call-ID", "term-call-2")
	d2 := e.router(nil).Initial(bg, r2)
	timeout.Target = d2.Targets[0]
	if more := d2.OnBranchFailure(bg, timeout); len(more) != 1 {
		t.Fatalf("the default handling did not go on: %v", uris(more))
	}
	if got := e.router(nil).Initial(bg, backFrom(t, r2, d2, 0)); got.Status != 403 || e.metrics.get("routing.odi.late") != 1 {
		t.Errorf("the late copy back is %d", got.Status)
	}
}

// TestARingingINVITEIsNotSentOnPastItsServer (code review on #359): a
// SESSION_CONTINUED operator server that had the callee ring, and then
// ends with 408, is not passed over: the callee would ring twice.
func TestARingingINVITEIsNotSentOnPastItsServer(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(5, operatorAS, method("INVITE"), ifc.SessionContinued))
	d := e.router(nil).Initial(bg, fromUser(t, "INVITE", impu2))
	f := proxy.BranchFailure{Target: d.Targets[0], Response: &sip.Response{StatusCode: 408}, Provisional: true, Progress: true}
	if more := d.OnBranchFailure(bg, f); len(more) != 0 {
		t.Errorf("sent on to %v", uris(more))
	}
}

// TestTheChainsAnswerKeepsItsRetryAfter (code review on #359): a default
// handling that goes on and finds the store failing answers 500 with
// Retry-After, as the first step would.
func TestTheChainsAnswerKeepsItsRetryAfter(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(10, rcsAS, method("MESSAGE"), ifc.SessionContinued))
	d := e.router(&profileOnce{Memory: e.store}).Initial(bg, fromUser(t, "MESSAGE", impu2))
	d.OnBranchFailure(bg, proxy.BranchFailure{Target: d.Targets[0], Response: &sip.Response{StatusCode: 408}, Err: proxy.ErrTargetTimeout})
	res := &sip.Response{StatusCode: 504, Reason: "Server Time-out"}
	d.OnFinal(bg, res)
	if res.StatusCode != 500 || res.Header.Get("Retry-After") != storeRetryAfter {
		t.Errorf("%d with Retry-After %q", res.StatusCode, res.Header.Get("Retry-After"))
	}
}
