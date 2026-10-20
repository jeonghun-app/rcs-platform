package icscf

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// Every row of the terminating part of the package's mapping table, with
// its clause (TS 24.229 §5.3.2.1, §5.3.2.2; results of TS 29.229 §6.2).
func TestTerminatingAnswersFollowTheMappingTable(t *testing.T) {
	via := func(route string) outcome { return outcome{uri: tel1, route: route} }
	retry := outcome{status: 480, retryAfter: "10"}
	cases := []struct {
		name   string
		lia    *cx.LIA
		err    error
		want   outcome
		metric string
	}{
		// §5.3.2.1: the Server-Name becomes the topmost Route, with lr.
		{"registered", lia(base(diameter.ResultSuccess), "sip:scscf-0.rcs.local", nil), nil, via("sip:scscf-0.rcs.local;lr"), "icscf.terminating.forwarded"},
		{"name already with lr", lia(base(diameter.ResultSuccess), "sip:scscf-0.rcs.local;lr", nil), nil, via("sip:scscf-0.rcs.local;lr"), "icscf.terminating.forwarded"},
		{"unregistered service with a name", lia(experimental(cx.UnregisteredService), "sip:scscf-0.rcs.local", nil), nil, via("sip:scscf-0.rcs.local;lr"), "icscf.terminating.forwarded"},
		{"server name not stored", lia(experimental(cx.SuccessServerNameNotStored), "sip:scscf-0.rcs.local", nil), nil, via("sip:scscf-0.rcs.local;lr"), "icscf.terminating.forwarded"},
		// §5.3.2.1: chosen by capability.
		{"unregistered service with capabilities", lia(experimental(cx.UnregisteredService), "", &cx.ServerCapabilities{Mandatory: []uint32{1}}), nil, via("sip:scscf-b.rcs.local;transport=tcp;lr"), "icscf.terminating.forwarded"},
		{"unregistered service, any S-CSCF", lia(experimental(cx.UnregisteredService), "", nil), nil, via(scscfURI + ";lr"), "icscf.terminating.forwarded"},
		// Local choice: TS 24.229 names no response for this.
		{"no S-CSCF qualifies", lia(experimental(cx.UnregisteredService), "", &cx.ServerCapabilities{Mandatory: []uint32{9}}), nil, outcome{status: 480}, "icscf.terminating.480"},
		// §5.3.2.1, §5.3.2.2.
		{"5001 user unknown", lia(experimental(cx.ErrorUserUnknown), "", nil), nil, outcome{status: 404}, "icscf.terminating.404"},
		{"5003 not registered", lia(experimental(cx.ErrorIdentityNotRegistered), "", nil), nil, outcome{status: 480}, "icscf.terminating.480"},
		{"another Cx error", lia(experimental(cx.ErrorFeatureUnsupported), "", nil), nil, outcome{status: 404}, "icscf.terminating.404"},
		{"base 5001 is not the user", lia(base(diameter.ResultAVPUnsupported), "", nil), nil, outcome{status: 404}, "icscf.terminating.404"},
		{"unable to comply", lia(base(diameter.ResultUnableToComply), "", nil), nil, outcome{status: 404}, "icscf.terminating.404"},
		{"authorization rejected", lia(base(diameter.ResultAuthorizationRejected), "", nil), nil, outcome{status: 404}, "icscf.terminating.404"},
		// Could not be completed: 480 with Retry-After (decision 3 on #15).
		{"too busy", lia(base(diameter.ResultTooBusy), "", nil), nil, retry, "icscf.hss.unavailable"},
		{"no HSS peer", nil, cxclient.ErrNoPeer, retry, "icscf.hss.unavailable"},
		{"time-out", nil, context.DeadlineExceeded, retry, "icscf.hss.unavailable"},
		{"malformed answer", nil, errors.New("cx: missing Result-Code"), retry, "icscf.hss.unavailable"},
		{"name that is not a SIP URI", lia(base(diameter.ResultSuccess), "scscf-0", nil), nil, retry, "icscf.hss.bad_server_name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newRig(t, twoSCSCFs)
			g.hss.lia, g.hss.err = tc.lia, tc.err
			if got := describe(t, g.route(invite(t, tel1))); got != tc.want {
				t.Errorf("decision = %+v, want %+v", got, tc.want)
			}
			if names := g.metrics.names(); !slices.Contains(names, tc.metric) {
				t.Errorf("metrics %v lack %s", names, tc.metric)
			}
		})
	}
}

func lia(r cx.Result, name string, caps *cx.ServerCapabilities) *cx.LIA {
	return &cx.LIA{Answer: cx.Answer{Result: r}, ServerName: name, ServerCapabilities: caps}
}

// TS 24.229 §5.3.2.1 step 1 b), and step 1 c) for a GRUU.
func TestTerminatingRequestURIForATelephoneNumberBecomesATelURI(t *testing.T) {
	cases := []struct {
		name, uri, wantURI, wantIMPU string
	}{
		{"user=phone", "sip:+15550100001@" + home + ";user=phone", tel1, tel1},
		{"escaped plus", "sip:%2B15550100001@" + home + ";user=phone", tel1, tel1},
		{"visual separators", "sip:+1-555-010-0001@" + home + ";user=phone", "tel:+1-555-010-0001", tel1},
		{"tel parameters carried forward", "sip:+15550100001;npdi;rn=+15550100009@" + home + ";user=phone", "tel:+15550100001;npdi;rn=+15550100009", tel1},
		{"tel URI as it is", tel1, tel1, tel1},
		{"without user=phone", "sip:+15550100001@" + home, "sip:+15550100001@" + home, impu1},
		// Step 1 b) is for global numbers; the HSS decides about the rest.
		{"local number", "sip:5550100001;phone-context=" + home + "@" + home + ";user=phone", "sip:5550100001;phone-context=" + home + "@" + home + ";user=phone", "sip:5550100001;phone-context=" + home + "@" + home},
		{"GRUU", "sip:+15550100001@" + home + ";user=phone;gr", "sip:+15550100001@" + home + ";user=phone;gr", impu1},
		{"user=phone with a part tel cannot carry", "sip:+15550100001;%3D@" + home + ";user=phone", "sip:+15550100001;%3D@" + home + ";user=phone", "sip:+15550100001;=@" + home},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newRig(t)
			d := g.route(invite(t, tc.uri))
			if got := describe(t, d).uri; got != tc.wantURI {
				t.Errorf("Request-URI = %s, want %s", got, tc.wantURI)
			}
			if got := g.hss.lastLIR(t).PublicIdentity; got != tc.wantIMPU {
				t.Errorf("LIR Public-Identity = %s, want %s", got, tc.wantIMPU)
			}
		})
	}
}

func TestTerminatingRequestForANonIdentityIsNotFoundWithoutAnLIR(t *testing.T) {
	for _, uri := range []string{"sip:" + home, "sip:icscf.rcs.local;lr"} {
		g := newRig(t)
		if got := describe(t, g.route(request(t, "OPTIONS", uri))); got.status != 404 {
			t.Errorf("%s: decision = %+v, want 404", uri, got)
		}
		if n := g.hss.calls(); n != 0 {
			t.Errorf("%s: the HSS got %d requests, want none", uri, n)
		}
	}
}

func TestTerminatingNonInviteRequestsAreLookedUpToo(t *testing.T) {
	for _, method := range []string{"MESSAGE", "SUBSCRIBE", "OPTIONS"} {
		g := newRig(t)
		d := g.route(request(t, method, impu1))
		if got := describe(t, d); got.route != scscfURI+";lr" {
			t.Errorf("%s: decision = %+v, want a Route to the S-CSCF", method, got)
		}
		if got := g.hss.lastLIR(t); got.PublicIdentity != impu1 || got.OriginatingRequest || got.AuthorizationType != cx.AuthorizeRegistration {
			t.Errorf("%s: LIR = %+v, want a plain one for %s", method, got, impu1)
		}
	}
}

// §5.3.2.1: a Route left below this I-CSCF's own, or a request inside a
// dialog, goes where it says.
func TestRequestsWithARouteOrInADialogAreForwardedWithoutAskingTheHSS(t *testing.T) {
	cases := []struct {
		name string
		req  *sip.Request
	}{
		{"Route left", invite(t, impu1, "Route: <sip:scscf.rcs.local;lr>")},
		{"in a dialog", invite(t, impu1, "To: <"+impu1+">;tag=t1")},
		{"ACK in a dialog", request(t, "ACK", "sip:192.0.2.20", "To: <"+impu1+">;tag=t1", "CSeq: 1 ACK")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newRig(t)
			d := g.route(tc.req)
			if got := describe(t, d); got.uri != tc.req.URI.String() || got.route != "" {
				t.Errorf("decision = %+v, want the request's own Request-URI and no Route", got)
			}
			if n := g.hss.calls(); n != 0 {
				t.Errorf("the HSS got %d requests, want none", n)
			}
			if names := g.metrics.names(); !slices.Equal(names, []string{"icscf.routed.forwarded"}) {
				t.Errorf("metrics = %v", names)
			}
		})
	}
}

// §5.3.2.1: P-Profile-Key is discarded in requests and responses.
func TestPProfileKeyIsRemovedFromForwardedRequestsAndResponses(t *testing.T) {
	cases := []struct {
		name string
		req  *sip.Request
	}{
		{"terminating", invite(t, impu1, "P-Profile-Key: <sip:!.*!@"+home+">")},
		{"register", register(t, "P-Profile-Key: <sip:!.*!@"+home+">")},
		{"routed", invite(t, impu1, "P-Profile-Key: <sip:!.*!@"+home+">", "Route: <sip:scscf.rcs.local;lr>")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newRig(t)
			d := g.route(tc.req)
			if d.Prepare == nil || d.OnResponse == nil {
				t.Fatal("decision has no Prepare or OnResponse")
			}
			fwd := tc.req.Clone()
			if err := d.Prepare(context.Background(), d.Targets[0], fwd); err != nil {
				t.Fatal(err)
			}
			if fwd.Header.Has("P-Profile-Key") {
				t.Error("the forwarded request keeps P-Profile-Key")
			}
			res, err := sip.NewResponse(tc.req, 200, "", "t2")
			if err != nil {
				t.Fatal(err)
			}
			if err := res.Header.Add("P-Profile-Key", "<sip:!.*!@"+home+">"); err != nil {
				t.Fatal(err)
			}
			d.OnResponse(context.Background(), res)
			if res.Header.Has("P-Profile-Key") {
				t.Error("the response passed back keeps P-Profile-Key")
			}
		})
	}
}

// The lr the Route gets must not change the URI the configuration holds.
func TestLooseRouteLeavesTheConfiguredURIAlone(t *testing.T) {
	g := newRig(t)
	g.hss.lia = lia(base(diameter.ResultSuccess), "", nil)
	for range 2 {
		if got := describe(t, g.route(invite(t, impu1))).route; got != scscfURI+";lr" {
			t.Fatalf("Route = %s, want %s;lr", got, scscfURI)
		}
	}
	if got := g.r.scscfs[0].uri.String(); got != scscfURI {
		t.Errorf("configured URI became %s", got)
	}
}

func TestTerminatingCancelledWhileTheHSSIsAskedIsCountedAsCancelled(t *testing.T) {
	g := newRig(t)
	g.hss.block = true
	entered := make(chan struct{})
	g.hss.entered = entered
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan proxy.Decision)
	go func() {
		done <- g.r.Route(ctx, &proxy.Request{Message: invite(t, impu1), Source: transport.Source{Flow: "f1"}})
	}()
	<-entered
	cancel()
	if got := describe(t, <-done); got.status != 487 {
		t.Errorf("decision = %+v, want 487", got)
	}
	if names := g.metrics.names(); !slices.Equal(names, []string{"icscf.terminating.cancelled"}) {
		t.Errorf("metrics = %v, want only the cancellation", names)
	}
}
