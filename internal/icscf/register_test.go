package icscf

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// twoSCSCFs configures an S-CSCF without capabilities and, after it, one
// with capability 1 and optional 2.
func twoSCSCFs(c *Config) {
	c.SCSCFs = []SCSCF{
		{URI: mustURI(scscfURI)},
		{URI: mustURI("sip:scscf-b.rcs.local;transport=tcp"), Mandatory: []uint32{1}, Optional: []uint32{2}},
	}
}

// Every row of the REGISTER part of the package's mapping table, with its
// clause (TS 24.229 §5.3.1.2, §5.3.1.3; results of TS 29.229 §6.2).
func TestRegisterAnswersFollowTheMappingTable(t *testing.T) {
	forward := func(uri string) outcome { return outcome{uri: uri, timeout: true} }
	retry := outcome{status: 480, retryAfter: "10"}
	named := "sip:scscf-0.rcs.local"
	cases := []struct {
		name   string
		uaa    *cx.UAA
		err    error
		want   outcome
		metric string
	}{
		// §5.3.1.2: the Server-Name becomes the Request-URI.
		{"first registration with a name", uaa(experimental(cx.FirstRegistration), named, nil), nil, forward(named), "icscf.register.forwarded"},
		{"subsequent registration", uaa(experimental(cx.SubsequentRegistration), named, nil), nil, forward(named), "icscf.register.forwarded"},
		{"unregistered service", uaa(experimental(cx.UnregisteredService), named, nil), nil, forward(named), "icscf.register.forwarded"},
		{"base success", uaa(base(diameter.ResultSuccess), named, nil), nil, forward(named), "icscf.register.forwarded"},
		{"a name wins over capabilities", uaa(experimental(cx.FirstRegistration), named, &cx.ServerCapabilities{Mandatory: []uint32{1}}), nil, forward(named), "icscf.register.forwarded"},
		// §5.3.1.2 step 1: chosen by capability.
		{"capabilities", uaa(experimental(cx.FirstRegistration), "", &cx.ServerCapabilities{Mandatory: []uint32{1}}), nil, forward("sip:scscf-b.rcs.local;transport=tcp"), "icscf.register.forwarded"},
		{"no capabilities means any", uaa(experimental(cx.FirstRegistration), "", nil), nil, forward(scscfURI), "icscf.register.forwarded"},
		// §5.3.1.3: no S-CSCF has the mandatory capabilities.
		{"no S-CSCF qualifies", uaa(experimental(cx.FirstRegistration), "", &cx.ServerCapabilities{Mandatory: []uint32{9}}), nil, outcome{status: 600}, "icscf.register.600"},
		// §5.3.1.3: a negative answer is 403.
		{"5001 user unknown", uaa(experimental(cx.ErrorUserUnknown), "", nil), nil, outcome{status: 403}, "icscf.register.403"},
		{"5002 identities do not match", uaa(experimental(cx.ErrorIdentitiesDontMatch), "", nil), nil, outcome{status: 403}, "icscf.register.403"},
		{"5003 not registered", uaa(experimental(cx.ErrorIdentityNotRegistered), "", nil), nil, outcome{status: 403}, "icscf.register.403"},
		{"5004 roaming not allowed", uaa(experimental(cx.ErrorRoamingNotAllowed), "", nil), nil, outcome{status: 403}, "icscf.register.403"},
		{"5005 already registered", uaa(experimental(cx.ErrorIdentityAlreadyRegistered), named, nil), nil, outcome{status: 403}, "icscf.register.403"},
		{"another Cx error", uaa(experimental(cx.ErrorInAssignmentType), "", nil), nil, outcome{status: 403}, "icscf.register.403"},
		{"authorization rejected", uaa(base(diameter.ResultAuthorizationRejected), "", nil), nil, outcome{status: 403}, "icscf.register.403"},
		{"authentication rejected", uaa(base(diameter.ResultAuthenticationRejected), "", nil), nil, outcome{status: 403}, "icscf.register.403"},
		{"unable to comply", uaa(base(diameter.ResultUnableToComply), "", nil), nil, outcome{status: 403}, "icscf.register.403"},
		// §5.3.1.3: a query that could not be completed is 480, with
		// Retry-After (decision 3 on #15).
		{"too busy", uaa(base(diameter.ResultTooBusy), "", nil), nil, retry, "icscf.hss.unavailable"},
		{"out of space", uaa(base(diameter.ResultOutOfSpace), "", nil), nil, retry, "icscf.hss.unavailable"},
		{"no HSS peer", nil, cxclient.ErrNoPeer, retry, "icscf.hss.unavailable"},
		{"protocol error", nil, &cxclient.ProtocolError{Command: "UAR", Result: base(diameter.ResultUnableToDeliver)}, retry, "icscf.hss.unavailable"},
		{"time-out", nil, context.DeadlineExceeded, retry, "icscf.hss.unavailable"},
		{"malformed answer", nil, errors.New("cx: missing Result-Code"), retry, "icscf.hss.unavailable"},
		{"name that is not a URI", uaa(experimental(cx.FirstRegistration), "scscf.rcs.local", nil), nil, retry, "icscf.hss.bad_server_name"},
		{"name that is not a SIP URI", uaa(experimental(cx.FirstRegistration), tel1, nil), nil, retry, "icscf.hss.bad_server_name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newRig(t, twoSCSCFs)
			g.hss.uaa, g.hss.err = tc.uaa, tc.err
			if got := describe(t, g.route(register(t))); got != tc.want {
				t.Errorf("decision = %+v, want %+v", got, tc.want)
			}
			if names := g.metrics.names(); !slices.Contains(names, tc.metric) {
				t.Errorf("metrics %v lack %s", names, tc.metric)
			}
		})
	}
}

func uaa(r cx.Result, name string, caps *cx.ServerCapabilities) *cx.UAA {
	return &cx.UAA{Answer: cx.Answer{Result: r}, ServerName: name, ServerCapabilities: caps}
}

func TestRegisterAsksAboutTheIMPUOfToInCanonicalForm(t *testing.T) {
	g := newRig(t)
	g.route(register(t, "To: <sip:%2B15550100001@IMS.MNC001.MCC001.3GPPNETWORK.ORG;user=phone>;foo=bar"))
	if got := g.hss.lastUAR(t).PublicIdentity; got != impu1 {
		t.Errorf("Public-Identity = %q, want %q", got, impu1)
	}
}

func TestRegisterSendsTheUsernameOfItsDigestCredentials(t *testing.T) {
	g := newRig(t)
	g.route(register(t,
		`Authorization: Digest username="`+impi1+`", realm="`+home+`", nonce="", uri="sip:`+home+`", response=""`))
	if got := g.hss.lastUAR(t).UserName; got != impi1 {
		t.Errorf("User-Name = %q, want %q", got, impi1)
	}
}

// TS 24.229 §5.3.1.2: without credentials the IMPI is the IMPU without its
// scheme, URI parameters and To parameters. A port would go too, but an IMPU
// has none (TS 23.003 §13.4), so a To with one is refused before.
func TestRegisterWithoutCredentialsDerivesTheIMPIFromTheIMPU(t *testing.T) {
	cases := []struct{ to, want string }{
		{"<sip:user1@" + home + ";transport=tcp>;x=y", "user1@" + home},
		{"<sips:user1@" + home + ">", "user1@" + home},
		{"<" + tel1 + ";phone-context=" + home + ">", "+15550100001"},
	}
	for _, tc := range cases {
		g := newRig(t)
		g.route(register(t, "To: "+tc.to, "Authorization: Bearer abc"))
		if got := g.hss.lastUAR(t).UserName; got != tc.want {
			t.Errorf("To %s: User-Name = %q, want %q", tc.to, got, tc.want)
		}
	}
}

func TestRegisterWithAUsernameThatIsNotAnIMPIIsForbiddenWithoutAUAR(t *testing.T) {
	g := newRig(t)
	d := g.route(register(t, `Authorization: Digest username="no-realm", realm="`+home+`", nonce="", uri="sip:`+home+`", response=""`))
	if got := describe(t, d); got.status != 403 {
		t.Errorf("decision = %+v, want 403", got)
	}
	if n := g.hss.calls(); n != 0 {
		t.Errorf("the HSS got %d requests, want none", n)
	}
}

func TestRegisterForAnIdentityThatIsNotAnIMPUIsForbiddenWithoutAUAR(t *testing.T) {
	g := newRig(t)
	d := g.route(register(t, "To: <sip:"+home+">"))
	if got := describe(t, d); got.status != 403 {
		t.Errorf("decision = %+v, want 403", got)
	}
	if n := g.hss.calls(); n != 0 {
		t.Errorf("the HSS got %d requests, want none", n)
	}
}

func TestRegisterNamesTheVisitedNetworkTheProxyCSCFInserted(t *testing.T) {
	cases := []struct{ field, want string }{
		{"", home},
		{`P-Visited-Network-ID: "Visited Network 1", other.example`, "Visited Network 1"},
		{"P-Visited-Network-ID: visited.example;x=1", "visited.example"},
		{"P-Visited-Network-ID: ,,,", home},
	}
	for _, tc := range cases {
		g := newRig(t)
		var extra []string
		if tc.field != "" {
			extra = append(extra, tc.field)
		}
		g.route(register(t, extra...))
		if got := string(g.hss.lastUAR(t).VisitedNetworkIdentifier); got != tc.want {
			t.Errorf("%q: Visited-Network-Identifier = %q, want %q", tc.field, got, tc.want)
		}
	}
}

// TS 29.228 §6.1.1: DE_REGISTRATION when every binding expires now.
func TestRegisterAsksForDeregistrationOnlyWhenEveryBindingExpiresNow(t *testing.T) {
	reg, dereg := cx.AuthorizeRegistration, cx.AuthorizeDeregistration
	cases := []struct {
		fields []string
		want   cx.UserAuthorizationType
	}{
		{[]string{"Contact: <sip:192.0.2.10>;expires=3600"}, reg},
		{[]string{"Contact: <sip:192.0.2.10>;expires=0"}, dereg},
		{[]string{"Contact: <sip:192.0.2.10>", "Expires: 0"}, dereg},
		{[]string{"Contact: <sip:192.0.2.10>", "Expires: 600"}, reg},
		{[]string{"Contact: <sip:192.0.2.10>"}, reg},
		{[]string{"Contact: <sip:192.0.2.10>;expires=0", "Expires: 600"}, dereg},
		{[]string{"Contact: <sip:192.0.2.10>;expires=600", "Expires: 0"}, reg},
		{[]string{"Contact: <sip:192.0.2.10>;expires=0, <sip:192.0.2.11>;expires=60"}, reg},
		{[]string{"Contact: <sip:192.0.2.10>;expires=0, <sip:192.0.2.11>;expires=0"}, dereg},
		{[]string{"Contact: *", "Expires: 0"}, dereg},
		{[]string{"Contact: *"}, reg},
		{[]string{"Contact:"}, reg}, // a query of the bindings
		{[]string{"Contact: <sip:192.0.2.10>;expires=soon"}, reg},
		{[]string{"Contact: <sip:192.0.2.10>", "Expires: never"}, reg},
	}
	for _, tc := range cases {
		g := newRig(t)
		g.route(request(t, "REGISTER", "sip:"+home, tc.fields...))
		if got := g.hss.lastUAR(t).AuthorizationType; got != tc.want {
			t.Errorf("%v: User-Authorization-Type = %d, want %d", tc.fields, got, tc.want)
		}
	}
}

// §5.3.1.2: the Request-URI is replaced rather than a Route added, and the
// branch is bounded by RegisterTimeout so that a silent S-CSCF is answered
// 504 (§5.3.1.3; proxy_test.go has the 504 itself).
func TestRegisterReplacesTheRequestURIAndBoundsTheBranch(t *testing.T) {
	g := newRig(t, func(c *Config) { c.RegisterTimeout = 7 * time.Second })
	d := g.route(register(t))
	if len(d.Targets) != 1 {
		t.Fatalf("targets = %+v, want one", d.Targets)
	}
	tg := d.Targets[0]
	if tg.URI.String() != scscfURI || len(tg.Routes) != 0 || tg.Timeout != 7*time.Second {
		t.Errorf("target = %s routes %v timeout %v, want %s, no routes, 7s", tg.URI.String(), tg.Routes, tg.Timeout, scscfURI)
	}
}

func TestRegisterCancelledWhileTheHSSIsAskedIsCountedAsCancelled(t *testing.T) {
	g := newRig(t)
	g.hss.block = true
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	g.hss.entered = entered
	done := make(chan proxy.Decision)
	go func() { done <- g.r.Route(ctx, &proxy.Request{Message: register(t)}) }()
	<-entered
	cancel()
	if got := describe(t, <-done); got.status != 487 {
		t.Errorf("decision = %+v, want 487", got)
	}
	if names := g.metrics.names(); !slices.Equal(names, []string{"icscf.register.cancelled"}) {
		t.Errorf("metrics = %v, want only the cancellation", names)
	}
}

// Without a tag the 480 cannot carry Retry-After, but it is still sent.
func TestHSSFailureIsAnswered480EvenWithoutRandomnessForATag(t *testing.T) {
	g := newRig(t, func(c *Config) { c.IDs.Rand = failingReader{} })
	g.hss.err = cxclient.ErrNoPeer
	if got := describe(t, g.route(register(t))); got != (outcome{status: 480}) {
		t.Errorf("decision = %+v, want a plain 480", got)
	}
}

func TestRetryAfterIsTheConfiguredSeconds(t *testing.T) {
	g := newRig(t, func(c *Config) { c.RetryAfter = 90 * time.Second })
	g.hss.err = cxclient.ErrNoPeer
	res := g.route(register(t)).Response
	if res == nil {
		t.Fatal("no response")
	}
	if got := res.Header.Get("Retry-After"); got != "90" {
		t.Errorf("Retry-After = %q, want 90", got)
	}
	to, err := res.Header.To()
	if err != nil || to.Tag() != fmt.Sprintf("%x", []byte{0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab}) {
		t.Errorf("To = %v (%v), want the generated tag", to, err)
	}
}
