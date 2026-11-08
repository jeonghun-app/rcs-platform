package icscf

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// The chatbot domain of these tests and rcs-as as the HSS names it
// (HSS_RCS_AS_URI) and as ICSCF_AS_ROUTES reaches it.
const (
	botDomain = "botplatform.mnc001.mcc001.3gppnetwork.org"
	bot1      = "sip:examplebot@" + botDomain
	asName    = "sip:rcs-as.rcs.local;transport=tcp"
	asURI     = "sip:rcs-as.rcs.local:5060;transport=tcp"
	asRoutes  = `[{"name":"` + asName + `","uri":"` + asURI + `"}]`
)

func botDomainOf(t *testing.T) chatbot.Domain {
	t.Helper()
	d, err := chatbot.NewDomain(botDomain, home)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// withChatbots sets the chatbot domain and rcs-as as the one AS route.
func withChatbots(t *testing.T) func(*Config) {
	return func(c *Config) {
		c.ChatbotDomain = botDomainOf(t)
		c.ASRoutes = []ASRoute{{Name: mustURI(asName), URI: mustURI(asURI)}}
	}
}

// ADR 0009 §3: the LIR asks for the normal form, and the AS the answer
// names becomes the topmost Route, at the URI ICSCF_AS_ROUTES gives, with
// the Request-URI as it came.
func TestAChatbotRequestGoesToTheASTheHSSNames(t *testing.T) {
	cases := []struct{ name, uri, impu string }{
		{"normal form", bot1, bot1},
		{"with a publisher", "sip:examplebot.pub-1@" + botDomain, "sip:examplebot.pub-1@" + botDomain},
		{"tk and the host in capitals", "sip:examplebot@" + strings.ToUpper(botDomain) + ";tk=on", bot1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newRig(t, withChatbots(t))
			g.hss.lia = lia(base(diameter.ResultSuccess), asName, nil)
			req := request(t, "MESSAGE", tc.uri, "To: <"+tc.uri+">")
			want := outcome{uri: req.URI.String(), route: asURI + ";lr"}
			if got := describe(t, g.route(req)); got != want {
				t.Errorf("decision = %+v, want %+v", got, want)
			}
			if got := g.hss.lastLIR(t).PublicIdentity; got != tc.impu {
				t.Errorf("LIR Public-Identity = %s, want %s", got, tc.impu)
			}
			if names := g.metrics.names(); !slices.Equal(names, []string{"icscf.terminating.forwarded"}) {
				t.Errorf("metrics = %v", names)
			}
		})
	}
}

// ADR 0009 §2: a URI at the chatbot domain that is not in normal form is
// 404, and the HSS is not asked.
func TestAURIAtTheChatbotDomainNotInNormalFormIsNotFoundWithoutAnLIR(t *testing.T) {
	label := strings.Repeat("a", 64)
	for name, uri := range map[string]string{
		"sips": "sips:examplebot@" + botDomain,
		"port": "sip:examplebot@" + botDomain + ":5060",
		// The parser refuses it in a Request-URI, so the Router gets it
		// only as set below.
		"header":             "sip:examplebot@" + botDomain + "?Subject=hi",
		"escape":             "sip:example%62ot@" + botDomain,
		"user=phone":         "sip:examplebot@" + botDomain + ";user=phone",
		"upper-case user":    "sip:ExampleBot@" + botDomain,
		"three labels":       "sip:example.bot.pub@" + botDomain,
		"64-character label": "sip:" + label + "@" + botDomain,
		"other parameter":    bot1 + ";lr",
	} {
		t.Run(name, func(t *testing.T) {
			g := newRig(t, withChatbots(t))
			req := request(t, "MESSAGE", bot1)
			req.URI = mustURI(uri)
			if got := describe(t, g.route(req)); got != (outcome{status: 404}) {
				t.Errorf("decision = %+v, want 404", got)
			}
			if n := g.hss.calls(); n != 0 {
				t.Errorf("the HSS got %d requests, want none", n)
			}
			if got := g.metrics.counts["icscf.terminating.404"]; got != 1 {
				t.Errorf("icscf.terminating.404 counted %d, want 1", got)
			}
		})
	}
}

// Memo H6: only an AS on ICSCF_AS_ROUTES is routed to. Any other name, an
// S-CSCF's included, or none is 500 with Retry-After, as an S-CSCF name
// nothing configured matches; the other answers map as for any user.
func TestAChatbotAnswerMapsAsForAnyUserButOnlyAListedASIsRoutedTo(t *testing.T) {
	unknown := outcome{status: 500, retryAfter: "10"}
	cases := []struct {
		name   string
		lia    *cx.LIA
		want   outcome
		metric string
	}{
		{"an S-CSCF's name", lia(base(diameter.ResultSuccess), scscfURI, nil), unknown, "icscf.as.unknown_name"},
		{"another AS", lia(base(diameter.ResultSuccess), "sip:other-as.rcs.local;transport=tcp", nil), unknown, "icscf.as.unknown_name"},
		{"the AS without its transport", lia(base(diameter.ResultSuccess), "sip:rcs-as.rcs.local", nil), unknown, "icscf.as.unknown_name"},
		{"the AS with a user part", lia(base(diameter.ResultSuccess), "sip:x@rcs-as.rcs.local;transport=tcp", nil), unknown, "icscf.as.unknown_name"},
		{"not a URI", lia(base(diameter.ResultSuccess), "rcs-as", nil), unknown, "icscf.as.unknown_name"},
		{"no name", lia(base(diameter.ResultSuccess), "", nil), unknown, "icscf.as.unknown_name"},
		// A directly routed PSI has no S-CSCF to choose by capability.
		{"the AS only inside the capabilities", lia(base(diameter.ResultSuccess), "", &cx.ServerCapabilities{ServerNames: []string{asName}}), unknown, "icscf.as.unknown_name"},
		{"5001 user unknown", lia(experimental(cx.ErrorUserUnknown), "", nil), outcome{status: 404}, "icscf.terminating.404"},
		{"5003 not registered", lia(experimental(cx.ErrorIdentityNotRegistered), "", nil), outcome{status: 480}, "icscf.terminating.480"},
		{"too busy", lia(base(diameter.ResultTooBusy), "", nil), outcome{status: 480, retryAfter: "10"}, "icscf.hss.unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newRig(t, withChatbots(t))
			g.hss.lia = tc.lia
			if got := describe(t, g.route(invite(t, bot1))); got != tc.want {
				t.Errorf("decision = %+v, want %+v", got, tc.want)
			}
			if names := g.metrics.names(); !slices.Contains(names, tc.metric) || slices.Contains(names, "icscf.terminating.forwarded") {
				t.Errorf("metrics %v, want %s and nothing forwarded", names, tc.metric)
			}
		})
	}
	t.Run("no AS route", func(t *testing.T) {
		g := newRig(t, withChatbots(t), func(c *Config) { c.ASRoutes = nil })
		g.hss.lia = lia(base(diameter.ResultSuccess), asName, nil)
		if got := describe(t, g.route(invite(t, bot1))); got != unknown {
			t.Errorf("decision = %+v, want %+v", got, unknown)
		}
	})
}

// With RCS_CHATBOT_DOMAIN unset, a URI at that host is any other user's,
// as before chatbots, even when AS routes are listed.
func TestWithoutAChatbotDomainNothingChanges(t *testing.T) {
	for _, uri := range []string{bot1, "sip:ExampleBot@" + botDomain} {
		g := newRig(t, withChatbots(t), func(c *Config) { c.ChatbotDomain = chatbot.Domain{} })
		g.hss.lia = lia(base(diameter.ResultSuccess), asName, nil)
		if got := describe(t, g.route(invite(t, uri))); got != (outcome{status: 500, retryAfter: "10"}) {
			t.Errorf("%s: decision = %+v, want the 500 of an S-CSCF name not configured", uri, got)
		}
		if got := g.hss.lastLIR(t).PublicIdentity; got != uri {
			t.Errorf("%s: LIR Public-Identity = %s", uri, got)
		}
		if g.metrics.counts["icscf.scscf.unknown_name"] != 1 {
			t.Errorf("%s: metrics = %v", uri, g.metrics.names())
		}
	}
}

// The AS's addresses are tried in turn as an S-CSCF's are, counted under
// icscf.as.
func TestEachAddressOfTheASIsTriedInTurn(t *testing.T) {
	a := transport.Destination{Network: transport.TCP, Addr: netip.MustParseAddrPort("10.0.5.1:5060")}
	b := transport.Destination{Network: transport.TCP, Addr: netip.MustParseAddrPort("10.0.5.2:5060")}
	g := newRig(t, withChatbots(t), func(c *Config) { c.Resolver = stubResolver{dsts: []transport.Destination{a, b}} })
	g.hss.lia = lia(base(diameter.ResultSuccess), asName, nil)
	m := invite(t, bot1)
	d := g.route(m)
	refused, _ := sip.NewResponse(m, 503, "", "t1")
	sendFailed := proxy.BranchFailure{Target: d.Targets[0], Response: refused, Err: errors.New("connection refused")}
	next := d.OnBranchFailure(context.Background(), sendFailed)
	if *d.Targets[0].Destination != a || len(next) != 1 || *next[0].Destination != b || next[0].Routes[0].URI.String() != asURI+";lr" {
		t.Fatalf("targets %+v, then %+v; want the AS's two addresses in turn", d.Targets, next)
	}
	if more := d.OnBranchFailure(context.Background(), sendFailed); more != nil {
		t.Fatalf("after the last refused: %+v, want none", more)
	}
	res, _ := sip.NewResponse(m, 500, "", "t1")
	d.OnResponse(context.Background(), res)
	if res.Header.Get("Retry-After") != "10" || g.metrics.counts["icscf.as.next_address"] != 1 || g.metrics.counts["icscf.as.unreachable"] != 1 {
		t.Errorf("Retry-After %q, metrics %v", res.Header.Get("Retry-After"), g.metrics.counts)
	}

	g = newRig(t, withChatbots(t), func(c *Config) { c.Resolver = stubResolver{err: errors.New("no such host")} })
	g.hss.lia = lia(base(diameter.ResultSuccess), asName, nil)
	if got := describe(t, g.route(invite(t, bot1))); got != (outcome{status: 500, retryAfter: "10"}) || g.metrics.counts["icscf.as.unreachable"] != 1 {
		t.Errorf("no address: decision = %+v, metrics %v", got, g.metrics.counts)
	}
}

func TestParseASRoutesRefusesOnlyWhatCannotBeUsed(t *testing.T) {
	entry := `{"name":"sip:as.rcs.local","uri":"sip:as.rcs.local:5060"}`
	var many []string
	for i := range MaxASRoutes + 1 {
		many = append(many, `{"name":"sip:as-`+string(rune('a'+i%26))+strings.Repeat("x", i/26)+`.rcs.local","uri":"sip:as.rcs.local"}`)
	}
	cases := map[string]string{
		"null":              `null`,
		"not JSON":          asName,
		"not an array":      entry,
		"trailing data":     `[` + entry + `] []`,
		"no name":           `[{"uri":"sip:as.rcs.local"}]`,
		"no uri":            `[{"name":"sip:as.rcs.local"}]`,
		"unknown field":     `[{"name":"sip:as.rcs.local","uri":"sip:as.rcs.local","weight":1}]`,
		"bad name":          `[{"name":"sip:","uri":"sip:as.rcs.local"}]`,
		"bad uri":           `[{"name":"sip:as.rcs.local","uri":"sip:"}]`,
		"tel name":          `[{"name":"tel:+15550100001","uri":"sip:as.rcs.local"}]`,
		"uri with a user":   `[{"name":"sip:as.rcs.local","uri":"sip:bot@as.rcs.local"}]`,
		"name with headers": `[{"name":"sip:as.rcs.local?x=y","uri":"sip:as.rcs.local"}]`,
		"uri with a maddr":  `[{"name":"sip:as.rcs.local","uri":"sip:as.rcs.local;maddr=192.0.2.1"}]`,
		"repeated name":     `[` + entry + `,{"name":"sip:AS.rcs.local","uri":"sip:other.rcs.local"}]`,
		"too many":          "[" + strings.Join(many, ",") + "]",
	}
	for name, in := range cases {
		if got, err := ParseASRoutes([]byte(in)); err == nil {
			t.Errorf("%s: parsed %+v, want an error", name, got)
		}
	}
	for _, in := range []string{"", " ", "[]", "[" + strings.Join(many[:MaxASRoutes], ",") + "]"} {
		if _, err := ParseASRoutes([]byte(in)); err != nil {
			t.Errorf("%.20q refused: %v", in, err)
		}
	}
}

func TestNewRefusesAnASRouteParseASRoutesWouldNot(t *testing.T) {
	for name, routes := range map[string][]ASRoute{
		"no name":      {{URI: mustURI(asURI)}},
		"a tel uri":    {{Name: mustURI(asName), URI: mustURI(tel1)}},
		"repeated":     {{Name: mustURI(asName), URI: mustURI(asURI)}, {Name: mustURI(asName), URI: mustURI(scscfURI)}},
		"too many":     slices.Repeat([]ASRoute{{Name: mustURI(asName), URI: mustURI(asURI)}}, MaxASRoutes+1),
		"with a maddr": {{Name: mustURI(asName), URI: mustURI(asURI + ";maddr=192.0.2.1")}},
	} {
		cfg := Config{HSS: &stubHSS{}, SCSCFs: []SCSCF{{URI: mustURI(scscfURI)}}, HomeDomain: home, ASRoutes: routes}
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New accepted %+v", name, routes)
		}
	}
}

func TestConfigureReadsTheChatbotDomainAndTheASRoutes(t *testing.T) {
	c, err := configure(with(devEnv, "RCS_CHATBOT_DOMAIN", botDomain, "ICSCF_AS_ROUTES", asRoutes))
	if err != nil {
		t.Fatal(err)
	}
	if c.ChatbotDomain.Name() != botDomain || len(c.ASRoutes) != 1 || c.ASRoutes[0].URI.String() != asURI {
		t.Errorf("chatbot domain %q, AS routes %+v", c.ChatbotDomain.Name(), c.ASRoutes)
	}
	if c, err := configure(devEnv); err != nil || c.ChatbotDomain.Name() != "" || c.ASRoutes != nil {
		t.Errorf("defaults: domain %q, routes %+v, %v; want neither", c.ChatbotDomain.Name(), c.ASRoutes, err)
	}
	for name, env := range map[string]map[string]string{
		"the IMS domain":               with(devEnv, "RCS_CHATBOT_DOMAIN", strings.ToUpper(home)),
		"a chatbot domain in capitals": with(devEnv, "RCS_CHATBOT_DOMAIN", strings.ToUpper(botDomain)),
		"bad AS routes":                with(devEnv, "ICSCF_AS_ROUTES", `[{"name":"sip:as.rcs.local"}]`),
	} {
		if _, err := configure(env); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// In staging and prod a chatbot domain needs an AS route (memo H6); dev
// takes it without, and answers such requests 500.
func TestProductionRefusesAChatbotDomainWithoutAnASRoute(t *testing.T) {
	const want = "RCS_CHATBOT_DOMAIN is set and ICSCF_AS_ROUTES is empty"
	if status, out := startup(t, with(prodEnv, "RCS_CHATBOT_DOMAIN", botDomain)); status != runtime.ExitFailure || !strings.Contains(out, want) {
		t.Fatalf("status %d, want %q refused:\n%s", status, want, out)
	}
	if _, out := startup(t, with(prodEnv, "RCS_CHATBOT_DOMAIN", botDomain, "ICSCF_AS_ROUTES", asRoutes)); strings.Contains(out, "ICSCF_") || strings.Contains(out, "CHATBOT") {
		t.Errorf("a chatbot domain with a route was refused:\n%s", out)
	}
	if _, out := startup(t, with(prodEnv, "ICSCF_AS_ROUTES", asRoutes)); strings.Contains(out, "ICSCF_") || strings.Contains(out, "CHATBOT") {
		t.Errorf("routes without a chatbot domain were refused:\n%s", out)
	}
	if _, err := configure(with(devEnv, "RCS_CHATBOT_DOMAIN", botDomain)); err != nil {
		t.Errorf("dev refused a chatbot domain without a route: %v", err)
	}
}

// Through Run: RCS_CHATBOT_DOMAIN and ICSCF_AS_ROUTES reach the Router, and
// the AS gets the request on its listed URI without P-Served-User, by whose
// absence rcs-as tells the PSI leg (ADR 0009 §3), or P-Profile-Key.
func TestAChatbotRequestReachesTheListedASThroughRun(t *testing.T) {
	hss := startHSS(t)
	as := startSCSCF(t)
	hss.answer = func(uint32) (cx.Result, string) { return cx.ResultCode(diameter.ResultSuccess), asName }
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI("sip:scscf.rcs.local;transport=tcp")}}, func(c *ServiceConfig, _ *deps) {
		c.ChatbotDomain = botDomainOf(t)
		c.ASRoutes = []ASRoute{{Name: mustURI(asName), URI: mustURI(as.uri())}}
	})
	r.waitReady(t)
	res := r.send(t, "MESSAGE", bot1+";tk=off", "From: <"+impu1+">;tag=f1", "To: <"+bot1+">",
		"P-Served-User: <"+impu1+">;sescase=orig", "P-Profile-Key: <sip:!.*!@"+botDomain+">")
	if res.StatusCode != 200 {
		t.Fatalf("MESSAGE answered %d", res.StatusCode)
	}
	got := as.next(t)
	routes, err := got.Header.Route()
	if err != nil || len(routes) != 1 || !strings.HasPrefix(routes[0].URI.String(), as.uri()) || got.URI.String() != bot1+";tk=off" {
		t.Fatalf("the AS got %s with Route %v (%v)", got.URI.String(), routes, err)
	}
	if got.Header.Has("P-Served-User") || got.Header.Has("P-Profile-Key") {
		t.Errorf("the AS got P-Served-User %q, P-Profile-Key %q", got.Header.Get("P-Served-User"), got.Header.Get("P-Profile-Key"))
	}
}

// ParseASRoutes either refuses its input or returns a list New accepts.
func FuzzParseASRoutes(f *testing.F) {
	for _, s := range []string{asRoutes, `[]`, ``, `null`, `[{"name":"sip:a.rcs.local","uri":"sip:a.rcs.local;maddr=x"}]`, asRoutes + ` x`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		list, err := ParseASRoutes(data)
		if err != nil {
			return
		}
		if _, err := New(Config{HSS: &stubHSS{}, SCSCFs: []SCSCF{{URI: mustURI(scscfURI)}}, HomeDomain: home, ASRoutes: list}); err != nil {
			t.Fatalf("ParseASRoutes returned a list New refuses: %v", err)
		}
	})
}

// Whatever the Request-URI, a request reaches the AS only when its parsed
// URI is a sip: URI at the chatbot domain whose user part matches the ERE
// hss stores (an oracle apart from the normaliser), and the LIR then asks
// for that user part at the domain; any other URI at the domain is 404
// with no LIR.
func FuzzChatbotRequestURI(f *testing.F) {
	for _, s := range []string{bot1, bot1 + ";tk=on", "sip:Bot@" + botDomain, "sips:bot@" + botDomain, "sip:bot@" + botDomain + ":5060", impu1, tel1} {
		f.Add(s)
	}
	user := regexp.MustCompile(`^(` + chatbot.UserPartERE + `)$`)
	f.Fuzz(func(t *testing.T, s string) {
		u, err := sip.ParseURI(s)
		if err != nil || !strings.EqualFold(strings.TrimSuffix(u.Host, "."), botDomain) {
			return
		}
		g := newRig(t, withChatbots(t))
		g.hss.lia = lia(base(diameter.ResultSuccess), asName, nil)
		req := request(t, "MESSAGE", bot1)
		req.URI = u
		got := describe(t, g.route(req))
		if got.route != asURI+";lr" {
			if got.status != 404 || g.hss.calls() != 0 {
				t.Fatalf("%s: decision %+v after %d HSS calls, want the AS or a 404 with no LIR", s, got, g.hss.calls())
			}
			return
		}
		if u.Scheme != "sip" || u.Port != 0 || !user.MatchString(u.User) || got.uri != u.String() {
			t.Fatalf("%s reached the AS as %s", s, got.uri)
		}
		if id := g.hss.lastLIR(t).PublicIdentity; id != "sip:"+u.User+"@"+botDomain {
			t.Fatalf("%s: LIR for %s", s, id)
		}
	})
}
