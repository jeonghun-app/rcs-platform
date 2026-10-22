package routing

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/secret"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// Hops of the tests' dialogs: rcs-as's task, a P-CSCF's core listener with
// a flow, and core addresses no dialog goes through.
var (
	asTask  = "sip:10.0.131.7:5060;transport=tcp"
	pcscfUE = "sip:" + flow(1) + "@198.51.100.5:5070;transport=tcp;lr"
	icscf   = "sip:" + flow(1) + "@10.0.130.25:5060;transport=tcp;lr"
	hss     = "sip:" + flow(1) + "@10.0.130.26:3868;transport=tcp;lr"
)

// inDialog is a request inside dialog-1 for target, with route as its Route
// after the S-CSCF's own entries ("" for none), which it consumed as routed.
func inDialog(t *testing.T, target, route string, routed ...sip.Address) *proxy.Request {
	t.Helper()
	fields := []string{
		"BYE " + target + " SIP/2.0",
		"Via: SIP/2.0/TCP pcscf.rcs.local;branch=z9hG4bK-bye",
		"Max-Forwards: 69",
		"From: <" + impu1 + ">;tag=a",
		"To: <sip:+15550100003@" + realm + ">;tag=b",
		"Call-ID: dialog-1",
		"CSeq: 2 BYE",
	}
	if route != "" {
		fields = append(fields, "Route: "+route)
	}
	return &proxy.Request{Message: parse(t, strings.Join(fields, "\r\n")+"\r\nContent-Length: 0\r\n\r\n"), Routed: routed}
}

// signedFor is the S-CSCF's Record-Route value rt signs dialog-1's hops
// with.
func signedFor(rt *Router, hops ...string) sip.Address {
	keys := make([]string, len(hops))
	for i, h := range hops {
		keys[i] = hopKey(mustURI(h))
	}
	return rt.signedRR("dialog-1", keys...)
}

// TestARequestInsideADialogGoesOnlyToAHopItsRouteSigned (#322): the next
// hop, the Route after the S-CSCF's or the Request-URI, must be one its
// Record-Route value signed for the dialog, at a P-CSCF's core port or an
// application server's, and never the S-CSCF; anything else is 403.
func TestARequestInsideADialogGoesOnlyToAHopItsRouteSigned(t *testing.T) {
	e := newEnv(t)
	rt := e.router(nil, func(c *Config) { c.Self = append(c.Self, mustURI("sip:10.0.131.9")) })
	old := e.router(nil, func(c *Config) {
		c.DialogKeys = []DialogKey{{ID: "k1", Key: secret.NewKey(bytes.Repeat([]byte{1}, MinDialogKeyBytes))}}
	})
	rotated := e.router(nil, func(c *Config) {
		c.DialogKeys = []DialogKey{{ID: "k3", Key: secret.NewKey(bytes.Repeat([]byte{3}, MinDialogKeyBytes))}, {ID: "k1", Key: secret.NewKey(bytes.Repeat([]byte{1}, MinDialogKeyBytes))}}
	})
	other := e.router(nil, func(c *Config) {
		c.DialogKeys = []DialogKey{{ID: "k2", Key: secret.NewKey(bytes.Repeat([]byte{9}, MinDialogKeyBytes))}}
	})
	ue := "sip:ue@192.0.2.40:5060;transport=tcp"
	for name, c := range map[string]struct {
		rt            *Router
		target, route string
		routed        []sip.Address
		allowed       bool
	}{
		"rcs-as's task, its Contact":        {rt, asTask, "", []sip.Address{signedFor(rt, asTask, pcscfUE)}, true},
		"a P-CSCF's flow":                   {rt, ue, "<" + pcscfUE + ">", []sip.Address{signedFor(rt, asTask, pcscfUE)}, true},
		"a hop signed with the old key":     {rotated, ue, "<" + pcscfUE + ">", []sip.Address{signedFor(old, pcscfUE)}, true},
		"the hop the dialog did not go to":  {rt, ue, "<" + icscf + ">", []sip.Address{signedFor(rt, asTask, pcscfUE)}, false},
		"another flow of the P-CSCF":        {rt, ue, "<sip:" + flow(2) + "@198.51.100.5:5070;transport=tcp;lr>", []sip.Address{signedFor(rt, pcscfUE)}, false},
		"another port of the hop":           {rt, ue, "<sip:" + flow(1) + "@198.51.100.5:5071;transport=tcp;lr>", []sip.Address{signedFor(rt, pcscfUE)}, false},
		"another transport of the hop":      {rt, ue, "<sip:" + flow(1) + "@198.51.100.5:5070;transport=udp;lr>", []sip.Address{signedFor(rt, pcscfUE)}, false},
		"a signed hop at no role's port":    {rt, ue, "<" + hss + ">", []sip.Address{signedFor(rt, hss)}, false},
		"the S-CSCF itself, signed":         {rt, "sip:10.0.131.9:5060;transport=tcp", "", []sip.Address{signedFor(rt, "sip:10.0.131.9:5060;transport=tcp")}, false},
		"no signature":                      {rt, asTask, "", []sip.Address{{URI: mustURI("sip:scscf.rcs.local;transport=tcp;lr")}}, false},
		"nothing routed":                    {rt, asTask, "", nil, false},
		"another key":                       {rt, asTask, "", []sip.Address{signedFor(other, asTask)}, false},
		"a key no longer kept":              {rt, asTask, "", []sip.Address{signedFor(old, asTask)}, false},
		"the hop the last entry signs":      {rt, asTask, "", []sip.Address{signedFor(rt, pcscfUE), signedFor(rt, asTask)}, true},
		"not the hop the last entry signs":  {rt, asTask, "", []sip.Address{signedFor(rt, asTask), signedFor(rt, pcscfUE)}, false},
		"a garbled signature":               {rt, asTask, "", []sip.Address{garbled(signedFor(rt, asTask))}, false},
		"a key's MAC under another's ID":    {rotated, asTask, "", []sip.Address{relabelled(signedFor(old, asTask), "k3")}, false},
		"a signed hop at 5070 over UDP":     {rt, ue, "<sip:10.0.140.1:5070;transport=udp;lr>", []sip.Address{signedFor(rt, "sip:10.0.140.1:5070;transport=udp")}, false},
		"a signed hop at 5060 over UDP":     {rt, "sip:10.0.140.1:5060;transport=udp", "", []sip.Address{signedFor(rt, "sip:10.0.140.1:5060;transport=udp")}, false},
		"a signature without a key ID part": {rt, asTask, "", []sip.Address{{URI: mustURI("sip:scscf.rcs.local;transport=tcp;lr;dlg=k2")}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			d := c.rt.InDialog(bg, inDialog(t, c.target, c.route, c.routed...))
			if got := d.Status == 0; got != c.allowed {
				t.Errorf("forwarded %v (status %d), want %v", got, d.Status, c.allowed)
			}
			if c.allowed && len(d.Targets) != 1 {
				t.Errorf("%d targets", len(d.Targets))
			}
			if !c.allowed && d.Status != 403 {
				t.Errorf("status %d, want 403", d.Status)
			}
		})
	}
	// Another Call-ID: the signature is the dialog's.
	r := inDialog(t, asTask, "", signedFor(rt, asTask))
	_ = r.Message.Header.Set("Call-ID", "dialog-2")
	if d := rt.InDialog(bg, r); d.Status != 403 {
		t.Errorf("another dialog's request is %d", d.Status)
	}
}

// TestAGroupsDialogReachesRcsAsAtTheConferenceContact (code review on #542):
// in a session with a group, and in a subscription to its roster, rcs-as's
// Contact, in every message of the dialog, is the conference URI
// (internal/rcsas/sipas focusContact), which the S-CSCF signed as the
// dialog's hop at the 2xx. With transport=tcp it is an application
// server's listener, so a BYE in the session, and a SUBSCRIBE refreshing
// or ending the roster subscription, go on. Without a transport it reads as UDP on 5060,
// where no application server listens, and both are refused 403.
func TestAGroupsDialogReachesRcsAsAtTheConferenceContact(t *testing.T) {
	e := newEnv(t)
	rt := e.router(nil)
	for name, c := range map[string]struct {
		contact string
		allowed bool
	}{
		"over TCP, as rcs-as writes it": {"sip:chat-00112233445566778899aabbccddeeff@conf.rcs.local;transport=tcp", true},
		"without a transport":           {"sip:chat-00112233445566778899aabbccddeeff@conf.rcs.local", false},
	} {
		t.Run(name, func(t *testing.T) {
			// A BYE in the session; a SUBSCRIBE refreshing the roster,
			// and one ending it (Expires: 0), at the Contact every
			// message of the dialog carries.
			for _, method := range []string{"BYE", "SUBSCRIBE", "unsubscribe"} {
				r := inDialog(t, c.contact, "", signedFor(rt, c.contact, pcscfUE))
				if method != "BYE" {
					expires := "600"
					if method == "unsubscribe" {
						expires = "0"
					}
					r.Message.Method = "SUBSCRIBE"
					_ = r.Message.Header.Set("CSeq", "2 SUBSCRIBE")
					_ = r.Message.Header.Set("Event", "conference")
					_ = r.Message.Header.Set("Expires", expires)
				}
				d := rt.InDialog(bg, r)
				if got := d.Status == 0 && len(d.Targets) == 1; got != c.allowed {
					t.Errorf("%s forwarded %v (status %d), want %v", method, got, d.Status, c.allowed)
				}
				if !c.allowed && d.Status != 403 {
					t.Errorf("%s status %d, want 403", method, d.Status)
				}
			}
		})
	}
}

// relabelled is a with its signature's key ID changed to id.
func relabelled(a sip.Address, id string) sip.Address {
	v, _ := a.URI.Param(dlgParam)
	_, macs, _ := strings.Cut(v, ".")
	a.URI.Params = append(sip.Params(nil), a.URI.Params...)
	a.URI.Params.Set(dlgParam, id+"."+macs)
	return a
}

// garbled is a with the last character of its signature changed.
func garbled(a sip.Address) sip.Address {
	v, _ := a.URI.Param(dlgParam)
	last := "A"
	if strings.HasSuffix(v, "A") {
		last = "B"
	}
	a.URI.Params = append(sip.Params(nil), a.URI.Params...)
	a.URI.Params.Set(dlgParam, v[:len(v)-1]+last)
	return a
}

func TestAnUnreadableRouteInsideADialogIs400(t *testing.T) {
	e := newEnv(t)
	d := e.router(nil).InDialog(bg, inDialog(t, "sip:ue@192.0.2.40", "<sip:rcs-as.rcs.local;lr"))
	if d.Status != 400 {
		t.Errorf("status %d", d.Status)
	}
}

// TestThePCSCFsPublicAddressEndsTheRouteSet (#14): rcsjta puts the Route of
// a dialog's first INVITE, the P-CSCF's public address, after the route
// set in its session refreshes; the request goes by its Request-URI, which
// must still be a hop the dialog was signed for.
func TestThePCSCFsPublicAddressEndsTheRouteSet(t *testing.T) {
	e := newEnv(t)
	rt := e.router(nil)
	signed := signedFor(rt, asTask, pcscfUE)
	for name, c := range map[string]struct {
		target, route string
		allowed       bool
	}{
		"to rcs-as's task":   {asTask, "<sip:pcscf.example.net:5061;transport=tls;lr>", true},
		"by its address":     {asTask, "<sip:203.0.113.5:5061;transport=tls;lr>", true},
		"with more after it": {asTask, "<sip:pcscf.example.net;lr>, <sip:10.0.3.7:8080;lr>", true},
		"to the I-CSCF":      {"sip:10.0.130.25:5060;transport=tcp", "<sip:pcscf.example.net;lr>", false},
	} {
		t.Run(name, func(t *testing.T) {
			r := inDialog(t, c.target, c.route, signed)
			d := rt.InDialog(bg, r)
			if got := d.Status == 0; got != c.allowed {
				t.Fatalf("forwarded %v (status %d), want %v", got, d.Status, c.allowed)
			}
			if !c.allowed {
				return
			}
			b := r.Message.Clone()
			if err := d.Prepare(bg, d.Targets[0], b); err != nil {
				t.Fatal(err)
			}
			if b.Header.Has("Route") || d.Targets[0].URI.String() != r.Message.URI.String() {
				t.Errorf("Route %q, Request-URI %s", b.Header.Get("Route"), d.Targets[0].URI.String())
			}
		})
	}
	if e.metrics.get("routing.in_dialog.trailing_route") != 3 {
		t.Errorf("counted %d", e.metrics.get("routing.in_dialog.trailing_route"))
	}
	// Without the P-CSCF's public address next, the Route is kept.
	r := inDialog(t, "sip:ue@192.0.2.40:5060", "<"+pcscfUE+">, <sip:pcscf.example.net;lr>", signed)
	if d := rt.InDialog(bg, r); d.Status != 0 || d.Prepare != nil {
		t.Errorf("status %d, Prepare set %v", d.Status, d.Prepare != nil)
	}
}

// TestNewRefusesARecordRouteOverAnotherTransport (#208): pcscf refuses
// the dialog's requests along it.
func TestNewRefusesARecordRouteOverAnotherTransport(t *testing.T) {
	for _, v := range []string{"<sip:scscf.rcs.local;lr>", "<sip:scscf.rcs.local;transport=udp;lr>"} {
		e := newEnv(t)
		rr, _ := sip.ParseAddress(v)
		if _, err := New(validConfig(e, func(c *Config) { c.RecordRoute = rr })); err == nil {
			t.Errorf("%s accepted", v)
		}
	}
	e := newEnv(t)
	rr, _ := sip.ParseAddress("<sip:scscf.rcs.local;transport=TCP;lr>")
	if _, err := New(validConfig(e, func(c *Config) { c.RecordRoute = rr })); err != nil {
		t.Error(err)
	}
}

// validConfig is a config New takes, changed by tweak.
func validConfig(e *env, tweak func(*Config)) Config {
	rr, _ := sip.ParseAddress("<sip:scscf.rcs.local;transport=tcp;lr>")
	c := Config{Store: e.store, RecordRoute: rr, Self: []sip.URI{mustURI("sip:scscf.rcs.local")}, DialogKeys: []DialogKey{{ID: "k2", Key: secret.NewKey(dialogKey)}},
		Registrar: e.hss, ICSCF: mustURI("sip:icscf.rcs.local;lr"), HomeDomain: realm}
	tweak(&c)
	return c
}

// TestNewRefusesWhatWouldLetAnyHopThrough (#322): an entry without a host
// would be taken for a URI without one, and a dialog key must be one.
func TestNewRefusesWhatWouldLetAnyHopThrough(t *testing.T) {
	key := DialogKey{ID: "k2", Key: secret.NewKey(dialogKey)}
	for name, tweak := range map[string]func(*Config){
		"no dialog key": func(c *Config) { c.DialogKeys = nil },
		"a short key": func(c *Config) {
			c.DialogKeys = []DialogKey{{ID: "k2", Key: secret.NewKey(dialogKey[:MinDialogKeyBytes-1])}}
		},
		"a key without an ID":      func(c *Config) { c.DialogKeys = []DialogKey{{Key: secret.NewKey(dialogKey)}} },
		"a key ID with a dot":      func(c *Config) { c.DialogKeys = []DialogKey{{ID: "k.2", Key: secret.NewKey(dialogKey)}} },
		"a long key ID":            func(c *Config) { c.DialogKeys = []DialogKey{{ID: "k23456789", Key: secret.NewKey(dialogKey)}} },
		"two keys of one ID":       func(c *Config) { c.DialogKeys = []DialogKey{key, key} },
		"a server without a port":  func(c *Config) { c.ApplicationServers = []sip.URI{mustURI("sip:rcs-as.rcs.local;transport=tcp")} },
		"a server without a host":  func(c *Config) { c.ApplicationServers = []sip.URI{{Scheme: "sip", Port: 5060}} },
		"a server that is not SIP": func(c *Config) { c.ApplicationServers = []sip.URI{mustURI("tel:+15550100005")} },
		"an empty public host":     func(c *Config) { c.EdgeProxyPublicHosts = []string{"pcscf.example.net", ""} },
		"a Self without a host":    func(c *Config) { c.Self = append(c.Self, sip.URI{Scheme: "sip"}) },
	} {
		e := newEnv(t)
		if _, err := New(validConfig(e, tweak)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestTheRouterKeepsItsOwnCopyOfTheKeys: a caller that clears its keys
// leaves the router signing as before.
func TestTheRouterKeepsItsOwnCopyOfTheKeys(t *testing.T) {
	e := newEnv(t)
	b := bytes.Clone(dialogKey)
	keys := []DialogKey{{ID: "k2", Key: secret.NewKey(b)}}
	rt := e.router(nil, func(c *Config) { c.DialogKeys = keys })
	clear(b)
	keys[0].ID = "x"
	if d := e.router(nil).InDialog(bg, inDialog(t, asTask, "", signedFor(rt, asTask))); d.Status != 0 {
		t.Errorf("status %d", d.Status)
	}
}
