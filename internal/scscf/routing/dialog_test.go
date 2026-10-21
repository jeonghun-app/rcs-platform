package routing

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// Hops of a dialog set up through the S-CSCF: the caller's P-CSCF entry,
// below the S-CSCF's in the request, and the callee's P-CSCF entry, above
// it in the response.
var (
	// As pcscf writes its core-facing value: the flow, outbound, the icid
	// and its own dialog MAC, also named dlg, which the S-CSCF's hops leave
	// out.
	callerPCSCF = "<sip:" + flow(7) + "@198.51.100.7:5070;transport=tcp;lr;ob;icid=call7;dlg=pcscfmac7>"
	calleePCSCF = "<sip:" + flow(1) + "@198.51.100.5:5070;transport=tcp;lr;ob;icid=call1;dlg=pcscfmac1>"
)

// setUp runs an INVITE for impu1 through Terminating with extra header
// fields: it returns the decision and the branch to the first target, as
// the proxy prepares it.
func setUp(t *testing.T, e *env, rt *Router, extra ...string) (proxy.Decision, *sip.Request) {
	t.Helper()
	r := request(t, "INVITE", impu1, extra...)
	if err := r.Message.Header.Set("Call-ID", "dialog-1"); err != nil {
		t.Fatal(err)
	}
	d := rt.Terminating(bg, r)
	if len(d.Targets) == 0 {
		t.Fatalf("status %d", d.Status)
	}
	b := r.Message.Clone()
	b.URI = d.Targets[0].URI
	for i := len(d.RecordRoute) - 1; i >= 0; i-- {
		if err := b.Header.Prepend("Record-Route", d.RecordRoute[i].String()); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Prepare(bg, d.Targets[0], b); err != nil {
		t.Fatal(err)
	}
	return d, b
}

// ourEntry is the S-CSCF's Record-Route value in h: its host, with dlg,
// which pcscf's values carry too.
func ourEntry(t *testing.T, h *sip.Header) sip.Address {
	t.Helper()
	rr, err := h.RecordRoute()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range rr {
		if _, ok := a.URI.Param(dlgParam); ok && a.URI.Host == "scscf.rcs.local" {
			return a
		}
	}
	t.Fatalf("no signed Record-Route in %v", rr)
	return sip.Address{}
}

// TestADialogsHopsAreSignedAsItIsSetUp (#322): the branch's Record-Route
// value signs the hop toward the caller, which the callee's requests go to;
// the response's signs that one and the hop toward the callee, which the
// caller's requests go to; neither signs anything else.
func TestADialogsHopsAreSignedAsItIsSetUp(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 1, time.Hour))
	rt := e.router(nil)
	d, branch := setUp(t, e, rt, "Record-Route: "+callerPCSCF, "Contact: <sip:ue7@192.0.2.17:5060>")
	inRequest := ourEntry(t, &branch.Header)
	if inRequest.URI.Host != "scscf.rcs.local" || !inRequest.URI.Params.Has("lr") {
		t.Errorf("Record-Route %s", inRequest.String())
	}
	callerHop := strings.Trim(callerPCSCF, "<>")
	if d := rt.InDialog(bg, inDialog(t, "sip:ue7@192.0.2.17:5060", "<"+callerHop+">", inRequest)); d.Status != 0 {
		t.Errorf("the callee's request toward the caller is %d", d.Status)
	}
	calleeHop := strings.Trim(calleePCSCF, "<>")
	if d := rt.InDialog(bg, inDialog(t, binding(1, 1, 0).URI, "<"+calleeHop+">", inRequest)); d.Status != 403 {
		t.Errorf("the branch's value signs the callee's hop: %d", d.Status)
	}

	// The callee's P-CSCF put two values above the S-CSCF's, the
	// client-facing one on top (RFC 5658 §5).
	rr, _ := branch.Header.Elements("Record-Route")
	res := &sip.Response{StatusCode: 200, Reason: "OK"}
	for _, v := range append([]string{"<sip:pcscf.example.net;lr>", calleePCSCF}, rr...) {
		_ = res.Header.Add("Record-Route", v)
	}
	_ = res.Header.Set("Contact", "<"+binding(1, 1, 0).URI+">")
	d.OnResponse(bg, res)
	inResponse := ourEntry(t, &res.Header)
	if inResponse.String() == inRequest.String() {
		t.Fatal("the response's value is the branch's")
	}
	if got, _ := res.Header.Elements("Record-Route"); len(got) != 4 || got[0] != "<sip:pcscf.example.net;lr>" || got[3] != callerPCSCF {
		t.Errorf("Record-Route %q", got)
	}
	for name, c := range map[string]struct {
		target, route string
		status        int
	}{
		"toward the callee": {binding(1, 1, 0).URI, "<" + calleeHop + ">", 0},
		"toward the caller": {"sip:ue7@192.0.2.17:5060", "<" + callerHop + ">", 0},
		"anywhere else":     {binding(1, 1, 0).URI, "<sip:" + flow(2) + "@198.51.100.5:5070;transport=tcp;lr>", 403},
	} {
		if d := rt.InDialog(bg, inDialog(t, c.target, c.route, inResponse)); d.Status != c.status {
			t.Errorf("%s: %d", name, d.Status)
		}
	}
	// A retransmitted 2xx is signed alike.
	again := &sip.Response{StatusCode: 200, Reason: "OK"}
	for _, v := range append([]string{"<sip:pcscf.example.net;lr>", calleePCSCF}, rr...) {
		_ = again.Header.Add("Record-Route", v)
	}
	d.OnResponse(bg, again)
	if ourEntry(t, &again.Header).String() != inResponse.String() {
		t.Error("the retransmission is signed otherwise")
	}
}

// TestADialogWithoutOtherProxiesIsSignedForTheContacts: a caller that
// recorded no route, rcs-as sending for its user (#137), is reached at its
// Contact, its task's address (code review major 1 on #322); a callee
// whose response has no value above the S-CSCF's, at its Contact.
func TestADialogWithoutOtherProxiesIsSignedForTheContacts(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 1, time.Hour))
	rt := e.router(nil)
	d, branch := setUp(t, e, rt, "Contact: <"+asTask+">")
	if d := rt.InDialog(bg, inDialog(t, asTask, "", ourEntry(t, &branch.Header))); d.Status != 0 {
		t.Errorf("toward rcs-as's task: %d", d.Status)
	}
	res := &sip.Response{StatusCode: 200, Reason: "OK"}
	rr, _ := branch.Header.Elements("Record-Route")
	for _, v := range rr {
		_ = res.Header.Add("Record-Route", v)
	}
	callee := "sip:" + flow(3) + "@198.51.100.6:5070;transport=tcp"
	_ = res.Header.Set("Contact", "<"+callee+">")
	d.OnResponse(bg, res)
	if d := rt.InDialog(bg, inDialog(t, callee, "", ourEntry(t, &res.Header))); d.Status != 0 {
		t.Errorf("toward the callee's Contact: %d", d.Status)
	}
}

// TestAResponseKeepsTheValuesOfOtherTransactions: one that passed the
// S-CSCF twice holds a value of the other pass, which is left as it is.
func TestAResponseKeepsTheValuesOfOtherTransactions(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 1, time.Hour))
	rt := e.router(nil)
	d, branch := setUp(t, e, rt, "Record-Route: "+callerPCSCF)
	otherPass := signedFor(rt, asTask).String()
	res := &sip.Response{StatusCode: 200, Reason: "OK"}
	rr, _ := branch.Header.Elements("Record-Route")
	for _, v := range append([]string{otherPass}, rr...) {
		_ = res.Header.Add("Record-Route", v)
	}
	d.OnResponse(bg, res)
	got, _ := res.Header.Elements("Record-Route")
	if len(got) != 3 || got[0] != otherPass || got[1] == rr[0] || got[2] != callerPCSCF {
		t.Errorf("Record-Route %q", got)
	}
	// The hop above this pass's value is the other pass's entry.
	if d := rt.InDialog(bg, inDialog(t, asTask, "", mustAddress(got[0]), mustAddress(got[1]))); d.Status != 403 {
		t.Errorf("status %d", d.Status)
	}
}

func mustAddress(s string) sip.Address {
	a, err := sip.ParseAddress(s)
	if err != nil {
		panic(err)
	}
	return a
}

// TestTheHopTowardTheCallerIsTheValueNextToTheSCSCFs: of the caller's
// P-CSCF's two values (RFC 5658 §5), the core-facing one on top, which the
// callee's requests go to.
func TestTheHopTowardTheCallerIsTheValueNextToTheSCSCFs(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 1, time.Hour))
	rt := e.router(nil)
	_, branch := setUp(t, e, rt, "Record-Route: "+callerPCSCF+", <sip:pcscf.example.net:5061;transport=tls;lr>")
	callerHop := strings.Trim(callerPCSCF, "<>")
	if d := rt.InDialog(bg, inDialog(t, "sip:ue7@192.0.2.17:5060", "<"+callerHop+">", ourEntry(t, &branch.Header))); d.Status != 0 {
		t.Errorf("toward the caller's P-CSCF: %d", d.Status)
	}
}

// TestOnlyTheSCSCFsOwnValueIsSigned: a branch whose topmost Record-Route
// value is not the S-CSCF's, as none is in an ACK, keeps its values.
func TestOnlyTheSCSCFsOwnValueIsSigned(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 1, time.Hour))
	rt := e.router(nil)
	r := request(t, "INVITE", impu1, "Record-Route: "+callerPCSCF)
	d := rt.Terminating(bg, r)
	b := r.Message.Clone()
	if err := d.Prepare(bg, d.Targets[0], b); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.Header.Elements("Record-Route"); len(got) != 1 || got[0] != callerPCSCF {
		t.Errorf("Record-Route %q", got)
	}
}

// TestAStandaloneRequestIsNotRecorded (#322): an OPTIONS or a MESSAGE sets
// up no dialog, and its Contact, which no proxy checked, is signed for
// nothing; a request naming that hop as inside a dialog is 403. An INVITE
// is recorded.
func TestAStandaloneRequestIsNotRecorded(t *testing.T) {
	core := "sip:10.0.130.25:5060;transport=tcp"
	for _, method := range []string{"OPTIONS", "MESSAGE", "INVITE", "SUBSCRIBE", "REFER"} {
		e := newEnv(t)
		e.registered(binding(1, 1, time.Hour))
		rt := e.router(nil)
		r := request(t, method, impu1, "Contact: <"+core+">")
		_ = r.Message.Header.Set("Call-ID", "dialog-1")
		d := rt.Terminating(bg, r)
		recorded := len(d.RecordRoute) == 1 && d.OnResponse != nil
		if want := method != "OPTIONS" && method != "MESSAGE"; recorded != want {
			t.Errorf("%s: recorded %v, want %v", method, recorded, want)
		}
		if recorded {
			continue
		}
		b := r.Message.Clone()
		if err := d.Prepare(bg, d.Targets[0], b); err != nil || b.Header.Has("Record-Route") {
			t.Errorf("%s: prepared %v with Record-Route %q", method, err, b.Header.Get("Record-Route"))
		}
		unsigned := sip.Address{URI: mustURI("sip:scscf.rcs.local;transport=tcp;lr")}
		if d := rt.InDialog(bg, inDialog(t, core, "", unsigned)); d.Status != 403 {
			t.Errorf("%s: a request to its Contact is %d", method, d.Status)
		}
	}
}

// TestADialogKeyPrintsWithoutItsKey (security on #322): fmt, slog and JSON
// show its ID alone, in a Config as on its own.
func TestADialogKeyPrintsWithoutItsKey(t *testing.T) {
	k := DialogKey{ID: "k2", Key: []byte("0123456789abcdef0123456789abcdef")}
	cfg := Config{DialogKeys: []DialogKey{k}}
	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("key", "key", k, "keys", cfg.DialogKeys)
	js, err := json.Marshal(struct{ Keys []DialogKey }{cfg.DialogKeys})
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{fmt.Sprint(k), fmt.Sprintf("%v %+v %#v %s %x", k, k, k, k, k), fmt.Sprintf("%+v", cfg), logged.String(), string(js)} {
		for _, leak := range []string{"0123456789abcdef", hex.EncodeToString(k.Key[:8]), base64.StdEncoding.EncodeToString(k.Key[:9])} {
			if strings.Contains(out, leak) {
				t.Errorf("%q gives the key away", out)
			}
		}
		if !strings.Contains(out, "k2") {
			t.Errorf("%q does not name the key", out)
		}
	}
}

// TestNewKeepsTheCurrentAndThePreviousKeyAlone: a third is refused, as a
// list that grew with each rotation would keep every key that leaked.
func TestNewKeepsTheCurrentAndThePreviousKeyAlone(t *testing.T) {
	e := newEnv(t)
	k := func(id string, b byte) DialogKey {
		return DialogKey{ID: id, Key: bytes.Repeat([]byte{b}, MinDialogKeyBytes)}
	}
	if _, err := New(validConfig(e, func(c *Config) { c.DialogKeys = []DialogKey{k("k3", 3), k("k2", 2)} })); err != nil {
		t.Errorf("two keys: %v", err)
	}
	if _, err := New(validConfig(e, func(c *Config) { c.DialogKeys = []DialogKey{k("k3", 3), k("k2", 2), k("k1", 1)} })); err == nil {
		t.Error("three keys accepted")
	}
}

// TestASignedSIPSHopIsItsTLSListener: sips: defaults to TLS on 5061, which
// the same URI written out names, and no TCP one does.
func TestASignedSIPSHopIsItsTLSListener(t *testing.T) {
	e := newEnv(t)
	rt := e.router(nil, func(c *Config) {
		c.ApplicationServers = append(c.ApplicationServers, mustURI("sips:rcs-as.rcs.local:5061"))
	})
	signed := signedFor(rt, "sips:as@10.0.131.7")
	for target, want := range map[string]int{
		"sips:as@10.0.131.7":                    0,
		"sips:as@10.0.131.7:5061;transport=tls": 0,
		"sip:as@10.0.131.7:5061;transport=tcp":  403,
	} {
		if d := rt.InDialog(bg, inDialog(t, target, "", signed)); d.Status != want {
			t.Errorf("%s: %d, want %d", target, d.Status, want)
		}
	}
}
