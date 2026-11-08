package hss

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

// leftover is an IMPU at the chatbot host provisioned before
// RCS_CHATBOT_DOMAIN was set, which only a direct store write can make now.
const leftover = "sip:bot@" + botDomain

// newChatbotCxEnv is an HSS with RCS_CHATBOT_DOMAIN set, holding a
// subscription whose implicit set has impu1 and leftover, and the PSI with
// a stored AS name other than the configured one.
func newChatbotCxEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.h = e.newHSS(func(o *Options) { o.ChatbotDomain, o.ChatbotASName = testChatbotDomain(t), chatbotAS })
	e.provision(impi1, impu1, leftover)
	e.putPSI(nil, &store.WildcardedPSI{PSI: chatbotPSI, ServerName: "sip:stored.example.net", Active: true})
	return e
}

func (e *env) putPSI(old, p *store.WildcardedPSI) *store.WildcardedPSI {
	e.t.Helper()
	saved, err := e.store.PutWildcardedPSI(context.Background(), old, p)
	if err != nil {
		e.t.Fatal(err)
	}
	return saved
}

// The chatbot host is the PSI's alone (the lead's decision on #679): an
// identity there neither registers nor authenticates, whatever is stored,
// and an LIR there is answered from the PSI.
func TestTheChatbotHostIsThePSIsAlone(t *testing.T) {
	e := newChatbotCxEnv(t)
	node := serveHSS(t, e.h, "hss-a.rcs.local")
	icscf := connectCSCF(t, node, "icscf-1.rcs.local")
	scscf := connectCSCF(t, node, "scscf-1.rcs.local")
	unknown := exp(cx.ErrorUserUnknown)

	for _, id := range []string{leftover, "sip:bot@" + strings.ToUpper(botDomain), "sips:bot@" + botDomain + "."} {
		wantResult(t, "UAR for "+id, icscf.uar(impi1, id, cx.AuthorizeRegistration).Result, unknown)
		wantResult(t, "MAR for "+id, scscf.mar(impi1, id, cx.SchemeDigestAKAv1MD5, 1, scscfName, nil).Result, unknown)
		wantResult(t, "SAR for "+id, scscf.sar(impi1, []string{id}, cx.Registration, scscfName).Result, unknown)
		wantResult(t, "SAR by IMPU for "+id, scscf.sar("", []string{id}, cx.Registration, scscfName).Result, unknown)
	}
	if s := e.sub(impi1); s.ServerName != "" || s.AuthPending || s.Identity(leftover).State != store.NotRegistered {
		t.Fatalf("the refused requests changed the subscription: %+v", s)
	}

	// In the range: the PSI, with the configured AS name, though an IMPU
	// is stored there.
	lia := icscf.lir(leftover, false)
	if lia.Result != resSuccess || lia.ServerName != chatbotAS || lia.WildcardedPublicIdentity != chatbotPSI || lia.ServerCapabilities != nil {
		t.Fatalf("LIA in the range = %+v", lia)
	}
	// At the host but outside the range, or not in normal form: unknown.
	for _, uri := range []string{"sip:a.b.c@" + botDomain, "sip:Bot@" + botDomain, leftover + ";tk=on", "sips:bot@" + botDomain, "sip:bot@" + strings.ToUpper(botDomain)} {
		if lia := icscf.lir(uri, false); lia.Result != unknown || lia.ServerName != "" || lia.WildcardedPublicIdentity != "" {
			t.Errorf("LIA for %s = %+v", uri, lia)
		}
	}

	// impu1 registers as before, and its set's User-Data leaves the
	// leftover out, so the S-CSCF never holds it as registered.
	wantResult(t, "UAR for impu1", icscf.uar(impi1, impu1, cx.AuthorizeRegistration).Result, exp(cx.FirstRegistration))
	scscf.mar(impi1, impu1, cx.SchemeDigestAKAv1MD5, 1, scscfName, nil)
	saa := scscf.sar(impi1, []string{impu1}, cx.Registration, scscfName)
	wantResult(t, "SAR for impu1", saa.Result, resSuccess)
	doc, err := ifc.ParseSubscription(saa.UserData)
	if err != nil {
		t.Fatal(err)
	}
	if ids := doc.ServiceProfiles[0].PublicIdentities; len(ids) != 1 || ids[0].Identity != impu1 {
		t.Fatalf("User-Data identities = %+v, want impu1 only", ids)
	}
	if lia := icscf.lir(impu1, false); lia.Result != resSuccess || lia.ServerName != scscfName || lia.WildcardedPublicIdentity != "" {
		t.Errorf("LIA for impu1 = %+v", lia)
	}
	// Registered with its set in the store, the leftover still gets the PSI.
	if lia := icscf.lir(leftover, false); lia.ServerName != chatbotAS {
		t.Errorf("LIA in the range after the set registered = %+v", lia)
	}
}

func TestWithoutAChatbotDomainCxIsAsOnMain(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1, leftover)
	e.putPSI(nil, &store.WildcardedPSI{PSI: chatbotPSI, ServerName: chatbotAS, Active: true})
	node := serveHSS(t, e.h, "hss-a.rcs.local")
	icscf := connectCSCF(t, node, "icscf-1.rcs.local")
	scscf := connectCSCF(t, node, "scscf-1.rcs.local")
	wantResult(t, "UAR", icscf.uar(impi1, leftover, cx.AuthorizeRegistration).Result, exp(cx.FirstRegistration))
	scscf.mar(impi1, leftover, cx.SchemeDigestAKAv1MD5, 1, scscfName, nil)
	saa := scscf.sar(impi1, []string{leftover}, cx.Registration, scscfName)
	wantResult(t, "SAR", saa.Result, resSuccess)
	if doc, err := ifc.ParseSubscription(saa.UserData); err != nil || len(doc.ServiceProfiles[0].PublicIdentities) != 2 {
		t.Fatalf("User-Data = %+v, %v", doc, err)
	}
	if lia := icscf.lir(leftover, false); lia.Result != resSuccess || lia.ServerName != scscfName || lia.WildcardedPublicIdentity != "" {
		t.Errorf("LIA = %+v", lia)
	}
	if lia := icscf.lir("sip:other@"+botDomain, false); lia.Result != exp(cx.ErrorUserUnknown) || lia.WildcardedPublicIdentity != "" {
		t.Errorf("LIA for an unknown URI = %+v", lia)
	}
}

// lirFor answers one LIR through the handler's decision, for the range
// tests below.
func (e *env) lirFor(uri string) (lirAnswer, error) {
	return (&CxServer{h: e.h}).decideLIR(context.Background(), &cx.LIR{PublicIdentity: uri})
}

func TestTheStoredPSIIsCheckedOnEveryReadAndCompiledOncePerVersion(t *testing.T) {
	e := newChatbotCxEnv(t)
	if out, err := e.lirFor(leftover); err != nil || out.serverName != chatbotAS {
		t.Fatalf("LIR = %+v, %v", out, err)
	}
	first := e.h.rangeOf
	if out, _ := e.lirFor("sip:other@" + botDomain); out.serverName != chatbotAS || e.h.rangeOf != first {
		t.Fatal("a second LIR of the same version compiled the range again")
	}
	// A new version is seen at the next LIR.
	v1, _ := e.store.WildcardedPSI(t.Context())
	v2 := e.putPSI(v1, &store.WildcardedPSI{PSI: "sip:!news!@" + botDomain, ServerName: chatbotAS, Active: true})
	if out, _ := e.lirFor(leftover); out.result != exp(cx.ErrorUserUnknown) {
		t.Fatalf("after the PSI was narrowed, LIR = %+v", out)
	}
	if out, _ := e.lirFor("sip:news@" + botDomain); out.wildcard != v2.PSI {
		t.Fatalf("LIR in the new range = %+v", out)
	}
	// An inactive PSI is no range.
	e.putPSI(v2, &store.WildcardedPSI{PSI: chatbotPSI, ServerName: chatbotAS, Active: false})
	if out, _ := e.lirFor(leftover); out.result != exp(cx.ErrorUserUnknown) || out.wildcard != "" {
		t.Fatalf("LIR with an inactive PSI = %+v", out)
	}
}

// A PSI stored for another RCS_CHATBOT_DOMAIN, as after the setting
// changed, gives no range; it is counted and logged once per version,
// without the PSI.
func TestAStoredPSIForAnotherChatbotDomainIsNoRangeAndIsReported(t *testing.T) {
	e := newEnv(t)
	e.h = e.newHSS(func(o *Options) { o.ChatbotDomain, o.ChatbotASName = testChatbotDomain(t), chatbotAS })
	e.putPSI(nil, &store.WildcardedPSI{PSI: "sip:!secretbot!@old-bots.example.net", ServerName: chatbotAS, Active: true})
	for range 3 {
		if out, err := e.lirFor("sip:secretbot@" + botDomain); err != nil || out.result != exp(cx.ErrorUserUnknown) {
			t.Fatalf("LIR = %+v, %v", out, err)
		}
	}
	logs := e.logs.String()
	if n := e.metrics.get("chatbot.psi_invalid"); n != 1 || strings.Count(logs, "does not hold under RCS_CHATBOT_DOMAIN") != 1 {
		t.Errorf("chatbot.psi_invalid = %d; logs:\n%s", n, logs)
	}
	if strings.Contains(logs, "secretbot") || strings.Contains(logs, "old-bots") {
		t.Error("the log carries the PSI")
	}
}

type failingPSIRead struct{ store.Store }

func (failingPSIRead) WildcardedPSI(context.Context) (*store.WildcardedPSI, error) {
	return nil, errors.New("test: the store is down")
}

// The two failures an LIR in the range cannot answer around: the PSI
// cannot be read, or the match cannot be paid for.
func TestAnLIRWhoseRangeCannotBeDecidedIsUnableToComply(t *testing.T) {
	e := newChatbotCxEnv(t)
	e.h.store = failingPSIRead{e.store}
	node := serveHSS(t, e.h, "hss-a.rcs.local")
	icscf := connectCSCF(t, node, "icscf-1.rcs.local")
	wantResult(t, "LIR with the store down", icscf.lir(leftover, false).Result, resUnable)

	e.h.store = e.store
	saved := containsInRange
	containsInRange = func(*chatbotRange, string) (bool, error) { return false, &ifc.LimitError{Limit: "MaxWork"} }
	t.Cleanup(func() { containsInRange = saved })
	lia := icscf.lir(leftover, false)
	wantResult(t, "LIR whose match failed", lia.Result, resUnable)
	if lia.WildcardedPublicIdentity != "" || e.metrics.get("cx.lir.chatbot_match_failed") != 1 {
		t.Errorf("LIA = %+v, match failures %d", lia, e.metrics.get("cx.lir.chatbot_match_failed"))
	}
}

// TestRunGivesCxTheChatbotRange: through Run, a PSI written over the API
// answers an LIR over Diameter with the configured AS name.
func TestRunGivesCxTheChatbotRange(t *testing.T) {
	cfg, err := configure(with(devEnv, "RCS_CHATBOT_DOMAIN", botDomain, "HSS_RCS_AS_URI", chatbotAS))
	if err != nil {
		t.Fatal(err)
	}
	_, addrs, cancel, done := startRun(t, cfg, defaultDeps())
	defer func() { cancel(); <-done }()
	req, _ := http.NewRequest("PUT", "http://"+addrs[1]+"/v1/chatbot-psi", strings.NewReader(psiBody(chatbotPSI)))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: realWait + time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT = %d", resp.StatusCode)
	}
	client, err := diameter.NewNode(nodeConfig(t, "icscf-1.rcs.local", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Shutdown(context.Background()) }()
	peer, err := client.Connect(diameter.PeerConfig{Address: addrs[0]})
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(realWait); !peer.Available(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no capabilities exchange with the HSS")
		}
	}
	msg, err := (&cx.LIR{Request: cx.Request{DestinationRealm: domain}, PublicIdentity: leftover}).Message(client)
	if err != nil {
		t.Fatal(err)
	}
	ans, err := peer.Send(context.Background(), msg)
	if err != nil {
		t.Fatal(err)
	}
	if lia, err := cx.ParseLIA(ans); err != nil || lia.Result != resSuccess || lia.ServerName != chatbotAS || lia.WildcardedPublicIdentity != chatbotPSI {
		t.Fatalf("LIA through Run = %+v, %v", lia, err)
	}
}

// The User-Data a PPR pushes leaves a chatbot-host IMPU out of its set, as
// an SAA's does.
func TestAPPRLeavesAChatbotHostIMPUOutOfUserData(t *testing.T) {
	a := newChatbotAPIEnv(t)
	a.h.chatbot = testChatbotDomain(t)
	profile := `{"id":"chat","initial_filter_criteria":[{"priority":1,"trigger_point":{"condition_type_cnf":false,"spt":[{"group":[0],"method":"MESSAGE"}]},` +
		`"application_server":{"server_name":"` + asURI + `","default_handling":"SESSION_TERMINATED"}}]}`
	if code, body, _ := a.do("POST", "/v1/service-profiles", adminToken, profile); code != http.StatusCreated {
		t.Fatalf("create profile = %d %v", code, body)
	}
	s := &store.Subscription{IMPI: impi1, Profile: "chat", ServerName: scscfName, PublicIdentities: []store.PublicIdentity{
		{IMPU: impu1, State: store.Registered}, {IMPU: leftover, State: store.Registered}}}
	if _, err := a.store.CreateSubscription(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	if code, body, _ := a.do("PUT", "/v1/service-profiles/chat", adminToken, strings.Replace(profile, `"MESSAGE"`, `"INVITE"`, 1)); code != http.StatusOK {
		t.Fatalf("put profile = %d %v", code, body)
	}
	select {
	case <-a.notifier.sent:
	case <-time.After(realWait):
		t.Fatal("no PPR")
	}
	if err := a.api.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, pprs := a.notifier.got()
	if len(pprs) != 1 {
		t.Fatalf("%d PPRs", len(pprs))
	}
	doc, err := ifc.ParseSubscription(pprs[0].UserData)
	if err != nil {
		t.Fatal(err)
	}
	if ids := doc.ServiceProfiles[0].PublicIdentities; len(ids) != 1 || ids[0].Identity != impu1 {
		t.Fatalf("PPR User-Data identities = %+v, want impu1 only", ids)
	}
}
