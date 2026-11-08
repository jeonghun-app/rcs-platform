package hss

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

// leftover is an IMPU at the chatbot host provisioned before
// RCS_CHATBOT_DOMAIN was set, which only a direct store write can make now;
// the others are the host's other stored forms, the last one not canonical
// (a record written past the API).
const (
	leftover         = "sip:bot@" + botDomain
	leftoverSIPS     = "sips:bot@" + botDomain
	leftoverDot      = "sip:dot@" + botDomain + "."
	leftoverUpperRaw = "sip:Up@BOTPLATFORM.MNC001.MCC001.3GPPNETWORK.ORG"
)

// newChatbotCxEnv is an HSS with RCS_CHATBOT_DOMAIN set, holding a
// subscription whose implicit set has impu1 and leftover, and the PSI with
// a stored AS name other than the configured one.
func newChatbotCxEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.h = e.newHSS(func(o *Options) { o.ChatbotDomain, o.ChatbotASName = testChatbotDomain(t), chatbotAS })
	e.provision(impi1, impu1, leftover, leftoverSIPS, leftoverDot, leftoverUpperRaw)
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

	// Each is stored, so only the host rule makes it unknown.
	for _, id := range []string{leftover, "sip:bot@" + strings.ToUpper(botDomain), leftoverSIPS, leftoverDot} {
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

	// impu1 registers as before, and its set's User-Data leaves every form
	// of the host out, the stored non-canonical one too, so the S-CSCF
	// never holds one as registered.
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
	none := newEnv(t)
	none.h = none.newHSS(func(o *Options) { o.ChatbotDomain, o.ChatbotASName = testChatbotDomain(t), chatbotAS })
	if out, err := none.lirFor(leftover); err != nil || out.result != exp(cx.ErrorUserUnknown) {
		t.Fatalf("LIR with no PSI stored = %+v, %v", out, err)
	}
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
	// A table restored or recreated stores a lower version than a task has
	// cached: it takes effect at the next LIR, an inactive one too.
	restored := func(cached string, active bool) lirAnswer {
		t.Helper()
		cur, _ := e.store.WildcardedPSI(t.Context())
		e.putPSI(cur, &store.WildcardedPSI{PSI: chatbotPSI, ServerName: chatbotAS, Active: active})
		e.h.rangeVersion, e.h.rangeOf, e.h.rangeInvalid = 100, testChatbotRange(t, cached), false
		out, err := e.lirFor(leftover)
		if err != nil || e.h.rangeVersion >= 100 {
			t.Fatalf("after a restore: %+v, %v, cached version %d", out, err, e.h.rangeVersion)
		}
		return out
	}
	if out := restored("sip:!news!@"+botDomain, true); out.wildcard != chatbotPSI {
		t.Errorf("a restored lower version was not taken: %+v", out)
	}
	if out := restored(chatbotPSI, false); out.result != exp(cx.ErrorUserUnknown) || out.wildcard != "" {
		t.Errorf("a restored inactive lower version still routes: %+v", out)
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
	// Counted on every LIR it leaves without a range, so that an alarm sees
	// it; logged once.
	if n := e.metrics.get("chatbot.psi_invalid"); n != 3 || strings.Count(logs, "does not hold under RCS_CHATBOT_DOMAIN") != 1 {
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

func userDataIdentities(t *testing.T, data []byte) []string {
	t.Helper()
	doc, err := ifc.ParseSubscription(data)
	if err != nil {
		t.Fatalf("User-Data: %v", err)
	}
	var ids []string
	for _, id := range doc.ServiceProfiles[0].PublicIdentities {
		ids = append(ids, id.Identity)
	}
	return ids
}

// A registration made before RCS_CHATBOT_DOMAIN was set holds the
// chatbot-host identity at the S-CSCF. Its refreshes say the User-Data is
// already there (USER_DATA_ALREADY_AVAILABLE) and name impu1, so they are
// never refused; the HSS sends the set's User-Data without the identity all
// the same, as it does for a stale set, and the S-CSCF takes it (the
// tester's probe on #695).
func TestARefreshOfASetRegisteredBeforeTheSettingGetsUserDataWithoutTheHost(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1, leftover)
	e.provision(impi2, impu2)
	e.provision(impi3, impu3, leftoverUpperRaw)
	before := serveHSS(t, e.h, "hss-a.rcs.local")
	setOn := e.newHSS(func(o *Options) { o.ChatbotDomain, o.ChatbotASName = testChatbotDomain(t), chatbotAS })
	after := serveHSS(t, setOn, "hss-b.rcs.local")
	old, cur := connectCSCF(t, before, "scscf-1.rcs.local"), connectCSCF(t, after, "scscf-1.rcs.local")
	for _, u := range []struct{ impi, impu string }{{impi1, impu1}, {impi2, impu2}, {impi3, impu3}} {
		old.mar(u.impi, u.impu, cx.SchemeDigestAKAv1MD5, 1, scscfName, nil)
		wantResult(t, "SAR before the setting", old.sar(u.impi, []string{u.impu}, cx.Registration, scscfName).Result, resSuccess)
	}
	refresh := func(impi, impu string) *cx.SAA {
		r := &cx.SAR{Request: cx.Request{DestinationRealm: domain}, UserName: impi, PublicIdentities: []string{impu},
			ServerName: scscfName, AssignmentType: cx.ReRegistration, UserDataAlreadyAvailable: cx.UserDataAlreadyAvailable}
		a, err := cx.ParseSAA(cur.send(r.Message(cur.node)))
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	saa := refresh(impi1, impu1)
	wantResult(t, "refresh", saa.Result, resSuccess)
	if ids := userDataIdentities(t, saa.UserData); len(ids) != 1 || ids[0] != impu1 {
		t.Fatalf("refresh User-Data identities = %v, want impu1 only", ids)
	}
	if n := e.metrics.get("chatbot.userdata_resent"); n != 1 {
		t.Errorf("chatbot.userdata_resent = %d, want 1", n)
	}
	// The same for an identity stored in a form that is not canonical.
	if ids := userDataIdentities(t, refresh(impi3, impu3).UserData); len(ids) != 1 || ids[0] != impu3 {
		t.Errorf("refresh with a non-canonical stored host: User-Data identities = %v", ids)
	}
	// A set without the host keeps the usual answer: no User-Data.
	if saa := refresh(impi2, impu2); saa.Result != resSuccess || len(saa.UserData) != 0 {
		t.Errorf("refresh of a set without the host = %+v", saa)
	}
	if s := e.sub(impi1); len(s.StaleSets) != 0 {
		t.Errorf("the resend was stored: %+v", s)
	}
}

// Deregistrations only clear state, so they may name an identity at the
// chatbot host; registering it stays refused.
func TestADeregistrationMayNameAChatbotHostIdentity(t *testing.T) {
	for _, typ := range []cx.ServerAssignmentType{cx.UserDeregistration, cx.TimeoutDeregistration, cx.AdministrativeDeregistration} {
		e := newChatbotCxEnv(t)
		e.modify(impi1, func(s *store.Subscription) {
			s.ServerName = scscfName
			setState(s, 0, store.Registered)
		})
		scscf := connectCSCF(t, serveHSS(t, e.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
		wantResult(t, "registration SAR", scscf.sar(impi1, []string{leftover}, cx.ReRegistration, scscfName).Result, exp(cx.ErrorUserUnknown))
		wantResult(t, fmt.Sprint("deregistration SAR ", typ), scscf.sar(impi1, []string{leftover}, typ, scscfName).Result, resSuccess)
		if s := e.sub(impi1); s.Identity(leftover).State != store.NotRegistered || s.Identity(impu1).State != store.NotRegistered || s.ServerName != "" {
			t.Errorf("after %v: %+v", typ, s)
		}
	}
}

// A set made only of chatbot-host identities, registered before the
// setting, gets an RTR when a change would push its User-Data, which would
// list no identity, and is then not registered at the HSS either.
func TestASetOfOnlyChatbotHostIdentitiesIsDeregisteredRatherThanPushed(t *testing.T) {
	a := newChatbotAPIEnv(t)
	a.h.chatbot = testChatbotDomain(t)
	profile := `{"id":"chat","initial_filter_criteria":[{"priority":1,"trigger_point":{"condition_type_cnf":false,"spt":[{"group":[0],"method":"MESSAGE"}]},` +
		`"application_server":{"server_name":"` + asURI + `","default_handling":"SESSION_TERMINATED"}}]}`
	if code, body, _ := a.do("POST", "/v1/service-profiles", adminToken, profile); code != http.StatusCreated {
		t.Fatalf("create profile = %d %v", code, body)
	}
	s := &store.Subscription{IMPI: impi1, Profile: "chat", ServerName: scscfName, PublicIdentities: []store.PublicIdentity{
		{IMPU: impu1, State: store.Registered}, {IMPU: leftover, ImplicitSet: 1, State: store.Registered}}}
	if _, err := a.store.CreateSubscription(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	if code, body, _ := a.do("PUT", "/v1/service-profiles/chat", adminToken, strings.Replace(profile, `"MESSAGE"`, `"INVITE"`, 1)); code != http.StatusOK {
		t.Fatalf("put profile = %d %v", code, body)
	}
	for range 2 {
		select {
		case <-a.notifier.sent:
		case <-time.After(realWait):
			t.Fatal("not every push went")
		}
	}
	if err := a.api.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	rtrs, pprs := a.notifier.got()
	if len(pprs) != 1 || len(rtrs) != 1 {
		t.Fatalf("%d PPRs and %d RTRs, want one of each", len(pprs), len(rtrs))
	}
	if ids := userDataIdentities(t, pprs[0].UserData); len(ids) != 1 || ids[0] != impu1 {
		t.Errorf("PPR User-Data identities = %v", ids)
	}
	if r := rtrs[0]; len(r.PublicIdentities) != 1 || r.PublicIdentities[0] != leftover || r.DeregistrationReason.Code != cx.PermanentTermination {
		t.Errorf("RTR = %+v", r)
	}
	got, err := a.store.Subscription(t.Context(), impi1)
	if err != nil || got.Identity(leftover).State != store.NotRegistered || got.Identity(impu1).State != store.Registered || got.ServerName != scscfName {
		t.Errorf("after the pushes: %+v, %v", got, err)
	}
	if n := a.metrics.get("push.chatbot_set_deregistered"); n != 1 {
		t.Errorf("push.chatbot_set_deregistered = %d", n)
	}
}

// The runbook has the operator drop a chatbot-host identity left in a
// registered set. If that write's push fails, or gets no answer, the
// S-CSCF keeps User-Data that lists the identity, and the HSS no longer
// stores anything that would make it resend (holdsChatbotHost): the write
// itself marks the set stale, so the next refresh replaces the data, even
// one saying the S-CSCF has it (the security review of #695).
func TestAWriteDroppingAChatbotHostIdentityMarksItsSetStale(t *testing.T) {
	for _, c := range []struct {
		name   string
		silent bool     // else every PPR fails
		ids    []string // the set as stored; the write keeps impu1 only
	}{
		{"the PPR fails", false, []string{impu1, leftover}},
		{"the PPR gets no answer", true, []string{impu1, leftover}},
		// The identity was the set's default: a SERVER_CHANGE RTR.
		{"the RTR gets no answer", true, []string{leftover, impu1}},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := newAPIEnv(t, func(o *APIOptions) {
				o.ChatbotDomain, o.ChatbotASName, o.PushTimeout = testChatbotDomain(t), chatbotAS, 200*time.Millisecond
				if c.silent {
					o.Notifier = &silentNotifier{}
				}
			})
			a.notifier.pprErr = errors.New("test: no peer")
			a.h.chatbot = testChatbotDomain(t)
			s := &store.Subscription{IMPI: impi1, Profile: DefaultProfileID, ServerName: scscfName}
			for _, id := range c.ids {
				s.PublicIdentities = append(s.PublicIdentities, store.PublicIdentity{IMPU: id, State: store.Registered})
			}
			if _, err := a.store.CreateSubscription(t.Context(), s); err != nil {
				t.Fatal(err)
			}
			if code, body, _ := a.do("PUT", subPath(impi1), adminToken, subscriptionBody(impi1, false, impu1)); code != http.StatusOK {
				t.Fatalf("put = %d %v", code, body)
			}
			if got := a.sub(impi1).StaleSets; !slices.Equal(got, []int{0}) {
				t.Errorf("stale sets after the write = %v, want [0]", got)
			}
			scscf := connectCSCF(t, serveHSS(t, a.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
			r := &cx.SAR{Request: cx.Request{DestinationRealm: domain}, UserName: impi1, PublicIdentities: []string{impu1},
				ServerName: scscfName, AssignmentType: cx.ReRegistration, UserDataAlreadyAvailable: cx.UserDataAlreadyAvailable}
			saa, err := cx.ParseSAA(scscf.send(r.Message(scscf.node)))
			if err != nil {
				t.Fatal(err)
			}
			wantResult(t, "refresh", saa.Result, resSuccess)
			if ids := userDataIdentities(t, saa.UserData); len(ids) != 1 || ids[0] != impu1 {
				t.Fatalf("refresh User-Data identities = %v, want impu1 only", ids)
			}
			if got := a.sub(impi1).StaleSets; len(got) != 0 {
				t.Errorf("stale sets after the refresh = %v", got)
			}
		})
	}
}

// Which sets a write marks stale for a chatbot-host identity it takes away
// (markChatbotHostLeft): a served set that loses one, removed or moved, and
// keeps another identity.
func TestOnlyAServedSetLosingAChatbotHostIdentityIsMarkedStale(t *testing.T) {
	type id struct {
		impu  string
		set   int
		state store.RegistrationState
	}
	sub := func(ids ...id) *store.Subscription {
		s := &store.Subscription{IMPI: impi1}
		for _, p := range ids {
			s.PublicIdentities = append(s.PublicIdentities, store.PublicIdentity{IMPU: p.impu, ImplicitSet: p.set, State: p.state})
		}
		return s
	}
	reg, unreg, not := store.Registered, store.Unregistered, store.NotRegistered
	staleAlready := sub(id{impu1, 0, not})
	staleAlready.StaleSets = []int{0}
	otherStale := sub(id{impu1, 0, not}, id{impu2, 1, reg})
	otherStale.StaleSets = []int{1}
	for _, c := range []struct {
		name      string
		old, next *store.Subscription
		domainSet bool
		want      []int
	}{
		{"removed from a registered set", sub(id{impu1, 0, reg}, id{leftover, 0, reg}), sub(id{impu1, 0, not}), true, []int{0}},
		{"removed from an unregistered set", sub(id{impu1, 0, unreg}, id{leftover, 0, unreg}), sub(id{impu1, 0, not}), true, []int{0}},
		{"stored in a form not canonical", sub(id{impu1, 0, reg}, id{leftoverUpperRaw, 0, reg}), sub(id{impu1, 0, not}), true, []int{0}},
		{"moved to another set", sub(id{impu1, 0, reg}, id{leftover, 0, reg}, id{impu2, 1, reg}),
			sub(id{impu1, 0, not}, id{leftover, 1, not}, id{impu2, 1, not}), true, []int{0}},
		{"already stale", sub(id{impu1, 0, reg}, id{leftover, 0, reg}), staleAlready, true, []int{0}},
		{"kept in order with a set already stale", sub(id{impu1, 0, reg}, id{leftover, 0, reg}, id{impu2, 1, reg}), otherStale, true, []int{0, 1}},
		{"kept", sub(id{impu1, 0, reg}, id{leftover, 0, reg}), sub(id{impu1, 0, not}, id{leftover, 0, not}), true, nil},
		{"the set emptied", sub(id{impu1, 0, reg}, id{leftover, 1, reg}), sub(id{impu1, 0, not}), true, nil},
		{"a set not served", sub(id{impu1, 0, not}, id{leftover, 0, not}), sub(id{impu1, 0, not}), true, nil},
		{"another identity removed", sub(id{impu1, 0, reg}, id{impu2, 0, reg}), sub(id{impu1, 0, not}), true, nil},
		{"RCS_CHATBOT_DOMAIN unset", sub(id{impu1, 0, reg}, id{leftover, 0, reg}), sub(id{impu1, 0, not}), false, nil},
	} {
		h := &HSS{}
		if c.domainSet {
			h.chatbot = testChatbotDomain(t)
		}
		h.markChatbotHostLeft(c.old, c.next)
		if !slices.Equal(c.next.StaleSets, c.want) {
			t.Errorf("%s: stale sets %v, want %v", c.name, c.next.StaleSets, c.want)
		}
	}
}

// fixedPSIRead returns psi whatever is stored, as a restored table can
// hold, at the version a task has cached, another PSI or activation.
type fixedPSIRead struct {
	store.Store
	psi store.WildcardedPSI
}

func (f *fixedPSIRead) WildcardedPSI(context.Context) (*store.WildcardedPSI, error) {
	p := f.psi
	return &p, nil
}

// The compiled range is kept for the PSI and its activation as well as the
// version, so that the same version number with other content takes effect
// (the tester's nit on #695).
func TestTheSameVersionWithAnotherPSIOrActivationTakesEffect(t *testing.T) {
	e := newChatbotCxEnv(t)
	read := &fixedPSIRead{Store: e.store, psi: store.WildcardedPSI{PSI: chatbotPSI, ServerName: chatbotAS, Active: true, Version: 5}}
	e.h.store = read
	news := "sip:!news!@" + botDomain
	for _, c := range []struct {
		psi    string
		active bool
		uri    string
		in     bool
	}{
		{chatbotPSI, true, leftover, true},
		{chatbotPSI, false, leftover, false},
		{chatbotPSI, true, leftover, true},
		{news, true, leftover, false},
		{news, true, "sip:news@" + botDomain, true},
	} {
		read.psi.PSI, read.psi.Active = c.psi, c.active
		out, err := e.lirFor(c.uri)
		if err != nil || (out.serverName == chatbotAS) != c.in {
			t.Errorf("v5 %s active %v, LIR %s = %+v, %v; want in the range %v", c.psi, c.active, c.uri, out, err, c.in)
		}
	}
}
