package hss

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/milenage"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// Tokens of 256 bits in base64url, as ADR 0007 asks; made up for the test.
var (
	adminToken     = "admin-0123456789abcdefghijklmnopqrstuvwxyzAB"
	adminTokenNext = "admin-next-0123456789abcdefghijklmnopqrstuvwx"
	acsToken       = "acs-0123456789abcdefghijklmnopqrstuvwxyzABCD"
	ftToken        = "ft-0123456789abcdefghijklmnopqrstuvwxyzABCDE"
)

// recordingNotifier records the RTRs and PPRs the API causes; pprErr, when
// set, is what every PPR fails with.
type recordingNotifier struct {
	mu     sync.Mutex
	rtrs   []*cx.RTR
	pprs   []*cx.PPR
	sent   chan struct{}
	pprErr error
}

func newRecorder() *recordingNotifier { return &recordingNotifier{sent: make(chan struct{}, 100)} }

func (n *recordingNotifier) Deregister(_ context.Context, r *cx.RTR) error {
	n.mu.Lock()
	n.rtrs = append(n.rtrs, r)
	n.mu.Unlock()
	n.sent <- struct{}{}
	return nil
}

func (n *recordingNotifier) PushProfile(_ context.Context, r *cx.PPR) error {
	n.mu.Lock()
	n.pprs = append(n.pprs, r)
	err := n.pprErr
	n.mu.Unlock()
	n.sent <- struct{}{}
	return err
}

func (n *recordingNotifier) got() ([]*cx.RTR, []*cx.PPR) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]*cx.RTR(nil), n.rtrs...), append([]*cx.PPR(nil), n.pprs...)
}

type apiEnv struct {
	*env
	api      *API
	notifier *recordingNotifier
	now      time.Time
	mu       sync.Mutex
	bodies   []string
}

func newAPIEnv(t *testing.T, mutate ...func(*APIOptions)) *apiEnv {
	t.Helper()
	a := &apiEnv{env: newEnv(t), notifier: newRecorder(), now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	o := APIOptions{
		Tokens:         Tokens{Admin: TokenPair{adminToken, adminTokenNext}, ACS: TokenPair{Current: acsToken}, FT: TokenPair{Current: ftToken}},
		Notifier:       a.notifier,
		DefaultProfile: DefaultProfileID,
		Now:            func() time.Time { a.mu.Lock(); defer a.mu.Unlock(); return a.now },
	}
	for _, m := range mutate {
		m(&o)
	}
	a.api = a.h.NewAPI(o)
	t.Cleanup(func() { _ = a.api.Close(context.Background()) })
	return a
}

func (a *apiEnv) advance(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.now = a.now.Add(d)
}

// do sends a request and returns the status and the decoded JSON body.
func (a *apiEnv) do(method, path, token, body string, headers ...string) (int, map[string]any, http.Header) {
	a.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	a.api.ServeHTTP(rec, req)
	raw := rec.Body.String()
	a.mu.Lock()
	a.bodies = append(a.bodies, raw)
	a.mu.Unlock()
	var out map[string]any
	if strings.TrimSpace(raw) != "" {
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			a.t.Fatalf("%s %s: body is not a JSON object: %q", method, path, raw)
		}
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		a.t.Errorf("%s %s: Cache-Control = %q", method, path, rec.Header().Get("Cache-Control"))
	}
	return rec.Code, out, rec.Header()
}

func subPath(impi string, rest ...string) string {
	return "/v1/subscriptions/" + url.PathEscape(impi) + strings.Join(rest, "")
}

func subscriptionBody(impi string, managed bool, impus ...string) string {
	ids := make([]string, len(impus))
	for i, impu := range impus {
		ids[i] = `{"impu":"` + impu + `","barred":false,"implicit_set":0}`
	}
	m := "false"
	if managed {
		m = "true"
	}
	return `{"impi":"` + impi + `","imsi":"` + imsi1 + `","public_identities":[` + strings.Join(ids, ",") + `],"acs_managed":` + m + `}`
}

const akaBody = `{"k":"465b5ce8b199b49faa5f0a2ee238a6bc","opc":"cd63cb71954a9f4e48a5994e37a02baf","amf":"b9b9"}`

func (a *apiEnv) create(impi string, managed bool, impus ...string) {
	a.t.Helper()
	if code, body, _ := a.do("POST", "/v1/subscriptions", adminToken, subscriptionBody(impi, managed, impus...)); code != http.StatusCreated {
		a.t.Fatalf("create = %d %v", code, body)
	}
}

func TestAPIAnswers503WhenNoTokenIsConfigured(t *testing.T) {
	a := newAPIEnv(t, func(o *APIOptions) { o.Tokens = Tokens{FT: TokenPair{Current: ftToken}} })
	for _, path := range []string{"/v1/subscriptions/" + impi1, "/v1/service-profiles/" + DefaultProfileID} {
		code, body, h := a.do("GET", path, adminToken, "")
		if code != http.StatusServiceUnavailable || body["error"] == nil || h.Get("Retry-After") == "" {
			t.Errorf("GET %s = %d %v", path, code, body)
		}
	}
	// The operation the configured token may use works.
	if code, _, _ := a.do("GET", subPath(impi1, "/ft-credential?algorithm=MD5"), ftToken, ""); code != http.StatusNotFound {
		t.Errorf("ft-credential = %d", code)
	}
}

func TestAPIAnswers401ForAMissingOrWrongToken(t *testing.T) {
	a := newAPIEnv(t)
	for name, header := range map[string]string{
		"missing":      "",
		"wrong":        "Bearer " + adminToken + "x",
		"prefix":       "Bearer " + adminToken[:20],
		"other scheme": "Basic " + adminToken,
		"empty":        "Bearer ",
	} {
		req := httptest.NewRequest("GET", subPath(impi1), nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		a.api.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("%s: %d, WWW-Authenticate %q", name, rec.Code, rec.Header().Get("WWW-Authenticate"))
		}
	}
	// Both tokens of a rotation work.
	a.create(impi1, false, impu1)
	for _, tok := range []string{adminToken, adminTokenNext} {
		if code, _, _ := a.do("GET", subPath(impi1), tok, ""); code != http.StatusOK {
			t.Errorf("rotation token: %d", code)
		}
	}
}

// The scope table of docs/api/hss-scopes.md, checked operation by
// operation: every caller outside an operation's scope gets 403.
func TestEveryOperationRefusesCallersOutsideItsScope(t *testing.T) {
	a := newAPIEnv(t)
	a.create(impi1, true, impu1)
	profile := `{"id":"p","initial_filter_criteria":[]}`
	for _, c := range []struct {
		method, path, body string
		allowed            []string
	}{
		{"POST", "/v1/subscriptions", subscriptionBody(impi2, false, impu2), []string{"admin"}},
		{"GET", subPath(impi1), "", []string{"admin", "acs"}},
		{"PUT", subPath(impi1), subscriptionBody(impi1, true, impu1), []string{"admin"}},
		{"PUT", subPath(impi1, "/aka"), akaBody, []string{"admin"}},
		{"POST", subPath(impi1, "/digest-credential"), "", []string{"admin", "acs"}},
		{"POST", subPath(impi1, "/ft-credential"), "", []string{"admin", "acs"}},
		{"GET", subPath(impi1, "/ft-credential?algorithm=SHA-256"), "", []string{"ft"}},
		{"POST", "/v1/service-profiles", profile, []string{"admin"}},
		{"GET", "/v1/service-profiles/" + DefaultProfileID, "", []string{"admin"}},
		{"PUT", "/v1/service-profiles/p", profile, []string{"admin"}},
		{"DELETE", "/v1/service-profiles/p", "", []string{"admin"}},
		{"DELETE", subPath(impi2), "", []string{"admin"}},
	} {
		for caller, tok := range map[string]string{"admin": adminToken, "acs": acsToken, "ft": ftToken} {
			code, body, _ := a.do(c.method, c.path, tok, c.body)
			if slices.Contains(c.allowed, caller) {
				if code == http.StatusForbidden || code == http.StatusUnauthorized {
					t.Errorf("%s %s by %s = %d %v", c.method, c.path, caller, code, body)
				}
			} else if code != http.StatusForbidden {
				t.Errorf("%s %s by %s = %d, want 403", c.method, c.path, caller, code)
			}
		}
	}
}

func TestACSWorksOnlyOnSubscriptionsHandedToIt(t *testing.T) {
	a := newAPIEnv(t)
	a.create(impi1, true, impu1)
	a.create(impi2, false, impu2)
	for _, c := range []struct{ method, rest string }{
		{"GET", ""}, {"POST", "/digest-credential"}, {"POST", "/ft-credential"},
	} {
		// An unmanaged subscription looks to acs exactly like a missing one,
		// so an acs token cannot tell which IMPIs exist outside its scope.
		unmanagedCode, unmanaged, _ := a.do(c.method, subPath(impi2, c.rest), acsToken, "")
		missingCode, missing, _ := a.do(c.method, subPath(impi3, c.rest), acsToken, "")
		if unmanagedCode != http.StatusNotFound || missingCode != unmanagedCode || stringify(unmanaged) != stringify(missing) {
			t.Errorf("acs %s %s: unmanaged %d %v, missing %d %v", c.method, c.rest, unmanagedCode, unmanaged, missingCode, missing)
		}
		if code, _, _ := a.do(c.method, subPath(impi2, c.rest), adminToken, ""); code >= 400 {
			t.Errorf("admin %s %s = %d", c.method, c.rest, code)
		}
	}
	if code, body, _ := a.do("GET", subPath(impi1), acsToken, ""); code != http.StatusOK || body["acs_managed"] != true {
		t.Errorf("acs read = %d %v", code, body)
	}
	if s := a.sub(impi2); s.DigestFor(domain) == nil {
		t.Error("the admin could not issue for an unmanaged subscription")
	}
}

func TestFTLookupOfAMalformedUserNameIsNotFound(t *testing.T) {
	a := newAPIEnv(t)
	for _, user := range []string{"alice", "alice@", "@" + domain, "al ice@" + domain, "al%41ice@" + domain} {
		code, body, _ := a.do("GET", subPath(user, "/ft-credential?algorithm=SHA-256"), ftToken, "")
		if code != http.StatusNotFound {
			t.Errorf("user %q = %d %v, want 404 (an unknown user, not a backend failure)", user, code, body)
		}
	}
}

func TestLocationAddressesTheCreatedSubscription(t *testing.T) {
	a := newAPIEnv(t)
	for i, impi := range []string{"a?b@" + domain, "a#b@" + domain} {
		code, _, h := a.do("POST", "/v1/subscriptions", adminToken, subscriptionBody(impi, false, []string{impu1, impu2}[i]))
		if code != http.StatusCreated {
			t.Fatalf("create = %d", code)
		}
		if got, _, _ := a.do("GET", h.Get("Location"), adminToken, ""); got != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", h.Get("Location"), got)
		}
	}
}

func TestACSTokensAreRateLimited(t *testing.T) {
	a := newAPIEnv(t, func(o *APIOptions) { o.ACSRate, o.ACSBurst = 1, 3 })
	a.create(impi1, true, impu1)
	for i := range 3 {
		if code, _, _ := a.do("GET", subPath(impi1), acsToken, ""); code != http.StatusOK {
			t.Fatalf("request %d = %d", i, code)
		}
	}
	code, _, h := a.do("GET", subPath(impi1), acsToken, "")
	if code != http.StatusTooManyRequests || h.Get("Retry-After") == "" {
		t.Fatalf("over the burst = %d", code)
	}
	// The admin is not limited, and the bucket refills.
	if code, _, _ := a.do("GET", subPath(impi1), adminToken, ""); code != http.StatusOK {
		t.Errorf("admin = %d", code)
	}
	a.advance(2 * time.Second)
	if code, _, _ := a.do("GET", subPath(impi1), acsToken, ""); code != http.StatusOK {
		t.Errorf("after refill = %d", code)
	}
	if a.metrics.get("api.rate_limited") != 1 {
		t.Error("rate limiting not counted")
	}
}

func TestEveryAuthenticatedRequestIsAudited(t *testing.T) {
	a := newAPIEnv(t)
	a.create(impi1, true, impu1)
	a.do("POST", subPath(impi1, "/digest-credential"), acsToken, "")
	a.do("GET", subPath(impi1), adminTokenNext, "")
	a.do("GET", subPath(impi1), "nope", "")
	var audits []map[string]any
	for _, line := range strings.Split(a.logs.String(), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil && rec["msg"] == "audit: provisioning request" {
			audits = append(audits, rec)
		}
	}
	if len(audits) != 4 {
		t.Fatalf("%d audit records, want 4", len(audits))
	}
	issue, next, anon := audits[1], audits[2], audits[3]
	if issue["caller"] != "acs" || issue["operation"] != "issue_ims_credential" || issue["status"] != float64(201) || issue["token"] != "current" {
		t.Errorf("issue audit = %v", issue)
	}
	if next["token"] != "next" || next["caller"] != "admin" {
		t.Errorf("rotation audit = %v", next)
	}
	if anon["caller"] != "unauthenticated" || anon["status"] != float64(401) {
		t.Errorf("unauthenticated audit = %v", anon)
	}
	logs := a.logs.String()
	if strings.Contains(logs, "15550100001") || strings.Contains(logs, imsi1) || strings.Contains(logs, adminToken) || strings.Contains(logs, acsToken) {
		t.Error("the audit log carries an identifier or a token")
	}
}

func TestSubscriptionLifecycle(t *testing.T) {
	a := newAPIEnv(t)
	code, body, h := a.do("POST", "/v1/subscriptions", adminToken,
		`{"impi":"`+impi1+`","public_identities":[{"impu":"sip:%2B15550100001@IMS.mnc001.mcc001.3gppnetwork.org","barred":false,"implicit_set":0},`+
			`{"impu":"`+tel1+`","barred":true,"implicit_set":0}],"acs_managed":false,`+
			`"charging_information":{"primary_event_charging_function_name":"aaa://ecf.`+domain+`"}}`)
	if code != http.StatusCreated || h.Get("ETag") != `"1"` || h.Get("Location") != "/v1/subscriptions/"+impi1 {
		t.Fatalf("create = %d %v %v", code, body, h)
	}
	ids := body["public_identities"].([]any)
	first := ids[0].(map[string]any)
	if first["impu"] != impu1 || first["registration_state"] != "NOT_REGISTERED" || first["identity_type"] != "PUBLIC_USER_IDENTITY" {
		t.Errorf("identity = %v: not in canonical form", first)
	}
	if body["service_profile"] != DefaultProfileID || body["version"] != float64(1) {
		t.Errorf("created = %v", body)
	}
	if code, _, _ := a.do("POST", "/v1/subscriptions", adminToken, subscriptionBody(impi1, false, impu2)); code != http.StatusConflict {
		t.Errorf("duplicate IMPI = %d", code)
	}
	if code, _, _ := a.do("POST", "/v1/subscriptions", adminToken, subscriptionBody(impi2, false, tel1)); code != http.StatusConflict {
		t.Errorf("taken IMPU = %d", code)
	}

	code, body, h = a.do("GET", subPath(impi1), adminToken, "")
	if code != http.StatusOK || h.Get("ETag") != `"1"` || body["charging_information"] == nil {
		t.Fatalf("get = %d %v", code, body)
	}

	// Replace, with and without a matching version.
	if code, _, _ := a.do("PUT", subPath(impi1), adminToken, subscriptionBody(impi1, true, impu1, impu3), "If-Match", `"7"`); code != http.StatusPreconditionFailed {
		t.Errorf("stale If-Match = %d", code)
	}
	code, body, _ = a.do("PUT", subPath(impi1), adminToken, subscriptionBody(impi1, true, impu1, impu3), "If-Match", `"1"`)
	if code != http.StatusOK || body["version"] != float64(2) || body["acs_managed"] != true || len(body["public_identities"].([]any)) != 2 {
		t.Fatalf("put = %d %v", code, body)
	}
	if _, err := a.store.SubscriptionByIMPU(context.Background(), tel1); err == nil {
		t.Error("the removed IMPU still points at the subscription")
	}
	if code, _, _ := a.do("PUT", subPath(impi1), adminToken, subscriptionBody(impi2, true, impu1)); code != http.StatusBadRequest {
		t.Errorf("IMPI in the body differs = %d", code)
	}
	if code, _, _ := a.do("PUT", subPath(impi2), adminToken, subscriptionBody(impi2, true, impu2)); code != http.StatusNotFound {
		t.Errorf("put of a missing subscription = %d", code)
	}

	if code, _, _ := a.do("DELETE", subPath(impi1), adminToken, "", "If-Match", `"1"`); code != http.StatusPreconditionFailed {
		t.Errorf("stale delete = %d", code)
	}
	if code, _, _ := a.do("DELETE", subPath(impi1), adminToken, ""); code != http.StatusNoContent {
		t.Fatalf("delete = %d", code)
	}
	if code, _, _ := a.do("GET", subPath(impi1), adminToken, ""); code != http.StatusNotFound {
		t.Errorf("get after delete = %d", code)
	}
	if code, _, _ := a.do("DELETE", subPath(impi1), adminToken, ""); code != http.StatusNotFound {
		t.Errorf("second delete = %d", code)
	}
}

func TestInvalidSubscriptionsAreRefusedWithoutQuotingThem(t *testing.T) {
	a := newAPIEnv(t)
	long := strings.Repeat("a", 300)
	ok := `{"impu":"` + impu1 + `","barred":false,"implicit_set":0}`
	many := strings.TrimSuffix(strings.Repeat(ok+",", store.MaxPublicIdentities+1), ",")
	for name, c := range map[string]struct {
		body string
		want int
	}{
		"not JSON":             {`{`, http.StatusBadRequest},
		"unknown field":        {`{"impi":"` + impi1 + `","public_identities":[` + ok + `],"secret":1}`, http.StatusBadRequest},
		"bad IMPI":             {subscriptionBody("no-realm", false, impu1), http.StatusBadRequest},
		"long IMPI":            {subscriptionBody(long+"@"+domain, false, impu1), http.StatusBadRequest},
		"bad IMSI":             {strings.Replace(subscriptionBody(impi1, false, impu1), `"imsi":"`+imsi1, `"imsi":"0010x`, 1), http.StatusBadRequest},
		"no identities":        {`{"impi":"` + impi1 + `","public_identities":[]}`, http.StatusBadRequest},
		"too many identities":  {`{"impi":"` + impi1 + `","public_identities":[` + many + `]}`, http.StatusBadRequest},
		"identity twice":       {subscriptionBody(impi1, false, impu1, impu1), http.StatusBadRequest},
		"same in two forms":    {subscriptionBody(impi1, false, impu1, "sip:%2B15550100001@"+domain), http.StatusBadRequest},
		"not a URI":            {subscriptionBody(impi1, false, "+15550100001"), http.StatusBadRequest},
		"local tel":            {subscriptionBody(impi1, false, "tel:5550100"), http.StatusBadRequest},
		"PSI":                  {`{"impi":"` + impi1 + `","public_identities":[{"impu":"` + impu1 + `","identity_type":"DISTINCT_PSI"}]}`, http.StatusBadRequest},
		"state is read-only":   {`{"impi":"` + impi1 + `","public_identities":[{"impu":"` + impu1 + `","registration_state":"REGISTERED"}]}`, http.StatusBadRequest},
		"negative set":         {`{"impi":"` + impi1 + `","public_identities":[{"impu":"` + impu1 + `","implicit_set":-1}]}`, http.StatusBadRequest},
		"bad profile ID":       {`{"impi":"` + impi1 + `","public_identities":[` + ok + `],"service_profile":"Bad Profile"}`, http.StatusBadRequest},
		"missing profile":      {`{"impi":"` + impi1 + `","public_identities":[` + ok + `],"service_profile":"nope"}`, http.StatusUnprocessableEntity},
		"charging not a URI":   {`{"impi":"` + impi1 + `","public_identities":[` + ok + `],"charging_information":{"primary_event_charging_function_name":"http://x"}}`, http.StatusBadRequest},
		"charging w/o primary": {`{"impi":"` + impi1 + `","public_identities":[` + ok + `],"charging_information":{"secondary_event_charging_function_name":"aaa://x.org"}}`, http.StatusBadRequest},
		"body too large":       {`{"impi":"` + strings.Repeat(" ", maxSubscriptionBody) + `"}`, http.StatusRequestEntityTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			code, body, _ := a.do("POST", "/v1/subscriptions", adminToken, c.body)
			if code != c.want {
				t.Fatalf("status = %d %v, want %d", code, body, c.want)
			}
			if msg, _ := body["error"].(string); msg == "" || strings.Contains(msg, "15550100001") || strings.Contains(msg, imsi1) {
				t.Errorf("error = %q", msg)
			}
		})
	}
	req := httptest.NewRequest("POST", "/v1/subscriptions", strings.NewReader(subscriptionBody(impi1, false, impu1)))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	a.api.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain body = %d", rec.Code)
	}
	if code, _, _ := a.do("GET", "/v1/subscriptions/not-an-impi", adminToken, ""); code != http.StatusBadRequest {
		t.Errorf("bad IMPI in the path = %d", code)
	}
	if code, _, _ := a.do("GET", subPath(impi1), adminToken, "", "If-Match", "7"); code != http.StatusNotFound {
		t.Errorf("If-Match on GET is ignored, got %d", code)
	}
	if code, _, _ := a.do("DELETE", subPath(impi1), adminToken, "", "If-Match", "7"); code != http.StatusBadRequest {
		t.Errorf("unquoted If-Match = %d", code)
	}
}

func TestAKAKeysAreWriteOnly(t *testing.T) {
	a := newAPIEnv(t)
	a.create(impi1, true, impu1)
	if code, _, _ := a.do("PUT", subPath(impi1, "/aka"), adminToken, akaBody); code != http.StatusNoContent {
		t.Fatalf("put aka = %d", code)
	}
	s := a.sub(impi1)
	if s.AKA == nil || s.AKA.AMF != testAMF || s.AKA.SQN != 0 {
		t.Fatalf("stored AKA = %+v", s.AKA)
	}
	k, err := a.keys.Open(s.AKA.K, aad("k", impi1))
	if err != nil || [16]byte(k) != testK {
		t.Fatalf("stored K does not open to the provisioned key: %v", err)
	}
	// OP is turned into OPc; SQN can be set.
	op := "cdc202d5123e20f62b6d676ac72cb318" // TS 35.208 test set 1 OP
	code, _, _ := a.do("PUT", subPath(impi1, "/aka"), adminToken, `{"k":"465b5ce8b199b49faa5f0a2ee238a6bc","op":"`+op+`","sqn":"000000000040"}`)
	if code != http.StatusNoContent {
		t.Fatalf("put aka with OP = %d", code)
	}
	s = a.sub(impi1)
	opc, _ := a.keys.Open(s.AKA.OPc, aad("opc", impi1))
	if [16]byte(opc) != testOPc || s.AKA.SQN != 0x40 || s.AKA.AMF != defaultAMF {
		t.Fatalf("OPc derived wrongly or SQN/AMF not set: %+v", s.AKA)
	}
	for name, body := range map[string]string{
		"both OP and OPc": `{"k":"465b5ce8b199b49faa5f0a2ee238a6bc","op":"` + op + `","opc":"` + op + `"}`,
		"neither":         `{"k":"465b5ce8b199b49faa5f0a2ee238a6bc"}`,
		"short K":         `{"k":"465b","opc":"` + op + `"}`,
		"bad AMF":         `{"k":"465b5ce8b199b49faa5f0a2ee238a6bc","opc":"` + op + `","amf":"zz"}`,
		"bad SQN":         `{"k":"465b5ce8b199b49faa5f0a2ee238a6bc","opc":"` + op + `","sqn":"1"}`,
	} {
		code, body, _ := a.do("PUT", subPath(impi1, "/aka"), adminToken, body)
		if code != http.StatusBadRequest || strings.Contains(body["error"].(string), "465b") {
			t.Errorf("%s = %d %v", name, code, body)
		}
	}
	if code, _, _ := a.do("PUT", subPath(impi2, "/aka"), adminToken, akaBody); code != http.StatusNotFound {
		t.Errorf("aka for a missing subscription = %d", code)
	}
	_, body, _ := a.do("GET", subPath(impi1), adminToken, "")
	creds := body["credentials"].(map[string]any)
	if creds["aka"] != true {
		t.Errorf("credentials = %v", creds)
	}
	for _, b := range a.bodies {
		assertNoSecrets(t, "API response", b, op)
	}
	assertNoSecrets(t, "logs", a.logs.String(), op)
}

func TestIssuedIMSCredentialAuthenticatesOverCx(t *testing.T) {
	a := newAPIEnv(t)
	a.create(impi1, true, impu1)
	code, body, _ := a.do("POST", subPath(impi1, "/digest-credential"), acsToken, "")
	if code != http.StatusCreated || body["realm"] != domain || body["username"] != impi1 {
		t.Fatalf("issue = %d %v", code, body)
	}
	pw := body["password"].(string)
	if len(pw) < 22 { // 128 bits in base64url
		t.Fatalf("password of %d characters", len(pw))
	}
	again, _, _ := a.do("POST", subPath(impi1, "/digest-credential"), acsToken, "")
	if again != http.StatusCreated {
		t.Fatal(again)
	}
	_, second, _ := a.do("POST", subPath(impi1, "/digest-credential"), acsToken, "")
	if second["password"] == pw {
		t.Error("two issues gave the same password")
	}
	pw = second["password"].(string)
	// The S-CSCF gets the HA1 of the last password.
	c := connectCSCF(t, serveHSS(t, a.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	maa := c.mar(impi1, impu1, cx.SchemeSIPDigest, 1, scscfName, nil)
	want, _ := digest.ComputeHA1(digest.SHA256, impi1, domain, []byte(pw))
	if maa.Result != resSuccess || maa.AuthDataItems[0].Digest.AlternateHA1 != want {
		t.Fatalf("MAA = %+v", maa)
	}
	// The password is in the issuing responses only, never in a log.
	if strings.Contains(a.logs.String(), pw) {
		t.Error("the password reached a log")
	}
	if _, body, _ := a.do("GET", subPath(impi1), acsToken, ""); strings.Contains(stringify(body), pw) {
		t.Error("the password is readable")
	}
}

func stringify(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestFTCredentialFollowsFtServersContract(t *testing.T) {
	a := newAPIEnv(t)
	a.do("POST", "/v1/subscriptions", adminToken,
		`{"impi":"`+impi1+`","public_identities":[{"impu":"`+tel1+`","barred":true},{"impu":"`+impu1+`"}],"acs_managed":true}`)
	if code, _, _ := a.do("GET", subPath(impi1, "/ft-credential?algorithm=MD5"), ftToken, ""); code != http.StatusNotFound {
		t.Errorf("before issue = %d", code)
	}
	code, issued, _ := a.do("POST", subPath(impi1, "/ft-credential"), acsToken, "")
	if code != http.StatusCreated || issued["realm"] != ftRealm {
		t.Fatalf("issue = %d %v", code, issued)
	}
	pw := issued["password"].(string)
	for _, alg := range []digest.Algorithm{digest.MD5, digest.SHA256} {
		code, body, _ := a.do("GET", subPath(impi1, "/ft-credential?algorithm="+string(alg)), ftToken, "")
		want, _ := digest.ComputeHA1(alg, impi1, ftRealm, []byte(pw))
		if code != http.StatusOK || body["ha1"] != want || body["impu"] != impu1 || body["impi"] != impi1 ||
			body["realm"] != ftRealm || body["algorithm"] != string(alg) {
			t.Errorf("%s: %d %v", alg, code, body)
		}
	}
	for _, q := range []string{"", "?algorithm=SHA-512-256", "?algorithm=MD5&algorithm=SHA-256", "?algorithm=md5"} {
		if code, _, _ := a.do("GET", subPath(impi1, "/ft-credential"+q), ftToken, ""); code != http.StatusBadRequest {
			t.Errorf("algorithm %q = %d", q, code)
		}
	}
	// The FT credential is not an IMS credential.
	if s := a.sub(impi1); s.DigestFor(domain) != nil {
		t.Error("issuing an FT credential created an IMS one")
	}
	if code, _, _ := a.do("GET", subPath(impi2, "/ft-credential?algorithm=MD5"), ftToken, ""); code != http.StatusNotFound {
		t.Errorf("unknown subscription = %d", code)
	}
	// Every identity barred: nobody to own the files.
	a.modify(impi1, func(s *store.Subscription) { s.PublicIdentities[1].Barred = true })
	if code, _, _ := a.do("GET", subPath(impi1, "/ft-credential?algorithm=MD5"), ftToken, ""); code != http.StatusNotFound {
		t.Errorf("all barred = %d", code)
	}
}

func TestFTCredentialsNeedAnFTRealm(t *testing.T) {
	e := newEnv(t)
	h := e.newHSS(func(o *Options) { o.FTRealm = "" })
	a := &apiEnv{env: e, api: h.NewAPI(APIOptions{Tokens: Tokens{Admin: TokenPair{Current: adminToken}, FT: TokenPair{Current: ftToken}}, DefaultProfile: DefaultProfileID})}
	a.create(impi1, true, impu1)
	if code, _, _ := a.do("POST", subPath(impi1, "/ft-credential"), adminToken, ""); code != http.StatusNotImplemented {
		t.Errorf("issue = %d", code)
	}
	if code, _, _ := a.do("GET", subPath(impi1, "/ft-credential?algorithm=MD5"), ftToken, ""); code != http.StatusNotFound {
		t.Errorf("get = %d", code)
	}
}

func TestStoreFailuresAre503SoCallersRetry(t *testing.T) {
	fs := &failingStore{Store: store.NewMemory()}
	e := newEnvWith(t, fs)
	a := &apiEnv{env: e, api: e.h.NewAPI(APIOptions{Tokens: Tokens{Admin: TokenPair{Current: adminToken}, ACS: TokenPair{Current: acsToken}, FT: TokenPair{Current: ftToken}}, DefaultProfile: DefaultProfileID})}
	a.create(impi1, true, impu1)
	fs.fail.Store(true)
	for _, c := range []struct{ method, path, token, body string }{
		{"GET", subPath(impi1), adminToken, ""},
		{"POST", "/v1/subscriptions", adminToken, subscriptionBody(impi2, false, impu2)},
		{"POST", subPath(impi1, "/digest-credential"), acsToken, ""},
		{"GET", subPath(impi1, "/ft-credential?algorithm=MD5"), ftToken, ""},
		{"DELETE", subPath(impi1), adminToken, ""},
		{"GET", "/v1/service-profiles/" + DefaultProfileID, adminToken, ""},
	} {
		code, body, h := a.do(c.method, c.path, c.token, c.body)
		if code != http.StatusServiceUnavailable || h.Get("Retry-After") == "" {
			t.Errorf("%s %s = %d %v", c.method, c.path, code, body)
		}
	}
	if strings.Contains(a.logs.String(), imsi1) {
		t.Error("the store error reached the log unredacted")
	}
}

func TestProvisioningChangesReachTheSCSCF(t *testing.T) {
	a := newAPIEnv(t)
	a.create(impi1, true, impu1, tel1)
	a.modify(impi1, func(s *store.Subscription) {
		s.ServerName = scscfName
		for i := range s.PublicIdentities {
			s.PublicIdentities[i].State = store.Registered
		}
	})
	// A new identity in the registered set: PPR with the new User-Data.
	code, body, _ := a.do("PUT", subPath(impi1), adminToken, subscriptionBody(impi1, true, impu1, tel1, impu3))
	if code != http.StatusOK {
		t.Fatalf("put = %d %v", code, body)
	}
	rtrs, pprs := a.notifier.got()
	if len(rtrs) != 0 || len(pprs) != 1 {
		t.Fatalf("%d RTRs, %d PPRs", len(rtrs), len(pprs))
	}
	doc, err := ifc.ParseSubscription(pprs[0].UserData)
	if err != nil || len(doc.ServiceProfiles[0].PublicIdentities) != 3 || pprs[0].UserName != impi1 {
		t.Fatalf("PPR User-Data: %v %+v", err, doc)
	}
	if s := a.sub(impi1); s.Identity(impu3).State != store.Registered {
		t.Error("the added identity did not take the set's state")
	}
	// A new IMS Digest password reaches the registered user's S-CSCF.
	a.do("POST", subPath(impi1, "/digest-credential"), adminToken, "")
	if _, pprs = a.notifier.got(); len(pprs) != 2 || pprs[1].AuthDataItem == nil || pprs[1].AuthDataItem.Digest == nil {
		t.Fatalf("digest PPR: %+v", pprs)
	}
	// The default identity changes: the user is deregistered to register again.
	a.do("PUT", subPath(impi1), adminToken, subscriptionBody(impi1, true, tel1, impu1))
	rtrs, _ = a.notifier.got()
	if len(rtrs) != 1 || rtrs[0].DeregistrationReason.Code != cx.ServerChange {
		t.Fatalf("RTRs: %+v", rtrs)
	}
	if s := a.sub(impi1); s.ServerName != "" || s.Identity(tel1).State != store.NotRegistered {
		t.Errorf("after the RTR: %+v", s)
	}
	// Deleting a served subscription deregisters it for good.
	a.modify(impi1, func(s *store.Subscription) {
		s.ServerName = scscfName
		for i := range s.PublicIdentities {
			s.PublicIdentities[i].State = store.Unregistered
		}
	})
	a.do("DELETE", subPath(impi1), adminToken, "")
	rtrs, _ = a.notifier.got()
	if len(rtrs) != 2 || rtrs[1].DeregistrationReason.Code != cx.PermanentTermination || rtrs[1].PublicIdentities != nil {
		t.Fatalf("delete RTR: %+v", rtrs)
	}
}

func TestServiceProfileLifecycleAndFanout(t *testing.T) {
	a := newAPIEnv(t)
	profile := `{"id":"chat","initial_filter_criteria":[{"priority":1,"trigger_point":{"condition_type_cnf":false,"spt":[{"group":[0],"method":"MESSAGE"}]},` +
		`"application_server":{"server_name":"` + asURI + `","default_handling":"SESSION_TERMINATED"}}],"mandatory_capabilities":[1]}`
	code, body, h := a.do("POST", "/v1/service-profiles", adminToken, profile)
	if code != http.StatusCreated || h.Get("ETag") != `"1"` || h.Get("Location") != "/v1/service-profiles/chat" {
		t.Fatalf("create = %d %v", code, body)
	}
	if code, _, _ := a.do("POST", "/v1/service-profiles", adminToken, profile); code != http.StatusConflict {
		t.Errorf("duplicate = %d", code)
	}
	code, body, _ = a.do("GET", "/v1/service-profiles/chat", adminToken, "")
	if code != http.StatusOK || len(body["initial_filter_criteria"].([]any)) != 1 {
		t.Fatalf("get = %d %v", code, body)
	}

	// Three subscribers use it; two are served.
	for i, impi := range []string{impi1, impi2, impi3} {
		impu := []string{impu1, impu2, impu3}[i]
		a.do("POST", "/v1/subscriptions", adminToken, `{"impi":"`+impi+`","public_identities":[{"impu":"`+impu+`"}],"service_profile":"chat"}`)
		if i < 2 {
			a.modify(impi, func(s *store.Subscription) { s.ServerName = scscfName; s.PublicIdentities[0].State = store.Registered })
		}
	}
	if code, _, _ := a.do("DELETE", "/v1/service-profiles/chat", adminToken, ""); code != http.StatusConflict {
		t.Errorf("delete in use = %d", code)
	}
	updated := strings.Replace(profile, `"MESSAGE"`, `"INVITE"`, 1)
	if code, _, _ := a.do("PUT", "/v1/service-profiles/chat", adminToken, updated, "If-Match", `"9"`); code != http.StatusPreconditionFailed {
		t.Errorf("stale put = %d", code)
	}
	code, body, _ = a.do("PUT", "/v1/service-profiles/chat", adminToken, updated, "If-Match", `"1"`)
	if code != http.StatusOK || body["version"] != float64(2) {
		t.Fatalf("put = %d %v", code, body)
	}
	for range 2 {
		select {
		case <-a.notifier.sent:
		case <-time.After(realWait):
			t.Fatal("fan-out did not push")
		}
	}
	if err := a.api.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, pprs := a.notifier.got()
	if len(pprs) != 2 {
		t.Fatalf("%d PPRs, want one per served subscriber", len(pprs))
	}
	users := []string{pprs[0].UserName, pprs[1].UserName}
	slices.Sort(users)
	if !slices.Equal(users, []string{impi1, impi2}) {
		t.Errorf("PPRs to %v", users)
	}
	doc, err := ifc.ParseSubscription(pprs[0].UserData)
	if err != nil || doc.ServiceProfiles[0].InitialFilterCriteria[0].TriggerPoint.SPTs[0].Condition != ifc.Method("INVITE") {
		t.Fatalf("PPR carries the old profile: %v %+v", err, doc)
	}
	for _, impi := range []string{impi1, impi2, impi3} {
		a.do("DELETE", subPath(impi), adminToken, "")
	}
	if code, _, _ := a.do("DELETE", "/v1/service-profiles/chat", adminToken, "", "If-Match", `"1"`); code != http.StatusPreconditionFailed {
		t.Errorf("stale delete = %d", code)
	}
	if code, _, _ := a.do("DELETE", "/v1/service-profiles/chat", adminToken, ""); code != http.StatusNoContent {
		t.Errorf("delete = %d", code)
	}
	if code, _, _ := a.do("GET", "/v1/service-profiles/chat", adminToken, ""); code != http.StatusNotFound {
		t.Errorf("get after delete = %d", code)
	}
}

func TestInvalidProfilesAreRefused(t *testing.T) {
	a := newAPIEnv(t)
	crit := func(n int, info string) string {
		items := make([]string, n)
		for i := range items {
			items[i] = `{"priority":` + strconv.Itoa(i) + `,"application_server":{"server_name":"` + asURI + `","default_handling":"SESSION_CONTINUED","service_info":"` + info + `"}}`
		}
		return strings.Join(items, ",")
	}
	for name, c := range map[string]struct {
		body string
		want int
	}{
		"bad id":           {`{"id":"Bad","initial_filter_criteria":[]}`, http.StatusBadRequest},
		"version given":    {`{"id":"p","initial_filter_criteria":[],"version":3}`, http.StatusBadRequest},
		"bad criteria":     {`{"id":"p","initial_filter_criteria":[{"priority":1}]}`, http.StatusBadRequest},
		"bad pattern":      {`{"id":"p","initial_filter_criteria":[{"priority":1,"trigger_point":{"condition_type_cnf":true,"spt":[{"group":[0],"request_uri":"\\d"}]},"application_server":{"server_name":"sip:a","default_handling":"SESSION_CONTINUED"}}]}`, http.StatusBadRequest},
		"too large":        {`{"id":"p","initial_filter_criteria":[` + crit(64, strings.Repeat("x", 2000)) + `]}`, http.StatusBadRequest},
		"capabilities":     {`{"id":"p","initial_filter_criteria":[],"optional_capabilities":[` + strings.TrimSuffix(strings.Repeat("1,", 33), ",") + `]}`, http.StatusBadRequest},
		"id differs (put)": {`{"id":"other","initial_filter_criteria":[]}`, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			method, path := "POST", "/v1/service-profiles"
			if strings.HasSuffix(name, "(put)") {
				method, path = "PUT", "/v1/service-profiles/"+DefaultProfileID
			}
			if code, body, _ := a.do(method, path, adminToken, c.body); code != c.want {
				t.Errorf("status = %d %v, want %d", code, body, c.want)
			}
		})
	}
	if code, _, _ := a.do("GET", "/v1/service-profiles/Bad", adminToken, ""); code != http.StatusBadRequest {
		t.Errorf("bad id in the path = %d", code)
	}
}

func TestAKAOverTheAPIAuthenticatesOverCx(t *testing.T) {
	a := newAPIEnv(t)
	a.create(impi1, false, impu1)
	a.do("PUT", subPath(impi1, "/aka"), adminToken, akaBody)
	c := connectCSCF(t, serveHSS(t, a.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	maa := c.mar(impi1, impu1, cx.SchemeDigestAKAv1MD5, 1, scscfName, nil)
	if maa.Result != resSuccess {
		t.Fatalf("MAA = %+v", maa)
	}
	m := milenage.New(testK, testOPc)
	if xres := m.F2([16]byte(maa.AuthDataItems[0].Authenticate[:16])); string(xres[:]) != string(maa.AuthDataItems[0].Authorization) {
		t.Error("the vector does not come from the provisioned keys")
	}
}

// setsBody is a subscription of impi with each identity in the implicit
// registration set given after it.
func setsBody(impi string, ids ...any) string {
	var parts []string
	for i := 0; i < len(ids); i += 2 {
		parts = append(parts, fmt.Sprintf(`{"impu":%q,"barred":false,"implicit_set":%d}`, ids[i], ids[i+1]))
	}
	return `{"impi":"` + impi + `","imsi":"` + imsi1 + `","public_identities":[` + strings.Join(parts, ",") + `],"acs_managed":true}`
}

// #213: provisioning that moves tel1 from set 0 to set 1, set 1 coming
// first in the subscription, sends the PPR for set 0, without tel1, and
// once it is answered, the PPR for set 1, with it (TS 29.228 §6.5.2.1).
func TestAMoveBetweenSetsPushesTheOldSetFirst(t *testing.T) {
	a := newAPIEnv(t)
	if code, body, _ := a.do("POST", "/v1/subscriptions", adminToken, setsBody(impi1, impu2, 1, impu1, 0, tel1, 0)); code != http.StatusCreated {
		t.Fatalf("create = %d %v", code, body)
	}
	a.modify(impi1, func(s *store.Subscription) {
		s.ServerName = scscfName
		for i := range s.PublicIdentities {
			s.PublicIdentities[i].State = store.Registered
		}
	})
	if code, body, _ := a.do("PUT", subPath(impi1), adminToken, setsBody(impi1, impu2, 1, tel1, 1, impu1, 0)); code != http.StatusOK {
		t.Fatalf("put = %d %v", code, body)
	}
	_, pprs := a.notifier.got()
	if len(pprs) != 2 {
		t.Fatalf("%d PPRs", len(pprs))
	}
	for i, want := range [][]string{{impu1}, {impu2, tel1}} {
		doc, err := ifc.ParseSubscription(pprs[i].UserData)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, p := range doc.ServiceProfiles[0].PublicIdentities {
			got = append(got, p.Identity)
		}
		if !slices.Equal(got, want) {
			t.Errorf("PPR %d names %v, want %v", i, got, want)
		}
	}
	if s := a.sub(impi1); s.Identity(tel1).State != store.Registered {
		t.Errorf("tel1 is %v in its new set", s.Identity(tel1).State)
	}
}

// impu4 is impi2's identity in the tests of one IMPI among two.
const impu4 = "sip:+15550100004@" + domain

// movedWithSecondUser provisions impi1 with set 0 {impu1} and set 1 {impu2,
// impu3}, and impi2 with {impu4}, all registered at one S-CSCF, then moves
// impu3 from set 1 to set 0, whose PPR goes second.
func (a *apiEnv) movedWithSecondUser(t *testing.T) {
	t.Helper()
	second := strings.Replace(setsBody(impi2, impu4, 0), imsi1, "001010000000002", 1)
	for _, b := range []string{setsBody(impi1, impu1, 0, impu2, 1, impu3, 1), second} {
		if code, body, _ := a.do("POST", "/v1/subscriptions", adminToken, b); code != http.StatusCreated {
			t.Fatalf("create = %d %v", code, body)
		}
	}
	for _, impi := range []string{impi1, impi2} {
		a.modify(impi, func(s *store.Subscription) {
			s.ServerName = scscfName
			for i := range s.PublicIdentities {
				s.PublicIdentities[i].State = store.Registered
			}
		})
	}
	if code, body, _ := a.do("PUT", subPath(impi1), adminToken, setsBody(impi1, impu1, 0, impu3, 0, impu2, 1)); code != http.StatusOK {
		t.Fatalf("put = %d %v", code, body)
	}
}

// #213: when the S-CSCF refuses the old set's PPR, as one that has lost the
// user (DIAMETER_ERROR_USER_UNKNOWN, 5001) or that does not take the data,
// impi1 is marked not registered as for any PPR (§6.2.2.1), and deregistered
// for the latter. The change's next PPR, the new set's, is not sent: the
// S-CSCF no longer holds the user. impi2, at the same S-CSCF, is untouched.
func TestAMoveWhoseFirstPPRIsRefusedStops(t *testing.T) {
	for name, c := range map[string]struct {
		result cx.Result
		rtr    bool
		metric string
	}{
		"user unknown":          {exp(cx.ErrorUserUnknown), false, "push.ppr.user_unknown"},
		"too much data":         {exp(cx.ErrorTooMuchData), true, "push.ppr.data_refused"},
		"unsupported user data": {exp(cx.ErrorNotSupportedUserData), true, "push.ppr.data_refused"},
	} {
		t.Run(name, func(t *testing.T) {
			a := newAPIEnv(t)
			a.notifier.pprErr = &RejectedError{Command: "PPR", Result: c.result}
			a.movedWithSecondUser(t)
			rtrs, pprs := a.notifier.got()
			if len(pprs) != 1 {
				t.Fatalf("%d PPRs", len(pprs))
			}
			if got := len(rtrs) == 1 && rtrs[0].UserName == impi1 && rtrs[0].DeregistrationReason.Code == cx.ServerChange; got != c.rtr || len(rtrs) > 1 {
				t.Fatalf("RTRs %+v, want SERVER_CHANGE %t", rtrs, c.rtr)
			}
			doc, err := ifc.ParseSubscription(pprs[0].UserData)
			if err != nil || len(doc.ServiceProfiles[0].PublicIdentities) != 1 || doc.ServiceProfiles[0].PublicIdentities[0].Identity != impu2 {
				t.Fatalf("the PPR sent is not set 1's: %v %+v", err, doc)
			}
			s := a.sub(impi1)
			for _, p := range s.PublicIdentities {
				if p.State != store.NotRegistered {
					t.Errorf("%s is %v", p.IMPU, p.State)
				}
			}
			if s.ServerName != "" || a.metrics.get(c.metric) != 1 {
				t.Errorf("server %q, %s %d", s.ServerName, c.metric, a.metrics.get(c.metric))
			}
			if other := a.sub(impi2); other.Identity(impu4).State != store.Registered || other.ServerName != scscfName {
				t.Errorf("impi2 changed: %+v", other)
			}
		})
	}
}

// refusingOnce refuses the first PPR with result, and then makes the store
// fail, so that marking the user not registered cannot be written.
type refusingOnce struct {
	*recordingNotifier
	result cx.Result
	fs     *failingStore
}

func (n *refusingOnce) PushProfile(ctx context.Context, r *cx.PPR) error {
	_, before := n.got()
	_ = n.recordingNotifier.PushProfile(ctx, r)
	if len(before) == 0 {
		n.fs.fail.Store(true)
		return &RejectedError{Command: "PPR", Result: n.result}
	}
	return nil
}

// Code review on #476: when the HSS cannot write that the user the S-CSCF
// refused is not registered, it has not deregistered the user, and the
// change's other pushes still go.
func TestARefusedPPRWhoseStateCannotBeWrittenLetsTheNextGo(t *testing.T) {
	for name, result := range map[string]cx.Result{
		"user unknown":          exp(cx.ErrorUserUnknown),
		"unsupported user data": exp(cx.ErrorNotSupportedUserData),
	} {
		t.Run(name, func(t *testing.T) {
			fs := &failingStore{Store: store.NewMemory()}
			e := newEnvWith(t, fs)
			id := func(impu string, set int) store.PublicIdentity {
				return store.PublicIdentity{IMPU: impu, ImplicitSet: set, State: store.Registered}
			}
			old := &store.Subscription{IMPI: impi1, IMSI: imsi1, Profile: DefaultProfileID, ServerName: scscfName,
				PublicIdentities: []store.PublicIdentity{id(impu2, 1), id(impu1, 0), id(tel1, 0)}}
			next := clone(old)
			next.PublicIdentities = []store.PublicIdentity{id(impu2, 1), id(tel1, 1), id(impu1, 0)}
			pushes := reconcile(old, next, false)
			if _, err := fs.Store.CreateSubscription(t.Context(), next); err != nil {
				t.Fatal(err)
			}
			p, err := fs.Store.Profile(t.Context(), DefaultProfileID)
			if err != nil {
				t.Fatal(err)
			}
			n := &refusingOnce{recordingNotifier: newRecorder(), result: result, fs: fs}
			e.h.notify(t.Context(), n, next, p, pushes, pushTimes{each: time.Second})
			if rtrs, pprs := n.got(); len(pprs) != 2 || len(rtrs) != 0 {
				t.Fatalf("%d PPRs, %d RTRs; want both PPRs and no RTR", len(pprs), len(rtrs))
			}
		})
	}
}

// QA on #476: an S-CSCF slow to answer the old set's PPR, past the push
// timeout, leaves the new set's PPR its own time: it is still sent.
func TestASlowAnswerLeavesTheNextPushItsOwnTime(t *testing.T) {
	const timeout = time.Second
	a := newAPIEnv(t, func(o *APIOptions) { o.PushTimeout = timeout })
	n := serveHSS(t, a.h, "hss-a.rcs.local")
	scscf := connectScriptedSCSCF(t, n, "scscf-1.rcs.local", func(i int) time.Duration {
		if i == 0 {
			return timeout + timeout/2
		}
		return 0
	})
	p := NewPusher(n.node, PusherOptions{SCSCFHostPattern: "scscf-*.rcs.local", Timeout: timeout, Metrics: a.metrics})
	a.api = a.h.NewAPI(APIOptions{
		Tokens:   Tokens{Admin: TokenPair{adminToken, adminTokenNext}, ACS: TokenPair{Current: acsToken}, FT: TokenPair{Current: ftToken}},
		Notifier: p, DefaultProfile: DefaultProfileID, PushTimeout: timeout,
	})
	if code, body, _ := a.do("POST", "/v1/subscriptions", adminToken, setsBody(impi1, impu2, 1, impu1, 0, tel1, 0)); code != http.StatusCreated {
		t.Fatalf("create = %d %v", code, body)
	}
	a.modify(impi1, func(s *store.Subscription) {
		s.ServerName = scscfName
		for i := range s.PublicIdentities {
			s.PublicIdentities[i].State = store.Registered
		}
	})
	if code, body, _ := a.do("PUT", subPath(impi1), adminToken, setsBody(impi1, impu2, 1, tel1, 1, impu1, 0)); code != http.StatusOK {
		t.Fatalf("put = %d %v", code, body)
	}
	if got := scscf.pprs.Load(); got != 2 {
		t.Fatalf("the S-CSCF got %d PPRs, want the old set's and the new set's", got)
	}
}

// connectScriptedSCSCF connects an S-CSCF to the HSS node to, which answers
// the i-th PPR with success after wait(i).
func connectScriptedSCSCF(t *testing.T, to *hssNode, host string, wait func(i int) time.Duration) *scriptedSCSCF {
	t.Helper()
	c := &scriptedSCSCF{}
	n, err := diameter.NewNode(nodeConfig(t, host, to.ln.dial))
	if err != nil {
		t.Fatal(err)
	}
	n.HandleFunc(cx.ApplicationID, cx.CodePushProfile, func(_ context.Context, _ *diameter.Peer, req *diameter.Message) (*diameter.Message, error) {
		if _, err := cx.ParsePPR(req); err != nil {
			return nil, err
		}
		time.Sleep(wait(int(c.pprs.Add(1) - 1)))
		return (&cx.PPA{Answer: cx.Answer{Result: resSuccess}}).Message(n, req)
	})
	peer, err := n.Connect(diameter.PeerConfig{Address: "hss:3868"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), realWait)
		defer cancel()
		_ = n.Shutdown(ctx)
	})
	deadline := time.Now().Add(realWait)
	for !peer.Available() || len(to.node.Peers()) == 0 || !to.node.Peers()[0].Available() {
		if time.Now().After(deadline) {
			t.Fatal("the S-CSCF did not connect")
		}
		time.Sleep(time.Millisecond)
	}
	return c
}

// scriptedSCSCF counts the PPRs it was sent.
type scriptedSCSCF struct{ pprs atomic.Int64 }

// TS 29.228 §6.2.2.1: a PPA that says the S-CSCF lost the user brings the
// HSS's state in line; one that refuses the data deregisters the user with
// SERVER_CHANGE so they register again.
func TestPPAFailuresAreActedOn(t *testing.T) {
	for name, c := range map[string]struct {
		result cx.Result
		rtr    bool
		metric string
	}{
		"user unknown":            {exp(cx.ErrorUserUnknown), false, "push.ppr.user_unknown"},
		"unsupported user data":   {exp(cx.ErrorNotSupportedUserData), true, "push.ppr.data_refused"},
		"too much data":           {exp(cx.ErrorTooMuchData), true, "push.ppr.data_refused"},
		"unable to comply (kept)": {resUnable, false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			a := newAPIEnv(t)
			a.notifier.pprErr = &RejectedError{Command: "PPR", Result: c.result}
			a.create(impi1, true, impu1)
			a.modify(impi1, func(s *store.Subscription) {
				s.ServerName, s.PublicIdentities[0].State = scscfName, store.Registered
			})
			a.do("PUT", subPath(impi1), adminToken, subscriptionBody(impi1, true, impu1, tel1))
			rtrs, pprs := a.notifier.got()
			if len(pprs) != 1 {
				t.Fatalf("%d PPRs", len(pprs))
			}
			if got := len(rtrs) == 1 && rtrs[0].DeregistrationReason.Code == cx.ServerChange; got != c.rtr {
				t.Errorf("RTRs = %+v, want SERVER_CHANGE %t", rtrs, c.rtr)
			}
			s := a.sub(impi1)
			if c.metric == "" {
				if s.Identity(impu1).State != store.Registered {
					t.Error("a PPA failure without a rule changed the state")
				}
				return
			}
			if s.Identity(impu1).State != store.NotRegistered || s.Identity(tel1).State != store.NotRegistered || s.ServerName != "" {
				t.Errorf("after the PPA: %+v", s)
			}
			if a.metrics.get(c.metric) != 1 {
				t.Errorf("%s not counted", c.metric)
			}
		})
	}
}

func TestReKeyingWithoutASequenceNumberKeepsTheCounter(t *testing.T) {
	a := newAPIEnv(t)
	a.create(impi1, true, impu1)
	if code, _, _ := a.do("PUT", subPath(impi1, "/aka"), adminToken,
		`{"k":"465b5ce8b199b49faa5f0a2ee238a6bc","opc":"cd63cb71954a9f4e48a5994e37a02baf","sqn":"000000000040"}`); code != http.StatusNoContent {
		t.Fatal(code)
	}
	if code, _, _ := a.do("PUT", subPath(impi1, "/aka"), adminToken, akaBody); code != http.StatusNoContent {
		t.Fatal(code)
	}
	if got := a.sub(impi1).AKA.SQN; got != 0x40 {
		t.Fatalf("SQN after re-keying = %#x, want 0x40 kept", got)
	}
}

// The audit slot comes from the variable a token was set in, so a rotation
// that empties HSS_*_TOKEN first still shows the next token as "next".
func TestAuditSlotFollowsTheTokenVariable(t *testing.T) {
	a := newAPIEnv(t, func(o *APIOptions) { o.Tokens.ACS = TokenPair{Next: acsToken} })
	a.create(impi1, true, impu1)
	a.do("GET", subPath(impi1), acsToken, "")
	var last map[string]any
	for _, line := range strings.Split(a.logs.String(), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil && rec["msg"] == "audit: provisioning request" {
			last = rec
		}
	}
	if last["caller"] != "acs" || last["token"] != "next" {
		t.Errorf("audit = %v", last)
	}
}

func TestDecodeStrictRefusesKeysThatDifferOnlyInCase(t *testing.T) {
	a := newAPIEnv(t)
	for _, variant := range []string{"ACS_MANAGED", "ac\u017f_managed", "acſ_managed"} {
		body := `{"impi":"` + impi1 + `","public_identities":[{"impu":"` + impu1 + `"}],"acs_managed":false,"` + variant + `":true}`
		if code, resp, _ := a.do("POST", "/v1/subscriptions", adminToken, body); code != http.StatusBadRequest {
			t.Fatalf("variant %q = %d, acs_managed %v; want 400", variant, code, resp["acs_managed"])
		}
	}
}

// silentNotifier holds every push until its context ends, as an S-CSCF
// that keeps the connection and never answers. It records when the first
// push came and the latest deadline of any.
type silentNotifier struct {
	mu       sync.Mutex
	sent     int
	first    time.Time
	deadline time.Time
}

func (n *silentNotifier) hold(ctx context.Context) error {
	d, _ := ctx.Deadline()
	n.mu.Lock()
	if n.sent == 0 {
		n.first = time.Now()
	}
	n.sent++
	if d.After(n.deadline) {
		n.deadline = d
	}
	n.mu.Unlock()
	<-ctx.Done()
	return ctx.Err()
}

func (n *silentNotifier) Deregister(ctx context.Context, _ *cx.RTR) error { return n.hold(ctx) }

func (n *silentNotifier) PushProfile(ctx context.Context, _ *cx.PPR) error { return n.hold(ctx) }

// sevenSets provisions impi1 in seven implicit sets, all registered, and a
// second profile, chat, to move it to.
func (a *apiEnv) sevenSets(t *testing.T) []any {
	t.Helper()
	ids := []any{impu1, 0, tel1, 1, impu2, 2, "tel:+15550100002", 3, impu3, 4, "tel:+15550100003", 5, impu4, 6}
	if code, body, _ := a.do("POST", "/v1/subscriptions", adminToken, setsBody(impi1, ids...)); code != http.StatusCreated {
		t.Fatalf("create = %d %v", code, body)
	}
	a.modify(impi1, func(s *store.Subscription) {
		s.ServerName = scscfName
		for i := range s.PublicIdentities {
			s.PublicIdentities[i].State = store.Registered
		}
	})
	if code, body, _ := a.do("POST", "/v1/service-profiles", adminToken, chatProfile); code != http.StatusCreated {
		t.Fatalf("profile = %d %v", code, body)
	}
	return ids
}

// chatProfile is a second service profile, chat, whose iFC sends MESSAGE
// to rcs-as.
const chatProfile = `{"id":"chat","initial_filter_criteria":[{"priority":1,"trigger_point":{"condition_type_cnf":false,"spt":[{"group":[0],"method":"MESSAGE"}]},` +
	`"application_server":{"server_name":"` + asURI + `","default_handling":"SESSION_TERMINATED"}}],"mandatory_capabilities":[1]}`

// toChat is ids moved to the chat profile: a PPR for each served set.
func toChat(ids []any) string {
	return strings.Replace(setsBody(impi1, ids...), `"acs_managed":true}`, `"acs_managed":true,"service_profile":"chat"}`, 1)
}

// #491: a change of a subscription served in seven implicit sets, at an
// S-CSCF that never answers, takes no longer than the push budget, which
// keeps the API's answer within its write timeout: the pushes left when it
// runs out are not sent, are counted and logged once, without any
// identifier in the clear, and their sets are marked stale.
func TestAChangesPushesStayWithinTheBudget(t *testing.T) {
	const each, budget, reserve = 200 * time.Millisecond, 600 * time.Millisecond, 50 * time.Millisecond
	silent := &silentNotifier{}
	a := newAPIEnv(t, func(o *APIOptions) {
		o.Notifier, o.PushTimeout, o.PushBudget, o.staleReserve = silent, each, budget, reserve
	})
	ids := a.sevenSets(t)
	if code, body, _ := a.do("PUT", subPath(impi1), adminToken, toChat(ids)); code != http.StatusOK {
		t.Fatalf("put = %d %v", code, body)
	}
	silent.mu.Lock()
	defer silent.mu.Unlock()
	sent, skipped := int64(silent.sent), a.metrics.get("push.over_budget")
	// The first PPR has its timeout and the second what is left before the
	// end, less a timeout kept for a refusal's follow-up: the five after
	// have less than pushFloor.
	if sent+skipped != 7 || sent > 2 {
		t.Fatalf("%d pushes sent, %d left over budget; want the seven, at most two sent", sent, skipped)
	}
	// No push had longer than the budget, less what it keeps, from the
	// change's start, which is before the first push: the deadlines are
	// compared, not the time the host took (#275).
	if late := silent.deadline.Sub(silent.first.Add(budget - reserve - each)); late > 0 {
		t.Errorf("a push's deadline is %v past what the budget leaves it", late)
	}
	if s := a.sub(impi1); len(s.StaleSets) != int(skipped) {
		t.Errorf("stale sets %v, %d pushes left over", s.StaleSets, skipped)
	}
	var lines []string
	for _, l := range strings.Split(a.logs.String(), "\n") {
		if strings.Contains(l, "ran out of time") {
			lines = append(lines, l)
		}
	}
	if len(lines) != 1 || !strings.Contains(lines[0], `"left":`+strconv.FormatInt(skipped, 10)) || !strings.Contains(lines[0], `"impi":"***`) {
		t.Fatalf("over-budget log lines %q", lines)
	}
	for _, clear := range []string{impi1, imsi1, "15550100", domain} {
		if strings.Contains(lines[0], clear) {
			t.Errorf("the log line names %q in the clear: %s", clear, lines[0])
		}
	}
}

// #491, the lead's decision on #524: what an over-budget change left out
// reaches the S-CSCF with the next registration of each set, though the
// S-CSCF says it holds the data (TS 29.228 §6.6), once.
func TestAStaleSetsNextRegistrationGetsItsUserData(t *testing.T) {
	const each, budget, reserve = 200 * time.Millisecond, 600 * time.Millisecond, 50 * time.Millisecond
	silent := &silentNotifier{}
	a := newAPIEnv(t, func(o *APIOptions) {
		o.Notifier, o.PushTimeout, o.PushBudget, o.staleReserve = silent, each, budget, reserve
	})
	ids := a.sevenSets(t)
	if code, body, _ := a.do("PUT", subPath(impi1), adminToken, toChat(ids)); code != http.StatusOK {
		t.Fatalf("put = %d %v", code, body)
	}
	s := a.sub(impi1)
	if len(s.StaleSets) == 0 || !slices.Contains(s.StaleSets, 6) {
		t.Fatalf("stale sets %v", s.StaleSets)
	}
	c := connectCSCF(t, serveHSS(t, a.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	reregister := func() *cx.SAA {
		r := &cx.SAR{Request: cx.Request{DestinationRealm: domain}, UserName: impi1, PublicIdentities: []string{impu4},
			ServerName: scscfName, AssignmentType: cx.ReRegistration, UserDataAlreadyAvailable: cx.UserDataAlreadyAvailable}
		saa, err := cx.ParseSAA(c.send(r.Message(c.node)))
		if err != nil {
			t.Fatal(err)
		}
		return saa
	}
	saa := reregister() // impu4's set, 6, was left over
	if saa.Result != resSuccess || saa.UserData == nil {
		t.Fatalf("the stale set's re-registration got %+v", saa)
	}
	doc, err := ifc.ParseSubscription(saa.UserData)
	if err != nil || len(doc.ServiceProfiles) != 1 || len(doc.ServiceProfiles[0].InitialFilterCriteria) != 1 ||
		doc.ServiceProfiles[0].InitialFilterCriteria[0].ApplicationServer.ServerName != asURI {
		t.Fatalf("User-Data %v %+v, want chat's", err, doc)
	}
	if s := a.sub(impi1); slices.Contains(s.StaleSets, 6) {
		t.Errorf("set 6 still stale: %v", s.StaleSets)
	}
	if saa := reregister(); saa.UserData != nil {
		t.Error("User-Data again, once the set had it")
	}
}

// Code review on #524: the shared profile's fan-out runs in the background
// and answers no request, so it has no budget: a subscriber's pushes each
// have the push timeout, however long they all take.
func TestTheFanOutHasNoBudget(t *testing.T) {
	slow := &slowNotifier{wait: 50 * time.Millisecond}
	a := newAPIEnv(t, func(o *APIOptions) {
		o.Notifier, o.PushTimeout, o.PushBudget, o.staleReserve = slow, time.Second, 100*time.Millisecond, 10*time.Millisecond
	})
	ids := a.sevenSets(t)
	if code, body, _ := a.do("PUT", subPath(impi1), adminToken, toChat(ids)); code != http.StatusOK {
		t.Fatalf("put = %d %v", code, body)
	}
	before := slow.count()
	updated := strings.Replace(chatProfile, `"MESSAGE"`, `"INVITE"`, 1)
	if code, body, _ := a.do("PUT", "/v1/service-profiles/chat", adminToken, updated, "If-Match", `"1"`); code != http.StatusOK {
		t.Fatalf("profile put = %d %v", code, body)
	}
	deadline := time.Now().Add(realWait)
	for slow.count()-before < 7 {
		if time.Now().After(deadline) {
			t.Fatalf("the fan-out pushed %d of the seven sets", slow.count()-before)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// slowNotifier answers every push after wait.
type slowNotifier struct {
	wait time.Duration
	mu   sync.Mutex
	n    int
}

func (n *slowNotifier) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.n
}

func (n *slowNotifier) Deregister(_ context.Context, _ *cx.RTR) error { return n.answer() }

func (n *slowNotifier) PushProfile(_ context.Context, _ *cx.PPR) error { return n.answer() }

func (n *slowNotifier) answer() error {
	time.Sleep(n.wait)
	n.mu.Lock()
	n.n++
	n.mu.Unlock()
	return nil
}

// #491: HSS_PUSH_TIMEOUT is at most MaxPushTimeout, so that a PPR and what
// its refusal brings fit in the change's budget, and HSS_API_TIMEOUT at most
// MaxAPITimeout, so that the change's store work and the budget fit in the
// API's write timeout.
func TestThePushTimeoutIsBounded(t *testing.T) {
	if 2*MaxPushTimeout+staleReserve > PushBudget || MaxAPITimeout+PushBudget >= apiWriteTimeout {
		t.Fatalf("timeout %v, budget %v, store work %v, write timeout %v", MaxPushTimeout, PushBudget, MaxAPITimeout, apiWriteTimeout)
	}
}
