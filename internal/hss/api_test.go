package hss

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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

// recordingNotifier records the RTRs and PPRs the API causes.
type recordingNotifier struct {
	mu   sync.Mutex
	rtrs []*cx.RTR
	pprs []*cx.PPR
	sent chan struct{}
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
	n.mu.Unlock()
	n.sent <- struct{}{}
	return nil
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
		Tokens:         Tokens{Admin: []string{adminToken, adminTokenNext}, ACS: []string{acsToken}, FT: []string{ftToken}},
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
	a := newAPIEnv(t, func(o *APIOptions) { o.Tokens = Tokens{FT: []string{ftToken}} })
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
	for _, path := range []string{subPath(impi2), subPath(impi2, "/digest-credential"), subPath(impi2, "/ft-credential")} {
		method := "POST"
		if path == subPath(impi2) {
			method = "GET"
		}
		if code, _, _ := a.do(method, path, acsToken, ""); code != http.StatusForbidden {
			t.Errorf("acs %s %s = %d, want 403", method, path, code)
		}
		if code, _, _ := a.do(method, path, adminToken, ""); code == http.StatusForbidden {
			t.Errorf("admin %s %s = 403", method, path)
		}
	}
	if code, body, _ := a.do("GET", subPath(impi1), acsToken, ""); code != http.StatusOK || body["acs_managed"] != true {
		t.Errorf("acs read = %d %v", code, body)
	}
	if s := a.sub(impi2); s.DigestFor(domain) == nil {
		t.Error("the admin could not issue for an unmanaged subscription")
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
	a := &apiEnv{env: e, api: h.NewAPI(APIOptions{Tokens: Tokens{Admin: []string{adminToken}, FT: []string{ftToken}}, DefaultProfile: DefaultProfileID})}
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
	a := &apiEnv{env: e, api: e.h.NewAPI(APIOptions{Tokens: Tokens{Admin: []string{adminToken}, ACS: []string{acsToken}, FT: []string{ftToken}}, DefaultProfile: DefaultProfileID})}
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
