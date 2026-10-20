package hss

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/hss/ifcjson"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

func TestDefaultProfileEvaluatesWithinHalfTheWorkBudget(t *testing.T) {
	set, err := ifc.Compile(DefaultRCSProfile(DefaultProfileID, asURI).Criteria)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkWork(set, ifc.Limits{MaxWork: ifc.DefaultMaxWork / 2}); err != nil {
		t.Fatalf("the default profile needs more than half the S-CSCF's budget: %v", err)
	}
}

func TestDefaultProfileSendsRCSTrafficToRCSAS(t *testing.T) {
	set, err := ifc.Compile(DefaultRCSProfile(DefaultProfileID, asURI).Criteria)
	if err != nil {
		t.Fatal(err)
	}
	reqs := map[string]*refRequest{}
	for _, r := range referenceRequests() {
		reqs[r.method] = r
	}
	options := *reqs["INVITE"]
	options.method = "OPTIONS"
	plainInvite := *reqs["INVITE"]
	plainInvite.headers = slices.DeleteFunc(slices.Clone(plainInvite.headers), func(h ifc.HeaderField) bool {
		return h.Name == "Contact" || h.Name == "Accept-Contact" || h.Name == "P-Preferred-Service"
	})
	for name, c := range map[string]struct {
		req  ifc.Request
		want []int
	}{
		"chat INVITE":      {reqs["INVITE"], []int{10}},
		"MESSAGE":          {reqs["MESSAGE"], []int{20}},
		"REGISTER":         {reqs["REGISTER"], []int{40}},
		"RCS OPTIONS":      {&options, []int{30}},
		"INVITE for voice": {&plainInvite, nil},
	} {
		for _, ctx := range referenceContexts {
			matched, err := set.Match(c.req, ctx)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			var got []int
			for _, fc := range matched {
				got = append(got, fc.Priority)
				if fc.ApplicationServer.ServerName != asURI {
					t.Errorf("%s goes to %s", name, fc.ApplicationServer.ServerName)
				}
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("%s in case %d: priorities %v, want %v", name, ctx.Case, got, c.want)
			}
		}
	}
}

// A request rcs-as sends itself carries a P-Served-User (servedUserHeader),
// and no trigger sends it back to rcs-as, in any session case; without the
// header the same request still goes there. A delivery that came back to
// rcs-as would be stored and sent again for ever (#137).
func TestDefaultProfileSkipsRCSASForARequestItServed(t *testing.T) {
	set, err := ifc.Compile(DefaultRCSProfile(DefaultProfileID, asURI).Criteria)
	if err != nil {
		t.Fatal(err)
	}
	options := *referenceByMethod(t, "INVITE")
	options.method = "OPTIONS"
	for _, r := range []*refRequest{referenceByMethod(t, "INVITE"), referenceByMethod(t, "MESSAGE"), referenceByMethod(t, "REGISTER"), &options} {
		for _, name := range []string{"P-Served-User", "p-served-user"} {
			served := *r
			served.headers = append(slices.Clone(r.headers),
				ifc.HeaderField{Name: name, Value: "<" + refPeer + ">;sescase=term;regstate=reg"})
			for _, ctx := range referenceContexts {
				matched, err := set.Match(&served, ctx)
				if err != nil {
					t.Fatalf("%s: %v", r.method, err)
				}
				if len(matched) != 0 {
					t.Errorf("%s with %s in case %d goes to %s", r.method, name, ctx.Case, matched[0].ApplicationServer.ServerName)
				}
				if plain, err := set.Match(r, ctx); err != nil || len(plain) != 1 {
					t.Errorf("%s without it in case %d: %d criteria, %v", r.method, ctx.Case, len(plain), err)
				}
			}
		}
	}
}

func referenceByMethod(t *testing.T, method string) *refRequest {
	t.Helper()
	for _, r := range referenceRequests() {
		if r.method == method {
			return r
		}
	}
	t.Fatalf("no reference %s", method)
	return nil
}

func TestReferenceRegisterHasA2KBContact(t *testing.T) {
	for _, r := range referenceRequests() {
		if r.method != "REGISTER" {
			continue
		}
		for _, h := range r.headers {
			if h.Name == "Contact" && (len(h.Value) < 2048 || len(h.Value) > 2200) {
				t.Errorf("Contact of %d bytes", len(h.Value))
			}
		}
	}
}

func TestProfileBeyondTheWorkBudgetIsRefusedWithTheLimitName(t *testing.T) {
	a := newAPIEnv(t)
	spt := `{"group":[0],"sip_header":{"header":"Contact","content":"x[ab]{200}y"}}`
	items := make([]string, 4)
	for i := range items {
		items[i] = `{"priority":` + string(rune('1'+i)) + `,"trigger_point":{"condition_type_cnf":false,"spt":[` + spt + `]},` +
			`"application_server":{"server_name":"` + asURI + `","default_handling":"SESSION_CONTINUED"}}`
	}
	code, body, _ := a.do("POST", "/v1/service-profiles", adminToken, `{"id":"costly","initial_filter_criteria":[`+strings.Join(items, ",")+`]}`)
	if code != http.StatusBadRequest || !strings.Contains(body["error"].(string), "MaxWork") {
		t.Fatalf("costly profile = %d %v", code, body)
	}
}

func TestProfileWithAPatternGoReadsDifferentlyFromPOSIXIsRefusedNamingTheConstruct(t *testing.T) {
	a := newAPIEnv(t)
	// The contents are JSON strings, so each backslash is written twice.
	for content, construct := range map[string]string{
		`[\\.]com`: "a backslash inside a bracket expression",
		`\\x41`:    `the escape \x`,
	} {
		profile := `{"id":"corner","initial_filter_criteria":[{"priority":1,"trigger_point":{"condition_type_cnf":false,"spt":[` +
			`{"group":[0],"sip_header":{"header":"Subject","content":"` + content + `"}}]},` +
			`"application_server":{"server_name":"` + asURI + `","default_handling":"SESSION_CONTINUED"}}]}`
		code, body, _ := a.do("POST", "/v1/service-profiles", adminToken, profile)
		if msg, _ := body["error"].(string); code != http.StatusBadRequest || !strings.Contains(msg, construct) {
			t.Errorf("%s: %d %v, want 400 naming %s", content, code, body, construct)
		}
	}
}

func TestProfileWithAPatternOverMaxPatternBytesIsRefusedNamingTheLimit(t *testing.T) {
	a := newAPIEnv(t)
	profile := `{"id":"long","initial_filter_criteria":[{"priority":1,"trigger_point":{"condition_type_cnf":false,"spt":[` +
		`{"group":[0],"sip_header":{"header":"Subject","content":"` + strings.Repeat("a", ifc.MaxPatternBytes+1) + `"}}]},` +
		`"application_server":{"server_name":"` + asURI + `","default_handling":"SESSION_CONTINUED"}}]}`
	code, body, _ := a.do("POST", "/v1/service-profiles", adminToken, profile)
	if msg, _ := body["error"].(string); code != http.StatusBadRequest || !strings.Contains(msg, "MaxPatternBytes") {
		t.Fatalf("%d %v, want 400 naming MaxPatternBytes", code, body)
	}
}

func TestProfileCostlierToCompileThanMaxSetCompileCostIsRefusedNamingTheLimit(t *testing.T) {
	a := newAPIEnv(t)
	items := make([]string, 12)
	for i := range items {
		items[i] = `{"priority":` + strconv.Itoa(i+1) + `,"trigger_point":{"condition_type_cnf":false,"spt":[` +
			`{"group":[0],"request_uri":"` + strings.Repeat("[^a]", ifc.MaxPatternBytes/4) + `"}]},` +
			`"application_server":{"server_name":"` + asURI + `","default_handling":"SESSION_CONTINUED"}}`
	}
	code, body, _ := a.do("POST", "/v1/service-profiles", adminToken, `{"id":"slow","initial_filter_criteria":[`+strings.Join(items, ",")+`]}`)
	if msg, _ := body["error"].(string); code != http.StatusBadRequest || !strings.Contains(msg, "MaxSetCompileCost") {
		t.Fatalf("%d %v, want 400 naming MaxSetCompileCost", code, body)
	}
}

func TestCostlyProfileIsAcceptedWithAWarning(t *testing.T) {
	a := newAPIEnv(t)
	// Two counted repetitions over the 2 KB Contact cost about 340 000
	// units each: more than half the budget together, but within it.
	spt := `{"group":[0],"sip_header":{"header":"Contact","content":"x[ab]{160}y"}}`
	crit := func(p string) string {
		return `{"priority":` + p + `,"trigger_point":{"condition_type_cnf":false,"spt":[` + spt + `]},` +
			`"application_server":{"server_name":"` + asURI + `","default_handling":"SESSION_CONTINUED"}}`
	}
	body := `{"id":"costly","initial_filter_criteria":[` + crit("1") + `,` + crit("2") + `]}`
	code, resp, _ := a.do("POST", "/v1/service-profiles", adminToken, body)
	if code != http.StatusCreated {
		t.Fatalf("costly profile = %d %v", code, resp)
	}
	warnings, _ := resp["warnings"].([]any)
	if len(warnings) != 1 || !strings.Contains(warnings[0].(string), "MaxWork") {
		t.Fatalf("warnings = %v", resp["warnings"])
	}
	if a.metrics.get("profile.costly") != 1 || !strings.Contains(a.logs.String(), "costly service profile") {
		t.Error("the warning was not logged and counted")
	}
	// The default profile gets none.
	_, resp, _ = a.do("PUT", "/v1/service-profiles/"+DefaultProfileID, adminToken,
		stringify(profileResponse(DefaultRCSProfile(DefaultProfileID, asURI), nil).profileJSON))
	if resp["warnings"] != nil {
		t.Errorf("default profile warnings = %v", resp["warnings"])
	}
}

// A write compiles the profile's criteria once (#120): the work check, the
// store's validation and the cost warning use the compiled set instead of
// compiling again, where they used to compile it four times. The warning
// still comes, so the set it needs was there.
func TestAProfileWriteCompilesItsCriteriaOnce(t *testing.T) {
	a := newAPIEnv(t)
	compiles := 0
	compileProfile = func(criteria []ifc.FilterCriteria) (*ifc.Set, error) {
		compiles++
		return ifc.Compile(criteria)
	}
	t.Cleanup(func() { compileProfile = ifc.Compile })
	spt := `{"group":[0],"sip_header":{"header":"Contact","content":"x[ab]{160}y"}}`
	crit := func(p string) string {
		return `{"priority":` + p + `,"trigger_point":{"condition_type_cnf":false,"spt":[` + spt + `]},` +
			`"application_server":{"server_name":"` + asURI + `","default_handling":"SESSION_CONTINUED"}}`
	}
	body := `{"id":"once","initial_filter_criteria":[` + crit("1") + `,` + crit("2") + `]}`
	for _, w := range []struct{ method, path string }{{"POST", "/v1/service-profiles"}, {"PUT", "/v1/service-profiles/once"}} {
		compiles = 0
		code, resp, _ := a.do(w.method, w.path, adminToken, body)
		if code != http.StatusCreated && code != http.StatusOK {
			t.Fatalf("%s = %d %v", w.method, code, resp)
		}
		if warnings, _ := resp["warnings"].([]any); len(warnings) != 1 {
			t.Fatalf("%s: warnings %v, want the cost warning", w.method, resp["warnings"])
		}
		if compiles != 1 {
			t.Errorf("%s compiled the criteria %d times, want once", w.method, compiles)
		}
	}
}

// compileProfile is the only compile of a write (#120): its criteria do not
// compile, so any other compile (ToIFC, the store, the cost warning) would
// refuse them, while the injected compile hands over a set compiled from
// costly but valid criteria, whose cost warning must come back (QA's test
// from the review of #125).
func TestTheInjectedCompileIsTheOnlyCompileOfAWrite(t *testing.T) {
	a := newAPIEnv(t)
	var valid []ifc.FilterCriteria
	for _, p := range []int{1, 2} {
		valid = append(valid, ifc.FilterCriteria{Priority: p,
			TriggerPoint:      &ifc.TriggerPoint{SPTs: []ifc.SPT{{Groups: []int{0}, Condition: ifc.SIPHeader{Header: "Contact", Content: "x[ab]{160}y"}}}},
			ApplicationServer: ifc.ApplicationServer{ServerName: asURI, DefaultHandling: ifc.SessionContinued}})
	}
	compiles := 0
	compileProfile = func([]ifc.FilterCriteria) (*ifc.Set, error) { compiles++; return ifc.Compile(valid) }
	t.Cleanup(func() { compileProfile = ifc.Compile })
	bad := ifcjson.FromIFC(valid)
	u := "(unclosed"
	bad[0].TriggerPoint.SPTs[0] = ifcjson.SPT{Groups: []int{0}, RequestURI: &u}
	enc, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"id":"once","initial_filter_criteria":` + string(enc) + `}`
	for _, w := range []struct{ method, path string }{{"POST", "/v1/service-profiles"}, {"PUT", "/v1/service-profiles/once"}} {
		compiles = 0
		code, resp, _ := a.do(w.method, w.path, adminToken, body)
		if code != http.StatusCreated && code != http.StatusOK {
			t.Fatalf("%s = %d %v: something besides compileProfile compiled the criteria", w.method, code, resp)
		}
		if ws, _ := resp["warnings"].([]any); len(ws) != 1 || !strings.Contains(ws[0].(string), "MaxWork") {
			t.Fatalf("%s: warnings %v, want the cost warning of the injected set", w.method, resp["warnings"])
		}
		if compiles != 1 {
			t.Errorf("%s: %d compiles, want 1", w.method, compiles)
		}
	}
}
