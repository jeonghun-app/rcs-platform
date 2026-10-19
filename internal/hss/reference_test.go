package hss

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

func TestDefaultProfileEvaluatesWithinHalfTheWorkBudget(t *testing.T) {
	p := DefaultRCSProfile(DefaultProfileID, asURI)
	if err := checkWork(p.Criteria, ifc.Limits{MaxWork: ifc.DefaultMaxWork / 2}); err != nil {
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
