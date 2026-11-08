package hss

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

const chatbotAS = "sip:rcs-as.rcs.local;transport=tcp"

func newChatbotAPIEnv(t *testing.T) *apiEnv {
	return newAPIEnv(t, func(o *APIOptions) { o.ChatbotDomain, o.ChatbotASName = testChatbotDomain(t), chatbotAS })
}

func psiBody(psi string) string { return `{"psi":"` + strings.ReplaceAll(psi, `\`, `\\`) + `"}` }

// psiAudits returns the audit records of PUT /v1/chatbot-psi.
func (a *apiEnv) psiAudits() []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(a.logs.String(), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil && rec["operation"] == "put_chatbot_psi" {
			out = append(out, rec)
		}
	}
	return out
}

func TestTheChatbotPSIIsWrittenOnceAndReplacedWithAnAuditLine(t *testing.T) {
	a := newChatbotAPIEnv(t)
	if code, _, _ := a.do("GET", "/v1/chatbot-psi", adminToken, ""); code != http.StatusNotFound {
		t.Fatalf("GET before any write = %d", code)
	}
	code, body, h := a.do("PUT", "/v1/chatbot-psi", adminToken, psiBody(chatbotPSI))
	if code != http.StatusCreated || body["psi"] != chatbotPSI || body["server_name"] != chatbotAS || body["active"] != true || body["version"] != float64(1) || h.Get("ETag") != `"1"` {
		t.Fatalf("first PUT = %d %v, ETag %q", code, body, h.Get("ETag"))
	}
	if code, got, _ := a.do("GET", "/v1/chatbot-psi", adminToken, ""); code != http.StatusOK || got["psi"] != chatbotPSI {
		t.Fatalf("GET = %d %v", code, got)
	}
	narrower := "sip:![a-z0-9-]{1,32}!@" + botDomain
	if code, body, _ := a.do("PUT", "/v1/chatbot-psi", adminTokenNext, psiBody(narrower)); code != http.StatusOK || body["psi"] != narrower || body["version"] != float64(2) {
		t.Fatalf("second PUT = %d %v", code, body)
	}
	if code, _, _ := a.do("PUT", "/v1/chatbot-psi", adminToken, psiBody(chatbotPSI), "If-Match", `"1"`); code != http.StatusPreconditionFailed {
		t.Errorf("PUT of an old version = %d, want 412", code)
	}
	// The request names the PSI only: the AS name is the configured one.
	if code, _, _ := a.do("PUT", "/v1/chatbot-psi", adminToken, `{"psi":"`+narrower+`","server_name":"sip:evil.example.net"}`); code != http.StatusBadRequest {
		t.Errorf("PUT with a server_name = %d, want 400", code)
	}

	audits := a.psiAudits()
	if len(audits) != 4 {
		t.Fatalf("%d audit records, want 4", len(audits))
	}
	first, second := audits[0], audits[1]
	if first["caller"] != "admin" || first["token"] != "current" || first["psi_before"] != "" || first["psi_version"] != float64(1) {
		t.Errorf("first write's audit = %v", first)
	}
	// Masked, the values differ only by their keyed hints, which an
	// unkeyed test redactor leaves out; the version tells the writes apart.
	if second["token"] != "next" || second["psi_before"] != first["psi_after"] || second["psi_after"] == "" || second["psi_version"] != float64(2) {
		t.Errorf("replacement's audit = %v, after the first %v", second, first)
	}
	if _, ok := audits[2]["psi_after"]; ok || audits[2]["status"] != float64(412) {
		t.Errorf("a refused write's audit = %v", audits[2])
	}
	if logs := a.logs.String(); strings.Contains(logs, "{1,63}") || strings.Contains(logs, "{1,32}") {
		t.Error("the audit log carries a PSI unmasked")
	}
}

func TestAPSIOutsideTheRulesIsRefusedWithoutQuotingIt(t *testing.T) {
	a := newChatbotAPIEnv(t)
	for name, psi := range map[string]string{
		"another host":   "sip:!secretbot!@" + domain,
		"not an ERE":     "sip:!(secretbot!@" + botDomain,
		"Perl syntax":    "sip:!(?i)secretbot!@" + botDomain,
		"over 256 bytes": "sip:!secretbot" + strings.Repeat("a", 256) + "!@" + botDomain,
	} {
		code, body, _ := a.do("PUT", "/v1/chatbot-psi", adminToken, psiBody(psi))
		if msg, _ := body["error"].(string); code != http.StatusBadRequest || !strings.HasPrefix(msg, "psi: ") || strings.Contains(msg, "secretbot") {
			t.Errorf("%s: %d %v", name, code, body)
		}
	}
	if code, _, _ := a.do("GET", "/v1/chatbot-psi", adminToken, ""); code != http.StatusNotFound {
		t.Errorf("a refused PSI was stored: GET = %d", code)
	}
}

func TestNoIMPUMayBeAtTheChatbotHost(t *testing.T) {
	a := newChatbotAPIEnv(t)
	for name, impu := range map[string]string{
		"the host":                 "sip:bot@" + botDomain,
		"the host in another case": "sip:bot@" + strings.ToUpper(botDomain),
		"sips":                     "sips:bot@" + botDomain,
		"a trailing dot":           "sip:bot@" + botDomain + ".",
		"an escaped user part":     "sip:b%6Ft@" + botDomain,
	} {
		code, body, _ := a.do("POST", "/v1/subscriptions", adminToken, subscriptionBody(impi1, false, impu1, impu))
		if msg, _ := body["error"].(string); code != http.StatusBadRequest || !strings.Contains(msg, "RCS_CHATBOT_DOMAIN") {
			t.Errorf("create with %s: %d %v", name, code, body)
		}
	}
	// Other hosts, a subdomain of the chatbot host among them, are IMPUs as before.
	a.create(impi1, false, impu1, "sip:bot@x."+botDomain, "tel:+15550100001")
	code, body, _ := a.do("PUT", subPath(impi1), adminToken, subscriptionBody(impi1, false, impu1, "sip:bot@"+botDomain))
	if code != http.StatusBadRequest || !strings.Contains(body["error"].(string), "RCS_CHATBOT_DOMAIN") {
		t.Fatalf("put adding an IMPU at the host = %d %v", code, body)
	}
	if s, err := a.store.Subscription(t.Context(), impi1); err != nil || len(s.PublicIdentities) != 3 {
		t.Fatalf("after the refused put: %+v, %v", s, err)
	}
}

// TestWithoutAChatbotDomainTheHSSIsAsOnMain: no PSI can be written, and an
// IMPU at what would be the chatbot host is provisioned as any other.
func TestWithoutAChatbotDomainTheHSSIsAsOnMain(t *testing.T) {
	a := newAPIEnv(t)
	code, body, _ := a.do("PUT", "/v1/chatbot-psi", adminToken, psiBody(chatbotPSI))
	if code != http.StatusConflict || !strings.Contains(body["error"].(string), "RCS_CHATBOT_DOMAIN") {
		t.Errorf("PUT = %d %v, want 409", code, body)
	}
	if code, _, _ := a.do("GET", "/v1/chatbot-psi", adminToken, ""); code != http.StatusNotFound {
		t.Errorf("GET = %d, want 404", code)
	}
	a.create(impi1, false, impu1, "sip:bot@"+botDomain)
}

func TestRunGivesTheAPITheChatbotDomainAndASName(t *testing.T) {
	cfg, err := configure(with(devEnv, "RCS_CHATBOT_DOMAIN", botDomain, "HSS_RCS_AS_URI", chatbotAS))
	if err != nil {
		t.Fatal(err)
	}
	_, addrs, cancel, done := startRun(t, cfg, defaultDeps())
	defer func() { cancel(); <-done }()
	req, _ := http.NewRequest("PUT", "http://"+addrs[1]+"/v1/chatbot-psi", strings.NewReader(psiBody(chatbotPSI)))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: realWait + time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got psiResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil || resp.StatusCode != http.StatusCreated || got.ServerName != chatbotAS {
		t.Fatalf("PUT through Run = %d %+v, %v", resp.StatusCode, got, err)
	}
}
