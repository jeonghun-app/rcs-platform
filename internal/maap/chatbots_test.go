package maap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

const botURI = "sip:bot-1.acme@" + botDomain

// failingRegistry answers every call with err.
type failingRegistry struct{ err error }

func (f failingRegistry) Register(context.Context, store.Chatbot) (store.Chatbot, error) {
	return store.Chatbot{}, f.err
}
func (f failingRegistry) Chatbot(context.Context, string) (store.Chatbot, error) {
	return store.Chatbot{}, f.err
}
func (f failingRegistry) Update(context.Context, store.Chatbot, store.Chatbot) (store.Chatbot, error) {
	return store.Chatbot{}, f.err
}
func (f failingRegistry) DeleteChatbot(context.Context, string) error { return f.err }

// chatbotAPIOver is the internal API with the registry routes over r, as
// in staging and prod (https webhooks only), with 8443 as a webhook port.
func chatbotAPIOver(t *testing.T, r store.Registry) (*internalAPI, *runtimetest.Harness) {
	h := runtimetest.New(t, "maap")
	a := newInternalAPI(TokenPair{Current: secret.NewString(operatorToken)}, newDecoder(2, h.Runtime.Metrics), h.Runtime)
	d, err := chatbot.NewDomain(botDomain, imsDomain)
	if err != nil {
		t.Fatal(err)
	}
	a.mountChatbots(&chatbotAPI{decoder: a.decoder, registry: r, domain: d, rules: fieldRules{ports: []uint16{8443}}})
	return a, h
}

// operator sends the operator's request.
func operator(a *internalAPI, method, path, body string) *httptest.ResponseRecorder {
	return serve(a, method, path, &trackedBody{Reader: strings.NewReader(body)}, "Bearer "+operatorToken)
}

// registration is a body registering id at uri with the JSON members more.
func registration(id, uri, more string) string {
	return fmt.Sprintf(`{"id":%q,"uri":%q%s}`, id, uri, more)
}

func decodeChatbot(t *testing.T, rec *httptest.ResponseRecorder) store.Chatbot {
	t.Helper()
	var c store.Chatbot
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil {
		t.Fatalf("%d %s: %v", rec.Code, rec.Body, err)
	}
	return c
}

func TestRegisterStoresTheURIInNormalFormAndTheChatbotReadsBack(t *testing.T) {
	a, _ := chatbotAPIOver(t, store.NewMemoryRegistry())
	rec := operator(a, "POST", "/v1/chatbots", registration("cb-1", "SIP:bot-1.acme@BotPlatform.mnc001.mcc001.3gppnetwork.org;tk=on",
		`,"display_name":"Acme","webhook":{"url":"https://bot.example.com/hook"},"permissions":{"msisdn":true},"sources":["2001:DB8::/32"]`))
	got := decodeChatbot(t, rec)
	if rec.Code != http.StatusCreated || rec.Header().Get("Location") != "/v1/chatbots/cb-1" || got.URI != botURI ||
		got.State != store.Active || got.Webhook.Verified || got.Sources[0] != "2001:db8::/32" {
		t.Fatalf("register = %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	rec = operator(a, "GET", "/v1/chatbots/cb-1", "")
	if rec.Code != http.StatusOK || rec.Body.String() != mustJSON(t, got) {
		t.Fatalf("read = %d %s", rec.Code, rec.Body)
	}
}

func mustJSON(t *testing.T, v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data) + "\n"
}

func TestRegisterAnswers409ForATakenIDOrURIAndADeletedID(t *testing.T) {
	r := store.NewMemoryRegistry()
	a, _ := chatbotAPIOver(t, r)
	if rec := operator(a, "POST", "/v1/chatbots", registration("cb-1", botURI, "")); rec.Code != http.StatusCreated {
		t.Fatalf("register = %d %s", rec.Code, rec.Body)
	}
	if err := r.DeleteChatbot(context.Background(), "cb-1"); err != nil {
		t.Fatal(err)
	}
	if rec := operator(a, "POST", "/v1/chatbots", registration("cb-2", botURI, "")); rec.Code != http.StatusCreated {
		t.Fatalf("register after the delete = %d %s", rec.Code, rec.Body)
	}
	for _, tc := range []struct{ id, uri, want string }{
		{"cb-2", "sip:bot-2@" + botDomain, "a chatbot with this ID is registered"},
		{"cb-3", "sip:bot-1.acme@BOTPLATFORM.mnc001.mcc001.3gppnetwork.org", "another chatbot holds this URI"},
		{"cb-1", "sip:bot-3@" + botDomain, "never registered again"},
	} {
		if rec := operator(a, "POST", "/v1/chatbots", registration(tc.id, tc.uri, "")); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s at %s: %d %s", tc.id, tc.uri, rec.Code, rec.Body)
		}
	}
}

// Every field rule of #709 is a 400 that names the field; the registry
// alone would accept a URI in normal form at any host.
func TestEveryBrokenFieldIs400(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a", n) }
	for _, tc := range []struct{ name, uri, more, want string }{
		{"URI at the IMS domain", "sip:bot-1@" + imsDomain, "", "uri: chatbot: not a chatbot URI"},
		{"URI at another bot platform", "sip:bot-1@botplatform.mnc002.mcc001.3gppnetwork.org", "", "uri: chatbot: not a chatbot URI"},
		{"URI with a port", "sip:bot-1@" + botDomain + ":5060", "", "uri: chatbot: a URI at the chatbot domain not in normal form"},
		{"tel URI", "tel:+15550100001", "", "uri: chatbot: not a chatbot URI"},
		{"display name over 128 bytes", botURI, `,"display_name":"` + long(129) + `"`, "a string longer than its field allows"},
		{"display name with a tab", botURI, `,"display_name":"a\tb"`, "display_name holds a control character"},
		{"display name with DEL", botURI, `,"display_name":"a\u007fb"`, "display_name holds a control character"},
		{"display name with NEL", botURI, `,"display_name":"a\u0085b"`, "display_name holds a control or format character"},
		{"display name with RLO", botURI, `,"display_name":"\u202eemca"`, "display_name holds a control or format character"},
		{"display name with ZWSP", botURI, `,"display_name":"Ac\u200bme"`, "display_name holds a control or format character"},
		{"text over 512 bytes", botURI, `,"out_of_service":"` + long(513) + `"`, "a string longer than its field allows"},
		{"text with NUL", botURI, `,"out_of_service":"a\u0000"`, "out_of_service is not text/plain"},
		{"text with ESC", botURI, `,"out_of_service":"\u001b[2J"`, "out_of_service is not text/plain"},
		{"text with DEL", botURI, `,"out_of_service":"a\u007fb"`, "out_of_service holds a control or format character"},
		{"text with RLO", botURI, `,"out_of_service":"a\u202eb"`, "out_of_service holds a control or format character"},
		{"http webhook", botURI, `,"webhook":{"url":"http://bot.example.com/hook"}`, "webhook.url: not https"},
		{"webhook with userinfo", botURI, `,"webhook":{"url":"https://u:p@bot.example.com/hook"}`, "webhook.url: userinfo"},
		{"webhook on another port", botURI, `,"webhook":{"url":"https://bot.example.com:9443/hook"}`, "webhook.url: a port"},
		{"verified set by the operator", botURI, `,"webhook":{"url":"https://bot.example.com/hook","verified":true}`, "unknown"},
		{"starts without MSISDN", botURI, `,"permissions":{"start_conversations":true}`, "requires permissions.msisdn"},
		{"limit over its default", botURI, `,"limits":{"sends_per_minute":601}`, "limits.sends_per_minute is not from 0, the default, to 600"},
		{"negative limit", botURI, `,"limits":{"requests_per_minute":-1}`, "limits.requests_per_minute is not from 0"},
		{"source with host bits", botURI, `,"sources":["192.0.2.1/24"]`, "sources holds an item that is not a network prefix"},
		{"source not a prefix", botURI, `,"sources":["192.0.2.1"]`, "sources holds an item that is not a network prefix"},
		{"nine sources", botURI, `,"sources":["10.0.0.0/8","10.0.0.0/8","10.0.0.0/8","10.0.0.0/8","10.0.0.0/8","10.0.0.0/8","10.0.0.0/8","10.0.0.0/8","10.0.0.0/8"]`, "array"},
		{"ID with a dot", botURI, "", "id is not 1–64"},
	} {
		id := "cb-1"
		if strings.HasPrefix(tc.name, "ID") {
			id = "cb.1"
		}
		a, h := chatbotAPIOver(t, store.NewMemoryRegistry())
		rec := operator(a, "POST", "/v1/chatbots", registration(id, tc.uri, tc.more))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: %d %s, want 400 %q", tc.name, rec.Code, rec.Body, tc.want)
		}
		if strings.Contains(h.Output(), "bot-1") || strings.Contains(h.Output(), "bot.example.com") {
			t.Errorf("%s: a value reached the log:\n%s", tc.name, h.Output())
		}
	}
	// The bounds themselves pass.
	a, _ := chatbotAPIOver(t, store.NewMemoryRegistry())
	rec := operator(a, "POST", "/v1/chatbots", registration(long(64), botURI, `,"display_name":"`+long(124)+`☕","out_of_service":"Back\r\nsoon.\t`+long(500)+
		`","webhook":{"url":"https://bot.example.com:8443/hook"},"permissions":{"msisdn":true,"start_conversations":true},`+
		`"limits":{"sends_per_minute":600,"sends_per_day":20000,"starts_per_minute":60,"starts_per_day":1000,"sends_per_subscriber_per_minute":20,`+
		`"sends_per_subscriber_per_day":200,"received_per_subscriber_per_minute":30,"received_per_minute":6000,"requests_per_minute":1200},`+
		`"sources":["192.0.2.7/32","10.0.0.0/8","10.0.0.0/8","10.0.0.0/8","10.0.0.0/8","10.0.0.0/8","10.0.0.0/8","::/0"]`))
	if rec.Code != http.StatusCreated {
		t.Errorf("every field at its bound: %d %s", rec.Code, rec.Body)
	}
}

// The audit line of a registration carries the structured fields, the
// webhook's host and the URI masked; of the free text only that it changed
// and its length (the lead's decision on #709).
func TestTheAuditLineCarriesNoFreeTextWebhookPathOrURI(t *testing.T) {
	a, h := chatbotAPIOver(t, store.NewMemoryRegistry())
	rec := operator(a, "POST", "/v1/chatbots", registration("cb-1", botURI, `,"display_name":"Secret Name","out_of_service":"Secret text",`+
		`"webhook":{"url":"https://bot.example.com:8443/secret-path?key=hidden"},"permissions":{"msisdn":true},"limits":{"sends_per_day":500},"sources":["192.0.2.7/32"]`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("register = %d %s", rec.Code, rec.Body)
	}
	audits := h.Logs("audit: internal request")
	if len(audits) != 1 {
		t.Fatalf("audit lines %v", audits)
	}
	line := mustJSON(t, audits[0])
	for _, want := range []string{
		`"operation":"register_chatbot"`, `"status":201`, `"token":"current"`, `"chatbot":"cb-1"`, `"id":{"after":"cb-1","before":""}`,
		`"display_name":{"changed":true,"len":11}`, `"out_of_service":{"changed":true,"len":11}`,
		`"webhook.url":{"after":"bot.example.com","before":""}`, `"permissions.msisdn":{"after":true,"before":null}`,
		`"limits.sends_per_day":{"after":500,"before":null}`, `"sources":{"after":["192.0.2.7/32"],"before":null}`, `"state":{"after":"active","before":""}`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("audit line lacks %s:\n%s", want, line)
		}
	}
	for _, never := range []string{"Secret", "secret-path", "hidden", "bot-1.acme"} {
		if strings.Contains(h.Output(), never) {
			t.Errorf("%q reached the log:\n%s", never, h.Output())
		}
	}
}

func TestStoreErrorsAreAnsweredByKind(t *testing.T) {
	for _, tc := range []struct {
		name         string
		err          error
		register     int
		read         int
		retryAfter   string
		inAuditError bool
	}{
		{"failure", fmt.Errorf("awsstore: get: ProvisionedThroughputExceededException"), 503, 503, "1", true},
		{"invalid", fmt.Errorf("%w: chatbot: unknown state", store.ErrInvalid), 400, 500, "", true},
		{"not found", store.ErrNotFound, 404, 404, "", false},
	} {
		a, h := chatbotAPIOver(t, failingRegistry{tc.err})
		reg := operator(a, "POST", "/v1/chatbots", registration("cb-1", botURI, ""))
		read := operator(a, "GET", "/v1/chatbots/cb-1", "")
		if reg.Code != tc.register || read.Code != tc.read || read.Header().Get("Retry-After") != tc.retryAfter {
			t.Errorf("%s: register %d, read %d %v", tc.name, reg.Code, read.Code, read.Header())
		}
		if audit := h.Logs("audit: internal request"); audit[1]["chatbot"] != "cb-1" || (audit[1]["store_error"] == tc.err.Error()) != tc.inAuditError {
			t.Errorf("%s: audit %v", tc.name, audit)
		}
	}
}

// An ID no chatbot can have is 404 without asking the registry, and is not
// logged.
func TestAMalformedIDIs404AndNotLogged(t *testing.T) {
	a, h := chatbotAPIOver(t, failingRegistry{fmt.Errorf("no call expected")})
	for _, path := range []string{"/v1/chatbots/a%0Ab", "/v1/chatbots/" + strings.Repeat("a", 65), "/v1/chatbots/a.b"} {
		if rec := operator(a, "GET", path, ""); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d %s", path, rec.Code, rec.Body)
		}
	}
	for _, audit := range h.Logs("audit: internal request") {
		if _, ok := audit["chatbot"]; ok {
			t.Errorf("audit %v", audit)
		}
	}
}
