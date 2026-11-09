package maap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
)

// conflictingRegistry fails the next conflicts updates with ErrConflict,
// and then every update with err if it is set, counting the updates.
type conflictingRegistry struct {
	*store.MemoryRegistry
	conflicts, updates atomic.Int32
	err                error
}

func (r *conflictingRegistry) Update(ctx context.Context, old, c store.Chatbot) (store.Chatbot, error) {
	r.updates.Add(1)
	switch {
	case r.conflicts.Add(-1) >= 0:
		return store.Chatbot{}, store.ErrConflict
	case r.err != nil:
		return store.Chatbot{}, r.err
	}
	return r.MemoryRegistry.Update(ctx, old, c)
}

// flakyDeleter fails its first call, then deletes.
type flakyDeleter struct{ calls atomic.Int32 }

func (d *flakyDeleter) DeleteChatbot(context.Context, string) error {
	if d.calls.Add(1) == 1 {
		return errors.New("subscribers: delete: InternalServerError")
	}
	return nil
}

// registered registers cb-1 at botURI with the JSON members more.
func registered(t *testing.T, a *internalAPI, more string) store.Chatbot {
	t.Helper()
	rec := operator(a, "POST", "/v1/chatbots", registration("cb-1", botURI, more))
	if rec.Code != http.StatusCreated {
		t.Fatalf("register = %d %s", rec.Code, rec.Body)
	}
	return decodeChatbot(t, rec)
}

func TestAChangeSetsTheFieldsGivenAndANewWebhookIsUnverified(t *testing.T) {
	r := store.NewMemoryRegistry()
	a, h := chatbotAPIOver(t, r)
	registered(t, a, `,"display_name":"Acme","webhook":{"url":"https://bot.example.com/a"},"permissions":{"msisdn":true},"limits":{"sends_per_day":100}`)
	// #683 marks the URL verified.
	c, err := r.Chatbot(context.Background(), "cb-1")
	verified := c
	verified.Webhook.Verified = true
	if _, err = r.Update(context.Background(), c, verified); err != nil {
		t.Fatal(err)
	}
	// The same URL keeps its verification.
	rec := operator(a, "PATCH", "/v1/chatbots/cb-1", `{"display_name":"Acme Support","webhook":{"url":"https://bot.example.com/a"}}`)
	got := decodeChatbot(t, rec)
	if rec.Code != http.StatusOK || got.DisplayName != "Acme Support" || !got.Webhook.Verified || got.Limits.SendsPerDay != 100 {
		t.Fatalf("change = %d %s", rec.Code, rec.Body)
	}
	// 0 sets a limit back to its default.
	rec = operator(a, "PATCH", "/v1/chatbots/cb-1", `{"webhook":{"url":"https://bot.example.com/b"},"limits":{"sends_per_day":0}}`)
	if got = decodeChatbot(t, rec); rec.Code != http.StatusOK || got.Webhook.Verified || got.Limits != (store.Limits{}) || got.DisplayName != "Acme Support" {
		t.Fatalf("change = %d %s", rec.Code, rec.Body)
	}
	audit := mustJSON(t, h.Logs("audit: internal request")[2])
	if !strings.Contains(audit, `"webhook.verified":{"after":null,"before":true}`) || !strings.Contains(audit, `"limits.sends_per_day":{"after":null,"before":100}`) ||
		strings.Contains(audit, "display_name") || strings.Contains(audit, "/b") {
		t.Errorf("audit line %s", audit)
	}
	for body, want := range map[string]string{
		`{"uri":"sip:bot-2@` + botDomain + `"}`: "id and uri never change",
		`{"id":"cb-2"}`:                         "id and uri never change",
		`{"permissions":{"msisdn":false,"start_conversations":true}}`: "requires permissions.msisdn",
		`{"display_name":"\u202e"}`:                                   "display_name holds a control, format or invisible character",
	} {
		if rec := operator(a, "PATCH", "/v1/chatbots/cb-1", body); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s: %d %s", body, rec.Code, rec.Body)
		}
	}
	if rec := operator(a, "PATCH", "/v1/chatbots/cb-2", `{}`); rec.Code != http.StatusNotFound {
		t.Errorf("change of an unknown chatbot = %d", rec.Code)
	}
}

// Permissions and limits merge field by field (#742 review, lead
// decision): lowering one limit leaves the others lowered, and setting
// msisdn leaves start_conversations on.
func TestAChangeMergesLimitsAndPermissionsFieldByField(t *testing.T) {
	a, _ := chatbotAPIOver(t, store.NewMemoryRegistry())
	registered(t, a, `,"permissions":{"msisdn":true,"start_conversations":true},"limits":{"sends_per_minute":10,"starts_per_day":5}`)
	both := store.Permissions{MSISDN: true, StartConversations: true}
	lowered := store.Limits{SendsPerMinute: 10, SendsPerDay: 500, StartsPerDay: 5}
	reset := store.Limits{SendsPerMinute: 10, SendsPerDay: 500}
	for _, step := range []struct {
		body        string
		status      int
		permissions store.Permissions
		limits      store.Limits
	}{
		{`{"limits":{"sends_per_day":500}}`, 200, both, lowered},
		{`{"permissions":{"msisdn":true}}`, 200, both, lowered},
		{`{"limits":{"sends_per_minute":null,"starts_per_day":0}}`, 200, both, reset},
		{`{"limits":{"sends_per_minute":601}}`, 400, both, reset},
		{`{"permissions":{"msisdn":false}}`, 400, both, reset}, // start_conversations is still on
		{`{"permissions":{"start_conversations":false}}`, 200, store.Permissions{MSISDN: true}, reset},
	} {
		if rec := operator(a, "PATCH", "/v1/chatbots/cb-1", step.body); rec.Code != step.status {
			t.Fatalf("%s: %d %s", step.body, rec.Code, rec.Body)
		}
		got := decodeChatbot(t, operator(a, "GET", "/v1/chatbots/cb-1", ""))
		if got.Permissions != step.permissions || got.Limits != step.limits {
			t.Fatalf("after %s: %+v %+v, want %+v %+v", step.body, got.Permissions, got.Limits, step.permissions, step.limits)
		}
	}
}

func TestSuspendAndResumeChangeTheStateOnly(t *testing.T) {
	a, h := chatbotAPIOver(t, store.NewMemoryRegistry())
	c := registered(t, a, `,"display_name":"Acme","out_of_service":"Back soon."`)
	for _, step := range []struct {
		path  string
		state store.State
	}{{"/v1/chatbots/cb-1/suspend", store.Suspended}, {"/v1/chatbots/cb-1/suspend", store.Suspended}, {"/v1/chatbots/cb-1/resume", store.Active}} {
		rec := operator(a, "POST", step.path, "")
		got := decodeChatbot(t, rec)
		want := c
		want.State = step.state
		if rec.Code != http.StatusOK || mustJSON(t, got) != mustJSON(t, want) {
			t.Fatalf("%s = %d %s", step.path, rec.Code, rec.Body)
		}
	}
	audits := h.Logs("audit: internal request")
	if s := mustJSON(t, audits[1]); !strings.Contains(s, `"state":{"after":"suspended","before":"active"}`) || strings.Contains(s, "display_name") {
		t.Errorf("suspend's audit line %s", s)
	}
	if rec := operator(a, "POST", "/v1/chatbots/cb-2/resume", ""); rec.Code != http.StatusNotFound {
		t.Errorf("resume of an unknown chatbot = %d", rec.Code)
	}
}

func TestAChangeThatLosesARaceIsAppliedToAFreshReadThenIs409(t *testing.T) {
	r := &conflictingRegistry{MemoryRegistry: store.NewMemoryRegistry()}
	a, _ := chatbotAPIOver(t, r)
	registered(t, a, "")
	r.conflicts.Store(maxChangeAttempts - 1)
	if rec := operator(a, "PATCH", "/v1/chatbots/cb-1", `{"display_name":"Acme"}`); rec.Code != http.StatusOK {
		t.Fatalf("change after %d conflicts = %d %s", maxChangeAttempts-1, rec.Code, rec.Body)
	}
	r.conflicts.Store(maxChangeAttempts)
	if rec := operator(a, "POST", "/v1/chatbots/cb-1/suspend", ""); rec.Code != http.StatusConflict {
		t.Fatalf("suspend after %d conflicts = %d %s", maxChangeAttempts, rec.Code, rec.Body)
	}
	// Only a conflict is tried again: a failed store is the operator's to
	// retry.
	r.conflicts.Store(0)
	r.updates.Store(0)
	r.err = errors.New("awsstore: put: InternalServerError")
	if rec := operator(a, "POST", "/v1/chatbots/cb-1/suspend", ""); rec.Code != http.StatusServiceUnavailable || r.updates.Load() != 1 {
		t.Fatalf("suspend on a failing store = %d after %d updates", rec.Code, r.updates.Load())
	}
}

// A deletion that fails part way is 503, and sending it again finishes:
// the URI is free, the ID is never registered again, and every table's
// deletion ran.
func TestARepeatedDeleteFinishesWhatAFailedOneLeft(t *testing.T) {
	d := &flakyDeleter{}
	a, h := chatbotAPIOver(t, store.NewMemoryRegistry(), d)
	registered(t, a, `,"display_name":"Acme"`)
	if rec := operator(a, "DELETE", "/v1/chatbots/cb-1", ""); rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("delete with a failing table = %d %v", rec.Code, rec.Header())
	}
	if rec := operator(a, "DELETE", "/v1/chatbots/cb-1", ""); rec.Code != http.StatusNoContent || d.calls.Load() != 2 {
		t.Fatalf("repeated delete = %d, %d deletions", rec.Code, d.calls.Load())
	}
	if rec := operator(a, "GET", "/v1/chatbots/cb-1", ""); rec.Code != http.StatusNotFound {
		t.Errorf("read after delete = %d", rec.Code)
	}
	if rec := operator(a, "POST", "/v1/chatbots", registration("cb-2", botURI, "")); rec.Code != http.StatusCreated {
		t.Errorf("the URI is not free: %d %s", rec.Code, rec.Body)
	}
	if rec := operator(a, "POST", "/v1/chatbots", registration("cb-1", "sip:bot-3@"+botDomain, "")); rec.Code != http.StatusConflict {
		t.Errorf("the deleted ID registered again: %d", rec.Code)
	}
	audits := h.Logs("audit: internal request")
	if s := mustJSON(t, audits[1]); !strings.Contains(s, `"store_error":"subscribers: delete: InternalServerError"`) ||
		!strings.Contains(s, `"state":{"after":"","before":"active"}`) || !strings.Contains(s, `"display_name":{"changed":true,"len":0}`) {
		t.Errorf("the first delete's audit line %s", s)
	}
	if _, ok := audits[2]["state"]; ok {
		t.Errorf("the repeat's audit line has values: %v", audits[2])
	}
}

func TestDeleteAnswersRegistryErrorsByKind(t *testing.T) {
	failed := errors.New("awsstore: transact write: InternalServerError")
	for _, tc := range []struct {
		read, delete error
		want         int
	}{
		{nil, nil, http.StatusNoContent}, // gone already
		// A record this release cannot read is deleted all the same.
		{fmt.Errorf("%w: unknown chatbot schema", store.ErrInvalid), nil, http.StatusNoContent},
		{failed, nil, http.StatusServiceUnavailable},
		{nil, fmt.Errorf("%w: the URI's reservation names another chatbot", store.ErrInvalid), http.StatusInternalServerError},
		{nil, failed, http.StatusServiceUnavailable},
	} {
		a, _ := chatbotAPIOver(t, deleteFake{store.NewMemoryRegistry(), tc.read, tc.delete})
		if rec := operator(a, "DELETE", "/v1/chatbots/cb-1", ""); rec.Code != tc.want {
			t.Errorf("read %v, delete %v: %d %s", tc.read, tc.delete, rec.Code, rec.Body)
		}
	}
}

// deleteFake is a registry whose Chatbot returns read, if set, and whose
// DeleteChatbot returns delete.
type deleteFake struct {
	*store.MemoryRegistry
	read, delete error
}

func (d deleteFake) Chatbot(ctx context.Context, id string) (store.Chatbot, error) {
	if d.read != nil {
		return store.Chatbot{}, d.read
	}
	return d.MemoryRegistry.Chatbot(ctx, id)
}

func (d deleteFake) DeleteChatbot(context.Context, string) error { return d.delete }

// budgetDeleter reports the deadline it was given and is unfinished until
// its calls run out.
type budgetDeleter struct {
	left      atomic.Int32
	deadlines chan time.Duration
}

func (d *budgetDeleter) DeleteChatbot(ctx context.Context, _ string) error {
	dl, _ := ctx.Deadline()
	d.deadlines <- time.Until(dl)
	if d.left.Add(-1) >= 0 {
		return store.ErrUnfinished
	}
	return nil
}

// A deletion runs for its budget, under the write timeout, and answers 503
// with Retry-After while a table has items left, until a call finishes it.
func TestADeleteRunsForItsBudgetAndAnswers503UntilDone(t *testing.T) {
	d := &budgetDeleter{deadlines: make(chan time.Duration, 3)}
	d.left.Store(2)
	a, _ := chatbotAPIOver(t, store.NewMemoryRegistry(), d)
	registered(t, a, "")
	for i, want := range []int{http.StatusServiceUnavailable, http.StatusServiceUnavailable, http.StatusNoContent} {
		rec := operator(a, "DELETE", "/v1/chatbots/cb-1", "")
		if rec.Code != want || want == http.StatusServiceUnavailable &&
			(rec.Header().Get("Retry-After") != "1" || !strings.Contains(rec.Body.String(), "call again until it answers 204")) {
			t.Fatalf("call %d = %d %v %s", i, rec.Code, rec.Header(), rec.Body)
		}
		if left := <-d.deadlines; left > deletionBudget || left < deletionBudget-5*time.Second {
			t.Fatalf("call %d: the deleter had %v", i, left)
		}
	}
}
