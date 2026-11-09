package store_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store/storetest"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

func TestMemoryRegistryMeetsTheContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Registry { return store.NewMemoryRegistry() })
}

func TestTheLongestChatbotRoundTrips(t *testing.T) {
	// "<" is written as a six-byte \u escape, the most any byte takes.
	fill := func(n int) string { return strings.Repeat("<", n) }
	label := strings.Repeat("a", 63)
	c := store.Chatbot{
		ID: strings.Repeat("A", store.MaxIDBytes), URI: "sip:" + label + "." + label + "@" + storetest.Domain,
		DisplayName: fill(store.MaxDisplayNameBytes), OutOfService: fill(store.MaxOutOfServiceText),
		Webhook: store.Webhook{URL: fill(store.MaxWebhookBytes), Verified: true}, State: store.Suspended,
		Limits: store.Limits{SendsPerMinute: 1 << 62, RequestsPerMinute: 1 << 62},
	}
	for range store.MaxSources {
		c.Sources = append(c.Sources, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00/120")
	}
	doc, err := store.EncodeChatbot(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.DecodeChatbot(doc, 7)
	c.Version = 7
	if err != nil || !reflect.DeepEqual(got, c) {
		t.Fatalf("round trip = %v\n%+v", err, got)
	}
}

func TestAChatbotBreakingTheRulesIsNotStored(t *testing.T) {
	for name, change := range map[string]func(*store.Chatbot){
		"empty ID":        func(c *store.Chatbot) { c.ID = "" },
		"long ID":         func(c *store.Chatbot) { c.ID = strings.Repeat("a", store.MaxIDBytes+1) },
		"ID with #":       func(c *store.Chatbot) { c.ID = "a#b" },
		"long name":       func(c *store.Chatbot) { c.DisplayName = strings.Repeat("a", store.MaxDisplayNameBytes+1) },
		"long text":       func(c *store.Chatbot) { c.OutOfService = strings.Repeat("a", store.MaxOutOfServiceText+1) },
		"long webhook":    func(c *store.Chatbot) { c.Webhook.URL = strings.Repeat("a", store.MaxWebhookBytes+1) },
		"no state":        func(c *store.Chatbot) { c.State = "" },
		"name not UTF-8":  func(c *store.Chatbot) { c.DisplayName = "a\xffb" },
		"text not UTF-8":  func(c *store.Chatbot) { c.OutOfService = "a\xffb" },
		"URL not UTF-8":   func(c *store.Chatbot) { c.Webhook.URL += "\xff" },
		"CR LF in name":   func(c *store.Chatbot) { c.DisplayName = "Acme\r\nInjected: 1" },
		"DEL in name":     func(c *store.Chatbot) { c.DisplayName = "Acme\x7f" },
		"tab in URL":      func(c *store.Chatbot) { c.Webhook.URL += "\t" },
		"host bits":       func(c *store.Chatbot) { c.Sources = []string{"192.0.2.1/24"} },
		"not a prefix":    func(c *store.Chatbot) { c.Sources = []string{"192.0.2.1"} },
		"long IPv6 form":  func(c *store.Chatbot) { c.Sources = []string{"2001:0db8::/32"} },
		"too many":        func(c *store.Chatbot) { c.Sources = make([]string, store.MaxSources+1) },
		"URI not normal":  func(c *store.Chatbot) { c.URI = strings.Replace(c.URI, "sip:", "sip:X", 1) },
		"URI at no host":  func(c *store.Chatbot) { c.URI = "sip:bot" },
		"URI with escape": func(c *store.Chatbot) { c.URI = strings.Replace(c.URI, "bot", "b%6ft", 1) },
	} {
		c := storetest.Chatbot()
		change(&c)
		if _, err := store.EncodeChatbot(c); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for i := range reflect.TypeFor[store.Limits]().NumField() {
		c := storetest.Chatbot()
		reflect.ValueOf(&c.Limits).Elem().Field(i).SetInt(-1)
		if _, err := store.EncodeChatbot(c); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("negative limit %d: %v", i, err)
		}
	}
}

func TestAStoredChatbotIsDecodedStrictly(t *testing.T) {
	doc, err := store.EncodeChatbot(storetest.Chatbot())
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"unknown field":  strings.Replace(string(doc), `"state"`, `"colour":"red","state"`, 1),
		"other schema":   strings.Replace(string(doc), `"schema":1`, `"schema":2`, 1),
		"trailing data":  string(doc) + "{}",
		"field in caps":  strings.Replace(string(doc), `"state"`, `"STATE"`, 1),
		"breaks a rule":  strings.Replace(string(doc), `"state":"active"`, `"state":"paused"`, 1),
		"not a document": "",
	} {
		if _, err := store.DecodeChatbot([]byte(bad), 1); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAuditChangesShowStructuredFieldsAndOnlyTheLengthOfText(t *testing.T) {
	before := storetest.Chatbot()
	after := before
	after.DisplayName = "Acme Secret Name"
	after.OutOfService = "Closed secret."
	after.Webhook.URL = "https://user:pw-secret@[fe80::1%25zone-secret]:8443/path-secret?q=query-secret#frag-secret"
	after.Limits.SendsPerDay = 1 << 62
	after.Sources = []string{"198.51.100.0/24"}
	after.State = store.Suspended
	var buf bytes.Buffer
	log := func(attrs []slog.Attr) string {
		buf.Reset()
		slog.New(slog.NewJSONHandler(&buf, nil)).LogAttrs(t.Context(), slog.LevelInfo, "audit", attrs...)
		return buf.String()
	}
	line := log(store.AuditChanges(before, after))
	for _, want := range []string{
		`"display_name":{"changed":true,"len":16}`, `"out_of_service":{"changed":true,"len":14}`,
		`"webhook.url":{"before":"bot.example.com","after":"fe80::1"}`,
		`"limits.sends_per_day":{"before":1000,"after":4611686018427387904}`,
		`"sources":{"before":["192.0.2.0/24","2001:db8::/32"],"after":["198.51.100.0/24"]}`,
		`"state":{"before":"active","after":"suspended"}`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("missing %s in %s", want, line)
		}
	}
	for _, leak := range []string{"Acme", "Secret", "secret", "Closed", "Back soon", "/hook", "zone", "user", "8443", `"uri"`, "permissions"} {
		if strings.Contains(line, leak) {
			t.Errorf("%q in %s", leak, line)
		}
	}
	// Registering is a change of every field set, the URI through pii.
	line = log(store.AuditChanges(store.Chatbot{}, before))
	uri, _ := json.Marshal(pii.URI("after", before.URI).Value.String())
	if !strings.Contains(line, `"uri":{"before":"","after":`+string(uri)+`}`) || strings.Contains(line, "bot-") ||
		!strings.Contains(line, `"permissions.msisdn":{"before":null,"after":true}`) {
		t.Errorf("registration: %s", line)
	}
	if got := store.AuditChanges(before, before); len(got) != 0 {
		t.Errorf("no change: %v", got)
	}
}

// FuzzDecodeChatbot reads arbitrary stored documents: nothing may panic,
// and what decodes encodes back to a document that decodes the same.
func FuzzDecodeChatbot(f *testing.F) {
	doc, err := store.EncodeChatbot(storetest.Chatbot())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(doc)
	f.Add([]byte(`{"schema":1,"chatbot":{"id":"a","uri":"sip:a@b.example","state":"active"}}`))
	f.Add([]byte(`{"schema":1,"chatbot":{"id":"a","uri":"sip:a@b.example","sources":[],"state":"active"}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := store.DecodeChatbot(data, 1)
		if err != nil {
			return
		}
		again, err := store.EncodeChatbot(got)
		if err != nil {
			t.Fatalf("decoded chatbot does not encode: %v", err)
		}
		back, err := store.DecodeChatbot(again, 1)
		if err != nil || !reflect.DeepEqual(back, got) {
			t.Fatalf("round trip changed the chatbot: %v\n%+v\n%+v", err, got, back)
		}
	})
}

// FuzzEncodeChatbot builds chatbots from arbitrary fields: whatever
// EncodeChatbot accepts must decode to the same chatbot, so that no record
// is stored that its readers refuse.
func FuzzEncodeChatbot(f *testing.F) {
	c := storetest.Chatbot()
	f.Add(c.ID, c.URI, c.DisplayName, c.OutOfService, c.Webhook.URL, c.Sources[0], string(c.State), int64(60))
	f.Fuzz(func(t *testing.T, id, uri, name, text, url, source, state string, limit int64) {
		c := store.Chatbot{ID: id, URI: uri, DisplayName: name, OutOfService: text, Webhook: store.Webhook{URL: url},
			Sources: []string{source}, State: store.State(state), Limits: store.Limits{SendsPerDay: limit}}
		doc, err := store.EncodeChatbot(c)
		if err != nil {
			return
		}
		got, err := store.DecodeChatbot(doc, 0)
		if err != nil || !reflect.DeepEqual(got, c) {
			t.Fatalf("an accepted chatbot does not round-trip: %v\n%+v\n%+v", err, c, got)
		}
	})
}
