package store_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store/storetest"
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
		"negative limit":  func(c *store.Chatbot) { c.Limits.ReceivedPerMinute = -1 },
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
