package routing

import (
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

const (
	botDomain = "botplatform.mnc001.mcc001.3gppnetwork.org"
	bot1      = "sip:examplebot@" + botDomain
)

func withChatbots(t *testing.T) func(*Config) {
	d, err := chatbot.NewDomain(botDomain, realm)
	if err != nil {
		t.Fatal(err)
	}
	return func(c *Config) { c.ChatbotDomain = d }
}

// ADR 0009 §3: once the originating chain is done, a request for a chatbot
// goes to the I-CSCF as one for the home domain does, its Request-URI as it
// came; one at the chatbot domain not in normal form is 404 (§2).
func TestTheEndOfAnOriginatingChainForAChatbotIsTheICSCF(t *testing.T) {
	for target, want := range map[string]string{
		bot1:                              bot1,
		"sip:examplebot.pub@" + botDomain: "sip:examplebot.pub@" + botDomain,
		"sip:examplebot@BotPlatform.mnc001.mcc001.3gppnetwork.org;tk=on": "sip:examplebot@BotPlatform.mnc001.mcc001.3gppnetwork.org;tk=on",
		"sip:ExampleBot@" + botDomain:                                    "",
		"sip:examplebot@" + botDomain + ":5060":                          "",
		"sips:examplebot@" + botDomain:                                   "",
		"sip:examplebot@" + botDomain + ";user=phone":                    "",
		"sip:a.b.c@" + botDomain:                                         "",
	} {
		e := newEnv(t)
		e.registered(binding(1, 0, time.Hour))
		d := e.router(nil, withChatbots(t)).Originating(bg, fromUser(t, "MESSAGE", target))
		if want == "" {
			if d.Status != 404 || e.metrics.get("routing.originating.no_route") != 1 {
				t.Errorf("%s: status %d, targets %v", target, d.Status, uris(d.Targets))
			}
			continue
		}
		if serverOf(t, d) != "icscf.rcs.local" || d.Targets[0].URI.String() != want || e.metrics.get("routing.originating.to_icscf") != 1 {
			t.Errorf("%s: to %v", target, uris(d.Targets))
		}
	}
}

// With RCS_CHATBOT_DOMAIN unset a chatbot URI is another domain's: 404.
func TestWithoutAChatbotDomainARequestForAChatbotIsNotFound(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	if d := e.router(nil).Originating(bg, fromUser(t, "MESSAGE", bot1)); d.Status != 404 {
		t.Errorf("status %d, targets %v", d.Status, uris(d.Targets))
	}
}

// The chatbot is reached after the originating iFC: rcs-as first, then,
// from where the chain left, the I-CSCF without the P-Served-User the
// S-CSCF put in toward the server.
func TestARequestForAChatbotPassesTheOriginatingChainFirst(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(20, rcsAS, method("MESSAGE"), ifc.SessionTerminated))
	r := fromUser(t, "MESSAGE", bot1)
	first := e.router(nil, withChatbots(t)).Initial(bg, r)
	if host := serverOf(t, first); host != "rcs-as.rcs.local" {
		t.Fatalf("first to %s", host)
	}
	back := backFrom(t, r, first, 0)
	last := e.router(nil, withChatbots(t)).Initial(bg, back)
	if host := serverOf(t, last); host != "icscf.rcs.local" || last.Targets[0].URI.String() != bot1 {
		t.Fatalf("then to %s for %s", host, last.Targets[0].URI.String())
	}
	if b := branchOf(t, back, last, last.Targets[0]); b.Header.Has("P-Served-User") {
		t.Error("the P-Served-User toward the server went on to the I-CSCF")
	}
}
