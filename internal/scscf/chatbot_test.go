package scscf

import (
	"strconv"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

const botDomain = "botplatform.mnc001.mcc001.3gppnetwork.org"

func TestConfigureReadsTheChatbotDomain(t *testing.T) {
	if c, err := configure(with(devEnv, "RCS_CHATBOT_DOMAIN", botDomain)); err != nil || c.ChatbotDomain.Name() != botDomain {
		t.Errorf("chatbot domain %q, %v", c.ChatbotDomain.Name(), err)
	}
	if c, err := configure(devEnv); err != nil || c.ChatbotDomain.Name() != "" {
		t.Errorf("default chatbot domain %q, %v; want none", c.ChatbotDomain.Name(), err)
	}
	// ADR 0009 §2: the chatbot range and the IMPUs must not meet.
	if _, err := configure(with(devEnv, "RCS_CHATBOT_DOMAIN", strings.ToUpper(realm))); err == nil || !strings.Contains(err.Error(), "RCS_CHATBOT_DOMAIN") {
		t.Errorf("the IMS domain as the chatbot domain: %v, want it refused", err)
	}
}

// Through Run: RCS_CHATBOT_DOMAIN reaches the router, and a registered
// user's MESSAGE to a chatbot goes to the I-CSCF instead of a 404.
func TestARequestForAChatbotReachesTheICSCFThroughRun(t *testing.T) {
	hss := startHSS(t)
	icscf := startSilentPeer(t)
	domain, err := chatbot.NewDomain(botDomain, realm)
	if err != nil {
		t.Fatal(err)
	}
	r := startSCSCFWith(t, hss, state.NewMemory(), 1, func(c *ServiceConfig, _ *deps) {
		c.ICSCF = mustURI("sip:" + icscf.addr + ";transport=tcp;lr")
		c.ChatbotDomain = domain
	})
	p := dialSCSCF(t, r)
	p.registerFully(t, deviceAt("127.0.0.1:5070", 1), 600)
	bot := "sip:examplebot@" + botDomain
	if _, err := p.c.Write([]byte(strings.Join([]string{
		"MESSAGE " + bot + " SIP/2.0",
		"Via: SIP/2.0/TCP 127.0.0.1:5070;branch=z9hG4bK-chatbot-1",
		"Max-Forwards: 69",
		"Route: <sip:scscf.rcs.local:" + strconv.Itoa(int(r.core.Port())) + ";lr;orig>",
		"P-Asserted-Identity: <" + impu + ">",
		"From: <" + impu + ">;tag=caller", "To: <" + bot + ">",
		"Call-ID: chatbot-1", "CSeq: 1 MESSAGE",
		"Content-Length: 0",
	}, "\r\n") + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the MESSAGE at the I-CSCF", func() bool { return icscf.got.Load() > 0 })
	if req := icscf.first.Load(); req == nil || req.Method != "MESSAGE" || req.URI.String() != bot {
		t.Fatalf("the I-CSCF got %v", req)
	}
}
