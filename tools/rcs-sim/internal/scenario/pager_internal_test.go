package scenario

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

func TestASIPClientAnswersWhatIsNotItsMessage(t *testing.T) {
	// Code review on #209: 405 with Allow (RFC 3261 §8.2.1), 481 for a
	// dialog it does not have (§12.2.2), and a random To tag (§19.3).
	c := &sipClient{messages: make(chan *sip.Request, 1), options: make(chan *sip.Request, 1)}
	ids := sip.IDGenerator{Rand: rand.Reader}
	request := func(method, toTag string) *sip.Request {
		req := &sip.Request{Method: method, URI: sip.URI{Scheme: "sip", User: "+15550100002", Host: "ims.mnc001.mcc001.3gppnetwork.org"}}
		to := "<sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org>"
		if toTag != "" {
			to += ";tag=" + toTag
		}
		for _, f := range [][2]string{
			{"Via", "SIP/2.0/TCP core.invalid;branch=z9hG4bKtest1"},
			{"From", "<sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org>;tag=a1"},
			{"To", to},
			{"Call-ID", "c1"},
			{"CSeq", "1 " + method},
		} {
			if err := req.Header.Add(f[0], f[1]); err != nil {
				t.Fatal(err)
			}
		}
		return req
	}
	info := c.answer(request("INFO", ""), ids)
	if info.StatusCode != 405 || info.Header.Get("Allow") != "MESSAGE, OPTIONS" {
		t.Fatalf("INFO answered %d, Allow %q", info.StatusCode, info.Header.Get("Allow"))
	}
	if to, _ := info.Header.To(); len(to.Tag()) < 8 {
		t.Fatalf("To tag %q", to.Tag())
	}
	if res := c.answer(request("NOTIFY", "gone"), ids); res.StatusCode != 481 {
		t.Fatalf("NOTIFY in a dialog the client does not have answered %d", res.StatusCode)
	}
	if res := c.answer(request("MESSAGE", ""), ids); res.StatusCode != 200 || len(c.messages) != 1 {
		t.Fatalf("MESSAGE answered %d, %d queued", res.StatusCode, len(c.messages))
	}
	if res := c.answer(request("MESSAGE", ""), ids); res.StatusCode != 486 {
		t.Fatalf("MESSAGE to a full queue answered %d", res.StatusCode)
	}
}

// TestASIPClientAnswersACapabilityQueryWithItsTags: an OPTIONS is answered
// 200 with the client's Contact, its feature tags with it, and queued for
// the scenario, as a MESSAGE is; 486 once the queue is full.
func TestASIPClientAnswersACapabilityQueryWithItsTags(t *testing.T) {
	contact, err := sip.ParseAddress(`<sip:192.0.2.10:5060;transport=tcp>;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"`)
	if err != nil {
		t.Fatal(err)
	}
	c := &sipClient{messages: make(chan *sip.Request, 1), options: make(chan *sip.Request, 1), contact: sip.Contact{Address: contact}}
	ids := sip.IDGenerator{Rand: rand.Reader}
	req := &sip.Request{Method: "OPTIONS", URI: sip.URI{Scheme: "sip", User: "+15550100002", Host: "ims.mnc001.mcc001.3gppnetwork.org"}}
	for _, f := range [][2]string{
		{"Via", "SIP/2.0/TCP core.invalid;branch=z9hG4bKtest2"},
		{"From", "<sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org>;tag=a1"},
		{"To", "<sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org>"},
		{"Call-ID", "c2"},
		{"CSeq", "1 OPTIONS"},
	} {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			t.Fatal(err)
		}
	}
	res := c.answer(req, ids)
	if res.StatusCode != 200 || len(c.options) != 1 || !strings.Contains(res.Header.Get("Contact"), "cpm.session") {
		t.Fatalf("OPTIONS answered %d with Contact %q, %d queued", res.StatusCode, res.Header.Get("Contact"), len(c.options))
	}
	if res := c.answer(req, ids); res.StatusCode != 486 {
		t.Fatalf("OPTIONS to a full queue answered %d", res.StatusCode)
	}
}
