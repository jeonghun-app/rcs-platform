package scenario

import (
	"crypto/rand"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

func TestASIPClientAnswersWhatIsNotItsMessage(t *testing.T) {
	// Code review on #209: 405 with Allow (RFC 3261 §8.2.1), 481 for a
	// dialog it does not have (§12.2.2), and a random To tag (§19.3).
	c := &sipClient{messages: make(chan *sip.Request, 1)}
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
	options := c.answer(request("OPTIONS", ""), ids)
	if options.StatusCode != 405 || options.Header.Get("Allow") != "MESSAGE" {
		t.Fatalf("OPTIONS answered %d, Allow %q", options.StatusCode, options.Header.Get("Allow"))
	}
	if to, _ := options.Header.To(); len(to.Tag()) < 8 {
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
