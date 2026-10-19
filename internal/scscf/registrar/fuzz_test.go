package registrar

import (
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// FuzzParseRegister feeds any message through parseRegister and
// applyContacts: neither may panic, and bindings stay within their limits.
func FuzzParseRegister(f *testing.F) {
	u := &ue{t: &testing.T{}, impi: impi1, impu: impu1, callID: "c", contact: "sip:ue@192.0.2.10", instance: "<urn:uuid:1>", regID: 1}
	f.Add([]byte(requestText(u, 600, "")))
	f.Add([]byte("REGISTER sip:" + realm + " SIP/2.0\r\nVia: SIP/2.0/TCP h;branch=z9hG4bK1\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:a@b>\r\nCall-ID: c\r\nCSeq: 1 REGISTER\r\nContact: *\r\nExpires: 0\r\nContent-Length: 0\r\n\r\n"))
	lim := expiryLimits{def: 3600, min: 300, max: 7200}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := sip.ParseMessage(b)
		if err != nil {
			return
		}
		req, ok := m.(*sip.Request)
		if !ok {
			return
		}
		r, fl := parseRegister(req, realm)
		if fl != nil {
			return
		}
		next, fl := applyContacts(nil, r, t0, lim)
		if fl == nil && len(next) > 32 {
			t.Fatalf("%d bindings", len(next))
		}
		for _, c := range next {
			if c.Expires.After(t0.Add(7200 * time.Second)) {
				t.Fatalf("binding beyond MaxExpires: %v", c.Expires)
			}
		}
	})
}
