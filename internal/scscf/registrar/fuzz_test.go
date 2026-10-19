package registrar

import (
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// FuzzParseRegister feeds any message through parseRegister, prepare and
// applyDelta. None may panic; bindings stay within their limits; what is
// accepted is what the store accepts (so nothing fails after SAR); and every
// binding the 200 lists parses back to the same instance and feature tags.
func FuzzParseRegister(f *testing.F) {
	u := &ue{t: &testing.T{}, impi: impi1, impu: impu1, callID: "c", contact: "sip:ue@192.0.2.10", instance: "<urn:uuid:1>", regID: 1}
	f.Add([]byte(requestText(u, 600, "")))
	f.Add([]byte(requestText(u, 600, "", `Contact: <sip:b@192.0.2.10>;+g.x="a\\b";+g.y="c\"d"`)))
	// From the #196 re-check: control characters behind a quoted-pair.
	for _, c := range []string{"\x00", "\x01", "\x7f"} {
		f.Add([]byte(requestText(u, 600, "", "Contact: <sip:b@192.0.2.10>;+g.x=\"a\\"+c+"b\"")))
		f.Add([]byte(requestText(u, 600, "", "Contact: <sip:b@192.0.2.10>;+sip.instance=\"<urn:uuid:a\\"+c+"b>\"")))
	}
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
		ops, fl := prepare(r, lim)
		if fl != nil {
			return
		}
		next, fl := applyDelta(nil, r, ops, t0)
		if fl != nil || len(next) == 0 {
			return
		}
		if len(next) > state.MaxContacts {
			t.Fatalf("%d bindings", len(next))
		}
		probe := &state.Registration{Key: state.SetKey{IMPI: r.impi, IMPU: r.impu}, Incarnation: 1, Identities: []state.SetIdentity{{IMPU: r.impu}}, Contacts: next}
		storable := probe.Validate() == nil
		for _, c := range next {
			if c.Expires.After(t0.Add(7200 * time.Second)) {
				t.Fatalf("binding beyond MaxExpires: %v", c.Expires)
			}
			if !storable {
				// register refuses it with 400 before SAR.
				continue
			}
			v := contactField(c, t0)
			var h sip.Header
			if err := h.Add("Contact", v); err != nil {
				t.Fatalf("200 Contact %q cannot be added: %v", v, err)
			}
			back, err := sip.ParseContacts(v)
			if err != nil || len(back) != 1 {
				t.Fatalf("200 Contact %q does not parse: %v", v, err)
			}
			if inst, _ := back[0].Instance(); inst != c.InstanceID {
				t.Fatalf("instance %q came back as %q", c.InstanceID, inst)
			}
			again, _ := binding(back[0], r, c.RegID != 0, c.FlowToken)
			if len(again.FeatureTags) != len(c.FeatureTags) {
				t.Fatalf("feature tags %q came back as %q", c.FeatureTags, again.FeatureTags)
			}
			for i := range c.FeatureTags {
				if again.FeatureTags[i] != c.FeatureTags[i] {
					t.Fatalf("feature tag %q came back as %q", c.FeatureTags[i], again.FeatureTags[i])
				}
			}
		}
	})
}
