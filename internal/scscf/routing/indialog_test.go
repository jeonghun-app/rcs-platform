package routing

import (
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// inDialog is a request inside a dialog for target, with route as its Route
// after the S-CSCF's own entries ("" for none).
func inDialog(t *testing.T, target, route string) *proxy.Request {
	t.Helper()
	fields := []string{
		"BYE " + target + " SIP/2.0",
		"Via: SIP/2.0/TCP pcscf.rcs.local;branch=z9hG4bK-bye",
		"Max-Forwards: 69",
		"From: <" + impu1 + ">;tag=a",
		"To: <sip:+15550100003@" + realm + ">;tag=b",
		"Call-ID: dialog-1",
		"CSeq: 2 BYE",
	}
	if route != "" {
		fields = append(fields, "Route: "+route)
	}
	return &proxy.Request{Message: parse(t, strings.Join(fields, "\r\n")+"\r\nContent-Length: 0\r\n\r\n")}
}

// TestARequestInsideADialogGoesOnlyWhereThePlatformRuns (#208): to an
// application server, or a P-CSCF's core listener naming a flow; anywhere
// else, the S-CSCF itself included, is 403.
func TestARequestInsideADialogGoesOnlyWhereThePlatformRuns(t *testing.T) {
	ue := "sip:ue@192.0.2.40:5060;transport=tcp"
	for name, c := range map[string]struct {
		target, route string
		allowed       bool
	}{
		"an application server":            {ue, "<sip:rcs-as.rcs.local;lr>", true},
		"a P-CSCF by name, with a flow":    {ue, "<sip:" + flow(1) + "@pcscf.rcs.local:5070;lr>", true},
		"a P-CSCF by address, with a flow": {ue, pathOf(1), true},
		"a P-CSCF named by the target":     {"sip:" + flow(1) + "@198.51.100.6:5070", "", true},
		"a P-CSCF without a flow":          {ue, "<sip:pcscf.rcs.local:5070;lr>", false},
		"a P-CSCF with what is no flow":    {ue, "<sip:term@pcscf.rcs.local:5070;lr>", false},
		"the I-CSCF":                       {ue, "<sip:icscf.rcs.local;lr>", false},
		"a private address":                {ue, "<sip:10.0.3.7:8080;lr>", false},
		"a flow token elsewhere":           {ue, "<sip:" + flow(1) + "@10.0.3.7;lr>", false},
		"the S-CSCF itself":                {ue, "<sip:" + flow(1) + "@scscf.rcs.local;lr>", false},
		"the client's contact itself":      {ue, "", false},
		"a tel URI":                        {"tel:+15550100003", "", false},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			d := e.router(nil).InDialog(bg, inDialog(t, c.target, c.route))
			if got := d.Status == 0; got != c.allowed {
				t.Errorf("forwarded %v (status %d), want %v", got, d.Status, c.allowed)
			}
			if c.allowed && len(d.Targets) != 1 {
				t.Errorf("%d targets", len(d.Targets))
			}
			if !c.allowed && d.Status != 403 {
				t.Errorf("status %d, want 403", d.Status)
			}
		})
	}
}

func TestAnUnreadableRouteInsideADialogIs400(t *testing.T) {
	e := newEnv(t)
	d := e.router(nil).InDialog(bg, inDialog(t, "sip:ue@192.0.2.40", "<sip:rcs-as.rcs.local;lr"))
	if d.Status != 400 {
		t.Errorf("status %d", d.Status)
	}
}
