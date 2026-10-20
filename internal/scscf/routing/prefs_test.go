package routing

import (
	"slices"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// TestCallerPreferenceRules (RFC 3841 §7.2): which bindings a preference
// keeps, by the feature tags each registered.
func TestCallerPreferenceRules(t *testing.T) {
	chat := `+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"`
	both := `+g.3gpp.iari-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush"`
	devices := []string{
		binding(1, 0, time.Hour, chat).URI,
		binding(2, 0, time.Hour, both, "+g.oma.sip-im").URI,
		binding(3, 0, time.Hour).URI,
	}
	cs := []state.Contact{binding(1, 0, time.Hour, chat), binding(2, 0, time.Hour, both, "+g.oma.sip-im"), binding(3, 0, time.Hour)}
	for name, c := range map[string]struct {
		field string
		want  []int
	}{
		"none":             {"", []int{0, 1, 2}},
		"require explicit": {"Accept-Contact: *;" + chat + ";require;explicit", []int{0}},
		"require, not stated matches implicitly (§7.2.4)": {"Accept-Contact: *;" + chat + ";require", []int{0, 1, 2}},
		"without require, all":                            {"Accept-Contact: *;" + chat, []int{0, 1, 2}},
		"one of a list":                                   {`Accept-Contact: *;+g.3gpp.iari-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush";require;explicit`, []int{1}},
		"any of a list":                                   {`Accept-Contact: *;+g.3gpp.iari-ref="urn%3Ax,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp";require;explicit`, []int{1}},
		"negated":                                         {`Accept-Contact: *;+g.3gpp.iari-ref="!urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp";require`, []int{0, 2}},
		"a flag":                                          {"Accept-Contact: *;+g.oma.sip-im;require;explicit", []int{1}},
		"two features, both needed":                       {"Accept-Contact: *;+g.oma.sip-im;" + chat + ";require;explicit", nil},
		"two preferences, each needed":                    {"Accept-Contact: *;+g.oma.sip-im;require;explicit\r\nAccept-Contact: *;" + chat + ";require;explicit", nil},
		"reject":                                          {"Reject-Contact: *;+g.oma.sip-im", []int{0, 2}},
		"reject needs every feature":                      {"Reject-Contact: *;+g.oma.sip-im;" + chat, []int{0, 1, 2}},
		"a preference that does not parse":                {"Accept-Contact: sip:nonsense;require", []int{0, 1, 2}},
	} {
		t.Run(name, func(t *testing.T) {
			var extra []string
			if c.field != "" {
				extra = append(extra, c.field)
			}
			r := request(t, "INVITE", impu1, extra...)
			var got []string
			for _, k := range accepted(cs, r.Message) {
				got = append(got, k.URI)
			}
			var want []string
			for _, i := range c.want {
				want = append(want, devices[i])
			}
			if !slices.Equal(got, want) {
				t.Errorf("kept %v, want %v", got, want)
			}
		})
	}
}
