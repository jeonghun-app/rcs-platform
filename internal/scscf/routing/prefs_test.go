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
		"require explicit": {"Accept-Contact: *;" + chat + ";require;explicit", []int{0, 2}},
		"require, not stated matches implicitly (§7.2.4)": {"Accept-Contact: *;" + chat + ";require", []int{0, 1, 2}},
		"without require, all":                            {"Accept-Contact: *;" + chat, []int{0, 1, 2}},
		"without require, even a contradicting one":       {`Accept-Contact: *;+g.3gpp.iari-ref="urn%3Aother"`, []int{0, 1, 2}},
		"a flag that must be false":                       {"Accept-Contact: *;+g.oma.sip-im=FALSE;require;explicit", []int{2}},
		"one of a list":                                   {`Accept-Contact: *;+g.3gpp.iari-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush";require;explicit`, []int{1, 2}},
		"any of a list":                                   {`Accept-Contact: *;+g.3gpp.iari-ref="urn%3Ax,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp";require;explicit`, []int{1, 2}},
		"a token without case (§7.2.4)":                   {`Accept-Contact: *;+G.3GPP.ICSI-REF="URN%3aURN-7%3a3GPP-SERVICE.IMS.ICSI.OMA.CPM.SESSION";require;explicit`, []int{0, 2}},
		"negated":                                         {`Accept-Contact: *;+g.3gpp.iari-ref="!urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp";require`, []int{0, 2}},
		"a flag":                                          {"Accept-Contact: *;+g.oma.sip-im;require;explicit", []int{1, 2}},
		"two features, both needed":                       {"Accept-Contact: *;+g.oma.sip-im;" + chat + ";require;explicit", []int{2}},
		"two preferences, each needed":                    {"Accept-Contact: *;+g.oma.sip-im;require;explicit\r\nAccept-Contact: *;" + chat + ";require;explicit", []int{2}},
		"reject":                                          {"Reject-Contact: *;+g.oma.sip-im", []int{0, 2}},
		"reject, not a binding without features":          {"Reject-Contact: *", []int{2}},
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

// TestCallerPreferenceValues (RFC 3840 §9, RFC 3841 §7.2.4): a string in
// angle brackets is one value, compared with case; a number is compared by
// value.
func TestCallerPreferenceValues(t *testing.T) {
	cs := []state.Contact{
		binding(1, 0, time.Hour, `+sip.description="<Alice, at home>"`, `+x.level="#=4"`),
		binding(2, 0, time.Hour, `+sip.description="<alice, at home>"`, `+x.level="#=12"`),
	}
	for name, c := range map[string]struct {
		field string
		want  []int
	}{
		"a whole string":         {`Accept-Contact: *;+sip.description="<Alice, at home>";require;explicit`, []int{0}},
		"not part of one":        {`Accept-Contact: *;+sip.description="<Alice>";require;explicit`, nil},
		"at least":               {`Accept-Contact: *;+x.level="#>=5";require;explicit`, []int{1}},
		"at most":                {`Accept-Contact: *;+x.level="#<=4";require;explicit`, []int{0}},
		"equal":                  {`Accept-Contact: *;+x.level="#=12";require;explicit`, []int{1}},
		"a range":                {`Accept-Contact: *;+x.level="#3:5";require;explicit`, []int{0}},
		"not a number":           {`Accept-Contact: *;+x.level="#>=1e1";require;explicit`, nil},
		"one of a numbers' list": {`Accept-Contact: *;+x.level="#<=1,#>=10";require;explicit`, []int{1}},
	} {
		t.Run(name, func(t *testing.T) {
			var got []string
			for _, k := range accepted(cs, request(t, "INVITE", impu1, c.field).Message) {
				got = append(got, k.URI)
			}
			var want []string
			for _, i := range c.want {
				want = append(want, cs[i].URI)
			}
			if !slices.Equal(got, want) {
				t.Errorf("kept %v, want %v", got, want)
			}
		})
	}
}
