package routing

import (
	"fmt"
	"slices"
	"strings"
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
		"a flag that must be false, quoted":               {`Accept-Contact: *;+g.oma.sip-im="FALSE";require;explicit`, []int{2}},
		"a flag quoted as TRUE":                           {`Accept-Contact: *;+g.oma.sip-im="TRUE";require;explicit`, []int{1, 2}},
		"a flag quoted as true":                           {`Accept-Contact: *;+g.oma.sip-im="true";require;explicit`, []int{1, 2}},
		"negated, the one with the value dropped":         {`Accept-Contact: *;+g.3gpp.iari-ref="!urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp";require;explicit`, []int{2}},
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
		"a preference that does not parse":                {"Accept-Contact: sip:nonsense", []int{0, 1, 2}},
		"one that does not parse, beside one that does":   {"Accept-Contact: sip:nonsense\r\nAccept-Contact: *;+g.oma.sip-im;require;explicit", []int{1, 2}},
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
		"at least, equal":        {`Accept-Contact: *;+x.level="#>=4";require;explicit`, []int{0, 1}},
		"a range above one":      {`Accept-Contact: *;+x.level="#5:20";require;explicit`, []int{1}},
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

// TestMoreCallerPreferencesThanEightAre400 (#322): each costs a pass over
// every binding of the user, and RCS sends one or two.
func TestMoreCallerPreferencesThanEightAre400(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	rt := e.router(nil)
	for name, c := range map[string]struct {
		field  string
		status int
	}{
		"eight accepts": {"Accept-Contact: " + strings.Repeat("*;audio, ", 7) + "*;audio", 0},
		"nine accepts":  {"Accept-Contact: " + strings.Repeat("*;audio, ", 8) + "*;audio", 400},
		"nine rejects":  {"Reject-Contact: " + strings.Repeat("*;video, ", 8) + "*;video", 400},
	} {
		if d := rt.Terminating(bg, request(t, "INVITE", impu1, c.field)); d.Status != c.status {
			t.Errorf("%s: status %d, want %d", name, d.Status, c.status)
		}
	}
}

// TestTheWorkOfCallerPreferencesIsBounded (#322, security's probe): a
// binding registered with long value lists, and a request repeating
// predicates over them in every element it may carry, cost one look-up per
// predicate value per binding, however long the binding's lists are.
func TestTheWorkOfCallerPreferencesIsBounded(t *testing.T) {
	var values []string
	for i := range 400 {
		values = append(values, fmt.Sprintf("urn%%3Ax%d", i))
	}
	tag := `+g.3gpp.iari-ref="` + strings.Join(values, ",") + `"`
	var cs []state.Contact
	for i := range 28 {
		cs = append(cs, binding(i+1, 0, time.Hour, tag, `+x.n="#=`+strings.Repeat("1", 10)+`"`))
	}
	var preds []string
	for i := range 40 {
		preds = append(preds, fmt.Sprintf("urn%%3Ay%d", i))
	}
	el := `*;+g.3gpp.iari-ref="` + strings.Join(preds, ",") + `";+x.n="#>=1,#<=2,#3:4";require`
	var els []string
	for range maxPreferences {
		els = append(els, el)
	}
	r := request(t, "INVITE", impu1, "Accept-Contact: "+strings.Join(els, ", "), "Reject-Contact: "+strings.Join(els, ", "))
	p, err := preferencesOf(r.Message)
	if err != nil {
		t.Fatal(err)
	}
	var ops int
	p.accepted(cs, &ops)
	// Per binding: the first accept's 40 values miss, and the work stops.
	if perBinding := 40 + 3; ops > len(cs)*perBinding {
		t.Errorf("%d values compared for %d bindings, want at most %d", ops, len(cs), len(cs)*perBinding)
	}
	// Bindings that match every predicate are compared with each.
	match := `+g.3gpp.iari-ref="` + strings.Join(preds, ",") + `"`
	for i := range cs {
		cs[i].FeatureTags = []string{match, `+x.n="#=1"`}
	}
	ops = 0
	p.accepted(cs, &ops)
	if most := len(cs) * 2 * maxPreferences * (1 + 1); ops > most {
		t.Errorf("%d values compared, want at most %d", ops, most)
	}
}

// TestABindingRegisteredWithAQuotedTRUEHasTheFlag (RFC 3840 §9): a
// boolean in quotes is the flag it writes out.
func TestABindingRegisteredWithAQuotedTRUEHasTheFlag(t *testing.T) {
	cs := []state.Contact{binding(1, 0, time.Hour, `+g.oma.sip-im="TRUE"`)}
	if got := accepted(cs, request(t, "INVITE", impu1, "Accept-Contact: *;+g.oma.sip-im;require;explicit").Message); len(got) != 1 {
		t.Error("a binding with +g.oma.sip-im=\"TRUE\" was dropped by the flag")
	}
}

// TestAnUnreadablePreferenceThatRequiresIs400: leaving it out would send
// the request where the caller asked it not to go.
func TestAnUnreadablePreferenceThatRequiresIs400(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	rt := e.router(nil)
	for field, status := range map[string]int{
		"Accept-Contact: sip:nonsense;require":          400,
		`Accept-Contact: *;+a="open;require`:            400,
		"Reject-Contact: sip:nonsense;require":          400,
		"Accept-Contact: sip:nonsense":                  0,
		"Accept-Contact: sip:nonsense, *;audio;require": 0,
	} {
		if d := rt.Terminating(bg, request(t, "INVITE", impu1, field)); d.Status != status {
			t.Errorf("%s: status %d, want %d", field, d.Status, status)
		}
	}
}

// TestANegatedValueKeepsABindingWithAnotherValue (QA on #322): !v asks for
// a binding without v, which one stating only another value is.
func TestANegatedValueKeepsABindingWithAnotherValue(t *testing.T) {
	geo := `+g.3gpp.iari-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush"`
	cs := []state.Contact{binding(1, 0, time.Hour, geo)}
	r := request(t, "INVITE", impu1, `Accept-Contact: *;+g.3gpp.iari-ref="!urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp";require;explicit`)
	if got := accepted(cs, r.Message); len(got) != 1 {
		t.Errorf("a binding with geopush only was dropped by !fthttp")
	}
}
