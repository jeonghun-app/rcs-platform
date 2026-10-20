package icscf

import (
	"slices"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

// TS 24.229 §5.3.1.2 step 1: every mandatory capability, then the most
// optional ones, then configuration order.
func TestRankKeepsTheSCSCFsWithEveryMandatoryCapabilityMostOptionalFirst(t *testing.T) {
	list := newCandidates([]SCSCF{
		{URI: mustURI("sip:a.rcs.local")},
		{URI: mustURI("sip:b.rcs.local"), Mandatory: []uint32{1}, Optional: []uint32{2}},
		{URI: mustURI("sip:c.rcs.local"), Mandatory: []uint32{1, 3}, Optional: []uint32{2, 4}},
		{URI: mustURI("sip:d.rcs.local"), Optional: []uint32{1, 2, 4}},
		{URI: mustURI("sip:e.rcs.local"), Mandatory: []uint32{1}, Optional: []uint32{1}},
	})
	cases := []struct {
		name string
		want *cx.ServerCapabilities
		out  []string
	}{
		{"none asked keeps every one in order", nil, []string{"a", "b", "c", "d", "e"}},
		{"empty capabilities are the same", &cx.ServerCapabilities{}, []string{"a", "b", "c", "d", "e"}},
		{"a mandatory capability excludes the rest", &cx.ServerCapabilities{Mandatory: []uint32{1}}, []string{"b", "c", "d", "e"}},
		{"an optional or mandatory one of the S-CSCF counts alike", &cx.ServerCapabilities{Mandatory: []uint32{3}}, []string{"c"}},
		{"more optional ones first", &cx.ServerCapabilities{Mandatory: []uint32{1}, Optional: []uint32{2, 4}}, []string{"c", "d", "b", "e"}},
		{"ties keep configuration order", &cx.ServerCapabilities{Optional: []uint32{2}}, []string{"b", "c", "d", "a", "e"}},
		{"a capability listed twice is worth one", &cx.ServerCapabilities{Optional: []uint32{2, 2, 2, 4}}, []string{"c", "d", "b", "a", "e"}},
		{"nobody has it", &cx.ServerCapabilities{Mandatory: []uint32{1, 9}}, nil},
		{"server names do not narrow the choice", &cx.ServerCapabilities{Mandatory: []uint32{3}, ServerNames: []string{"sip:a.rcs.local"}}, []string{"c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, u := range rank(list, tc.want) {
				got = append(got, u.Host[:1])
			}
			if !slices.Equal(got, tc.out) {
				t.Errorf("rank = %v, want %v", got, tc.out)
			}
		})
	}
}

// The I-CSCF chooses the first ranked one, and does not modify the answer.
func TestSelectionTakesTheFirstRankedSCSCFAndLeavesTheAnswerAlone(t *testing.T) {
	g := newRig(t, func(c *Config) {
		c.SCSCFs = []SCSCF{
			{URI: mustURI("sip:a.rcs.local"), Optional: []uint32{5}},
			{URI: mustURI("sip:b.rcs.local"), Optional: []uint32{5, 6}},
		}
	})
	caps := &cx.ServerCapabilities{Optional: []uint32{6, 5, 6}}
	g.hss.uaa = uaa(experimental(cx.FirstRegistration), "", caps)
	if got := describe(t, g.route(register(t))).uri; got != "sip:b.rcs.local" {
		t.Errorf("chose %s, want sip:b.rcs.local", got)
	}
	if !slices.Equal(caps.Optional, []uint32{6, 5, 6}) {
		t.Errorf("the answer's capabilities became %v", caps.Optional)
	}
}
