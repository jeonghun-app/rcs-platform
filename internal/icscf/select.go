package icscf

import (
	"slices"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// candidate is a configured S-CSCF with its capabilities as a set.
type candidate struct {
	uri  sip.URI
	caps map[uint32]struct{}
}

func newCandidates(list []SCSCF) []candidate {
	out := make([]candidate, len(list))
	for i, s := range list {
		caps := make(map[uint32]struct{}, len(s.Mandatory)+len(s.Optional))
		for _, c := range s.Mandatory {
			caps[c] = struct{}{}
		}
		for _, c := range s.Optional {
			caps[c] = struct{}{}
		}
		out[i] = candidate{uri: s.URI, caps: caps}
	}
	return out
}

// rank returns the configured S-CSCFs that have every mandatory capability
// of want, those with more of its optional capabilities first and in
// configuration order otherwise (TS 24.229 §5.3.1.2 step 1, §5.3.2.1). A nil
// want, which the HSS sends when any S-CSCF will do (TS 29.228 §6.7), keeps
// them all in configuration order.
//
// Server-Name values inside want are not compared with the configured URIs
// here: when there are any, the Router uses the first instead of ranking at
// all (TS 29.228 §6.7).
//
// The Router forwards to the first. The rest are what a re-selection after
// the first fails (§5.3.1.3, §5.3.2.2) would try in turn; it is not done
// while the platform has a single S-CSCF service name (package
// documentation).
func rank(list []candidate, want *cx.ServerCapabilities) []sip.URI {
	type scored struct {
		uri   sip.URI
		score int
	}
	var mandatory, optional []uint32
	if want != nil {
		mandatory = want.Mandatory
		// An HSS listing a capability twice must not make it worth two.
		optional = slices.Compact(slices.Sorted(slices.Values(want.Optional)))
	}
	var ok []scored
	for _, c := range list {
		if hasAll(c.caps, mandatory) {
			ok = append(ok, scored{c.uri, count(c.caps, optional)})
		}
	}
	// Stable, so equal scores keep configuration order.
	slices.SortStableFunc(ok, func(a, b scored) int { return b.score - a.score })
	out := make([]sip.URI, len(ok))
	for i, s := range ok {
		out[i] = s.uri
	}
	return out
}

func hasAll(caps map[uint32]struct{}, want []uint32) bool {
	for _, c := range want {
		if _, ok := caps[c]; !ok {
			return false
		}
	}
	return true
}

// count is how many of want are in caps.
func count(caps map[uint32]struct{}, want []uint32) int {
	n := 0
	for _, c := range want {
		if _, ok := caps[c]; ok {
			n++
		}
	}
	return n
}
