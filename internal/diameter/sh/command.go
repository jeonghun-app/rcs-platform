package sh

import (
	"fmt"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

// checkCommand returns an error unless m is an Sh request (or answer) with
// the command code.
func checkCommand(m *diameter.Message, code uint32, request bool) error {
	if m.ApplicationID == ApplicationID && m.Code == code && m.IsRequest() == request {
		return nil
	}
	return fmt.Errorf("sh: message is application %d command %d (R=%t), want Sh command %d (R=%t)",
		m.ApplicationID, m.Code, m.IsRequest(), code, request)
}

func errMissing(command, field string) error {
	return fmt.Errorf("sh: %s has no %s", command, field)
}

func optionalUTF8(s cx.AVPSpec, v string) []*diameter.AVP {
	if v == "" {
		return nil
	}
	return []*diameter.AVP{s.UTF8String(v)}
}

// wildcardAVPs are the Wildcarded-Public-Identity and Wildcarded-IMPU that
// most Sh commands may carry next to User-Identity.
func wildcardAVPs(public, impu string) []*diameter.AVP {
	return append(optionalUTF8(specWildcardedPublicIdentity, public), optionalUTF8(specWildcardedIMPU, impu)...)
}

func readWildcards(f *cx.Fields) (public, impu string) {
	return f.UTF8String(specWildcardedPublicIdentity, cx.Optional), f.UTF8String(specWildcardedIMPU, cx.Optional)
}

// dataReferences encodes the one or more Data-Reference AVPs a UDR, PUR or
// SNR requires (*{Data-Reference} in TS 29.329 §6.1).
func dataReferences(command string, refs []DataReference) ([]*diameter.AVP, error) {
	if len(refs) == 0 {
		return nil, errMissing(command, "Data-Reference")
	}
	out := make([]*diameter.AVP, len(refs))
	for i, r := range refs {
		out[i] = specDataReference.Enumerated(int32(r))
	}
	return out, nil
}

func readDataReferences(f *cx.Fields) []DataReference {
	if !f.Has(specDataReference) {
		// Reported as a missing AVP with the Failed-AVP RFC 6733 §7.5 asks
		// for.
		f.Enumerated(specDataReference, cx.Required)
		return nil
	}
	var out []DataReference
	for _, v := range f.AllEnumerated(specDataReference) {
		out = append(out, DataReference(v))
	}
	return out
}

func serviceIndications(values []string) []*diameter.AVP {
	out := make([]*diameter.AVP, len(values))
	for i, v := range values {
		out[i] = specServiceIndication.OctetString([]byte(v))
	}
	return out
}

func readServiceIndications(f *cx.Fields) []string {
	var out []string
	for _, v := range f.AllOctetString(specServiceIndication) {
		out = append(out, string(v))
	}
	return out
}

func identitySets(sets []IdentitySet) []*diameter.AVP {
	out := make([]*diameter.AVP, len(sets))
	for i, s := range sets {
		out[i] = specIdentitySet.Enumerated(int32(s))
	}
	return out
}

func readIdentitySets(f *cx.Fields) []IdentitySet {
	var out []IdentitySet
	for _, v := range f.AllEnumerated(specIdentitySet) {
		out = append(out, IdentitySet(v))
	}
	return out
}
