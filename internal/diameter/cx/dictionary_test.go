package cx

import (
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
)

func TestDictionaryKnowsEveryCxAVPWithItsType(t *testing.T) {
	d := testDictionary(t)
	for _, want := range []diameter.AVPDef{
		{Name: "Public-Identity", Code: 601, VendorID: 10415, Type: diameter.TypeUTF8String},
		{Name: "User-Data", Code: 606, VendorID: 10415, Type: diameter.TypeOctetString},
		{Name: "SIP-Auth-Data-Item", Code: 612, VendorID: 10415, Type: diameter.TypeGrouped},
		{Name: "Server-Assignment-Type", Code: 614, VendorID: 10415, Type: diameter.TypeEnumerated},
		{Name: "Supported-Features", Code: 628, VendorID: 10415, Type: diameter.TypeGrouped},
		{Name: "SIP-Digest-Authenticate", Code: 635, VendorID: 10415, Type: diameter.TypeGrouped},
		{Name: "Digest-HA1", Code: 121, VendorID: 0, Type: diameter.TypeUTF8String},
	} {
		got, ok := d.Lookup(want.Code, want.VendorID)
		if !ok || got != want {
			t.Errorf("Lookup(%d, %d) = %+v, %v; want %+v", want.Code, want.VendorID, got, ok, want)
		}
	}
}

func TestCxAVPsCarryTheMBitTheirTableRequires(t *testing.T) {
	for _, s := range []struct {
		spec AVPSpec
		m    bool
	}{
		{specPublicIdentity, true},
		{specSIPAuthDataItem, true},
		{specDigestHA1, true},
		{specSupportedFeaturesInRequest, true},
		{specSupportedFeaturesInAnswer, false},
		{specFeatureList, false},
		{specAssociatedIdentities, false},
		{specWildcardedPublicIdentity, false},
		{specSIPDigestAuthenticate, false},
	} {
		a := s.spec.UTF8String("")
		if a.Mandatory() != s.m {
			t.Errorf("%s M bit = %t, want %t (TS 29.229 Table 6.3.0.1)", s.spec.Name, a.Mandatory(), s.m)
		}
		if (a.Flags&diameter.FlagVendor != 0) != (s.spec.VendorID != 0) {
			t.Errorf("%s V bit does not follow its vendor", s.spec.Name)
		}
	}
}
