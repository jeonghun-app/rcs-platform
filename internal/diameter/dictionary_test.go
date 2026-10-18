package diameter

import (
	"strings"
	"testing"
)

func TestBaseDictionaryHasEveryBaseAVPTheIssueLists(t *testing.T) {
	d, err := NewDictionary()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]DataType{
		"Origin-Host":                    TypeDiameterIdentity,
		"Origin-Realm":                   TypeDiameterIdentity,
		"Destination-Host":               TypeDiameterIdentity,
		"Destination-Realm":              TypeDiameterIdentity,
		"Session-Id":                     TypeUTF8String,
		"Result-Code":                    TypeUnsigned32,
		"Experimental-Result":            TypeGrouped,
		"Experimental-Result-Code":       TypeUnsigned32,
		"Auth-Application-Id":            TypeUnsigned32,
		"Vendor-Specific-Application-Id": TypeGrouped,
		"Host-IP-Address":                TypeAddress,
		"Vendor-Id":                      TypeUnsigned32,
		"Product-Name":                   TypeUTF8String,
		"Supported-Vendor-Id":            TypeUnsigned32,
		"Origin-State-Id":                TypeUnsigned32,
		"Failed-AVP":                     TypeGrouped,
		"Error-Message":                  TypeUTF8String,
		"Disconnect-Cause":               TypeEnumerated,
		"Auth-Session-State":             TypeEnumerated,
		"Route-Record":                   TypeDiameterIdentity,
		"Proxy-Info":                     TypeGrouped,
		"Event-Timestamp":                TypeTime,
		"Redirect-Host":                  TypeDiameterURI,
	}
	for name, typ := range want {
		def, ok := d.ByName(name)
		if !ok {
			t.Errorf("%s missing", name)
			continue
		}
		if def.Type != typ {
			t.Errorf("%s has type %v, want %v", name, def.Type, typ)
		}
		if got, ok := d.Lookup(def.Code, def.VendorID); !ok || got != def {
			t.Errorf("Lookup(%d, %d) = %+v, %v", def.Code, def.VendorID, got, ok)
		}
	}
}

func TestByNameIgnoresCase(t *testing.T) {
	d, _ := NewDictionary()
	if def, ok := d.ByName("origin-HOST"); !ok || def.Code != AVPOriginHost {
		t.Fatalf("ByName = %+v, %v", def, ok)
	}
}

func TestApplicationDefinitionsExtendTheBaseDictionary(t *testing.T) {
	d := testDictionary(t)
	if def, ok := d.Lookup(codeGroup, testVendor); !ok || def.Name != "Test-Grouped" {
		t.Fatalf("Lookup = %+v, %v", def, ok)
	}
	if _, ok := d.Lookup(codeGroup, 0); ok {
		t.Fatal("vendor AVP found without its vendor")
	}
	if _, ok := d.Lookup(AVPOriginHost, 0); !ok {
		t.Fatal("base AVPs missing from an extended dictionary")
	}
}

func TestConflictingDefinitionsAreRefused(t *testing.T) {
	tests := []struct {
		name string
		defs []AVPDef
		want string
	}{
		{"same code and vendor, different name", []AVPDef{{"Not-Origin-Host", AVPOriginHost, 0, TypeDiameterIdentity}}, "defined as both"},
		{"same name, different code", []AVPDef{{"Origin-Host", 9999, 0, TypeDiameterIdentity}}, "used for both"},
		{"no name", []AVPDef{{"", 9999, 0, TypeOctetString}}, "no name"},
		{"unknown type", []AVPDef{{"Bad", 9999, 0, DataType(200)}}, "unknown type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewDictionary(tt.defs...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestRepeatingAnIdenticalDefinitionIsAllowed(t *testing.T) {
	if _, err := NewDictionary(AVPDef{"Origin-Host", AVPOriginHost, 0, TypeDiameterIdentity}); err != nil {
		t.Fatal(err)
	}
}

func TestDataTypesHaveTheirSpecificationNames(t *testing.T) {
	if TypeDiameterIdentity.String() != "DiameterIdentity" || TypeGrouped.String() != "Grouped" {
		t.Fatalf("names: %v %v", TypeDiameterIdentity, TypeGrouped)
	}
	if DataType(99).String() != "DataType(99)" {
		t.Fatalf("unknown type name: %v", DataType(99))
	}
}
