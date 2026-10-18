package diameter

import (
	"fmt"
	"strings"
)

// DataType is an AVP data format (RFC 6733 §4.2 basic formats, §4.3 derived
// formats, §4.4 Grouped). It decides how the decoder validates a payload.
type DataType uint8

// Data types. Float32 and Float64 are left out: no base, Cx or Sh AVP uses
// them. An AVP whose type has no special rule is validated as OctetString.
const (
	TypeOctetString DataType = iota
	TypeInteger32
	TypeInteger64
	TypeUnsigned32
	TypeUnsigned64
	TypeGrouped
	TypeAddress
	TypeTime
	TypeUTF8String
	TypeDiameterIdentity
	TypeDiameterURI
	TypeEnumerated
)

var typeNames = [...]string{
	TypeOctetString:      "OctetString",
	TypeInteger32:        "Integer32",
	TypeInteger64:        "Integer64",
	TypeUnsigned32:       "Unsigned32",
	TypeUnsigned64:       "Unsigned64",
	TypeGrouped:          "Grouped",
	TypeAddress:          "Address",
	TypeTime:             "Time",
	TypeUTF8String:       "UTF8String",
	TypeDiameterIdentity: "DiameterIdentity",
	TypeDiameterURI:      "DiameterURI",
	TypeEnumerated:       "Enumerated",
}

func (t DataType) String() string {
	if int(t) < len(typeNames) {
		return typeNames[t]
	}
	return fmt.Sprintf("DataType(%d)", t)
}

// minPayload is the smallest valid payload for t. It sizes the zero-filled
// payload of a Failed-AVP built for an AVP whose length was unusable
// (RFC 6733 §7.1.5, DIAMETER_INVALID_AVP_LENGTH).
func (t DataType) minPayload() int {
	switch t {
	case TypeInteger32, TypeUnsigned32, TypeTime, TypeEnumerated:
		return 4
	case TypeInteger64, TypeUnsigned64:
		return 8
	case TypeAddress:
		return 2 + 4
	}
	return 0
}

// AVPDef describes one AVP: its wire identity (code and vendor) and the name
// and data type the specification gives it.
type AVPDef struct {
	Name     string
	Code     uint32
	VendorID uint32
	Type     DataType
}

type avpKey struct{ code, vendor uint32 }

// Dictionary maps AVPs to their definitions. It is immutable once built, so a
// single dictionary can be shared by every connection without locking.
//
// The decoder uses it to validate payloads, to descend into Grouped AVPs, and
// to answer DIAMETER_AVP_UNSUPPORTED for an AVP with the M bit that it does not
// know (RFC 6733 §4.1). An application whose AVPs are missing from the
// dictionary therefore cannot receive mandatory ones, which is the behaviour
// the RFC asks of a node that does not implement them.
type Dictionary struct {
	byKey  map[avpKey]AVPDef
	byName map[string]AVPDef
}

// NewDictionary returns a dictionary of the base AVPs plus defs. Application
// packages export their definitions and services combine them here, for
// example NewDictionary(cx.AVPs...). Two definitions with the same code and
// vendor, or the same name, are an error unless they are identical.
func NewDictionary(defs ...AVPDef) (*Dictionary, error) {
	d := &Dictionary{
		byKey:  make(map[avpKey]AVPDef, len(baseAVPs)+len(defs)),
		byName: make(map[string]AVPDef, len(baseAVPs)+len(defs)),
	}
	for _, list := range [][]AVPDef{baseAVPs, defs} {
		for _, def := range list {
			if err := d.add(def); err != nil {
				return nil, err
			}
		}
	}
	return d, nil
}

func (d *Dictionary) add(def AVPDef) error {
	if def.Name == "" {
		return fmt.Errorf("diameter: AVP %d (vendor %d) has no name", def.Code, def.VendorID)
	}
	if int(def.Type) >= len(typeNames) {
		return fmt.Errorf("diameter: AVP %s has unknown type %d", def.Name, def.Type)
	}
	key := avpKey{def.Code, def.VendorID}
	if old, ok := d.byKey[key]; ok && old != def {
		return fmt.Errorf("diameter: AVP %d (vendor %d) defined as both %s and %s",
			def.Code, def.VendorID, old.Name, def.Name)
	}
	name := strings.ToLower(def.Name)
	if old, ok := d.byName[name]; ok && old != def {
		return fmt.Errorf("diameter: AVP name %s used for both %d and %d", def.Name, old.Code, def.Code)
	}
	d.byKey[key] = def
	d.byName[name] = def
	return nil
}

// Lookup returns the definition for an AVP code and vendor.
func (d *Dictionary) Lookup(code, vendorID uint32) (AVPDef, bool) {
	def, ok := d.byKey[avpKey{code, vendorID}]
	return def, ok
}

// ByName returns the definition with the given name, compared without regard
// to case.
func (d *Dictionary) ByName(name string) (AVPDef, bool) {
	def, ok := d.byName[strings.ToLower(name)]
	return def, ok
}

// baseAVPs are the AVPs of RFC 6733 §4.5 and §8 that the base protocol and the
// Cx/Sh applications use. Accounting, redirect-usage and re-authentication
// AVPs are left out until something needs them.
var baseAVPs = []AVPDef{
	{"User-Name", AVPUserName, 0, TypeUTF8String},
	{"Class", AVPClass, 0, TypeOctetString},
	{"Session-Timeout", AVPSessionTimeout, 0, TypeUnsigned32},
	{"Proxy-State", AVPProxyState, 0, TypeOctetString},
	{"Event-Timestamp", AVPEventTimestamp, 0, TypeTime},
	{"Host-IP-Address", AVPHostIPAddress, 0, TypeAddress},
	{"Auth-Application-Id", AVPAuthApplicationID, 0, TypeUnsigned32},
	{"Acct-Application-Id", AVPAcctApplicationID, 0, TypeUnsigned32},
	{"Vendor-Specific-Application-Id", AVPVendorSpecificApplicationID, 0, TypeGrouped},
	{"Session-Id", AVPSessionID, 0, TypeUTF8String},
	{"Origin-Host", AVPOriginHost, 0, TypeDiameterIdentity},
	{"Supported-Vendor-Id", AVPSupportedVendorID, 0, TypeUnsigned32},
	{"Vendor-Id", AVPVendorID, 0, TypeUnsigned32},
	{"Firmware-Revision", AVPFirmwareRevision, 0, TypeUnsigned32},
	{"Result-Code", AVPResultCode, 0, TypeUnsigned32},
	{"Product-Name", AVPProductName, 0, TypeUTF8String},
	{"Disconnect-Cause", AVPDisconnectCause, 0, TypeEnumerated},
	{"Auth-Request-Type", AVPAuthRequestType, 0, TypeEnumerated},
	{"Auth-Session-State", AVPAuthSessionState, 0, TypeEnumerated},
	{"Origin-State-Id", AVPOriginStateID, 0, TypeUnsigned32},
	{"Failed-AVP", AVPFailedAVP, 0, TypeGrouped},
	{"Proxy-Host", AVPProxyHost, 0, TypeDiameterIdentity},
	{"Error-Message", AVPErrorMessage, 0, TypeUTF8String},
	{"Route-Record", AVPRouteRecord, 0, TypeDiameterIdentity},
	{"Destination-Realm", AVPDestinationRealm, 0, TypeDiameterIdentity},
	{"Proxy-Info", AVPProxyInfo, 0, TypeGrouped},
	{"Redirect-Host", AVPRedirectHost, 0, TypeDiameterURI},
	{"Destination-Host", AVPDestinationHost, 0, TypeDiameterIdentity},
	{"Error-Reporting-Host", AVPErrorReportingHost, 0, TypeDiameterIdentity},
	{"Origin-Realm", AVPOriginRealm, 0, TypeDiameterIdentity},
	{"Experimental-Result", AVPExperimentalResult, 0, TypeGrouped},
	{"Experimental-Result-Code", AVPExperimentalResultCode, 0, TypeUnsigned32},
	{"Inband-Security-Id", AVPInbandSecurityID, 0, TypeUnsigned32},
}
