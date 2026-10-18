package cx

import (
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
)

// AVPSpec is an AVP definition together with the flags it is sent with. The M
// bit follows the "must" column of TS 29.229 Table 6.3.0.1 (and of
// TS 29.329 Table 6.3.1 for Sh); a receiver ignores it for AVPs it
// understands, as both tables say, so it matters only when sending.
type AVPSpec struct {
	diameter.AVPDef
	Flags diameter.AVPFlags
}

func spec(name string, code, vendor uint32, t diameter.DataType, flags diameter.AVPFlags) AVPSpec {
	return AVPSpec{AVPDef: diameter.AVPDef{Name: name, Code: code, VendorID: vendor, Type: t}, Flags: flags}
}

// UTF8String returns the AVP carrying s. Like the other constructors it does
// not check the value against the type; [Fields] does that on receipt.
func (s AVPSpec) UTF8String(v string) *diameter.AVP {
	return diameter.NewAVP(s.Code, s.Flags, s.VendorID, []byte(v))
}

// OctetString returns the AVP carrying b.
func (s AVPSpec) OctetString(b []byte) *diameter.AVP {
	return diameter.NewAVP(s.Code, s.Flags, s.VendorID, b)
}

// Unsigned32 returns the AVP carrying v.
func (s AVPSpec) Unsigned32(v uint32) *diameter.AVP {
	return diameter.NewAVP(s.Code, s.Flags, s.VendorID, diameter.Unsigned32(v))
}

// Enumerated returns the AVP carrying v.
func (s AVPSpec) Enumerated(v int32) *diameter.AVP {
	return diameter.NewAVP(s.Code, s.Flags, s.VendorID, diameter.Enumerated(v))
}

// Time returns the AVP carrying t.
func (s AVPSpec) Time(t time.Time) *diameter.AVP {
	return diameter.NewAVP(s.Code, s.Flags, s.VendorID, diameter.Time(t))
}

// Grouped returns the AVP holding children.
func (s AVPSpec) Grouped(children ...*diameter.AVP) *diameter.AVP {
	return diameter.NewGrouped(s.Code, s.Flags, s.VendorID, children...)
}

const (
	m    = diameter.FlagMandatory
	none = diameter.AVPFlags(0)
)

// Base protocol AVPs this package reads and writes (RFC 6733 §4.5, §8).
var (
	specSessionID                   = spec("Session-Id", diameter.AVPSessionID, 0, diameter.TypeUTF8String, m)
	specOriginHost                  = spec("Origin-Host", diameter.AVPOriginHost, 0, diameter.TypeDiameterIdentity, m)
	specOriginRealm                 = spec("Origin-Realm", diameter.AVPOriginRealm, 0, diameter.TypeDiameterIdentity, m)
	specDestinationHost             = spec("Destination-Host", diameter.AVPDestinationHost, 0, diameter.TypeDiameterIdentity, m)
	specDestinationRealm            = spec("Destination-Realm", diameter.AVPDestinationRealm, 0, diameter.TypeDiameterIdentity, m)
	specUserName                    = spec("User-Name", diameter.AVPUserName, 0, diameter.TypeUTF8String, m)
	specVendorID                    = spec("Vendor-Id", diameter.AVPVendorID, 0, diameter.TypeUnsigned32, m)
	specAuthApplicationID           = spec("Auth-Application-Id", diameter.AVPAuthApplicationID, 0, diameter.TypeUnsigned32, m)
	specVendorSpecificApplicationID = spec("Vendor-Specific-Application-Id", diameter.AVPVendorSpecificApplicationID, 0, diameter.TypeGrouped, m)
	specAuthSessionState            = spec("Auth-Session-State", diameter.AVPAuthSessionState, 0, diameter.TypeEnumerated, m)
	specResultCode                  = spec("Result-Code", diameter.AVPResultCode, 0, diameter.TypeUnsigned32, m)
	specExperimentalResult          = spec("Experimental-Result", diameter.AVPExperimentalResult, 0, diameter.TypeGrouped, m)
	specExperimentalResultCode      = spec("Experimental-Result-Code", diameter.AVPExperimentalResultCode, 0, diameter.TypeUnsigned32, m)
	specSupportedFeaturesInRequest  = spec("Supported-Features", AVPSupportedFeatures, Vendor3GPP, diameter.TypeGrouped, m)
	specSupportedFeaturesInAnswer   = spec("Supported-Features", AVPSupportedFeatures, Vendor3GPP, diameter.TypeGrouped, none)
	specFeatureListID               = spec("Feature-List-ID", AVPFeatureListID, Vendor3GPP, diameter.TypeUnsigned32, none)
	specFeatureList                 = spec("Feature-List", AVPFeatureList, Vendor3GPP, diameter.TypeUnsigned32, none)
	specVisitedNetworkIdentifier    = spec("Visited-Network-Identifier", AVPVisitedNetworkIdentifier, Vendor3GPP, diameter.TypeOctetString, m)
	specPublicIdentity              = spec("Public-Identity", AVPPublicIdentity, Vendor3GPP, diameter.TypeUTF8String, m)
	specServerName                  = spec("Server-Name", AVPServerName, Vendor3GPP, diameter.TypeUTF8String, m)
	specServerCapabilities          = spec("Server-Capabilities", AVPServerCapabilities, Vendor3GPP, diameter.TypeGrouped, m)
	specMandatoryCapability         = spec("Mandatory-Capability", AVPMandatoryCapability, Vendor3GPP, diameter.TypeUnsigned32, m)
	specOptionalCapability          = spec("Optional-Capability", AVPOptionalCapability, Vendor3GPP, diameter.TypeUnsigned32, m)
	specUserData                    = spec("User-Data", AVPUserData, Vendor3GPP, diameter.TypeOctetString, m)
	specSIPNumberAuthItems          = spec("SIP-Number-Auth-Items", AVPSIPNumberAuthItems, Vendor3GPP, diameter.TypeUnsigned32, m)
	specSIPAuthenticationScheme     = spec("SIP-Authentication-Scheme", AVPSIPAuthenticationScheme, Vendor3GPP, diameter.TypeUTF8String, m)
	specSIPAuthenticate             = spec("SIP-Authenticate", AVPSIPAuthenticate, Vendor3GPP, diameter.TypeOctetString, m)
	specSIPAuthorization            = spec("SIP-Authorization", AVPSIPAuthorization, Vendor3GPP, diameter.TypeOctetString, m)
	specSIPAuthenticationContext    = spec("SIP-Authentication-Context", AVPSIPAuthenticationContext, Vendor3GPP, diameter.TypeOctetString, m)
	specSIPAuthDataItem             = spec("SIP-Auth-Data-Item", AVPSIPAuthDataItem, Vendor3GPP, diameter.TypeGrouped, m)
	specSIPItemNumber               = spec("SIP-Item-Number", AVPSIPItemNumber, Vendor3GPP, diameter.TypeUnsigned32, m)
	specServerAssignmentType        = spec("Server-Assignment-Type", AVPServerAssignmentType, Vendor3GPP, diameter.TypeEnumerated, m)
	specDeregistrationReason        = spec("Deregistration-Reason", AVPDeregistrationReason, Vendor3GPP, diameter.TypeGrouped, m)
	specReasonCode                  = spec("Reason-Code", AVPReasonCode, Vendor3GPP, diameter.TypeEnumerated, m)
	specReasonInfo                  = spec("Reason-Info", AVPReasonInfo, Vendor3GPP, diameter.TypeUTF8String, m)
	specChargingInformation         = spec("Charging-Information", AVPChargingInformation, Vendor3GPP, diameter.TypeGrouped, m)
	specPrimaryEventChargingFn      = spec("Primary-Event-Charging-Function-Name", AVPPrimaryEventChargingFunctionName, Vendor3GPP, diameter.TypeDiameterURI, m)
	specSecondaryEventChargingFn    = spec("Secondary-Event-Charging-Function-Name", AVPSecondaryEventChargingFunctionName, Vendor3GPP, diameter.TypeDiameterURI, m)
	specPrimaryChargingCollectionFn = spec("Primary-Charging-Collection-Function-Name", AVPPrimaryChargingCollectionFunctionName, Vendor3GPP, diameter.TypeDiameterURI, m)
	specSecondaryChargingCollectFn  = spec("Secondary-Charging-Collection-Function-Name", AVPSecondaryChargingCollectionFunctionName, Vendor3GPP, diameter.TypeDiameterURI, m)
	specUserAuthorizationType       = spec("User-Authorization-Type", AVPUserAuthorizationType, Vendor3GPP, diameter.TypeEnumerated, m)
	specUserDataAlreadyAvailable    = spec("User-Data-Already-Available", AVPUserDataAlreadyAvailable, Vendor3GPP, diameter.TypeEnumerated, m)
	specConfidentialityKey          = spec("Confidentiality-Key", AVPConfidentialityKey, Vendor3GPP, diameter.TypeOctetString, m)
	specIntegrityKey                = spec("Integrity-Key", AVPIntegrityKey, Vendor3GPP, diameter.TypeOctetString, m)
	specAssociatedIdentities        = spec("Associated-Identities", AVPAssociatedIdentities, Vendor3GPP, diameter.TypeGrouped, none)
	specOriginatingRequest          = spec("Originating-Request", AVPOriginatingRequest, Vendor3GPP, diameter.TypeEnumerated, m)
	specWildcardedPublicIdentity    = spec("Wildcarded-Public-Identity", AVPWildcardedPublicIdentity, Vendor3GPP, diameter.TypeUTF8String, none)
	specSIPDigestAuthenticate       = spec("SIP-Digest-Authenticate", AVPSIPDigestAuthenticate, Vendor3GPP, diameter.TypeGrouped, none)
	specWildcardedIMPU              = spec("Wildcarded-IMPU", AVPWildcardedIMPU, Vendor3GPP, diameter.TypeUTF8String, none)
	specAlternateDigestAlgorithm    = spec("Alternate-Digest-Algorithm", AVPAlternateDigestAlgorithm, Vendor3GPP, diameter.TypeUTF8String, none)
	specAlternateDigestHA1          = spec("Alternate-Digest-HA1", AVPAlternateDigestHA1, Vendor3GPP, diameter.TypeUTF8String, none)
	specDigestRealm                 = spec("Digest-Realm", AVPDigestRealm, 0, diameter.TypeUTF8String, m)
	specDigestQoP                   = spec("Digest-QoP", AVPDigestQoP, 0, diameter.TypeUTF8String, m)
	specDigestAlgorithm             = spec("Digest-Algorithm", AVPDigestAlgorithm, 0, diameter.TypeUTF8String, m)
	specDigestHA1                   = spec("Digest-HA1", AVPDigestHA1, 0, diameter.TypeUTF8String, m)
)

// AVPs are the definitions of the Cx AVPs this package uses, to be added to the
// base dictionary of every node that speaks Cx:
//
//	dict, err := diameter.NewDictionary(cx.AVPs...)
//
// Without them a node rejects every Cx request: almost all Cx AVPs carry the M
// bit, and RFC 6733 §4.1 makes a node refuse mandatory AVPs it does not know.
// Digest-HA1 is a UTF8String as TS 29.229 Table 6.3.0.1 lists it.
var AVPs = defs(
	specSupportedFeaturesInRequest,
	specFeatureListID,
	specFeatureList,
	specVisitedNetworkIdentifier,
	specPublicIdentity,
	specServerName,
	specServerCapabilities,
	specMandatoryCapability,
	specOptionalCapability,
	specUserData,
	specSIPNumberAuthItems,
	specSIPAuthenticationScheme,
	specSIPAuthenticate,
	specSIPAuthorization,
	specSIPAuthenticationContext,
	specSIPAuthDataItem,
	specSIPItemNumber,
	specServerAssignmentType,
	specDeregistrationReason,
	specReasonCode,
	specReasonInfo,
	specChargingInformation,
	specPrimaryEventChargingFn,
	specSecondaryEventChargingFn,
	specPrimaryChargingCollectionFn,
	specSecondaryChargingCollectFn,
	specUserAuthorizationType,
	specUserDataAlreadyAvailable,
	specConfidentialityKey,
	specIntegrityKey,
	specAssociatedIdentities,
	specOriginatingRequest,
	specWildcardedPublicIdentity,
	specSIPDigestAuthenticate,
	specWildcardedIMPU,
	specAlternateDigestAlgorithm,
	specAlternateDigestHA1,
	specDigestRealm,
	specDigestQoP,
	specDigestAlgorithm,
	specDigestHA1,
)

func defs(specs ...AVPSpec) []diameter.AVPDef {
	out := make([]diameter.AVPDef, len(specs))
	for i, s := range specs {
		out[i] = s.AVPDef
	}
	return out
}
