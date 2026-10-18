package sh

import (
	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

func spec(name string, code uint32, t diameter.DataType, flags diameter.AVPFlags) cx.AVPSpec {
	return cx.AVPSpec{AVPDef: diameter.AVPDef{Name: name, Code: code, VendorID: cx.Vendor3GPP, Type: t}, Flags: flags}
}

const (
	m    = diameter.FlagMandatory
	none = diameter.AVPFlags(0)
)

// AVPs of TS 29.329 Table 6.3.1 that this package reads or writes, including
// the ones Sh shares with Cx, which are defined exactly as in package cx so
// that a node serving both can merge the two lists.
var (
	specUserIdentity             = spec("User-Identity", AVPUserIdentity, diameter.TypeGrouped, m)
	specMSISDN                   = spec("MSISDN", AVPMSISDN, diameter.TypeOctetString, m)
	specDataReference            = spec("Data-Reference", AVPDataReference, diameter.TypeEnumerated, m)
	specServiceIndication        = spec("Service-Indication", AVPServiceIndication, diameter.TypeOctetString, m)
	specSubsReqType              = spec("Subs-Req-Type", AVPSubsReqType, diameter.TypeEnumerated, m)
	specIdentitySet              = spec("Identity-Set", AVPIdentitySet, diameter.TypeEnumerated, none)
	specExpiryTime               = spec("Expiry-Time", AVPExpiryTime, diameter.TypeTime, none)
	specSendDataIndication       = spec("Send-Data-Indication", AVPSendDataIndication, diameter.TypeEnumerated, none)
	specOneTimeNotification      = spec("One-Time-Notification", AVPOneTimeNotification, diameter.TypeEnumerated, none)
	specRepositoryDataID         = spec("Repository-Data-ID", AVPRepositoryDataID, diameter.TypeGrouped, none)
	specSequenceNumber           = spec("Sequence-Number", AVPSequenceNumber, diameter.TypeUnsigned32, none)
	specPublicIdentity           = spec("Public-Identity", cx.AVPPublicIdentity, diameter.TypeUTF8String, m)
	specServerName               = spec("Server-Name", cx.AVPServerName, diameter.TypeUTF8String, m)
	specWildcardedPublicIdentity = spec("Wildcarded-Public-Identity", cx.AVPWildcardedPublicIdentity, diameter.TypeUTF8String, none)
	specWildcardedIMPU           = spec("Wildcarded-IMPU", cx.AVPWildcardedIMPU, diameter.TypeUTF8String, none)
	specSupportedFeatures        = spec("Supported-Features", cx.AVPSupportedFeatures, diameter.TypeGrouped, m)
	specFeatureListID            = spec("Feature-List-ID", cx.AVPFeatureListID, diameter.TypeUnsigned32, none)
	specFeatureList              = spec("Feature-List", cx.AVPFeatureList, diameter.TypeUnsigned32, none)
	specDestinationHost          = cx.AVPSpec{AVPDef: diameter.AVPDef{Name: "Destination-Host", Code: diameter.AVPDestinationHost, Type: diameter.TypeDiameterIdentity}, Flags: m}
	specUserName                 = cx.AVPSpec{AVPDef: diameter.AVPDef{Name: "User-Name", Code: diameter.AVPUserName, Type: diameter.TypeUTF8String}, Flags: m}
)

// Sh and Cx both call their User-Data AVP "User-Data" (702 here, 606 in Cx).
// A dictionary needs distinct names, and a node serving both applications
// needs both AVPs, so this one carries a qualifier.
var specUserData = spec("User-Data (Sh)", AVPUserData, diameter.TypeOctetString, m)

// AVPs are the definitions of the Sh AVPs this package uses, for the
// dictionary of every node that speaks Sh:
//
//	dict, err := diameter.NewDictionary(sh.AVPs...)
//
// or, for a node that speaks Cx too,
//
//	dict, err := diameter.NewDictionary(slices.Concat(cx.AVPs, sh.AVPs)...)
var AVPs = []diameter.AVPDef{
	specUserIdentity.AVPDef,
	specMSISDN.AVPDef,
	specUserData.AVPDef,
	specDataReference.AVPDef,
	specServiceIndication.AVPDef,
	specSubsReqType.AVPDef,
	specIdentitySet.AVPDef,
	specExpiryTime.AVPDef,
	specSendDataIndication.AVPDef,
	specOneTimeNotification.AVPDef,
	specRepositoryDataID.AVPDef,
	specSequenceNumber.AVPDef,
	specPublicIdentity.AVPDef,
	specServerName.AVPDef,
	specWildcardedPublicIdentity.AVPDef,
	specWildcardedIMPU.AVPDef,
	specSupportedFeatures.AVPDef,
	specFeatureListID.AVPDef,
	specFeatureList.AVPDef,
}

// ErrorAVPs supplies the AVPs of the failure answers a node builds itself for
// Sh requests:
//
//	node.SetErrorAVPs(sh.ApplicationID, sh.ErrorAVPs)
func ErrorAVPs(*diameter.Message) []*diameter.AVP { return cx.ApplicationAVPs(Application) }
