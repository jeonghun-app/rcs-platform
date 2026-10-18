package sh

import (
	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

// ApplicationID is the IANA-assigned identifier of the Sh application
// (TS 29.329 §6). Like Cx it belongs to vendor 3GPP.
const ApplicationID uint32 = 16777217

// Application is how a node advertises Sh in its capabilities exchange.
var Application = diameter.Application{ID: ApplicationID, VendorID: cx.Vendor3GPP}

// Command codes (TS 29.329 Table 6.1.1).
const (
	CodeUserData               uint32 = 306 // UDR/UDA
	CodeProfileUpdate          uint32 = 307 // PUR/PUA
	CodeSubscribeNotifications uint32 = 308 // SNR/SNA
	CodePushNotification       uint32 = 309 // PNR/PNA
)

// AVP codes of TS 29.329 Table 6.3.1 that this package reads or writes,
// all of vendor 3GPP. Sh also uses the Cx AVPs Public-Identity,
// Server-Name, Wildcarded-Public-Identity, Wildcarded-IMPU and
// Supported-Features, whose codes are in package cx.
const (
	AVPUserIdentity        uint32 = 700
	AVPMSISDN              uint32 = 701
	AVPUserData            uint32 = 702
	AVPDataReference       uint32 = 703
	AVPServiceIndication   uint32 = 704
	AVPSubsReqType         uint32 = 705
	AVPIdentitySet         uint32 = 708
	AVPExpiryTime          uint32 = 709
	AVPSendDataIndication  uint32 = 710
	AVPOneTimeNotification uint32 = 712
	AVPRepositoryDataID    uint32 = 715
	AVPSequenceNumber      uint32 = 716
)

// Experimental-Result-Code values of TS 29.329 §6.2, sent with vendor 3GPP.
// Sh also uses the Cx codes DIAMETER_ERROR_USER_UNKNOWN,
// DIAMETER_ERROR_IDENTITIES_DONT_MATCH, DIAMETER_ERROR_TOO_MUCH_DATA and
// DIAMETER_ERROR_FEATURE_UNSUPPORTED, which are in package cx.
const (
	UserDataNotAvailable  uint32 = 4100 // DIAMETER_USER_DATA_NOT_AVAILABLE
	PriorUpdateInProgress uint32 = 4101 // DIAMETER_PRIOR_UPDATE_IN_PROGRESS

	ErrorUserDataNotRecognized    uint32 = 5100 // DIAMETER_ERROR_USER_DATA_NOT_RECOGNIZED
	ErrorOperationNotAllowed      uint32 = 5101 // DIAMETER_ERROR_OPERATION_NOT_ALLOWED
	ErrorUserDataCannotBeRead     uint32 = 5102 // DIAMETER_ERROR_USER_DATA_CANNOT_BE_READ
	ErrorUserDataCannotBeModified uint32 = 5103 // DIAMETER_ERROR_USER_DATA_CANNOT_BE_MODIFIED
	ErrorUserDataCannotBeNotified uint32 = 5104 // DIAMETER_ERROR_USER_DATA_CANNOT_BE_NOTIFIED
	ErrorTransparentDataOutOfSync uint32 = 5105 // DIAMETER_ERROR_TRANSPARENT_DATA_OUT_OF_SYNC
	ErrorSubsDataAbsent           uint32 = 5106 // DIAMETER_ERROR_SUBS_DATA_ABSENT
	ErrorNoSubscriptionToData     uint32 = 5107 // DIAMETER_ERROR_NO_SUBSCRIPTION_TO_DATA
	ErrorDSAINotAvailable         uint32 = 5108 // DIAMETER_ERROR_DSAI_NOT_AVAILABLE
)

// DataReference names a kind of user data (TS 29.329 §6.3.4; the data
// itself is described in TS 29.328 §7.6).
type DataReference int32

// Data-Reference values, named after the data they ask for. Value 20 is
// reserved.
const (
	RefRepositoryData                    DataReference = 0
	RefIMSPublicIdentity                 DataReference = 10
	RefIMSUserState                      DataReference = 11
	RefSCSCFName                         DataReference = 12
	RefInitialFilterCriteria             DataReference = 13
	RefLocationInformation               DataReference = 14
	RefUserState                         DataReference = 15
	RefChargingInformation               DataReference = 16
	RefMSISDN                            DataReference = 17
	RefPSIActivation                     DataReference = 18
	RefDSAI                              DataReference = 19
	RefServiceLevelTraceInfo             DataReference = 21
	RefIPAddressSecureBindingInformation DataReference = 22
	RefServicePriorityLevel              DataReference = 23
	RefSMSRegistrationInfo               DataReference = 24
	RefUEReachabilityForIP               DataReference = 25
	RefTADSInformation                   DataReference = 26
	RefSTNSR                             DataReference = 27
	RefUESRVCCCapability                 DataReference = 28
	RefExtendedPriority                  DataReference = 29
	RefCSRN                              DataReference = 30
	RefReferenceLocationInformation      DataReference = 31
	RefIMSI                              DataReference = 32
	RefIMSPrivateUserIdentity            DataReference = 33
	RefIMEISV                            DataReference = 34
	RefUE5GSRVCCCapability               DataReference = 35
	RefASRegistrationInfo                DataReference = 36
)

// IdentitySet selects which public identities a request for
// IMSPublicIdentity data returns (TS 29.329 §6.3.10, TS 29.328 §7.6.2).
type IdentitySet int32

// Identity-Set values.
const (
	AllIdentities        IdentitySet = 0
	RegisteredIdentities IdentitySet = 1
	ImplicitIdentities   IdentitySet = 2
	AliasIdentities      IdentitySet = 3
)

// SubsReqType says whether an SNR subscribes or unsubscribes
// (TS 29.329 §6.3.6).
type SubsReqType int32

// Subs-Req-Type values.
const (
	Subscribe   SubsReqType = 0
	Unsubscribe SubsReqType = 1
)

// Single-valued and boolean-like enumerations, which the typed messages
// show as bool.
const (
	sendDataIndicationNotRequested int32 = 0 // USER_DATA_NOT_REQUESTED
	sendDataIndicationRequested    int32 = 1 // USER_DATA_REQUESTED
	oneTimeNotificationRequested   int32 = 0 // ONE_TIME_NOTIFICATION_REQUESTED
)
