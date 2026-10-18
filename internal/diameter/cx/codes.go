package cx

import "github.com/jeonghun-app/rcs-platform/internal/diameter"

// Identifiers of the Cx application (TS 29.229 §6, §6.4).
const (
	// ApplicationID is the IANA-assigned identifier of the Cx/Dx application.
	ApplicationID uint32 = 16777216
	// Vendor3GPP is the IANA enterprise number of 3GPP. It is the Vendor-Id of
	// every Cx AVP and of the Cx Experimental-Result-Codes.
	Vendor3GPP uint32 = 10415
	// VendorETSI is ETSI's enterprise number. TS 29.229 §5.6 asks Cx nodes to
	// list it in Supported-Vendor-Id next to 3GPP.
	VendorETSI uint32 = 13019
)

// Application is how a node advertises Cx in its capabilities exchange: inside
// Vendor-Specific-Application-Id, with vendor 3GPP (TS 29.229 §5.6).
var Application = diameter.Application{ID: ApplicationID, VendorID: Vendor3GPP}

// Command codes (TS 29.229 Table 6.1.1). A request and its answer share the
// code and differ in the R bit.
const (
	CodeUserAuthorization       uint32 = 300 // UAR/UAA
	CodeServerAssignment        uint32 = 301 // SAR/SAA
	CodeLocationInfo            uint32 = 302 // LIR/LIA
	CodeMultimediaAuth          uint32 = 303 // MAR/MAA
	CodeRegistrationTermination uint32 = 304 // RTR/RTA
	CodePushProfile             uint32 = 305 // PPR/PPA
)

// AVP codes of TS 29.229 Table 6.3.0.1 that this package reads or writes. All
// have vendor 3GPP except the Digest ones, which RFC 4740 defines without a
// vendor.
const (
	AVPVisitedNetworkIdentifier uint32 = 600
	AVPPublicIdentity           uint32 = 601
	AVPServerName               uint32 = 602
	AVPServerCapabilities       uint32 = 603
	AVPMandatoryCapability      uint32 = 604
	AVPOptionalCapability       uint32 = 605
	AVPUserData                 uint32 = 606
	AVPSIPNumberAuthItems       uint32 = 607
	AVPSIPAuthenticationScheme  uint32 = 608
	AVPSIPAuthenticate          uint32 = 609
	AVPSIPAuthorization         uint32 = 610
	AVPSIPAuthenticationContext uint32 = 611
	AVPSIPAuthDataItem          uint32 = 612
	AVPSIPItemNumber            uint32 = 613
	AVPServerAssignmentType     uint32 = 614
	AVPDeregistrationReason     uint32 = 615
	AVPReasonCode               uint32 = 616
	AVPReasonInfo               uint32 = 617
	AVPChargingInformation      uint32 = 618
	// The four charging function names (§6.3.20 to §6.3.23).
	AVPPrimaryEventChargingFunctionName        uint32 = 619
	AVPSecondaryEventChargingFunctionName      uint32 = 620
	AVPPrimaryChargingCollectionFunctionName   uint32 = 621
	AVPSecondaryChargingCollectionFunctionName uint32 = 622
	AVPUserAuthorizationType                   uint32 = 623
	AVPUserDataAlreadyAvailable                uint32 = 624
	AVPConfidentialityKey                      uint32 = 625
	AVPIntegrityKey                            uint32 = 626
	AVPSupportedFeatures                       uint32 = 628
	AVPFeatureListID                           uint32 = 629
	AVPFeatureList                             uint32 = 630
	AVPAssociatedIdentities                    uint32 = 632
	AVPOriginatingRequest                      uint32 = 633
	AVPWildcardedPublicIdentity                uint32 = 634
	AVPSIPDigestAuthenticate                   uint32 = 635
	AVPWildcardedIMPU                          uint32 = 636
	AVPAlternateDigestAlgorithm                uint32 = 662
	AVPAlternateDigestHA1                      uint32 = 663

	// RFC 4740 Digest AVPs, without a vendor (TS 29.229 §6.3.37 to §6.3.41).
	AVPDigestRealm     uint32 = 104
	AVPDigestQoP       uint32 = 110
	AVPDigestAlgorithm uint32 = 111
	AVPDigestHA1       uint32 = 121
)

// Experimental-Result-Code values of TS 29.229 §6.2, sent with vendor 3GPP
// (see [ExperimentalResult]). The success codes share numbers with base
// Result-Codes (2001 is also DIAMETER_SUCCESS), so a code is meaningful only
// together with its vendor.
const (
	FirstRegistration          uint32 = 2001 // DIAMETER_FIRST_REGISTRATION
	SubsequentRegistration     uint32 = 2002 // DIAMETER_SUBSEQUENT_REGISTRATION
	UnregisteredService        uint32 = 2003 // DIAMETER_UNREGISTERED_SERVICE
	SuccessServerNameNotStored uint32 = 2004 // DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED

	ErrorUserUnknown                   uint32 = 5001 // DIAMETER_ERROR_USER_UNKNOWN
	ErrorIdentitiesDontMatch           uint32 = 5002 // DIAMETER_ERROR_IDENTITIES_DONT_MATCH
	ErrorIdentityNotRegistered         uint32 = 5003 // DIAMETER_ERROR_IDENTITY_NOT_REGISTERED
	ErrorRoamingNotAllowed             uint32 = 5004 // DIAMETER_ERROR_ROAMING_NOT_ALLOWED
	ErrorIdentityAlreadyRegistered     uint32 = 5005 // DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED
	ErrorAuthSchemeNotSupported        uint32 = 5006 // DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED
	ErrorInAssignmentType              uint32 = 5007 // DIAMETER_ERROR_IN_ASSIGNMENT_TYPE
	ErrorTooMuchData                   uint32 = 5008 // DIAMETER_ERROR_TOO_MUCH_DATA
	ErrorNotSupportedUserData          uint32 = 5009 // DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA
	ErrorFeatureUnsupported            uint32 = 5011 // DIAMETER_ERROR_FEATURE_UNSUPPORTED
	ErrorServingNodeFeatureUnsupported uint32 = 5012 // DIAMETER_ERROR_SERVING_NODE_FEATURE_UNSUPPORTED
)

// authSessionStateNoStateMaintained is the only Auth-Session-State Cx uses:
// the HSS keeps no Diameter session state (TS 29.229 §5.3, RFC 6733 §8.11).
const authSessionStateNoStateMaintained int32 = 1

// ServerAssignmentType says why an S-CSCF sends a SAR (TS 29.229 §6.3.15).
// Values 12 to 14 belong to SWx and are not used on Cx.
type ServerAssignmentType int32

// Server-Assignment-Type values.
const (
	NoAssignment                         ServerAssignmentType = 0
	Registration                         ServerAssignmentType = 1
	ReRegistration                       ServerAssignmentType = 2
	UnregisteredUser                     ServerAssignmentType = 3
	TimeoutDeregistration                ServerAssignmentType = 4
	UserDeregistration                   ServerAssignmentType = 5
	TimeoutDeregistrationStoreServerName ServerAssignmentType = 6
	UserDeregistrationStoreServerName    ServerAssignmentType = 7
	AdministrativeDeregistration         ServerAssignmentType = 8
	AuthenticationFailure                ServerAssignmentType = 9
	AuthenticationTimeout                ServerAssignmentType = 10
	DeregistrationTooMuchData            ServerAssignmentType = 11
)

// UserAuthorizationType is the kind of authorisation an I-CSCF asks for in a
// UAR (TS 29.229 §6.3.24). The zero value, REGISTRATION, is also what an
// absent AVP means, so it is not sent.
type UserAuthorizationType int32

// User-Authorization-Type values.
const (
	AuthorizeRegistration                UserAuthorizationType = 0
	AuthorizeDeregistration              UserAuthorizationType = 1
	AuthorizeRegistrationAndCapabilities UserAuthorizationType = 2
)

// UserDataAvailability tells the HSS whether the S-CSCF already holds the
// user profile (User-Data-Already-Available, TS 29.229 §6.3.26).
type UserDataAvailability int32

// User-Data-Already-Available values.
const (
	UserDataNotAvailable     UserDataAvailability = 0
	UserDataAlreadyAvailable UserDataAvailability = 1
)

// ReasonCode is why the HSS deregisters a user in an RTR (TS 29.229 §6.3.17;
// the S-CSCF behaviour for each is in TS 29.228 §6.1.3).
type ReasonCode int32

// Reason-Code values.
const (
	PermanentTermination ReasonCode = 0
	NewServerAssigned    ReasonCode = 1
	ServerChange         ReasonCode = 2
	RemoveSCSCF          ReasonCode = 3
)

// SIP-Authentication-Scheme values (TS 29.229 §6.3.9). The AKA scheme name is
// the same for AKAv1 and AKAv2: the HSS returns the same vector for both.
const (
	SchemeDigestAKAv1MD5   = "Digest-AKAv1-MD5"
	SchemeSIPDigest        = "SIP Digest"
	SchemeNASSBundled      = "NASS-Bundled"
	SchemeEarlyIMSSecurity = "Early-IMS-Security"
	SchemeUnknown          = "Unknown"
)
