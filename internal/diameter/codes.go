package diameter

// Command codes of the base protocol (RFC 6733 §3.1).
const (
	CodeCapabilitiesExchange uint32 = 257
	CodeDeviceWatchdog       uint32 = 280
	CodeDisconnectPeer       uint32 = 282
)

// Application identifiers with a meaning in the base protocol (RFC 6733 §2.4).
const (
	// AppCommon carries the base protocol's own messages (CER, DWR, DPR).
	AppCommon uint32 = 0
	// AppRelay, advertised in a CER or CEA, means the peer accepts every
	// application.
	AppRelay uint32 = 0xffffffff
)

// AVP codes of the base AVPs this package knows (RFC 6733 §4.5, and RFC 6733
// §8 for the session AVPs).
const (
	AVPUserName                    uint32 = 1
	AVPClass                       uint32 = 25
	AVPSessionTimeout              uint32 = 27
	AVPProxyState                  uint32 = 33
	AVPEventTimestamp              uint32 = 55
	AVPHostIPAddress               uint32 = 257
	AVPAuthApplicationID           uint32 = 258
	AVPAcctApplicationID           uint32 = 259
	AVPVendorSpecificApplicationID uint32 = 260
	AVPSessionID                   uint32 = 263
	AVPOriginHost                  uint32 = 264
	AVPSupportedVendorID           uint32 = 265
	AVPVendorID                    uint32 = 266
	AVPFirmwareRevision            uint32 = 267
	AVPResultCode                  uint32 = 268
	AVPProductName                 uint32 = 269
	AVPDisconnectCause             uint32 = 273
	AVPAuthRequestType             uint32 = 274
	AVPAuthSessionState            uint32 = 277
	AVPOriginStateID               uint32 = 278
	AVPFailedAVP                   uint32 = 279
	AVPProxyHost                   uint32 = 280
	AVPErrorMessage                uint32 = 281
	AVPRouteRecord                 uint32 = 282
	AVPDestinationRealm            uint32 = 283
	AVPProxyInfo                   uint32 = 284
	AVPRedirectHost                uint32 = 292
	AVPDestinationHost             uint32 = 293
	AVPErrorReportingHost          uint32 = 294
	AVPOriginRealm                 uint32 = 296
	AVPExperimentalResult          uint32 = 297
	AVPExperimentalResultCode      uint32 = 298
	AVPInbandSecurityID            uint32 = 299
)

// Result-Code values (RFC 6733 §7.1). The thousands digit is the class: 2xxx
// success, 3xxx protocol error (answered with the E bit, §7.2), 4xxx transient
// failure, 5xxx permanent failure.
const (
	ResultSuccess uint32 = 2001

	ResultCommandUnsupported     uint32 = 3001
	ResultUnableToDeliver        uint32 = 3002
	ResultRealmNotServed         uint32 = 3003
	ResultTooBusy                uint32 = 3004
	ResultLoopDetected           uint32 = 3005
	ResultRedirectIndication     uint32 = 3006
	ResultApplicationUnsupported uint32 = 3007
	ResultInvalidHdrBits         uint32 = 3008
	ResultInvalidAVPBits         uint32 = 3009
	ResultUnknownPeer            uint32 = 3010

	ResultAuthenticationRejected uint32 = 4001
	ResultOutOfSpace             uint32 = 4002
	ResultElectionLost           uint32 = 4003

	ResultAVPUnsupported        uint32 = 5001
	ResultUnknownSessionID      uint32 = 5002
	ResultAuthorizationRejected uint32 = 5003
	ResultInvalidAVPValue       uint32 = 5004
	ResultMissingAVP            uint32 = 5005
	ResultResourcesExceeded     uint32 = 5006
	ResultContradictingAVPs     uint32 = 5007
	ResultAVPNotAllowed         uint32 = 5008
	ResultAVPOccursTooManyTimes uint32 = 5009
	ResultNoCommonApplication   uint32 = 5010
	ResultUnsupportedVersion    uint32 = 5011
	ResultUnableToComply        uint32 = 5012
	ResultInvalidBitInHeader    uint32 = 5013
	ResultInvalidAVPLength      uint32 = 5014
	ResultInvalidMessageLength  uint32 = 5015
	ResultInvalidAVPBitCombo    uint32 = 5016
	ResultNoCommonSecurity      uint32 = 5017
)

// IsProtocolError reports whether a result code is in the protocol error class,
// whose answers carry the E bit (RFC 6733 §7.1.3, §7.2).
func IsProtocolError(resultCode uint32) bool {
	return resultCode >= 3000 && resultCode < 4000
}

// Disconnect-Cause values (RFC 6733 §5.4.3).
const (
	DisconnectRebooting            int32 = 0
	DisconnectBusy                 int32 = 1
	DisconnectDoNotWantToTalkToYou int32 = 2
)

// Inband-Security-Id values (RFC 6733 §6.10). This package offers only
// NO_INBAND_SECURITY: Diameter stays inside the VPC.
const (
	InbandSecurityNone uint32 = 0
	InbandSecurityTLS  uint32 = 1
)
