package ifc

// Subscription is an IMSSubscription document (TS 29.228 Annex E, tIMSSubscription):
// the private identity and the service profiles of its public identities.
type Subscription struct {
	PrivateID       string
	ServiceProfiles []ServiceProfile
}

// ServiceProfile is one tServiceProfile: the public identities that share
// a set of services and the filter criteria for them.
type ServiceProfile struct {
	PublicIdentities                 []PublicIdentity
	CoreNetworkServicesAuthorization *CoreNetworkServicesAuthorization
	InitialFilterCriteria            []FilterCriteria
	// SharedIFCSetIDs name criteria sets the S-CSCF holds locally (the SiFC
	// feature, TS 29.229 §7.1.1); this package does not resolve them.
	SharedIFCSetIDs []int
}

// PublicIdentity is one tPublicIdentity with the parts of its extensions
// that IMS services use.
type PublicIdentity struct {
	Identity string
	// BarringIndication bars the identity from every IMS communication
	// except registration and re-registration (TS 29.228 B.2.1).
	BarringIndication bool
	IdentityType      IdentityType
	WildcardedPSI     string
	DisplayName       string
	// AliasIdentityGroupID groups the identities that are aliases of each
	// other (the AliasInd feature, TS 29.229 §7.1.1).
	AliasIdentityGroupID string
	WildcardedIMPU       string
}

// IdentityType is a tIdentityType (TS 29.228 Table E.1). An absent
// IdentityType reads as IdentityPublicUser.
type IdentityType int

// IdentityType values.
const (
	IdentityPublicUser      IdentityType = 0 // DISTINCT PUBLIC_USER_IDENTITY
	IdentityDistinctPSI     IdentityType = 1
	IdentityWildcardedPSI   IdentityType = 2
	IdentityNonDistinctIMPU IdentityType = 3
	IdentityWildcardedIMPU  IdentityType = 4
)

// CoreNetworkServicesAuthorization is a tCoreNetworkServicesAuthorization.
type CoreNetworkServicesAuthorization struct {
	// SubscribedMediaProfileID is nil when the element is absent: 0 is a
	// valid profile.
	SubscribedMediaProfileID *int
}

// FilterCriteria is one initial filter criterion (tInitialFilterCriteria,
// TS 29.228 B.2.2).
type FilterCriteria struct {
	// Priority orders evaluation: lower numbers first. No two criteria of a
	// profile may share one.
	Priority int
	// TriggerPoint is nil for a criterion that always matches.
	TriggerPoint      *TriggerPoint
	ApplicationServer ApplicationServer
	ProfilePart       ProfilePart
}

// ProfilePart says which part of the user profile a criterion belongs to
// (ProfilePartIndicator). The zero value, an absent indicator, means both.
type ProfilePart int

// ProfilePart values. They are not the wire values: on the wire REGISTERED is
// 0 and UNREGISTERED 1, and absence is the third state.
const (
	ProfilePartAny ProfilePart = iota
	ProfilePartRegistered
	ProfilePartUnregistered
)

// TriggerPoint is a tTrigger: service point triggers in conjunctive normal
// form when ConditionTypeCNF is true, disjunctive otherwise (TS 29.228
// Annex C).
type TriggerPoint struct {
	ConditionTypeCNF bool
	SPTs             []SPT
}

// SPT is one service point trigger (tSePoTri, TS 29.228 B.2.3).
type SPT struct {
	ConditionNegated bool
	// Groups places the trigger in one or more ORed (CNF) or ANDed (DNF)
	// sets; at least one is required.
	Groups []int
	// Condition is what the trigger tests: a [RequestURI], [Method],
	// [SIPHeader], [SessionCase] or [SessionDescription].
	Condition Condition
	// RegistrationTypes narrows a Method "REGISTER" trigger to some kinds of
	// registration. It is ignored on other triggers (TS 29.228 B.2.3).
	RegistrationTypes []RegistrationType
}

// Condition is the test of an [SPT]. The set of conditions is closed: they
// are the choices of tSePoTri.
type Condition interface {
	condition()
}

// RequestURI is a pattern for the Request-URI: its hostport for a SIP URI,
// its telephone-subscriber for a tel URI (TS 29.228 Annex F).
type RequestURI string

// Method is a SIP method name, compared exactly: methods are case-sensitive
// (RFC 3261 §7.1).
type Method string

// SIPHeader is a header trigger: Header is a pattern for the header name and
// Content, when not empty, a pattern for one of its values. Without Content
// the trigger tests whether such a header is present (TS 29.228 B.2.3).
type SIPHeader struct {
	Header  string
	Content string
}

// SessionDescription is an SDP trigger: Line is a pattern for the type of an
// SDP line (the letter before "=") and Content, when not empty, a pattern for
// its value.
type SessionDescription struct {
	Line    string
	Content string
}

// SessionCase says on whose behalf the S-CSCF handles a request
// (tDirectionOfRequest, TS 29.228 Table E.1).
type SessionCase int

// SessionCase values, which are also the wire values.
const (
	Originating             SessionCase = 0
	TerminatingRegistered   SessionCase = 1
	TerminatingUnregistered SessionCase = 2
	OriginatingUnregistered SessionCase = 3
	OriginatingCDIV         SessionCase = 4 // originating after call diversion
)

func (RequestURI) condition()         {}
func (Method) condition()             {}
func (SIPHeader) condition()          {}
func (SessionCase) condition()        {}
func (SessionDescription) condition() {}

// RegistrationType is a tRegistrationType.
type RegistrationType int

// RegistrationType values, which are also the wire values.
const (
	InitialRegistration RegistrationType = 0
	ReRegistration      RegistrationType = 1
	DeRegistration      RegistrationType = 2
)

// ApplicationServer is a tApplicationServer: where a matching request goes.
type ApplicationServer struct {
	ServerName string
	// DefaultHandling says what to do when the server cannot be reached.
	// TS 29.228 gives no default for an absent element; it reads as
	// SessionContinued, which keeps the session alive.
	DefaultHandling DefaultHandling
	// ServiceInfo is passed to the server transparently (TS 23.218).
	ServiceInfo string
	// IncludeRegisterRequest and IncludeRegisterResponse ask the S-CSCF to
	// put the REGISTER, or its final response, in the body of the
	// third-party REGISTER (TS 29.228 B.2.2).
	IncludeRegisterRequest  bool
	IncludeRegisterResponse bool
}

// DefaultHandling is a tDefaultHandling.
type DefaultHandling int

// DefaultHandling values, which are also the wire values.
const (
	SessionContinued  DefaultHandling = 0
	SessionTerminated DefaultHandling = 1
)
