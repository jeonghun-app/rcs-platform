package ifc

import "encoding/xml"

// The wire types mirror the complex types of TS 29.228 Table E.2, one Go
// type per schema type, with fields in schema sequence order so that Marshal
// writes elements in the order the schema requires. Every element is a slice:
// the parser counts occurrences instead of letting a repeated element
// silently replace the first, and Marshal omits an empty slice.

type wireSubscription struct {
	XMLName        xml.Name             `xml:"IMSSubscription"`
	PrivateID      []string             `xml:"PrivateID"`
	ServiceProfile []wireServiceProfile `xml:"ServiceProfile"`
}

type wireServiceProfile struct {
	PublicIdentity                   []wirePublicIdentity          `xml:"PublicIdentity"`
	CoreNetworkServicesAuthorization []wireCoreNetworkServices     `xml:"CoreNetworkServicesAuthorization"`
	InitialFilterCriteria            []wireFilterCriteria          `xml:"InitialFilterCriteria"`
	Extension                        []wireServiceProfileExtension `xml:"Extension"`
}

type wireServiceProfileExtension struct {
	SharedIFCSetID []string `xml:"SharedIFCSetID"`
}

type wireCoreNetworkServices struct {
	SubscribedMediaProfileID []string `xml:"SubscribedMediaProfileId"`
}

type wirePublicIdentity struct {
	BarringIndication []string                      `xml:"BarringIndication"`
	Identity          []string                      `xml:"Identity"`
	Extension         []wirePublicIdentityExtension `xml:"Extension"`
}

type wirePublicIdentityExtension struct {
	IdentityType  []string                       `xml:"IdentityType"`
	WildcardedPSI []string                       `xml:"WildcardedPSI"`
	Extension     []wirePublicIdentityExtension2 `xml:"Extension"`
}

type wirePublicIdentityExtension2 struct {
	DisplayName          []string                       `xml:"DisplayName"`
	AliasIdentityGroupID []string                       `xml:"AliasIdentityGroupID"`
	Extension            []wirePublicIdentityExtension3 `xml:"Extension"`
}

type wirePublicIdentityExtension3 struct {
	WildcardedIMPU []string `xml:"WildcardedIMPU"`
}

type wireFilterCriteria struct {
	Priority             []string                `xml:"Priority"`
	TriggerPoint         []wireTriggerPoint      `xml:"TriggerPoint"`
	ApplicationServer    []wireApplicationServer `xml:"ApplicationServer"`
	ProfilePartIndicator []string                `xml:"ProfilePartIndicator"`
}

type wireTriggerPoint struct {
	ConditionTypeCNF []string  `xml:"ConditionTypeCNF"`
	SPT              []wireSPT `xml:"SPT"`
}

type wireSPT struct {
	ConditionNegated   []string                 `xml:"ConditionNegated"`
	Group              []string                 `xml:"Group"`
	RequestURI         []string                 `xml:"RequestURI"`
	Method             []string                 `xml:"Method"`
	SIPHeader          []wireHeader             `xml:"SIPHeader"`
	SessionCase        []string                 `xml:"SessionCase"`
	SessionDescription []wireSessionDescription `xml:"SessionDescription"`
	Extension          []wireSPTExtension       `xml:"Extension"`
}

type wireSPTExtension struct {
	RegistrationType []string `xml:"RegistrationType"`
}

type wireHeader struct {
	Header  []string `xml:"Header"`
	Content []string `xml:"Content"`
}

type wireSessionDescription struct {
	Line    []string `xml:"Line"`
	Content []string `xml:"Content"`
}

type wireApplicationServer struct {
	ServerName      []string                         `xml:"ServerName"`
	DefaultHandling []string                         `xml:"DefaultHandling"`
	ServiceInfo     []string                         `xml:"ServiceInfo"`
	Extension       []wireApplicationServerExtension `xml:"Extension"`
}

type wireApplicationServerExtension struct {
	IncludeRegisterRequest  []struct{} `xml:"IncludeRegisterRequest"`
	IncludeRegisterResponse []struct{} `xml:"IncludeRegisterResponse"`
}
