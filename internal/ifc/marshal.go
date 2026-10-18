package ifc

import (
	"encoding/xml"
	"strconv"
)

// Marshal writes the subscription as an IMSSubscription document. It refuses
// a subscription that ParseSubscription would refuse, so a document the HSS
// sends is one it would accept itself, and a value with characters XML
// cannot carry, which encoding/xml would otherwise replace silently.
//
// Optional elements with their default value (BarringIndication false, an
// absent ProfilePartIndicator) are left out; DefaultHandling is always
// written, because TS 29.228 does not say what its absence means.
func (s *Subscription) Marshal() ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	w := wireSubscription{PrivateID: []string{s.PrivateID}}
	for i := range s.ServiceProfiles {
		w.ServiceProfile = append(w.ServiceProfile, wireProfile(&s.ServiceProfiles[i]))
	}
	body, err := xml.Marshal(&w)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(xml.Header)+len(body))
	out = append(out, xml.Header...)
	return append(out, body...), nil
}

func list(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func boolean(b bool) []string {
	if b {
		return []string{"1"}
	}
	return nil
}

func integer(n int) []string { return []string{strconv.Itoa(n)} }

func wireProfile(p *ServiceProfile) wireServiceProfile {
	var w wireServiceProfile
	for i := range p.PublicIdentities {
		w.PublicIdentity = append(w.PublicIdentity, wireIdentity(&p.PublicIdentities[i]))
	}
	if c := p.CoreNetworkServicesAuthorization; c != nil {
		var wc wireCoreNetworkServices
		if c.SubscribedMediaProfileID != nil {
			wc.SubscribedMediaProfileID = integer(*c.SubscribedMediaProfileID)
		}
		w.CoreNetworkServicesAuthorization = []wireCoreNetworkServices{wc}
	}
	for i := range p.InitialFilterCriteria {
		w.InitialFilterCriteria = append(w.InitialFilterCriteria, wireCriteria(&p.InitialFilterCriteria[i]))
	}
	if len(p.SharedIFCSetIDs) > 0 {
		var ext wireServiceProfileExtension
		for _, id := range p.SharedIFCSetIDs {
			ext.SharedIFCSetID = append(ext.SharedIFCSetID, strconv.Itoa(id))
		}
		w.Extension = []wireServiceProfileExtension{ext}
	}
	return w
}

func wireIdentity(id *PublicIdentity) wirePublicIdentity {
	w := wirePublicIdentity{BarringIndication: boolean(id.BarringIndication), Identity: []string{id.Identity}}
	var ext3 []wirePublicIdentityExtension3
	if id.WildcardedIMPU != "" {
		ext3 = []wirePublicIdentityExtension3{{WildcardedIMPU: list(id.WildcardedIMPU)}}
	}
	var ext2 []wirePublicIdentityExtension2
	if id.DisplayName != "" || id.AliasIdentityGroupID != "" || ext3 != nil {
		ext2 = []wirePublicIdentityExtension2{{
			DisplayName:          list(id.DisplayName),
			AliasIdentityGroupID: list(id.AliasIdentityGroupID),
			Extension:            ext3,
		}}
	}
	if id.IdentityType != IdentityPublicUser || id.WildcardedPSI != "" || ext2 != nil {
		ext := wirePublicIdentityExtension{WildcardedPSI: list(id.WildcardedPSI), Extension: ext2}
		if id.IdentityType != IdentityPublicUser {
			ext.IdentityType = integer(int(id.IdentityType))
		}
		w.Extension = []wirePublicIdentityExtension{ext}
	}
	return w
}

func wireCriteria(fc *FilterCriteria) wireFilterCriteria {
	w := wireFilterCriteria{Priority: integer(fc.Priority)}
	if tp := fc.TriggerPoint; tp != nil {
		wt := wireTriggerPoint{ConditionTypeCNF: []string{"0"}}
		if tp.ConditionTypeCNF {
			wt.ConditionTypeCNF = []string{"1"}
		}
		for i := range tp.SPTs {
			wt.SPT = append(wt.SPT, wireTrigger(&tp.SPTs[i]))
		}
		w.TriggerPoint = []wireTriggerPoint{wt}
	}
	as := &fc.ApplicationServer
	was := wireApplicationServer{
		ServerName:      []string{as.ServerName},
		DefaultHandling: integer(int(as.DefaultHandling)),
		ServiceInfo:     list(as.ServiceInfo),
	}
	if as.IncludeRegisterRequest || as.IncludeRegisterResponse {
		var ext wireApplicationServerExtension
		if as.IncludeRegisterRequest {
			ext.IncludeRegisterRequest = []struct{}{{}}
		}
		if as.IncludeRegisterResponse {
			ext.IncludeRegisterResponse = []struct{}{{}}
		}
		was.Extension = []wireApplicationServerExtension{ext}
	}
	w.ApplicationServer = []wireApplicationServer{was}
	if fc.ProfilePart != ProfilePartAny {
		w.ProfilePartIndicator = integer(int(fc.ProfilePart - ProfilePartRegistered))
	}
	return w
}

func wireTrigger(spt *SPT) wireSPT {
	w := wireSPT{ConditionNegated: boolean(spt.ConditionNegated)}
	for _, g := range spt.Groups {
		w.Group = append(w.Group, strconv.Itoa(g))
	}
	switch c := spt.Condition.(type) {
	case RequestURI:
		w.RequestURI = []string{string(c)}
	case Method:
		w.Method = []string{string(c)}
	case SIPHeader:
		w.SIPHeader = []wireHeader{{Header: []string{c.Header}, Content: list(c.Content)}}
	case SessionCase:
		w.SessionCase = integer(int(c))
	case SessionDescription:
		w.SessionDescription = []wireSessionDescription{{Line: []string{c.Line}, Content: list(c.Content)}}
	}
	if len(spt.RegistrationTypes) > 0 {
		var ext wireSPTExtension
		for _, t := range spt.RegistrationTypes {
			ext.RegistrationType = append(ext.RegistrationType, strconv.Itoa(int(t)))
		}
		w.Extension = []wireSPTExtension{ext}
	}
	return w
}
