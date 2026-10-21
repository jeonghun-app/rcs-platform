package ifc

import "math"

// validate checks what the schema requires of a subscription built in code,
// and that every value can be written as XML. ParseSubscription runs it too,
// so the two directions accept the same documents.
func (s *Subscription) validate() error {
	r := &reader{}
	const where = "IMSSubscription"
	r.identity(where, "PrivateID", s.PrivateID)
	if len(s.ServiceProfiles) == 0 {
		r.fail(where, "ServiceProfile is missing")
	}
	for i := range s.ServiceProfiles {
		r.validateProfile(at(where, "ServiceProfile", i), &s.ServiceProfiles[i])
	}
	return r.err
}

// identity checks a value of an anyURI type: present, writable, and already
// in the collapsed form the parser would read it in.
func (r *reader) identity(where, name, v string) {
	switch {
	case v == "":
		r.fail(where, "%s is missing", name)
	default:
		r.optionalIdentity(where, name, v)
	}
}

func (r *reader) optionalIdentity(where, name, v string) {
	if v != collapse(v) || !isXMLText(v) {
		r.fail(where, "%s has white space around it or characters XML cannot carry", name)
	}
}

func (r *reader) text(where, name, v string) {
	if !isXMLText(v) {
		r.fail(where, "%s has characters XML cannot carry", name)
	}
}

func (r *reader) validateProfile(where string, p *ServiceProfile) {
	if len(p.PublicIdentities) == 0 {
		r.fail(where, "PublicIdentity is missing")
	}
	for i := range p.PublicIdentities {
		id := &p.PublicIdentities[i]
		w := at(where, "PublicIdentity", i)
		r.identity(w, "Identity", id.Identity)
		if id.IdentityType < IdentityPublicUser || id.IdentityType > IdentityWildcardedIMPU {
			r.fail(w, "IdentityType is out of range")
		}
		r.optionalIdentity(w, "WildcardedPSI", id.WildcardedPSI)
		r.optionalIdentity(w, "WildcardedIMPU", id.WildcardedIMPU)
		r.text(w, "DisplayName", id.DisplayName)
		r.text(w, "AliasIdentityGroupID", id.AliasIdentityGroupID)
	}
	if c := p.CoreNetworkServicesAuthorization; c != nil && c.SubscribedMediaProfileID != nil && *c.SubscribedMediaProfileID < 0 {
		r.fail(where, "SubscribedMediaProfileId is negative")
	}
	for i := range p.InitialFilterCriteria {
		r.validateCriteria(at(where, "InitialFilterCriteria", i), &p.InitialFilterCriteria[i])
	}
	for _, id := range p.SharedIFCSetIDs {
		if id < 0 {
			r.fail(where, "SharedIFCSetID is negative")
		}
	}
}

func (r *reader) validateCriteria(where string, fc *FilterCriteria) {
	// A priority fits an int32, as TS 29.228 writes it (xs:int), and as the
	// S-CSCF signs it into a request's place in the chain; parsing runs this
	// too.
	if fc.Priority < 0 || fc.Priority > math.MaxInt32 {
		r.fail(where, "Priority is negative or beyond an int32")
	}
	if fc.ProfilePart < ProfilePartAny || fc.ProfilePart > ProfilePartUnregistered {
		r.fail(where, "ProfilePart is out of range")
	}
	as := &fc.ApplicationServer
	r.identity(where, "ApplicationServer/ServerName", as.ServerName)
	r.text(where, "ApplicationServer/ServiceInfo", as.ServiceInfo)
	if as.DefaultHandling != SessionContinued && as.DefaultHandling != SessionTerminated {
		r.fail(where, "DefaultHandling is out of range")
	}
	if fc.TriggerPoint == nil {
		return
	}
	if len(fc.TriggerPoint.SPTs) == 0 {
		r.fail(where, "TriggerPoint has no SPT")
	}
	for i := range fc.TriggerPoint.SPTs {
		r.validateSPT(at(where+"/TriggerPoint", "SPT", i), &fc.TriggerPoint.SPTs[i])
	}
}

func (r *reader) validateSPT(where string, spt *SPT) {
	if len(spt.Groups) == 0 {
		r.fail(where, "Group is missing")
	}
	for _, g := range spt.Groups {
		if g < 0 {
			r.fail(where, "Group is negative")
		}
	}
	if len(spt.RegistrationTypes) > 2 {
		r.fail(where, "RegistrationType occurs more than twice")
	}
	for _, t := range spt.RegistrationTypes {
		if t < InitialRegistration || t > DeRegistration {
			r.fail(where, "RegistrationType is out of range")
		}
	}
	switch c := spt.Condition.(type) {
	case RequestURI:
		r.text(where, "RequestURI", string(c))
	case Method:
		r.text(where, "Method", string(c))
	case SIPHeader:
		r.text(where, "SIPHeader/Header", c.Header)
		r.text(where, "SIPHeader/Content", c.Content)
	case SessionCase:
		if c < Originating || c > OriginatingCDIV {
			r.fail(where, "SessionCase is out of range")
		}
	case SessionDescription:
		r.text(where, "SessionDescription/Line", c.Line)
		r.text(where, "SessionDescription/Content", c.Content)
	default:
		r.fail(where, "has no condition")
	}
}
