package cx

import "github.com/jeonghun-app/rcs-platform/internal/diameter"

// SAR is a Server-Assignment-Request (TS 29.229 §6.1.3): the S-CSCF tells the
// HSS that it serves, or stops serving, the user and asks for the user profile
// (TS 29.228 §6.1.2).
type SAR struct {
	Request
	// UserName is the private identity; TS 29.228 §6.1.2 lets an S-CSCF
	// leave it out for an unregistered user.
	UserName                 string
	PublicIdentities         []string
	WildcardedPublicIdentity string
	ServerName               string
	AssignmentType           ServerAssignmentType
	UserDataAlreadyAvailable UserDataAvailability
}

// Message builds the request.
func (r *SAR) Message(n *diameter.Node) (*diameter.Message, error) {
	if r.ServerName == "" {
		return nil, errMissing("SAR", "Server-Name")
	}
	body := optionalUTF8(specUserName, r.UserName)
	for _, p := range r.PublicIdentities {
		body = append(body, specPublicIdentity.UTF8String(p))
	}
	body = append(body, optionalUTF8(specWildcardedPublicIdentity, r.WildcardedPublicIdentity)...)
	body = append(body,
		specServerName.UTF8String(r.ServerName),
		specServerAssignmentType.Enumerated(int32(r.AssignmentType)),
		specUserDataAlreadyAvailable.Enumerated(int32(r.UserDataAlreadyAvailable)),
	)
	return r.NewMessage(n, Application, CodeServerAssignment, body...)
}

// ParseSAR reads a received SAR.
func ParseSAR(m *diameter.Message) (*SAR, error) {
	if err := checkCommand(m, CodeServerAssignment, true); err != nil {
		return nil, err
	}
	req, f := ParseRequest(m)
	r := &SAR{
		Request:                  req,
		UserName:                 f.UTF8String(specUserName, Optional),
		PublicIdentities:         f.AllUTF8String(specPublicIdentity),
		WildcardedPublicIdentity: f.UTF8String(specWildcardedPublicIdentity, Optional),
		ServerName:               f.UTF8String(specServerName, Required),
		AssignmentType:           ServerAssignmentType(f.Enumerated(specServerAssignmentType, Required)),
		UserDataAlreadyAvailable: UserDataAvailability(f.Enumerated(specUserDataAlreadyAvailable, Required)),
	}
	if err := f.Err(); err != nil {
		return nil, err
	}
	return r, nil
}

// SAA is a Server-Assignment-Answer (TS 29.229 §6.1.4). On success UserData
// holds the IMSSubscription document (TS 29.228 Annex E), which package ifc
// parses.
type SAA struct {
	Answer
	UserName            string
	UserData            []byte
	ChargingInformation *ChargingInformation
	// AssociatedIdentities are the private identities sharing the
	// subscription; nil when the AVP is absent.
	AssociatedIdentities     []string
	ServerName               string
	WildcardedPublicIdentity string
}

// Message builds the answer to req.
func (a *SAA) Message(n *diameter.Node, req *diameter.Message) (*diameter.Message, error) {
	body := optionalUTF8(specUserName, a.UserName)
	body = append(body, optionalOctets(specUserData, a.UserData)...)
	if a.ChargingInformation != nil {
		ci, err := a.ChargingInformation.avp()
		if err != nil {
			return nil, err
		}
		body = append(body, ci)
	}
	body = append(body, associatedIdentities(a.AssociatedIdentities)...)
	body = append(body, optionalUTF8(specServerName, a.ServerName)...)
	body = append(body, optionalUTF8(specWildcardedPublicIdentity, a.WildcardedPublicIdentity)...)
	return a.NewMessage(n, req, Application, body...)
}

// ParseSAA reads a received SAA.
func ParseSAA(m *diameter.Message) (*SAA, error) {
	if err := checkCommand(m, CodeServerAssignment, false); err != nil {
		return nil, err
	}
	ans, f := ParseAnswer(m)
	a := &SAA{
		Answer:                   ans,
		UserName:                 f.UTF8String(specUserName, Optional),
		UserData:                 f.OctetString(specUserData, Optional),
		ChargingInformation:      readChargingInformation(f),
		AssociatedIdentities:     readAssociatedIdentities(f),
		ServerName:               f.UTF8String(specServerName, Optional),
		WildcardedPublicIdentity: f.UTF8String(specWildcardedPublicIdentity, Optional),
	}
	if err := f.Err(); err != nil {
		return nil, err
	}
	return a, nil
}
