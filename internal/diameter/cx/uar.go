package cx

import "github.com/jeonghun-app/rcs-platform/internal/diameter"

// UAR is a User-Authorization-Request (TS 29.229 §6.1.1): the I-CSCF asks
// whether a REGISTER may proceed and which S-CSCF serves the user
// (TS 29.228 §6.1.1).
type UAR struct {
	Request
	UserName                 string // the private user identity
	PublicIdentity           string
	VisitedNetworkIdentifier []byte
	// AuthorizationType is derived from the REGISTER's expiry; the default,
	// AuthorizeRegistration, is left out of the message.
	AuthorizationType UserAuthorizationType
}

// Message builds the request.
func (r *UAR) Message(n *diameter.Node) (*diameter.Message, error) {
	switch {
	case r.UserName == "":
		return nil, errMissing("UAR", "User-Name")
	case r.PublicIdentity == "":
		return nil, errMissing("UAR", "Public-Identity")
	case len(r.VisitedNetworkIdentifier) == 0:
		return nil, errMissing("UAR", "Visited-Network-Identifier")
	}
	body := []*diameter.AVP{
		specUserName.UTF8String(r.UserName),
		specPublicIdentity.UTF8String(r.PublicIdentity),
		specVisitedNetworkIdentifier.OctetString(r.VisitedNetworkIdentifier),
	}
	if r.AuthorizationType != AuthorizeRegistration {
		body = append(body, specUserAuthorizationType.Enumerated(int32(r.AuthorizationType)))
	}
	return r.NewMessage(n, Application, CodeUserAuthorization, body...)
}

// ParseUAR reads a received UAR.
func ParseUAR(m *diameter.Message) (*UAR, error) {
	if err := checkCommand(m, CodeUserAuthorization, true); err != nil {
		return nil, err
	}
	req, f := ParseRequest(m)
	r := &UAR{
		Request:                  req,
		UserName:                 f.UTF8String(specUserName, Required),
		PublicIdentity:           f.UTF8String(specPublicIdentity, Required),
		VisitedNetworkIdentifier: f.OctetString(specVisitedNetworkIdentifier, Required),
		AuthorizationType:        UserAuthorizationType(f.Enumerated(specUserAuthorizationType, Optional)),
	}
	if err := f.Err(); err != nil {
		return nil, err
	}
	return r, nil
}

// UAA is a User-Authorization-Answer (TS 29.229 §6.1.2). On success the
// result is DIAMETER_FIRST_REGISTRATION, DIAMETER_SUBSEQUENT_REGISTRATION or
// DIAMETER_UNREGISTERED_SERVICE, and the answer names the S-CSCF or lists the
// capabilities from which the I-CSCF picks one.
type UAA struct {
	Answer
	ServerName         string
	ServerCapabilities *ServerCapabilities
}

// Message builds the answer to req.
func (a *UAA) Message(n *diameter.Node, req *diameter.Message) (*diameter.Message, error) {
	body := optionalUTF8(specServerName, a.ServerName)
	if a.ServerCapabilities != nil {
		body = append(body, a.ServerCapabilities.avp())
	}
	return a.NewMessage(n, req, Application, body...)
}

// ParseUAA reads a received UAA.
func ParseUAA(m *diameter.Message) (*UAA, error) {
	if err := checkCommand(m, CodeUserAuthorization, false); err != nil {
		return nil, err
	}
	ans, f := ParseAnswer(m)
	a := &UAA{
		Answer:             ans,
		ServerName:         f.UTF8String(specServerName, Optional),
		ServerCapabilities: readServerCapabilities(f),
	}
	if err := f.Err(); err != nil {
		return nil, err
	}
	return a, nil
}
