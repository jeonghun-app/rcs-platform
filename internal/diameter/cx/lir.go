package cx

import "github.com/jeonghun-app/rcs-platform/internal/diameter"

// originatingRequestOriginating is the only Originating-Request value
// (TS 29.229 §6.3.34).
const originatingRequestOriginating int32 = 0

// LIR is a Location-Info-Request (TS 29.229 §6.1.5): the I-CSCF asks which
// S-CSCF serves the target of a terminating request (TS 29.228 §6.1.4).
type LIR struct {
	Request
	PublicIdentity string
	// OriginatingRequest marks a request an AS originates on behalf of the
	// user, which the HSS treats like an originating one.
	OriginatingRequest bool
	// AuthorizationType, when AuthorizeRegistrationAndCapabilities, asks for
	// capabilities because the assigned S-CSCF cannot be reached. Other
	// values are not sent.
	AuthorizationType UserAuthorizationType
}

// Message builds the request.
func (r *LIR) Message(n *diameter.Node) (*diameter.Message, error) {
	if r.PublicIdentity == "" {
		return nil, errMissing("LIR", "Public-Identity")
	}
	var body []*diameter.AVP
	if r.OriginatingRequest {
		body = append(body, specOriginatingRequest.Enumerated(originatingRequestOriginating))
	}
	body = append(body, specPublicIdentity.UTF8String(r.PublicIdentity))
	if r.AuthorizationType != AuthorizeRegistration {
		body = append(body, specUserAuthorizationType.Enumerated(int32(r.AuthorizationType)))
	}
	return r.NewMessage(n, Application, CodeLocationInfo, body...)
}

// ParseLIR reads a received LIR.
func ParseLIR(m *diameter.Message) (*LIR, error) {
	if err := checkCommand(m, CodeLocationInfo, true); err != nil {
		return nil, err
	}
	req, f := ParseRequest(m)
	r := &LIR{Request: req}
	if f.Has(specOriginatingRequest) {
		// The AVP has a single value, so its presence is the information;
		// any other value is a sender error worth refusing.
		if v := f.Enumerated(specOriginatingRequest, Required); v != originatingRequestOriginating && f.Err() == nil {
			f.Fail(diameter.ResultInvalidAVPValue, m.Find(AVPOriginatingRequest, Vendor3GPP), "invalid Originating-Request")
		}
		r.OriginatingRequest = true
	}
	r.PublicIdentity = f.UTF8String(specPublicIdentity, Required)
	r.AuthorizationType = UserAuthorizationType(f.Enumerated(specUserAuthorizationType, Optional))
	if err := f.Err(); err != nil {
		return nil, err
	}
	return r, nil
}

// LIA is a Location-Info-Answer (TS 29.229 §6.1.6).
type LIA struct {
	Answer
	ServerName               string
	ServerCapabilities       *ServerCapabilities
	WildcardedPublicIdentity string
}

// Message builds the answer to req.
func (a *LIA) Message(n *diameter.Node, req *diameter.Message) (*diameter.Message, error) {
	body := optionalUTF8(specServerName, a.ServerName)
	if a.ServerCapabilities != nil {
		body = append(body, a.ServerCapabilities.avp())
	}
	body = append(body, optionalUTF8(specWildcardedPublicIdentity, a.WildcardedPublicIdentity)...)
	return a.NewMessage(n, req, Application, body...)
}

// ParseLIA reads a received LIA.
func ParseLIA(m *diameter.Message) (*LIA, error) {
	if err := checkCommand(m, CodeLocationInfo, false); err != nil {
		return nil, err
	}
	ans, f := ParseAnswer(m)
	a := &LIA{
		Answer:                   ans,
		ServerName:               f.UTF8String(specServerName, Optional),
		ServerCapabilities:       readServerCapabilities(f),
		WildcardedPublicIdentity: f.UTF8String(specWildcardedPublicIdentity, Optional),
	}
	if err := f.Err(); err != nil {
		return nil, err
	}
	return a, nil
}
