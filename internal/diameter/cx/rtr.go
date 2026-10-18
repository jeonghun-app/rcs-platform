package cx

import "github.com/jeonghun-app/rcs-platform/internal/diameter"

// RTR is a Registration-Termination-Request (TS 29.229 §6.1.9): the HSS
// deregisters a user administratively (TS 29.228 §6.1.3). Destination-Host is
// required on HSS-initiated requests (TS 29.229 §5.5). Under ADR 0005 the HSS
// sends the request on any connected scscf peer of the realm, not to the
// Origin-Host recorded at SAR time, which may belong to a task that has gone,
// so Destination-Host names the peer chosen ([diameter.Peer.Host]).
type RTR struct {
	Request
	UserName             string
	AssociatedIdentities []string // nil when absent
	// PublicIdentities lists the identities to deregister; none means every
	// identity of UserName.
	PublicIdentities     []string
	DeregistrationReason DeregistrationReason
}

// DeregistrationReason is the Deregistration-Reason of an RTR (TS 29.229
// §6.3.16). Info is text the S-CSCF may pass on to the user.
type DeregistrationReason struct {
	Code ReasonCode
	Info string
}

// Message builds the request.
func (r *RTR) Message(n *diameter.Node) (*diameter.Message, error) {
	switch {
	case r.DestinationHost == "":
		return nil, errMissing("RTR", "Destination-Host")
	case r.UserName == "":
		return nil, errMissing("RTR", "User-Name")
	}
	body := []*diameter.AVP{specUserName.UTF8String(r.UserName)}
	body = append(body, associatedIdentities(r.AssociatedIdentities)...)
	for _, p := range r.PublicIdentities {
		body = append(body, specPublicIdentity.UTF8String(p))
	}
	reason := []*diameter.AVP{specReasonCode.Enumerated(int32(r.DeregistrationReason.Code))}
	reason = append(reason, optionalUTF8(specReasonInfo, r.DeregistrationReason.Info)...)
	body = append(body, specDeregistrationReason.Grouped(reason...))
	return r.NewMessage(n, Application, CodeRegistrationTermination, body...)
}

// ParseRTR reads a received RTR.
func ParseRTR(m *diameter.Message) (*RTR, error) {
	if err := checkCommand(m, CodeRegistrationTermination, true); err != nil {
		return nil, err
	}
	req, f := ParseRequest(m)
	if req.DestinationHost == "" {
		f.one(specDestinationHost, Required)
	}
	r := &RTR{
		Request:              req,
		UserName:             f.UTF8String(specUserName, Required),
		AssociatedIdentities: readAssociatedIdentities(f),
		PublicIdentities:     f.AllUTF8String(specPublicIdentity),
	}
	if g := f.Grouped(specDeregistrationReason, Required); g != nil {
		r.DeregistrationReason = DeregistrationReason{
			Code: ReasonCode(g.Enumerated(specReasonCode, Required)),
			Info: g.UTF8String(specReasonInfo, Optional),
		}
	}
	if err := f.Err(); err != nil {
		return nil, err
	}
	return r, nil
}

// RTA is a Registration-Termination-Answer (TS 29.229 §6.1.10).
type RTA struct {
	Answer
	AssociatedIdentities []string // nil when absent
}

// Message builds the answer to req.
func (a *RTA) Message(n *diameter.Node, req *diameter.Message) (*diameter.Message, error) {
	return a.NewMessage(n, req, Application, associatedIdentities(a.AssociatedIdentities)...)
}

// ParseRTA reads a received RTA.
func ParseRTA(m *diameter.Message) (*RTA, error) {
	if err := checkCommand(m, CodeRegistrationTermination, false); err != nil {
		return nil, err
	}
	ans, f := ParseAnswer(m)
	a := &RTA{Answer: ans, AssociatedIdentities: readAssociatedIdentities(f)}
	if err := f.Err(); err != nil {
		return nil, err
	}
	return a, nil
}
