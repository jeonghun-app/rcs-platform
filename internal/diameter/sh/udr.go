package sh

import (
	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

// UDR is a User-Data-Request (TS 29.329 §6.1.1): an AS reads user data
// (Sh-Pull, TS 29.328 §6.1.1).
type UDR struct {
	cx.Request
	UserIdentity             UserIdentity
	WildcardedPublicIdentity string
	WildcardedIMPU           string
	// ServerName is the AS's own SIP URI, needed for some data such as the
	// iFC relevant to it.
	ServerName string
	// ServiceIndications name the repository data wanted with
	// RefRepositoryData.
	ServiceIndications []string
	DataReferences     []DataReference // at least one
	IdentitySets       []IdentitySet
	UserName           string
}

// Message builds the request.
func (r *UDR) Message(n *diameter.Node) (*diameter.Message, error) {
	id, err := r.UserIdentity.avp()
	if err != nil {
		return nil, err
	}
	refs, err := dataReferences("UDR", r.DataReferences)
	if err != nil {
		return nil, err
	}
	body := []*diameter.AVP{id}
	body = append(body, wildcardAVPs(r.WildcardedPublicIdentity, r.WildcardedIMPU)...)
	body = append(body, optionalUTF8(specServerName, r.ServerName)...)
	body = append(body, serviceIndications(r.ServiceIndications)...)
	body = append(body, refs...)
	body = append(body, identitySets(r.IdentitySets)...)
	body = append(body, optionalUTF8(specUserName, r.UserName)...)
	return r.NewMessage(n, Application, CodeUserData, body...)
}

// ParseUDR reads a received UDR.
func ParseUDR(m *diameter.Message) (*UDR, error) {
	if err := checkCommand(m, CodeUserData, true); err != nil {
		return nil, err
	}
	req, f := cx.ParseRequest(m)
	r := &UDR{Request: req, UserIdentity: readUserIdentity(f, m)}
	r.WildcardedPublicIdentity, r.WildcardedIMPU = readWildcards(f)
	r.ServerName = f.UTF8String(specServerName, cx.Optional)
	r.ServiceIndications = readServiceIndications(f)
	r.DataReferences = readDataReferences(f)
	r.IdentitySets = readIdentitySets(f)
	r.UserName = f.UTF8String(specUserName, cx.Optional)
	if err := f.Err(); err != nil {
		return nil, err
	}
	return r, nil
}

// UDA is a User-Data-Answer (TS 29.329 §6.1.2). UserData is an Sh-Data
// document, which [ParseData] reads.
type UDA struct {
	cx.Answer
	WildcardedPublicIdentity string
	WildcardedIMPU           string
	UserData                 []byte
}

// Message builds the answer to req.
func (a *UDA) Message(n *diameter.Node, req *diameter.Message) (*diameter.Message, error) {
	body := wildcardAVPs(a.WildcardedPublicIdentity, a.WildcardedIMPU)
	if a.UserData != nil {
		body = append(body, specUserData.OctetString(a.UserData))
	}
	return a.NewMessage(n, req, Application, body...)
}

// ParseUDA reads a received UDA.
func ParseUDA(m *diameter.Message) (*UDA, error) {
	if err := checkCommand(m, CodeUserData, false); err != nil {
		return nil, err
	}
	ans, f := cx.ParseAnswer(m)
	a := &UDA{Answer: ans}
	a.WildcardedPublicIdentity, a.WildcardedIMPU = readWildcards(f)
	a.UserData = f.OctetString(specUserData, cx.Optional)
	if err := f.Err(); err != nil {
		return nil, err
	}
	return a, nil
}
