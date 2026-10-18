package sh

import (
	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

// PUR is a Profile-Update-Request (TS 29.329 §6.1.3): an AS updates data in
// the HSS, in practice its repository data (Sh-Update, TS 29.328 §6.1.2).
// UserData is an Sh-Data document, which [Data.Marshal] writes.
type PUR struct {
	cx.Request
	UserIdentity             UserIdentity
	WildcardedPublicIdentity string
	WildcardedIMPU           string
	UserName                 string
	// DataReferences has one entry unless both sides support the
	// Update-Eff-Enhance feature (§6.1.3).
	DataReferences []DataReference
	UserData       []byte
}

// Message builds the request.
func (r *PUR) Message(n *diameter.Node) (*diameter.Message, error) {
	id, err := r.UserIdentity.avp()
	if err != nil {
		return nil, err
	}
	refs, err := dataReferences("PUR", r.DataReferences)
	if err != nil {
		return nil, err
	}
	if len(r.UserData) == 0 {
		return nil, errMissing("PUR", "User-Data")
	}
	body := []*diameter.AVP{id}
	body = append(body, wildcardAVPs(r.WildcardedPublicIdentity, r.WildcardedIMPU)...)
	body = append(body, optionalUTF8(specUserName, r.UserName)...)
	body = append(body, refs...)
	body = append(body, specUserData.OctetString(r.UserData))
	return r.NewMessage(n, Application, CodeProfileUpdate, body...)
}

// ParsePUR reads a received PUR.
func ParsePUR(m *diameter.Message) (*PUR, error) {
	if err := checkCommand(m, CodeProfileUpdate, true); err != nil {
		return nil, err
	}
	req, f := cx.ParseRequest(m)
	r := &PUR{Request: req, UserIdentity: readUserIdentity(f, m)}
	r.WildcardedPublicIdentity, r.WildcardedIMPU = readWildcards(f)
	r.UserName = f.UTF8String(specUserName, cx.Optional)
	r.DataReferences = readDataReferences(f)
	r.UserData = f.OctetString(specUserData, cx.Required)
	if err := f.Err(); err != nil {
		return nil, err
	}
	return r, nil
}

// PUA is a Profile-Update-Answer (TS 29.329 §6.1.4).
type PUA struct {
	cx.Answer
	WildcardedPublicIdentity string
	WildcardedIMPU           string
	// RepositoryDataID, when present, says which version of the repository
	// data the HSS now holds.
	RepositoryDataID *RepositoryDataID
	// DataReference is present only with the Update-Eff-Enhance feature;
	// nil when absent, since RefRepositoryData is 0.
	DataReference *DataReference
}

// Message builds the answer to req.
func (a *PUA) Message(n *diameter.Node, req *diameter.Message) (*diameter.Message, error) {
	body := wildcardAVPs(a.WildcardedPublicIdentity, a.WildcardedIMPU)
	if a.RepositoryDataID != nil {
		id, err := a.RepositoryDataID.avp()
		if err != nil {
			return nil, err
		}
		body = append(body, id)
	}
	if a.DataReference != nil {
		body = append(body, specDataReference.Enumerated(int32(*a.DataReference)))
	}
	return a.NewMessage(n, req, Application, body...)
}

// ParsePUA reads a received PUA.
func ParsePUA(m *diameter.Message) (*PUA, error) {
	if err := checkCommand(m, CodeProfileUpdate, false); err != nil {
		return nil, err
	}
	ans, f := cx.ParseAnswer(m)
	a := &PUA{Answer: ans}
	a.WildcardedPublicIdentity, a.WildcardedIMPU = readWildcards(f)
	a.RepositoryDataID = readRepositoryDataID(f)
	if f.Has(specDataReference) {
		ref := DataReference(f.Enumerated(specDataReference, cx.Required))
		a.DataReference = &ref
	}
	if err := f.Err(); err != nil {
		return nil, err
	}
	return a, nil
}
