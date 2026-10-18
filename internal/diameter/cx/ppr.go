package cx

import "github.com/jeonghun-app/rcs-platform/internal/diameter"

// PPR is a Push-Profile-Request (TS 29.229 §6.1.11): the HSS sends a changed
// user profile, charging information or SIP Digest data to the S-CSCF serving
// the user (TS 29.228 §6.2.2). Like an RTR it needs Destination-Host.
type PPR struct {
	Request
	UserName            string
	UserData            []byte
	ChargingInformation *ChargingInformation
	AuthDataItem        *AuthDataItem
}

// Message builds the request.
func (r *PPR) Message(n *diameter.Node) (*diameter.Message, error) {
	switch {
	case r.DestinationHost == "":
		return nil, errMissing("PPR", "Destination-Host")
	case r.UserName == "":
		return nil, errMissing("PPR", "User-Name")
	}
	body := []*diameter.AVP{specUserName.UTF8String(r.UserName)}
	body = append(body, optionalOctets(specUserData, r.UserData)...)
	if r.ChargingInformation != nil {
		ci, err := r.ChargingInformation.avp()
		if err != nil {
			return nil, err
		}
		body = append(body, ci)
	}
	if r.AuthDataItem != nil {
		item, err := r.AuthDataItem.avp()
		if err != nil {
			return nil, err
		}
		body = append(body, item)
	}
	return r.NewMessage(n, Application, CodePushProfile, body...)
}

// ParsePPR reads a received PPR.
func ParsePPR(m *diameter.Message) (*PPR, error) {
	if err := checkCommand(m, CodePushProfile, true); err != nil {
		return nil, err
	}
	req, f := ParseRequest(m)
	if req.DestinationHost == "" {
		f.one(specDestinationHost, Required)
	}
	r := &PPR{
		Request:             req,
		UserName:            f.UTF8String(specUserName, Required),
		UserData:            f.OctetString(specUserData, Optional),
		ChargingInformation: readChargingInformation(f),
	}
	if g := f.Grouped(specSIPAuthDataItem, Optional); g != nil {
		item := readAuthDataItem(g)
		r.AuthDataItem = &item
	}
	if err := f.Err(); err != nil {
		return nil, err
	}
	return r, nil
}

// PPA is a Push-Profile-Answer (TS 29.229 §6.1.12).
type PPA struct {
	Answer
}

// Message builds the answer to req.
func (a *PPA) Message(n *diameter.Node, req *diameter.Message) (*diameter.Message, error) {
	return a.NewMessage(n, req, Application)
}

// ParsePPA reads a received PPA.
func ParsePPA(m *diameter.Message) (*PPA, error) {
	if err := checkCommand(m, CodePushProfile, false); err != nil {
		return nil, err
	}
	ans, f := ParseAnswer(m)
	if err := f.Err(); err != nil {
		return nil, err
	}
	return &PPA{Answer: ans}, nil
}
