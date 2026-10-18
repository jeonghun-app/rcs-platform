package sh

import (
	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

// PNR is a Push-Notification-Request (TS 29.329 §6.1.7): the HSS tells a
// subscribed AS that user data changed (Sh-Notif, TS 29.328 §6.1.4). The HSS
// sends it to a known AS, so Destination-Host is required.
type PNR struct {
	cx.Request
	UserIdentity             UserIdentity
	WildcardedPublicIdentity string
	WildcardedIMPU           string
	UserName                 string
	UserData                 []byte
}

// Message builds the request.
func (r *PNR) Message(n *diameter.Node) (*diameter.Message, error) {
	if r.DestinationHost == "" {
		return nil, errMissing("PNR", "Destination-Host")
	}
	if len(r.UserData) == 0 {
		return nil, errMissing("PNR", "User-Data")
	}
	id, err := r.UserIdentity.avp()
	if err != nil {
		return nil, err
	}
	body := []*diameter.AVP{id}
	body = append(body, wildcardAVPs(r.WildcardedPublicIdentity, r.WildcardedIMPU)...)
	body = append(body, optionalUTF8(specUserName, r.UserName)...)
	body = append(body, specUserData.OctetString(r.UserData))
	return r.NewMessage(n, Application, CodePushNotification, body...)
}

// ParsePNR reads a received PNR.
func ParsePNR(m *diameter.Message) (*PNR, error) {
	if err := checkCommand(m, CodePushNotification, true); err != nil {
		return nil, err
	}
	req, f := cx.ParseRequest(m)
	if req.DestinationHost == "" && f.Err() == nil {
		f.DiameterIdentity(specDestinationHost, cx.Required)
	}
	r := &PNR{Request: req, UserIdentity: readUserIdentity(f, m)}
	r.WildcardedPublicIdentity, r.WildcardedIMPU = readWildcards(f)
	r.UserName = f.UTF8String(specUserName, cx.Optional)
	r.UserData = f.OctetString(specUserData, cx.Required)
	if err := f.Err(); err != nil {
		return nil, err
	}
	return r, nil
}

// PNA is a Push-Notification-Answer (TS 29.329 §6.1.8).
type PNA struct {
	cx.Answer
}

// Message builds the answer to req.
func (a *PNA) Message(n *diameter.Node, req *diameter.Message) (*diameter.Message, error) {
	return a.NewMessage(n, req, Application)
}

// ParsePNA reads a received PNA.
func ParsePNA(m *diameter.Message) (*PNA, error) {
	if err := checkCommand(m, CodePushNotification, false); err != nil {
		return nil, err
	}
	ans, f := cx.ParseAnswer(m)
	if err := f.Err(); err != nil {
		return nil, err
	}
	return &PNA{Answer: ans}, nil
}
