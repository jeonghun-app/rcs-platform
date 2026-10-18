package sh

import (
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

// SNR is a Subscribe-Notifications-Request (TS 29.329 §6.1.5): an AS asks to
// be told when user data changes, or stops asking (Sh-Subs-Notif,
// TS 29.328 §6.1.3).
type SNR struct {
	cx.Request
	UserIdentity             UserIdentity
	WildcardedPublicIdentity string
	WildcardedIMPU           string
	ServiceIndications       []string
	// SendDataIndication asks for the current data in the answer.
	SendDataIndication bool
	ServerName         string
	SubsReqType        SubsReqType
	DataReferences     []DataReference // at least one
	IdentitySets       []IdentitySet
	// ExpiryTime is when the subscription should end; zero leaves it to the
	// HSS. Time AVPs have one-second resolution.
	ExpiryTime time.Time
	// OneTimeNotification asks to be notified once only; it applies to UE
	// reachability (§6.3.22).
	OneTimeNotification bool
	UserName            string
}

// Message builds the request.
func (r *SNR) Message(n *diameter.Node) (*diameter.Message, error) {
	id, err := r.UserIdentity.avp()
	if err != nil {
		return nil, err
	}
	refs, err := dataReferences("SNR", r.DataReferences)
	if err != nil {
		return nil, err
	}
	body := []*diameter.AVP{id}
	body = append(body, wildcardAVPs(r.WildcardedPublicIdentity, r.WildcardedIMPU)...)
	body = append(body, serviceIndications(r.ServiceIndications)...)
	if r.SendDataIndication {
		body = append(body, specSendDataIndication.Enumerated(sendDataIndicationRequested))
	}
	body = append(body, optionalUTF8(specServerName, r.ServerName)...)
	body = append(body, specSubsReqType.Enumerated(int32(r.SubsReqType)))
	body = append(body, refs...)
	body = append(body, identitySets(r.IdentitySets)...)
	if !r.ExpiryTime.IsZero() {
		body = append(body, specExpiryTime.Time(r.ExpiryTime))
	}
	if r.OneTimeNotification {
		body = append(body, specOneTimeNotification.Enumerated(oneTimeNotificationRequested))
	}
	body = append(body, optionalUTF8(specUserName, r.UserName)...)
	return r.NewMessage(n, Application, CodeSubscribeNotifications, body...)
}

// ParseSNR reads a received SNR.
func ParseSNR(m *diameter.Message) (*SNR, error) {
	if err := checkCommand(m, CodeSubscribeNotifications, true); err != nil {
		return nil, err
	}
	req, f := cx.ParseRequest(m)
	r := &SNR{Request: req, UserIdentity: readUserIdentity(f, m)}
	r.WildcardedPublicIdentity, r.WildcardedIMPU = readWildcards(f)
	r.ServiceIndications = readServiceIndications(f)
	if f.Has(specSendDataIndication) {
		switch v := f.Enumerated(specSendDataIndication, cx.Required); v {
		case sendDataIndicationRequested:
			r.SendDataIndication = true
		case sendDataIndicationNotRequested:
		default:
			f.Fail(diameter.ResultInvalidAVPValue, m.Find(AVPSendDataIndication, cx.Vendor3GPP), "invalid Send-Data-Indication")
		}
	}
	r.ServerName = f.UTF8String(specServerName, cx.Optional)
	r.SubsReqType = SubsReqType(f.Enumerated(specSubsReqType, cx.Required))
	r.DataReferences = readDataReferences(f)
	r.IdentitySets = readIdentitySets(f)
	r.ExpiryTime = f.Time(specExpiryTime, cx.Optional)
	if f.Has(specOneTimeNotification) {
		if v := f.Enumerated(specOneTimeNotification, cx.Required); v != oneTimeNotificationRequested && f.Err() == nil {
			f.Fail(diameter.ResultInvalidAVPValue, m.Find(AVPOneTimeNotification, cx.Vendor3GPP), "invalid One-Time-Notification")
		}
		r.OneTimeNotification = true
	}
	r.UserName = f.UTF8String(specUserName, cx.Optional)
	if err := f.Err(); err != nil {
		return nil, err
	}
	return r, nil
}

// SNA is a Subscribe-Notifications-Answer (TS 29.329 §6.1.6).
type SNA struct {
	cx.Answer
	WildcardedPublicIdentity string
	WildcardedIMPU           string
	// UserData is the current data, when the SNR asked for it.
	UserData []byte
	// ExpiryTime is when the HSS will end the subscription; zero when
	// absent.
	ExpiryTime time.Time
}

// Message builds the answer to req.
func (a *SNA) Message(n *diameter.Node, req *diameter.Message) (*diameter.Message, error) {
	body := wildcardAVPs(a.WildcardedPublicIdentity, a.WildcardedIMPU)
	if a.UserData != nil {
		body = append(body, specUserData.OctetString(a.UserData))
	}
	if !a.ExpiryTime.IsZero() {
		body = append(body, specExpiryTime.Time(a.ExpiryTime))
	}
	return a.NewMessage(n, req, Application, body...)
}

// ParseSNA reads a received SNA.
func ParseSNA(m *diameter.Message) (*SNA, error) {
	if err := checkCommand(m, CodeSubscribeNotifications, false); err != nil {
		return nil, err
	}
	ans, f := cx.ParseAnswer(m)
	a := &SNA{Answer: ans}
	a.WildcardedPublicIdentity, a.WildcardedIMPU = readWildcards(f)
	a.UserData = f.OctetString(specUserData, cx.Optional)
	a.ExpiryTime = f.Time(specExpiryTime, cx.Optional)
	if err := f.Err(); err != nil {
		return nil, err
	}
	return a, nil
}
