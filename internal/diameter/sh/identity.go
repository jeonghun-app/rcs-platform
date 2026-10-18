package sh

import (
	"errors"
	"fmt"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

// UserIdentity names the user a request is about (TS 29.329 §6.3.1): a
// public identity or an MSISDN, exactly one of them.
type UserIdentity struct {
	PublicIdentity string
	// MSISDN is the international number as digits, without "+", such as
	// "15550100001". On the wire it is TBCD-encoded (§6.3.2).
	MSISDN string
}

// maxMSISDNDigits is the longest international number E.164 allows.
const maxMSISDNDigits = 15

// ErrInvalidMSISDN reports an MSISDN that is not 1 to 15 decimal digits, or
// a TBCD encoding of one that is malformed.
var ErrInvalidMSISDN = errors.New("sh: invalid MSISDN")

// EncodeMSISDN returns the TBCD form of an MSISDN (TS 29.329 §6.3.2): two
// digits per octet, the first in the low nibble, and 1111 filling the high
// nibble of the last octet when the number of digits is odd.
func EncodeMSISDN(digits string) ([]byte, error) {
	if len(digits) == 0 || len(digits) > maxMSISDNDigits {
		return nil, ErrInvalidMSISDN
	}
	out := make([]byte, (len(digits)+1)/2)
	for i := 0; i < len(digits); i++ {
		d := digits[i]
		if d < '0' || d > '9' {
			return nil, ErrInvalidMSISDN
		}
		if i%2 == 0 {
			out[i/2] = 0xf0 | (d - '0')
		} else {
			out[i/2] = out[i/2]&0x0f | (d-'0')<<4
		}
	}
	return out, nil
}

// DecodeMSISDN reads the TBCD form of an MSISDN. A filler is accepted only
// where EncodeMSISDN puts one, so that every accepted encoding is the only
// encoding of its number.
func DecodeMSISDN(b []byte) (string, error) {
	if len(b) == 0 || len(b) > (maxMSISDNDigits+1)/2 {
		return "", ErrInvalidMSISDN
	}
	digits := make([]byte, 0, 2*len(b))
	for i, o := range b {
		low, high := o&0x0f, o>>4
		if low > 9 {
			return "", ErrInvalidMSISDN
		}
		digits = append(digits, '0'+low)
		switch {
		case high <= 9:
			digits = append(digits, '0'+high)
		case high == 0xf && i == len(b)-1:
		default:
			return "", ErrInvalidMSISDN
		}
	}
	if len(digits) > maxMSISDNDigits {
		return "", ErrInvalidMSISDN
	}
	return string(digits), nil
}

func (u UserIdentity) avp() (*diameter.AVP, error) {
	switch {
	case u.PublicIdentity != "" && u.MSISDN != "":
		return nil, errors.New("sh: User-Identity has both a Public-Identity and an MSISDN")
	case u.PublicIdentity != "":
		return specUserIdentity.Grouped(specPublicIdentity.UTF8String(u.PublicIdentity)), nil
	case u.MSISDN != "":
		tbcd, err := EncodeMSISDN(u.MSISDN)
		if err != nil {
			return nil, err
		}
		return specUserIdentity.Grouped(specMSISDN.OctetString(tbcd)), nil
	}
	return nil, errors.New("sh: User-Identity has neither a Public-Identity nor an MSISDN")
}

// readUserIdentity reads the required User-Identity. With both identities,
// or neither, the request does not say whom it is about.
func readUserIdentity(f *cx.Fields, m *diameter.Message) UserIdentity {
	g := f.Grouped(specUserIdentity, cx.Required)
	if g == nil {
		return UserIdentity{}
	}
	u := UserIdentity{PublicIdentity: g.UTF8String(specPublicIdentity, cx.Optional)}
	if tbcd := g.OctetString(specMSISDN, cx.Optional); tbcd != nil {
		msisdn, err := DecodeMSISDN(tbcd)
		if err != nil {
			g.Fail(diameter.ResultInvalidAVPValue, specMSISDN.OctetString(tbcd), "invalid MSISDN")
		}
		u.MSISDN = msisdn
	}
	if f.Err() == nil && (u.PublicIdentity == "") == (u.MSISDN == "") {
		f.Fail(diameter.ResultInvalidAVPValue, m.Find(AVPUserIdentity, cx.Vendor3GPP),
			"User-Identity must hold one Public-Identity or one MSISDN")
	}
	return u
}

// RepositoryDataID identifies a version of an AS's repository data
// (TS 29.329 §6.3.24).
type RepositoryDataID struct {
	ServiceIndication string
	SequenceNumber    uint32
}

func (r *RepositoryDataID) avp() (*diameter.AVP, error) {
	if r.ServiceIndication == "" {
		return nil, fmt.Errorf("sh: Repository-Data-ID has no Service-Indication")
	}
	return specRepositoryDataID.Grouped(
		specServiceIndication.OctetString([]byte(r.ServiceIndication)),
		specSequenceNumber.Unsigned32(r.SequenceNumber),
	), nil
}

func readRepositoryDataID(f *cx.Fields) *RepositoryDataID {
	g := f.Grouped(specRepositoryDataID, cx.Optional)
	if g == nil {
		return nil
	}
	return &RepositoryDataID{
		ServiceIndication: string(g.OctetString(specServiceIndication, cx.Required)),
		SequenceNumber:    g.Unsigned32(specSequenceNumber, cx.Required),
	}
}
