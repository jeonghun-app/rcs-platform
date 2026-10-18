package cx

import (
	"errors"
	"fmt"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
)

// Request holds the AVPs every Cx and Sh request carries besides its own:
// session, routing (TS 29.229 §5.5) and Supported-Features (§7.2).
//
// When a request is built, SessionID, OriginHost and OriginRealm come from the
// node unless SessionID is set; Destination-Host is sent only when set. When a
// request is parsed, every field is filled in from the message.
type Request struct {
	SessionID        string
	OriginHost       string
	OriginRealm      string
	DestinationHost  string
	DestinationRealm string
	// SupportedFeatures are the feature lists the request needs (§7.2.1).
	SupportedFeatures []SupportedFeatures
}

// SupportedFeatures is one feature list (TS 29.229 §6.3.29). Within a request
// the AVP is sent with the M bit, within an answer without it (§7.2.1).
type SupportedFeatures struct {
	VendorID      uint32
	FeatureListID uint32
	FeatureList   uint32
}

// Cx features of Feature-List-ID 1 (TS 29.229 Table 7.1.1), as bits of
// [SupportedFeatures.FeatureList].
const (
	FeatureSharedIFCSets   uint32 = 1 << 0 // SiFC
	FeatureAliasIndication uint32 = 1 << 1 // AliasInd
)

// NewMessage builds a request of application app with the command code and
// the command's own AVPs (body), adding Session-Id, the origin AVPs, the
// destination AVPs, Vendor-Specific-Application-Id, Auth-Session-State and
// Supported-Features. The request is proxiable, as every Cx and Sh command
// format says.
func (r *Request) NewMessage(n *diameter.Node, app diameter.Application, code uint32, body ...*diameter.AVP) (*diameter.Message, error) {
	if r.DestinationRealm == "" {
		return nil, errors.New("cx: request has no Destination-Realm")
	}
	sid := r.SessionID
	if sid == "" {
		sid = n.NewSessionID("")
	}
	avps := ApplicationAVPs(app)
	if r.DestinationHost != "" {
		host, err := identityAVP(specDestinationHost, r.DestinationHost)
		if err != nil {
			return nil, err
		}
		avps = append(avps, host)
	}
	realm, err := identityAVP(specDestinationRealm, r.DestinationRealm)
	if err != nil {
		return nil, err
	}
	avps = append(avps, realm)
	for _, sf := range r.SupportedFeatures {
		avps = append(avps, sf.avp(specSupportedFeaturesInRequest))
	}
	avps = append(avps, body...)
	msg := n.NewRequest(code, app.ID, sid, avps...)
	msg.Flags |= diameter.FlagProxiable
	return msg, nil
}

// identityAVP builds a DiameterIdentity AVP, refusing a value the peer would
// reject (RFC 6733 §4.3.1), so that a configuration mistake shows up here and
// not as a DIAMETER_INVALID_AVP_VALUE from the other side.
func identityAVP(s AVPSpec, v string) (*diameter.AVP, error) {
	a := s.UTF8String(v)
	if _, err := a.DiameterIdentity(); err != nil {
		return nil, fmt.Errorf("cx: %s is not a valid DiameterIdentity", s.Name)
	}
	return a, nil
}

// ParseRequest reads the common AVPs of a received request. The fields of the
// command itself are left in the returned reader.
func ParseRequest(m *diameter.Message) (Request, *Fields) {
	f := NewFields(m.AVPs)
	r := Request{
		SessionID:        f.UTF8String(specSessionID, Required),
		OriginHost:       f.DiameterIdentity(specOriginHost, Required),
		OriginRealm:      f.DiameterIdentity(specOriginRealm, Required),
		DestinationHost:  f.DiameterIdentity(specDestinationHost, Optional),
		DestinationRealm: f.DiameterIdentity(specDestinationRealm, Required),
	}
	r.SupportedFeatures = readSupportedFeatures(f)
	return r, f
}

func (sf SupportedFeatures) avp(s AVPSpec) *diameter.AVP {
	return s.Grouped(
		specVendorID.Unsigned32(sf.VendorID),
		specFeatureListID.Unsigned32(sf.FeatureListID),
		specFeatureList.Unsigned32(sf.FeatureList),
	)
}

func readSupportedFeatures(f *Fields) []SupportedFeatures {
	var out []SupportedFeatures
	for _, g := range f.AllGrouped(specSupportedFeaturesInRequest) {
		out = append(out, SupportedFeatures{
			VendorID:      g.Unsigned32(specVendorID, Required),
			FeatureListID: g.Unsigned32(specFeatureListID, Required),
			FeatureList:   g.Unsigned32(specFeatureList, Required),
		})
	}
	return out
}

// ApplicationAVPs are the Vendor-Specific-Application-Id and
// Auth-Session-State (NO_STATE_MAINTAINED) that every message of a 3GPP
// application carries (TS 29.229 §5.3, §6.1).
func ApplicationAVPs(app diameter.Application) []*diameter.AVP {
	return []*diameter.AVP{
		specVendorSpecificApplicationID.Grouped(
			specVendorID.Unsigned32(app.VendorID),
			specAuthApplicationID.Unsigned32(app.ID),
		),
		specAuthSessionState.Enumerated(authSessionStateNoStateMaintained),
	}
}

// ErrorAVPs supplies the AVPs of the failure answers a node builds itself for
// Cx requests. Register it at start-up:
//
//	node.SetErrorAVPs(cx.ApplicationID, cx.ErrorAVPs)
func ErrorAVPs(*diameter.Message) []*diameter.AVP { return ApplicationAVPs(Application) }

// Result is the outcome an answer reports: a base Result-Code, or an
// Experimental-Result-Code of a vendor. Cx and Sh use Experimental-Result for
// their own codes and Result-Code for the base ones (TS 29.229 §6.2).
type Result struct {
	Code uint32
	// Vendor is 0 for a Result-Code and the vendor of an
	// Experimental-Result-Code otherwise.
	Vendor uint32
}

// ResultCode returns a base protocol result, such as
// ResultCode(diameter.ResultSuccess).
func ResultCode(code uint32) Result { return Result{Code: code} }

// ExperimentalResult returns a 3GPP Experimental-Result, such as
// ExperimentalResult(cx.FirstRegistration).
func ExperimentalResult(code uint32) Result { return Result{Code: code, Vendor: Vendor3GPP} }

// IsSuccess reports whether the result is in the 2xxx success class, base or
// experimental.
func (r Result) IsSuccess() bool { return r.Code >= 2000 && r.Code < 3000 }

func (r Result) String() string {
	if r.Vendor != 0 {
		return fmt.Sprintf("experimental result %d (vendor %d)", r.Code, r.Vendor)
	}
	return fmt.Sprintf("result %d", r.Code)
}

// Answer holds the AVPs every Cx and Sh answer carries besides its own.
// Session-Id and the origin AVPs come from the node and the request when an
// answer is built and are filled in when one is parsed.
type Answer struct {
	SessionID   string
	OriginHost  string
	OriginRealm string
	Result      Result
	// SupportedFeatures lists the features the answering node supports
	// (TS 29.229 §7.2.1).
	SupportedFeatures []SupportedFeatures
}

// NewMessage builds the answer to req for application app, with the
// command's own AVPs (body) after the common ones. A protocol error (3xxx) is
// refused: it has its own answer format (RFC 6733 §7.2), which the node
// builds when a handler returns a [*diameter.Error].
func (a *Answer) NewMessage(n *diameter.Node, req *diameter.Message, app diameter.Application, body ...*diameter.AVP) (*diameter.Message, error) {
	if a.Result.Code == 0 {
		return nil, errors.New("cx: answer has no result")
	}
	if a.Result.Vendor == 0 && diameter.IsProtocolError(a.Result.Code) {
		return nil, fmt.Errorf("cx: protocol error %d must be returned as a *diameter.Error", a.Result.Code)
	}
	avps := ApplicationAVPs(app)
	for _, sf := range a.SupportedFeatures {
		avps = append(avps, sf.avp(specSupportedFeaturesInAnswer))
	}
	avps = append(avps, body...)
	var msg *diameter.Message
	if a.Result.Vendor != 0 {
		msg = n.NewExperimentalAnswer(req, a.Result.Vendor, a.Result.Code, avps...)
	} else {
		msg = n.NewAnswer(req, a.Result.Code, avps...)
	}
	msg.Flags |= diameter.FlagProxiable
	return msg, nil
}

// ParseAnswer reads the common AVPs of a received answer. An answer must
// carry exactly one of Result-Code and Experimental-Result: with both, it
// would be a guess which one the sender meant.
func ParseAnswer(m *diameter.Message) (Answer, *Fields) {
	f := NewFields(m.AVPs)
	a := Answer{
		SessionID:   f.UTF8String(specSessionID, Required),
		OriginHost:  f.DiameterIdentity(specOriginHost, Required),
		OriginRealm: f.DiameterIdentity(specOriginRealm, Required),
	}
	switch rc, er := f.Has(specResultCode), f.Has(specExperimentalResult); {
	case rc && er:
		f.Fail(diameter.ResultContradictingAVPs, m.Find(specExperimentalResult.Code, 0),
			"both Result-Code and Experimental-Result")
	case rc:
		a.Result = ResultCode(f.Unsigned32(specResultCode, Required))
	default:
		if g := f.Grouped(specExperimentalResult, Required); g != nil {
			a.Result = Result{
				Vendor: g.Unsigned32(specVendorID, Required),
				Code:   g.Unsigned32(specExperimentalResultCode, Required),
			}
			// Vendor 0 would make the code indistinguishable from a
			// Result-Code; vendor 0 is the IETF, whose codes go in Result-Code
			// (RFC 6733 §7.6).
			if a.Result.Vendor == 0 && f.Err() == nil {
				f.Fail(diameter.ResultInvalidAVPValue, m.Find(specExperimentalResult.Code, 0),
					"Experimental-Result without a vendor")
			}
		}
	}
	if a.Result.Code == 0 && f.Err() == nil {
		f.Fail(diameter.ResultInvalidAVPValue, resultAVP(m), "result code 0")
	}
	a.SupportedFeatures = readSupportedFeatures(f)
	return a, f
}

func resultAVP(m *diameter.Message) *diameter.AVP {
	if a := m.Find(specResultCode.Code, 0); a != nil {
		return a
	}
	return m.Find(specExperimentalResult.Code, 0)
}
