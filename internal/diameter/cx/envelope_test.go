package cx

import (
	"errors"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
)

func sampleUAR() *UAR {
	return &UAR{
		Request:                  request(""),
		UserName:                 impi,
		PublicIdentity:           impu,
		VisitedNetworkIdentifier: []byte(visitedNet),
	}
}

func TestRequestsAreProxiableCxRequestsWithTheApplicationAVPs(t *testing.T) {
	m := must(sampleUAR().Message(newNode(t, icscfHost)))
	if m.Flags != diameter.FlagRequest|diameter.FlagProxiable {
		t.Errorf("flags = %#x, want REQ|PXY", m.Flags)
	}
	if m.ApplicationID != ApplicationID || m.Code != CodeUserAuthorization {
		t.Errorf("application %d command %d", m.ApplicationID, m.Code)
	}
	if m.AVPs[0].Code != diameter.AVPSessionID {
		t.Errorf("first AVP is %d, want Session-Id (RFC 6733 §8.8)", m.AVPs[0].Code)
	}
	checkApplicationAVPs(t, m)
	sf := m.Find(AVPSupportedFeatures, Vendor3GPP)
	if sf == nil || !sf.Mandatory() {
		t.Errorf("Supported-Features in a request = %+v, want it with the M bit (TS 29.229 §7.2.1)", sf)
	}
}

func TestAnswersAreProxiableAndCarryTheApplicationAVPs(t *testing.T) {
	req := transmit(t, must(sampleUAR().Message(newNode(t, icscfHost))))
	uaa := &UAA{Answer: answer(ExperimentalResult(SubsequentRegistration)), ServerName: scscfName}
	m := must(uaa.Message(newNode(t, hssHost), req))
	if m.Flags != diameter.FlagProxiable {
		t.Errorf("flags = %#x, want PXY only", m.Flags)
	}
	if m.HopByHop != req.HopByHop || m.EndToEnd != req.EndToEnd {
		t.Error("answer identifiers differ from the request's")
	}
	checkApplicationAVPs(t, m)
	if m.Find(diameter.AVPResultCode, 0) != nil {
		t.Error("Result-Code sent next to Experimental-Result (TS 29.229 §6.2)")
	}
	sf := m.Find(AVPSupportedFeatures, Vendor3GPP)
	if sf == nil || sf.Mandatory() {
		t.Errorf("Supported-Features in an answer = %+v, want it without the M bit (TS 29.229 §7.2.1)", sf)
	}
}

func checkApplicationAVPs(t *testing.T, m *diameter.Message) {
	t.Helper()
	vsai := m.Find(diameter.AVPVendorSpecificApplicationID, 0)
	if vsai == nil {
		t.Fatal("no Vendor-Specific-Application-Id")
	}
	f := NewFields(must(vsai.Grouped()))
	if v, app := f.Unsigned32(specVendorID, Required), f.Unsigned32(specAuthApplicationID, Required); v != Vendor3GPP || app != ApplicationID {
		t.Errorf("Vendor-Specific-Application-Id = vendor %d application %d", v, app)
	}
	st := m.Find(diameter.AVPAuthSessionState, 0)
	if st == nil {
		t.Fatal("no Auth-Session-State")
	}
	if v, _ := st.Enumerated(); v != 1 {
		t.Errorf("Auth-Session-State = %d, want NO_STATE_MAINTAINED (1)", v)
	}
}

func TestErrorAVPsAreTheApplicationAVPs(t *testing.T) {
	got := ErrorAVPs(&diameter.Message{})
	if len(got) != 2 || got[0].Code != diameter.AVPVendorSpecificApplicationID || got[1].Code != diameter.AVPAuthSessionState {
		t.Fatalf("ErrorAVPs = %+v", got)
	}
}

// answerWith builds a UAA from raw AVPs after the common ones, as an
// arbitrary HSS might send it.
func answerWith(avps ...*diameter.AVP) *diameter.Message {
	m := &diameter.Message{Flags: diameter.FlagProxiable, Code: CodeUserAuthorization, ApplicationID: ApplicationID}
	m.Add(
		specSessionID.UTF8String("icscf;1;2"),
		specOriginHost.UTF8String(hssHost),
		specOriginRealm.UTF8String(realm),
	)
	m.Add(avps...)
	return m
}

func experimental(vendor uint32, code *uint32) *diameter.AVP {
	children := []*diameter.AVP{specVendorID.Unsigned32(vendor)}
	if code != nil {
		children = append(children, specExperimentalResultCode.Unsigned32(*code))
	}
	return specExperimentalResult.Grouped(children...)
}

func ptr[T any](v T) *T { return &v }

func TestAnswerResultIsReadFromResultCodeOrExperimentalResult(t *testing.T) {
	tests := map[string]struct {
		avps    []*diameter.AVP
		want    Result
		success bool
	}{
		"Experimental-Result FIRST_REGISTRATION": {
			avps: []*diameter.AVP{experimental(Vendor3GPP, ptr(FirstRegistration))},
			want: Result{Code: FirstRegistration, Vendor: Vendor3GPP}, success: true,
		},
		"Experimental-Result ERROR_USER_UNKNOWN": {
			avps: []*diameter.AVP{experimental(Vendor3GPP, ptr(ErrorUserUnknown))},
			want: ExperimentalResult(ErrorUserUnknown),
		},
		"Experimental-Result of another vendor": {
			avps: []*diameter.AVP{experimental(VendorETSI, ptr(uint32(5555)))},
			want: Result{Code: 5555, Vendor: VendorETSI},
		},
		"Result-Code DIAMETER_UNABLE_TO_COMPLY": {
			avps: []*diameter.AVP{specResultCode.Unsigned32(diameter.ResultUnableToComply)},
			want: ResultCode(diameter.ResultUnableToComply),
		},
		"Result-Code DIAMETER_SUCCESS": {
			avps: []*diameter.AVP{specResultCode.Unsigned32(diameter.ResultSuccess)},
			want: ResultCode(diameter.ResultSuccess), success: true,
		},
		// A protocol error answer (E bit) still has to be readable: it is how
		// a caller learns that the HSS could not be reached.
		"Result-Code DIAMETER_UNABLE_TO_DELIVER": {
			avps: []*diameter.AVP{specResultCode.Unsigned32(diameter.ResultUnableToDeliver)},
			want: ResultCode(diameter.ResultUnableToDeliver),
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			uaa, err := ParseUAA(transmit(t, answerWith(tc.avps...)))
			if err != nil {
				t.Fatal(err)
			}
			if uaa.Result != tc.want || uaa.Result.IsSuccess() != tc.success {
				t.Errorf("Result = %v (success %t), want %v (success %t)", uaa.Result, uaa.Result.IsSuccess(), tc.want, tc.success)
			}
		})
	}
}

func TestAnswerWithAnUnusableResultIsRejected(t *testing.T) {
	tests := map[string]struct {
		avps     []*diameter.AVP
		code     uint32
		failedIn uint32 // code of the top-level Failed-AVP child
	}{
		"no result at all": {
			code: diameter.ResultMissingAVP, failedIn: diameter.AVPExperimentalResult,
		},
		"both Result-Code and Experimental-Result": {
			avps: []*diameter.AVP{specResultCode.Unsigned32(diameter.ResultSuccess), experimental(Vendor3GPP, ptr(FirstRegistration))},
			code: diameter.ResultContradictingAVPs, failedIn: diameter.AVPExperimentalResult,
		},
		"Experimental-Result without its code": {
			avps: []*diameter.AVP{experimental(Vendor3GPP, nil)},
			code: diameter.ResultMissingAVP, failedIn: diameter.AVPExperimentalResult,
		},
		"Experimental-Result with vendor 0": {
			avps: []*diameter.AVP{experimental(0, ptr(FirstRegistration))},
			code: diameter.ResultInvalidAVPValue, failedIn: diameter.AVPExperimentalResult,
		},
		"Result-Code 0": {
			avps: []*diameter.AVP{specResultCode.Unsigned32(0)},
			code: diameter.ResultInvalidAVPValue, failedIn: diameter.AVPResultCode,
		},
		"two Result-Codes": {
			avps: []*diameter.AVP{specResultCode.Unsigned32(diameter.ResultSuccess), specResultCode.Unsigned32(5001)},
			code: diameter.ResultAVPOccursTooManyTimes, failedIn: diameter.AVPResultCode,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseUAA(transmit(t, answerWith(tc.avps...)))
			var derr *diameter.Error
			if !errors.As(err, &derr) {
				t.Fatalf("err = %v, want a *diameter.Error", err)
			}
			if derr.ResultCode != tc.code || derr.FailedAVP == nil || derr.FailedAVP.Code != tc.failedIn {
				t.Errorf("error = %d with Failed-AVP %+v, want %d in AVP %d", derr.ResultCode, derr.FailedAVP, tc.code, tc.failedIn)
			}
		})
	}
}

func TestMissingAVPInsideAGroupIsReportedInsideTheGroup(t *testing.T) {
	_, err := ParseUAA(transmit(t, answerWith(experimental(Vendor3GPP, nil))))
	var derr *diameter.Error
	if !errors.As(err, &derr) {
		t.Fatal(err)
	}
	inner := must(derr.FailedAVP.Grouped())
	if len(inner) != 1 || inner[0].Code != diameter.AVPExperimentalResultCode || len(inner[0].Data) != 4 {
		t.Errorf("Failed-AVP holds %+v, want a zero Experimental-Result-Code (RFC 6733 §7.5)", inner)
	}
}

func TestResultsDescribeThemselves(t *testing.T) {
	if s := ExperimentalResult(ErrorUserUnknown).String(); s != "experimental result 5001 (vendor 10415)" {
		t.Errorf("String() = %q", s)
	}
	if s := ResultCode(diameter.ResultSuccess).String(); s != "result 2001" {
		t.Errorf("String() = %q", s)
	}
}

func TestAnswersRefuseNoResultAndProtocolErrors(t *testing.T) {
	hss := newNode(t, hssHost)
	req := transmit(t, must(sampleUAR().Message(newNode(t, icscfHost))))
	for _, r := range []Result{{}, ResultCode(diameter.ResultUnableToDeliver)} {
		if _, err := (&UAA{Answer: Answer{Result: r}}).Message(hss, req); err == nil {
			t.Errorf("answer with %v built", r)
		}
	}
	// 3xxx is only a protocol error as a base Result-Code; as a vendor code
	// it is the vendor's to define.
	if _, err := (&UAA{Answer: Answer{Result: Result{Code: 3999, Vendor: Vendor3GPP}}}).Message(hss, req); err != nil {
		t.Errorf("experimental 3999 refused: %v", err)
	}
}

func TestRequestsRefuseAnInvalidDestination(t *testing.T) {
	n := newNode(t, icscfHost)
	for name, edit := range map[string]func(*UAR){
		"no realm":      func(r *UAR) { r.DestinationRealm = "" },
		"invalid realm": func(r *UAR) { r.DestinationRealm = "ims test" },
		"invalid host":  func(r *UAR) { r.DestinationHost = "hss\x00" },
	} {
		t.Run(name, func(t *testing.T) {
			r := sampleUAR()
			edit(r)
			if _, err := r.Message(n); err == nil {
				t.Error("request built")
			}
		})
	}
}

func TestAFaultWithoutAnAVPInsideAGroupIsKeptWithoutFailedAVP(t *testing.T) {
	f := NewFields([]*diameter.AVP{experimental(Vendor3GPP, ptr(FirstRegistration))})
	g := f.Grouped(specExperimentalResult, Required)
	g.Fail(diameter.ResultUnableToComply, nil, "caller fault")
	var derr *diameter.Error
	if !errors.As(f.Err(), &derr) || derr.ResultCode != diameter.ResultUnableToComply || derr.FailedAVP != nil {
		t.Errorf("Err() = %v", f.Err())
	}
}
