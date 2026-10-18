package cx

import (
	"reflect"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
)

func check[T any](t *testing.T, what string, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s after the round trip:\n got %+v\nwant %+v", what, got, want)
	}
}

func TestUserAuthorizationRoundTripKeepsEveryField(t *testing.T) {
	icscf, hss := newNode(t, icscfHost), newNode(t, hssHost)
	const sid = "icscf-1.ims.mnc001.mcc001.3gppnetwork.org;1;1"
	uar := &UAR{
		Request:                  request(sid),
		UserName:                 impi,
		PublicIdentity:           impu,
		VisitedNetworkIdentifier: []byte(visitedNet),
		AuthorizationType:        AuthorizeRegistrationAndCapabilities,
	}
	req := transmit(t, must(uar.Message(icscf)))
	want := *uar
	want.Request = requestAsReceived(sid, icscfHost)
	check(t, "UAR", must(ParseUAR(req)), &want)

	uaa := &UAA{
		Answer: answer(ExperimentalResult(FirstRegistration)),
		ServerCapabilities: &ServerCapabilities{
			Mandatory:   []uint32{1, 2},
			Optional:    []uint32{7},
			ServerNames: []string{scscfName},
		},
	}
	wantA := *uaa
	wantA.Answer = answerAsReceived(sid, ExperimentalResult(FirstRegistration))
	check(t, "UAA", must(ParseUAA(transmit(t, must(uaa.Message(hss, req))))), &wantA)
}

func TestServerAssignmentRoundTripCarriesTheUserProfile(t *testing.T) {
	scscf, hss := newNode(t, scscfHost), newNode(t, hssHost)
	const sid = "scscf-1.ims.mnc001.mcc001.3gppnetwork.org;1;2"
	sar := &SAR{
		Request:                  request(sid),
		UserName:                 impi,
		PublicIdentities:         []string{impu, telURI},
		WildcardedPublicIdentity: "sip:chatbot!.*!@ims.mnc001.mcc001.3gppnetwork.org",
		ServerName:               scscfName,
		AssignmentType:           Registration,
		UserDataAlreadyAvailable: UserDataNotAvailable,
	}
	req := transmit(t, must(sar.Message(scscf)))
	want := *sar
	want.Request = requestAsReceived(sid, scscfHost)
	check(t, "SAR", must(ParseSAR(req)), &want)

	saa := &SAA{
		Answer:   answer(ResultCode(diameter.ResultSuccess)),
		UserName: impi,
		UserData: []byte("<?xml version=\"1.0\"?><IMSSubscription/>"),
		ChargingInformation: &ChargingInformation{
			PrimaryEventChargingFunctionName:      "aaa://ocs1.ims.mnc001.mcc001.3gppnetwork.org",
			PrimaryChargingCollectionFunctionName: "aaa://cdf1.ims.mnc001.mcc001.3gppnetwork.org:3868",
		},
		AssociatedIdentities:     []string{impi, "001010000000002@ims.mnc001.mcc001.3gppnetwork.org"},
		ServerName:               scscfName,
		WildcardedPublicIdentity: "sip:chatbot!.*!@ims.mnc001.mcc001.3gppnetwork.org",
	}
	wantA := *saa
	wantA.Answer = answerAsReceived(sid, ResultCode(diameter.ResultSuccess))
	check(t, "SAA", must(ParseSAA(transmit(t, must(saa.Message(hss, req))))), &wantA)
}

func TestLocationInfoRoundTripKeepsTheOriginatingMark(t *testing.T) {
	icscf, hss := newNode(t, icscfHost), newNode(t, hssHost)
	const sid = "icscf-1.ims.mnc001.mcc001.3gppnetwork.org;1;3"
	lir := &LIR{
		Request:            request(sid),
		PublicIdentity:     telURI,
		OriginatingRequest: true,
		AuthorizationType:  AuthorizeRegistrationAndCapabilities,
	}
	req := transmit(t, must(lir.Message(icscf)))
	want := *lir
	want.Request = requestAsReceived(sid, icscfHost)
	check(t, "LIR", must(ParseLIR(req)), &want)

	lia := &LIA{
		Answer:                   answer(ExperimentalResult(UnregisteredService)),
		ServerName:               scscfName,
		ServerCapabilities:       &ServerCapabilities{},
		WildcardedPublicIdentity: "tel:+155501000!.*!",
	}
	wantA := *lia
	wantA.Answer = answerAsReceived(sid, ExperimentalResult(UnregisteredService))
	check(t, "LIA", must(ParseLIA(transmit(t, must(lia.Message(hss, req))))), &wantA)
}

func TestMultimediaAuthRoundTripCarriesAKAAndDigestVectors(t *testing.T) {
	scscf, hss := newNode(t, scscfHost), newNode(t, hssHost)
	const sid = "scscf-1.ims.mnc001.mcc001.3gppnetwork.org;1;4"
	mar := &MAR{
		Request:        request(sid),
		UserName:       impi,
		PublicIdentity: impu,
		AuthDataItem: AuthDataItem{
			Scheme: SchemeDigestAKAv1MD5,
			// RAND‖AUTS for a resynchronisation.
			Authorization: append(seq(16, 0x10), seq(14, 0x40)...),
		},
		NumberAuthItems: 1,
		ServerName:      scscfName,
	}
	req := transmit(t, must(mar.Message(scscf)))
	want := *mar
	want.Request = requestAsReceived(sid, scscfHost)
	check(t, "MAR", must(ParseMAR(req)), &want)

	maa := &MAA{
		Answer:          answer(ResultCode(diameter.ResultSuccess)),
		UserName:        impi,
		PublicIdentity:  impu,
		NumberAuthItems: 2,
		AuthDataItems: []AuthDataItem{
			{
				ItemNumber:         1,
				Scheme:             SchemeDigestAKAv1MD5,
				Authenticate:       seq(32, 0x01),
				Authorization:      seq(8, 0x81),
				ConfidentialityKey: seq(16, 0xa0),
				IntegrityKey:       seq(16, 0xc0),
			},
			{
				ItemNumber: 2,
				Scheme:     SchemeSIPDigest,
				Digest: &DigestAuthenticate{
					Realm:              realm,
					Algorithm:          "MD5",
					QoP:                "auth",
					HA1:                "0123456789abcdef0123456789abcdef",
					AlternateAlgorithm: "SHA-256",
					AlternateHA1:       "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
				},
			},
		},
	}
	wantA := *maa
	wantA.Answer = answerAsReceived(sid, ResultCode(diameter.ResultSuccess))
	check(t, "MAA", must(ParseMAA(transmit(t, must(maa.Message(hss, req))))), &wantA)
}

func TestRegistrationTerminationRoundTripCarriesTheReason(t *testing.T) {
	hss, scscf := newNode(t, hssHost), newNode(t, scscfHost)
	const sid = "hss.ims.mnc001.mcc001.3gppnetwork.org;1;5"
	rtr := &RTR{
		Request: Request{
			SessionID:        sid,
			DestinationHost:  scscfHost,
			DestinationRealm: realm,
		},
		UserName:             impi,
		AssociatedIdentities: []string{},
		PublicIdentities:     []string{impu},
		DeregistrationReason: DeregistrationReason{Code: PermanentTermination, Info: "subscription ended"},
	}
	req := transmit(t, must(rtr.Message(hss)))
	want := *rtr
	want.OriginHost, want.OriginRealm = hssHost, realm
	check(t, "RTR", must(ParseRTR(req)), &want)

	rta := &RTA{
		Answer:               Answer{Result: ResultCode(diameter.ResultSuccess)},
		AssociatedIdentities: []string{impi},
	}
	wantA := *rta
	wantA.Answer = Answer{SessionID: sid, OriginHost: scscfHost, OriginRealm: realm, Result: ResultCode(diameter.ResultSuccess)}
	check(t, "RTA", must(ParseRTA(transmit(t, must(rta.Message(scscf, req))))), &wantA)
}

func TestPushProfileRoundTripCarriesNewDigestData(t *testing.T) {
	hss, scscf := newNode(t, hssHost), newNode(t, scscfHost)
	const sid = "hss.ims.mnc001.mcc001.3gppnetwork.org;1;6"
	ppr := &PPR{
		Request:             Request{SessionID: sid, DestinationHost: scscfHost, DestinationRealm: realm},
		UserName:            impi,
		UserData:            []byte("<IMSSubscription/>"),
		ChargingInformation: &ChargingInformation{SecondaryEventChargingFunctionName: "aaas://ocs2.ims.mnc001.mcc001.3gppnetwork.org"},
		AuthDataItem: &AuthDataItem{Scheme: SchemeSIPDigest, Digest: &DigestAuthenticate{
			Realm: realm, QoP: "auth", HA1: "fedcba9876543210fedcba9876543210",
		}},
	}
	req := transmit(t, must(ppr.Message(hss)))
	want := *ppr
	want.OriginHost, want.OriginRealm = hssHost, realm
	check(t, "PPR", must(ParsePPR(req)), &want)

	ppa := &PPA{Answer: Answer{Result: ExperimentalResult(ErrorNotSupportedUserData)}}
	wantA := &PPA{Answer: Answer{SessionID: sid, OriginHost: scscfHost, OriginRealm: realm, Result: ExperimentalResult(ErrorNotSupportedUserData)}}
	check(t, "PPA", must(ParsePPA(transmit(t, must(ppa.Message(scscf, req))))), wantA)
}

func TestOptionalFieldsLeftEmptyAreNotSent(t *testing.T) {
	icscf := newNode(t, icscfHost)
	uar := &UAR{
		Request:                  Request{DestinationRealm: realm},
		UserName:                 impi,
		PublicIdentity:           impu,
		VisitedNetworkIdentifier: []byte(visitedNet),
	}
	m := must(uar.Message(icscf))
	for _, code := range []uint32{AVPUserAuthorizationType, AVPSupportedFeatures} {
		if m.Find(code, Vendor3GPP) != nil {
			t.Errorf("AVP %d sent although its field is empty", code)
		}
	}
	if m.Find(diameter.AVPDestinationHost, 0) != nil {
		t.Error("Destination-Host sent although it is empty")
	}
	sid, ok := m.SessionID()
	if !ok || sid == "" {
		t.Errorf("Session-Id = %q, %v; want one from the node", sid, ok)
	}
}

// seq returns n bytes counting up from start, a recognisable stand-in for
// key material.
func seq(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}
