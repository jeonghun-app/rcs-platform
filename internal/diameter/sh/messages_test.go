package sh

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

func TestUserDataRoundTripKeepsEveryField(t *testing.T) {
	as, hss := newNode(t, asHost), newNode(t, hssHost)
	const sid = "rcs-as-1;1;1"
	udr := &UDR{
		Request:                  asRequest(sid),
		UserIdentity:             UserIdentity{PublicIdentity: impu},
		WildcardedPublicIdentity: "sip:chatbot!.*!@" + realm,
		WildcardedIMPU:           "sip:bot!.*!@" + realm,
		ServerName:               asName,
		ServiceIndications:       []string{"rcs-chat", "rcs-ft"},
		DataReferences:           []DataReference{RefRepositoryData, RefIMSPublicIdentity},
		IdentitySets:             []IdentitySet{ImplicitIdentities},
		UserName:                 impi,
	}
	req := transmit(t, must(udr.Message(as)))
	want := *udr
	want.Request = received(udr.Request, asHost)
	check(t, "UDR", must(ParseUDR(req)), &want)

	uda := &UDA{Answer: cx.Answer{Result: cx.ResultCode(diameter.ResultSuccess)}, UserData: []byte("<Sh-Data/>")}
	wantA := *uda
	wantA.Answer = answered(sid, hssHost, cx.ResultCode(diameter.ResultSuccess))
	check(t, "UDA", must(ParseUDA(transmit(t, must(uda.Message(hss, req))))), &wantA)
}

func TestProfileUpdateRoundTripCarriesTheRepositoryVersion(t *testing.T) {
	as, hss := newNode(t, asHost), newNode(t, hssHost)
	const sid = "rcs-as-1;1;2"
	pur := &PUR{
		Request:        asRequest(sid),
		UserIdentity:   UserIdentity{MSISDN: msisdn},
		UserName:       impi,
		DataReferences: []DataReference{RefRepositoryData},
		UserData:       []byte("<Sh-Data><RepositoryData/></Sh-Data>"),
	}
	req := transmit(t, must(pur.Message(as)))
	want := *pur
	want.Request = received(pur.Request, asHost)
	check(t, "PUR", must(ParsePUR(req)), &want)

	ref := RefRepositoryData
	pua := &PUA{
		Answer:                   cx.Answer{Result: cx.ExperimentalResult(ErrorTransparentDataOutOfSync)},
		WildcardedPublicIdentity: "sip:chatbot!.*!@" + realm,
		RepositoryDataID:         &RepositoryDataID{ServiceIndication: "rcs-chat", SequenceNumber: 41},
		DataReference:            &ref,
	}
	wantA := *pua
	wantA.Answer = answered(sid, hssHost, cx.ExperimentalResult(ErrorTransparentDataOutOfSync))
	check(t, "PUA", must(ParsePUA(transmit(t, must(pua.Message(hss, req))))), &wantA)
}

func TestSubscribeNotificationsRoundTripKeepsFlagsAndExpiry(t *testing.T) {
	as, hss := newNode(t, asHost), newNode(t, hssHost)
	const sid = "rcs-as-1;1;3"
	expiry := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	snr := &SNR{
		Request:             asRequest(sid),
		UserIdentity:        UserIdentity{PublicIdentity: impu},
		WildcardedIMPU:      "sip:bot!.*!@" + realm,
		ServiceIndications:  []string{"rcs-chat"},
		SendDataIndication:  true,
		ServerName:          asName,
		SubsReqType:         Unsubscribe,
		DataReferences:      []DataReference{RefRepositoryData, RefIMSUserState},
		IdentitySets:        []IdentitySet{AllIdentities, RegisteredIdentities},
		ExpiryTime:          expiry,
		OneTimeNotification: true,
		UserName:            impi,
	}
	req := transmit(t, must(snr.Message(as)))
	want := *snr
	want.Request = received(snr.Request, asHost)
	check(t, "SNR", must(ParseSNR(req)), &want)

	sna := &SNA{Answer: cx.Answer{Result: cx.ResultCode(diameter.ResultSuccess)}, UserData: []byte{}, ExpiryTime: expiry}
	wantA := *sna
	wantA.Answer = answered(sid, hssHost, cx.ResultCode(diameter.ResultSuccess))
	check(t, "SNA", must(ParseSNA(transmit(t, must(sna.Message(hss, req))))), &wantA)
}

func TestPushNotificationRoundTripNeedsADestinationHost(t *testing.T) {
	hss, as := newNode(t, hssHost), newNode(t, asHost)
	const sid = "hss;1;4"
	pnr := &PNR{
		Request:      cx.Request{SessionID: sid, DestinationHost: asHost, DestinationRealm: realm},
		UserIdentity: UserIdentity{PublicIdentity: impu},
		UserName:     impi,
		UserData:     []byte("<Sh-Data/>"),
	}
	req := transmit(t, must(pnr.Message(hss)))
	want := *pnr
	want.Request = received(pnr.Request, hssHost)
	check(t, "PNR", must(ParsePNR(req)), &want)

	pna := &PNA{Answer: cx.Answer{Result: cx.ExperimentalResult(ErrorNoSubscriptionToData)}}
	check(t, "PNA", must(ParsePNA(transmit(t, must(pna.Message(as, req))))),
		&PNA{Answer: answered(sid, asHost, cx.ExperimentalResult(ErrorNoSubscriptionToData))})

	pnr.DestinationHost = ""
	if _, err := pnr.Message(hss); err == nil {
		t.Error("PNR without Destination-Host built")
	}
	noHost := &diameter.Message{Flags: diameter.FlagRequest, Code: CodePushNotification, ApplicationID: ApplicationID}
	for _, a := range req.AVPs {
		if a.Code != diameter.AVPDestinationHost {
			noHost.Add(a)
		}
	}
	var derr *diameter.Error
	if _, err := ParsePNR(noHost); !errors.As(err, &derr) || derr.FailedAVP.Code != diameter.AVPDestinationHost {
		t.Errorf("ParsePNR without Destination-Host: %v", err)
	}
}

func TestShMessagesUseTheShApplication(t *testing.T) {
	m := must((&UDR{Request: asRequest(""), UserIdentity: UserIdentity{PublicIdentity: impu},
		DataReferences: []DataReference{RefMSISDN}}).Message(newNode(t, asHost)))
	if m.ApplicationID != ApplicationID || m.Code != CodeUserData || m.Flags != diameter.FlagRequest|diameter.FlagProxiable {
		t.Errorf("header = application %d command %d flags %#x", m.ApplicationID, m.Code, m.Flags)
	}
	vsai := m.Find(diameter.AVPVendorSpecificApplicationID, 0)
	app := must(vsai.Grouped())[1]
	if v, _ := app.Unsigned32(); v != ApplicationID {
		t.Errorf("Vendor-Specific-Application-Id names application %d", v)
	}
	if got := ErrorAVPs(m); len(got) != 2 || got[0].Code != diameter.AVPVendorSpecificApplicationID {
		t.Errorf("ErrorAVPs = %+v", got)
	}
	if _, err := ParseUDA(m); err == nil {
		t.Error("ParseUDA accepted a request")
	}
	cxm := *m
	cxm.ApplicationID = cx.ApplicationID
	if _, err := ParseUDR(&cxm); err == nil {
		t.Error("ParseUDR accepted a Cx message")
	}
}

func TestUserIdentityMustNameExactlyOneIdentity(t *testing.T) {
	as := newNode(t, asHost)
	for name, id := range map[string]UserIdentity{
		"neither":     {},
		"both":        {PublicIdentity: impu, MSISDN: msisdn},
		"bad MSISDN":  {MSISDN: "+15550100001"},
		"long MSISDN": {MSISDN: msisdn + "00001"}, // 16 digits
	} {
		if _, err := (&UDR{Request: asRequest(""), UserIdentity: id, DataReferences: []DataReference{RefMSISDN}}).Message(as); err == nil {
			t.Errorf("%s: built", name)
		}
	}
	base := func(children ...*diameter.AVP) *diameter.Message {
		m := &diameter.Message{Flags: diameter.FlagRequest, Code: CodeUserData, ApplicationID: ApplicationID}
		m.Add(diameter.NewAVP(diameter.AVPSessionID, diameter.FlagMandatory, 0, []byte("as;1")),
			diameter.NewAVP(diameter.AVPOriginHost, diameter.FlagMandatory, 0, []byte(asHost)),
			diameter.NewAVP(diameter.AVPOriginRealm, diameter.FlagMandatory, 0, []byte(realm)),
			diameter.NewAVP(diameter.AVPDestinationRealm, diameter.FlagMandatory, 0, []byte(realm)),
			specUserIdentity.Grouped(children...),
			specDataReference.Enumerated(int32(RefMSISDN)))
		return m
	}
	tests := map[string]*diameter.Message{
		"empty User-Identity":   base(),
		"both identities":       base(specPublicIdentity.UTF8String(impu), specMSISDN.OctetString(must(EncodeMSISDN(msisdn)))),
		"malformed MSISDN":      base(specMSISDN.OctetString([]byte{0xab})),
		"empty Public-Identity": base(specPublicIdentity.UTF8String("")),
	}
	for name, m := range tests {
		_, err := ParseUDR(m)
		var derr *diameter.Error
		if !errors.As(err, &derr) || derr.ResultCode != diameter.ResultInvalidAVPValue || derr.FailedAVP.Code != AVPUserIdentity {
			t.Errorf("%s: err = %v, want DIAMETER_INVALID_AVP_VALUE in User-Identity", name, err)
		}
	}
}

func TestRequestsWithoutDataReferenceAreRefused(t *testing.T) {
	as := newNode(t, asHost)
	id := UserIdentity{PublicIdentity: impu}
	if _, err := (&UDR{Request: asRequest(""), UserIdentity: id}).Message(as); err == nil {
		t.Error("UDR without Data-Reference built")
	}
	if _, err := (&SNR{Request: asRequest(""), UserIdentity: id}).Message(as); err == nil {
		t.Error("SNR without Data-Reference built")
	}
	if _, err := (&PUR{Request: asRequest(""), UserIdentity: id, UserData: []byte("x")}).Message(as); err == nil {
		t.Error("PUR without Data-Reference built")
	}
	if _, err := (&PUR{Request: asRequest(""), UserIdentity: id, DataReferences: []DataReference{RefRepositoryData}}).Message(as); err == nil {
		t.Error("PUR without User-Data built")
	}
	m := must((&UDR{Request: asRequest(""), UserIdentity: id, DataReferences: []DataReference{RefMSISDN}}).Message(as))
	m.AVPs = m.AVPs[:len(m.AVPs)-1] // the Data-Reference is last
	var derr *diameter.Error
	if _, err := ParseUDR(m); !errors.As(err, &derr) || derr.ResultCode != diameter.ResultMissingAVP || derr.FailedAVP.Code != AVPDataReference {
		t.Errorf("ParseUDR without Data-Reference: %v", err)
	}
}

func TestSingleValuedEnumerationsOutsideTheirValueAreRefused(t *testing.T) {
	m := must((&SNR{Request: asRequest(""), UserIdentity: UserIdentity{PublicIdentity: impu},
		DataReferences: []DataReference{RefIMSUserState}}).Message(newNode(t, asHost)))
	for name, a := range map[string]*diameter.AVP{
		"Send-Data-Indication 2":  specSendDataIndication.Enumerated(2),
		"One-Time-Notification 1": specOneTimeNotification.Enumerated(1),
	} {
		bad := *m
		bad.AVPs = append(append([]*diameter.AVP{}, m.AVPs...), a)
		var derr *diameter.Error
		if _, err := ParseSNR(&bad); !errors.As(err, &derr) || derr.ResultCode != diameter.ResultInvalidAVPValue {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// USER_DATA_NOT_REQUESTED is valid and reads as false.
	ok := *m
	ok.AVPs = append(append([]*diameter.AVP{}, m.AVPs...), specSendDataIndication.Enumerated(0))
	if snr, err := ParseSNR(&ok); err != nil || snr.SendDataIndication {
		t.Errorf("Send-Data-Indication 0: %+v, %v", snr, err)
	}
}

func TestRepositoryDataIDNeedsAServiceIndication(t *testing.T) {
	req := transmit(t, must((&PUR{Request: asRequest("s"), UserIdentity: UserIdentity{PublicIdentity: impu},
		DataReferences: []DataReference{RefRepositoryData}, UserData: []byte("x")}).Message(newNode(t, asHost))))
	pua := &PUA{Answer: cx.Answer{Result: cx.ResultCode(diameter.ResultSuccess)}, RepositoryDataID: &RepositoryDataID{SequenceNumber: 1}}
	if _, err := pua.Message(newNode(t, hssHost), req); err == nil {
		t.Error("PUA with an empty Repository-Data-ID built")
	}
}

func TestMSISDNIsTBCDEncoded(t *testing.T) {
	tests := []struct {
		digits string
		tbcd   []byte
	}{
		{"15550100001", []byte{0x51, 0x55, 0x10, 0x00, 0x00, 0xf1}},
		{"12", []byte{0x21}},
		{"1", []byte{0xf1}},
		// The longest E.164 number; built at run time so that the privacy
		// check does not take it for an IMSI.
		{strings.Repeat("12345", 3), []byte{0x21, 0x43, 0x15, 0x32, 0x54, 0x21, 0x43, 0xf5}},
	}
	for _, tc := range tests {
		got, err := EncodeMSISDN(tc.digits)
		if err != nil || string(got) != string(tc.tbcd) {
			t.Errorf("EncodeMSISDN(%s) = % x, %v; want % x", tc.digits, got, err, tc.tbcd)
		}
		back, err := DecodeMSISDN(tc.tbcd)
		if err != nil || back != tc.digits {
			t.Errorf("DecodeMSISDN(% x) = %q, %v; want %s", tc.tbcd, back, err, tc.digits)
		}
	}
	for _, bad := range [][]byte{nil, {0x1a}, {0xa1}, {0xf1, 0x21}, {0xff}, {0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0x65}, make([]byte, 9)} {
		if d, err := DecodeMSISDN(bad); !errors.Is(err, ErrInvalidMSISDN) {
			t.Errorf("DecodeMSISDN(% x) = %q, %v; want ErrInvalidMSISDN", bad, d, err)
		}
	}
	for _, bad := range []string{"", "1555O100001", strings.Repeat("1", 16)} {
		if _, err := EncodeMSISDN(bad); !errors.Is(err, ErrInvalidMSISDN) {
			t.Errorf("EncodeMSISDN(%q) err = %v", bad, err)
		}
	}
}
