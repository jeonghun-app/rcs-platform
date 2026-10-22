package cx

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

// marWith builds a MAR with the common AVPs and then avps, as an arbitrary
// S-CSCF might send it.
func marWith(avps ...*diameter.AVP) *diameter.Message {
	m := &diameter.Message{Flags: diameter.FlagRequest | diameter.FlagProxiable, Code: CodeMultimediaAuth, ApplicationID: ApplicationID}
	m.Add(
		specSessionID.UTF8String("scscf;1;1"),
		specOriginHost.UTF8String(scscfHost),
		specOriginRealm.UTF8String(realm),
		specDestinationRealm.UTF8String(realm),
	)
	m.Add(avps...)
	return m
}

func validMARBody() []*diameter.AVP {
	return []*diameter.AVP{
		specUserName.UTF8String(impi),
		specPublicIdentity.UTF8String(impu),
		specSIPAuthDataItem.Grouped(specSIPAuthenticationScheme.UTF8String(SchemeDigestAKAv1MD5)),
		specSIPNumberAuthItems.Unsigned32(1),
		specServerName.UTF8String(scscfName),
	}
}

// without returns body minus the AVPs with the given code.
func without(body []*diameter.AVP, code uint32) []*diameter.AVP {
	var out []*diameter.AVP
	for _, a := range body {
		if a.Code != code {
			out = append(out, a)
		}
	}
	return out
}

func TestMalformedRequestsAreRejectedWithTheResultCodeToAnswer(t *testing.T) {
	tests := map[string]struct {
		avps   []*diameter.AVP
		code   uint32
		failed uint32 // code of the Failed-AVP
	}{
		"missing User-Name": {
			avps: without(validMARBody(), diameter.AVPUserName),
			code: diameter.ResultMissingAVP, failed: diameter.AVPUserName,
		},
		"missing SIP-Auth-Data-Item": {
			avps: without(validMARBody(), AVPSIPAuthDataItem),
			code: diameter.ResultMissingAVP, failed: AVPSIPAuthDataItem,
		},
		"two Public-Identity AVPs": {
			avps: append(validMARBody(), specPublicIdentity.UTF8String(telURI)),
			code: diameter.ResultAVPOccursTooManyTimes, failed: AVPPublicIdentity,
		},
		"Public-Identity that is not UTF-8": {
			avps: append(without(validMARBody(), AVPPublicIdentity), avp(specPublicIdentity, []byte{0xff, 0xfe})),
			code: diameter.ResultInvalidAVPValue, failed: AVPPublicIdentity,
		},
		"empty User-Name": {
			avps: append(without(validMARBody(), diameter.AVPUserName), specUserName.UTF8String("")),
			code: diameter.ResultInvalidAVPValue, failed: diameter.AVPUserName,
		},
		"SIP-Number-Auth-Items of 0": {
			avps: append(without(validMARBody(), AVPSIPNumberAuthItems), specSIPNumberAuthItems.Unsigned32(0)),
			code: diameter.ResultInvalidAVPValue, failed: AVPSIPNumberAuthItems,
		},
		"SIP-Auth-Data-Item that is not a group": {
			avps: append(without(validMARBody(), AVPSIPAuthDataItem), avp(specSIPAuthDataItem, []byte{1, 2, 3})),
			code: diameter.ResultInvalidAVPLength, failed: AVPSIPAuthDataItem,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Skip the wire: the dictionary would reject some of these
			// before ParseMAR sees them, and ParseMAR must not rely on it.
			_, err := ParseMAR(marWith(tc.avps...))
			var derr *diameter.Error
			if !errors.As(err, &derr) {
				t.Fatalf("err = %v, want a *diameter.Error", err)
			}
			if derr.ResultCode != tc.code || derr.FailedAVP == nil || derr.FailedAVP.Code != tc.failed {
				t.Errorf("got %d with Failed-AVP %+v, want %d for AVP %d", derr.ResultCode, derr.FailedAVP, tc.code, tc.failed)
			}
			if derr.Message == "" || strings.Contains(derr.Message, impi) {
				t.Errorf("Error-Message %q must say what is wrong without quoting the message", derr.Message)
			}
		})
	}
}

func TestRepeatedAVPIsReportedWithItsSecondInstance(t *testing.T) {
	_, err := ParseMAR(marWith(append(validMARBody(), specPublicIdentity.UTF8String(telURI))...))
	var derr *diameter.Error
	if !errors.As(err, &derr) || string(derr.FailedAVP.Data) != telURI {
		t.Fatalf("err = %v, want Failed-AVP holding the second Public-Identity (RFC 6733 §7.5)", err)
	}
}

func TestWrongLengthOfAFixedSizeAVPIsAnInvalidLength(t *testing.T) {
	body := append(without(validMARBody(), AVPSIPNumberAuthItems), avp(specSIPNumberAuthItems, []byte{0, 1}))
	_, err := ParseMAR(marWith(body...))
	var derr *diameter.Error
	if !errors.As(err, &derr) || derr.ResultCode != diameter.ResultInvalidAVPLength {
		t.Fatalf("err = %v, want DIAMETER_INVALID_AVP_LENGTH", err)
	}
}

func TestDigestParametersMissingFromAnAnswerAreReportedInsideTheirGroups(t *testing.T) {
	item := specSIPAuthDataItem.Grouped(specSIPDigestAuthenticate.Grouped(
		specDigestRealm.UTF8String(realm), specDigestQoP.UTF8String("auth")))
	m := answerWith(specResultCode.Unsigned32(diameter.ResultSuccess), item)
	m.Code = CodeMultimediaAuth
	_, err := ParseMAA(m)
	var derr *diameter.Error
	if !errors.As(err, &derr) || derr.ResultCode != diameter.ResultMissingAVP {
		t.Fatalf("err = %v, want DIAMETER_MISSING_AVP", err)
	}
	digest := must(derr.FailedAVP.Grouped())
	if derr.FailedAVP.Code != AVPSIPAuthDataItem || len(digest) != 1 || digest[0].Code != AVPSIPDigestAuthenticate {
		t.Fatalf("Failed-AVP = %+v, want SIP-Auth-Data-Item > SIP-Digest-Authenticate > Digest-HA1", derr.FailedAVP)
	}
	if ha1 := must(digest[0].Grouped()); len(ha1) != 1 || ha1[0].Code != AVPDigestHA1 {
		t.Errorf("innermost Failed-AVP = %+v, want Digest-HA1", ha1)
	}
}

func TestParsersRefuseAMessageOfAnotherCommand(t *testing.T) {
	uar := transmit(t, must(sampleUAR().Message(newNode(t, icscfHost))))
	parsers := map[string]func(*diameter.Message) error{
		"UAA": func(m *diameter.Message) error { _, err := ParseUAA(m); return err },
		"SAR": func(m *diameter.Message) error { _, err := ParseSAR(m); return err },
		"SAA": func(m *diameter.Message) error { _, err := ParseSAA(m); return err },
		"LIR": func(m *diameter.Message) error { _, err := ParseLIR(m); return err },
		"LIA": func(m *diameter.Message) error { _, err := ParseLIA(m); return err },
		"MAR": func(m *diameter.Message) error { _, err := ParseMAR(m); return err },
		"MAA": func(m *diameter.Message) error { _, err := ParseMAA(m); return err },
		"RTR": func(m *diameter.Message) error { _, err := ParseRTR(m); return err },
		"RTA": func(m *diameter.Message) error { _, err := ParseRTA(m); return err },
		"PPR": func(m *diameter.Message) error { _, err := ParsePPR(m); return err },
		"PPA": func(m *diameter.Message) error { _, err := ParsePPA(m); return err },
	}
	for name, parse := range parsers {
		err := parse(uar)
		var derr *diameter.Error
		if err == nil || errors.As(err, &derr) {
			t.Errorf("Parse%s(UAR) = %v, want a plain error", name, err)
		}
	}
	other := *uar
	other.ApplicationID = 16777217
	if _, err := ParseUAR(&other); err == nil {
		t.Error("ParseUAR accepted a message of another application")
	}
}

func TestHSSInitiatedRequestsNeedADestinationHost(t *testing.T) {
	hss := newNode(t, hssHost)
	rtr := &RTR{Request: Request{DestinationRealm: realm}, UserName: impi}
	if _, err := rtr.Message(hss); err == nil {
		t.Error("RTR without Destination-Host built")
	}
	ppr := &PPR{Request: Request{DestinationRealm: realm}, UserName: impi}
	if _, err := ppr.Message(hss); err == nil {
		t.Error("PPR without Destination-Host built")
	}
	m := &diameter.Message{Flags: diameter.FlagRequest, Code: CodeRegistrationTermination, ApplicationID: ApplicationID}
	m.Add(specSessionID.UTF8String("hss;1;1"), specOriginHost.UTF8String(hssHost), specOriginRealm.UTF8String(realm),
		specDestinationRealm.UTF8String(realm), specUserName.UTF8String(impi),
		specDeregistrationReason.Grouped(specReasonCode.Enumerated(0)))
	_, err := ParseRTR(m)
	var derr *diameter.Error
	if !errors.As(err, &derr) || derr.ResultCode != diameter.ResultMissingAVP || derr.FailedAVP.Code != diameter.AVPDestinationHost {
		t.Errorf("ParseRTR without Destination-Host: %v", err)
	}
	m.Code = CodePushProfile
	if _, err := ParsePPR(m); !errors.As(err, &derr) || derr.FailedAVP.Code != diameter.AVPDestinationHost {
		t.Errorf("ParsePPR without Destination-Host: %v", err)
	}
}

func TestRequestsMissingARequiredFieldAreNotBuilt(t *testing.T) {
	n := newNode(t, scscfHost)
	r := request("")
	tests := map[string]func() (*diameter.Message, error){
		"UAR without User-Name": func() (*diameter.Message, error) {
			return (&UAR{Request: r, PublicIdentity: impu, VisitedNetworkIdentifier: []byte("v")}).Message(n)
		},
		"UAR without Public-Id": func() (*diameter.Message, error) {
			return (&UAR{Request: r, UserName: impi, VisitedNetworkIdentifier: []byte("v")}).Message(n)
		},
		"UAR without visited net": func() (*diameter.Message, error) {
			return (&UAR{Request: r, UserName: impi, PublicIdentity: impu}).Message(n)
		},
		"SAR without Server-Name": func() (*diameter.Message, error) { return (&SAR{Request: r, UserName: impi}).Message(n) },
		"LIR without Public-Id":   func() (*diameter.Message, error) { return (&LIR{Request: r}).Message(n) },
		"MAR without User-Name": func() (*diameter.Message, error) {
			return (&MAR{Request: r, PublicIdentity: impu, NumberAuthItems: 1, ServerName: scscfName}).Message(n)
		},
		"MAR without Public-Id": func() (*diameter.Message, error) {
			return (&MAR{Request: r, UserName: impi, NumberAuthItems: 1, ServerName: scscfName}).Message(n)
		},
		"MAR asking for no vectors": func() (*diameter.Message, error) {
			return (&MAR{Request: r, UserName: impi, PublicIdentity: impu, ServerName: scscfName}).Message(n)
		},
		"MAR without Server-Name": func() (*diameter.Message, error) {
			return (&MAR{Request: r, UserName: impi, PublicIdentity: impu, NumberAuthItems: 1}).Message(n)
		},
		"RTR without User-Name": func() (*diameter.Message, error) { return (&RTR{Request: r}).Message(n) },
		"PPR without User-Name": func() (*diameter.Message, error) { return (&PPR{Request: r}).Message(n) },
		"MAR with a digest without HA1": func() (*diameter.Message, error) {
			return (&MAR{Request: r, UserName: impi, PublicIdentity: impu, NumberAuthItems: 1, ServerName: scscfName,
				AuthDataItem: AuthDataItem{Digest: &DigestAuthenticate{Realm: realm, QoP: "auth"}}}).Message(n)
		},
		"PPR with a digest without realm": func() (*diameter.Message, error) {
			return (&PPR{Request: r, UserName: impi, AuthDataItem: &AuthDataItem{Digest: &DigestAuthenticate{QoP: "auth", HA1: secret.NewString("x")}}}).Message(n)
		},
		"PPR with a digest without QoP": func() (*diameter.Message, error) {
			return (&PPR{Request: r, UserName: impi, AuthDataItem: &AuthDataItem{Digest: &DigestAuthenticate{Realm: realm, HA1: secret.NewString("x")}}}).Message(n)
		},
		"PPR with a charging name that is not a URI": func() (*diameter.Message, error) {
			return (&PPR{Request: r, UserName: impi, ChargingInformation: &ChargingInformation{PrimaryEventChargingFunctionName: "ocs.example"}}).Message(n)
		},
	}
	for name, build := range tests {
		if _, err := build(); err == nil {
			t.Errorf("%s: built", name)
		}
	}
}

func TestAnswersWithInvalidNestedFieldsAreNotBuilt(t *testing.T) {
	hss := newNode(t, hssHost)
	req := transmit(t, must(sampleUAR().Message(newNode(t, icscfHost))))
	ok := Answer{Result: ResultCode(diameter.ResultSuccess)}
	if _, err := (&SAA{Answer: ok, ChargingInformation: &ChargingInformation{SecondaryChargingCollectionFunctionName: "cdf"}}).Message(hss, req); err == nil {
		t.Error("SAA with an invalid charging name built")
	}
	if _, err := (&MAA{Answer: ok, AuthDataItems: []AuthDataItem{{Digest: &DigestAuthenticate{}}}}).Message(hss, req); err == nil {
		t.Error("MAA with an empty digest built")
	}
}

func TestAuthenticationVectorsAreNotPrintedOrLogged(t *testing.T) {
	ha1 := "0123456789abcdef0123456789abcdef"
	item := AuthDataItem{
		ItemNumber: 1, Scheme: SchemeDigestAKAv1MD5,
		Authenticate: seq(32, 0x61), Authorization: secret.NewKey(seq(8, 0x61)),
		ConfidentialityKey: secret.NewKey(seq(16, 0x61)), IntegrityKey: secret.NewKey(seq(16, 0x61)),
		Digest: &DigestAuthenticate{Realm: realm, QoP: "auth", HA1: secret.NewString(ha1)},
	}
	maa := MAA{Answer: answer(ResultCode(diameter.ResultSuccess)), AuthDataItems: []AuthDataItem{item}}
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("x", "item", item, "digest", *item.Digest)
	outputs := map[string]string{
		"%v":     fmt.Sprintf("%v", item),
		"%+v":    fmt.Sprintf("%+v", item),
		"%#v":    fmt.Sprintf("%#v", item),
		"MAA %v": fmt.Sprintf("%+v", maa),
		"digest": fmt.Sprintf("%v %#v", *item.Digest, *item.Digest),
		"slog":   logged.String(),
	}
	for name, out := range outputs {
		// The test vectors are runs of ASCII letters starting at 'a', so a
		// leak shows up as "abcdefgh" in any rendering of the bytes.
		if strings.Contains(out, ha1) || strings.Contains(out, "abcdefgh") || strings.Contains(out, "97 98 99") {
			t.Errorf("%s leaks credentials: %s", name, out)
		}
	}
	if !strings.Contains(outputs["slog"], SchemeDigestAKAv1MD5) {
		t.Errorf("slog output lost the scheme: %s", outputs["slog"])
	}
}

// TestCredentialsInsideMessagesDoNotReachJSONLogs logs messages and items the
// way a service would, through the JSON handler internal/runtime uses, and
// as plain JSON. Neither the raw credentials nor their base64 form may appear;
// the messages' own log form leaves out the identities too.
func TestCredentialsInsideMessagesDoNotReachJSONLogs(t *testing.T) {
	ha1 := "0123456789abcdef0123456789abcdef"
	key := seq(16, 0x61)
	item := AuthDataItem{ItemNumber: 1, Scheme: SchemeDigestAKAv1MD5,
		Authenticate: seq(32, 0x41), Authorization: secret.NewKey(seq(8, 0x30)),
		ConfidentialityKey: secret.NewKey(key), IntegrityKey: secret.NewKey(key),
		Digest: &DigestAuthenticate{Realm: realm, QoP: "auth", HA1: secret.NewString(ha1), AlternateHA1: secret.NewString(ha1 + ha1)}}
	credentials := []string{ha1, "abcdefgh",
		base64.StdEncoding.EncodeToString(key)[:12],
		base64.StdEncoding.EncodeToString(seq(32, 0x41))[:12],
		base64.StdEncoding.EncodeToString(seq(8, 0x30))[:8]}
	jsonLog := func(v any) string {
		var b bytes.Buffer
		slog.New(slog.NewJSONHandler(&b, nil)).Info("x", "msg", v)
		return b.String()
	}
	maa := MAA{Answer: answer(ResultCode(diameter.ResultSuccess)), UserName: impi, PublicIdentity: impu, NumberAuthItems: 1, AuthDataItems: []AuthDataItem{item}}
	mar := MAR{Request: request("s"), UserName: impi, PublicIdentity: impu, AuthDataItem: item, NumberAuthItems: 1}
	ppr := PPR{Request: request("s"), UserName: impi, AuthDataItem: &item}
	messages := map[string]any{
		"*MAA": &maa, "MAA": maa,
		"*MAR": &mar, "MAR": mar,
		"*PPR": &ppr, "PPR": ppr,
	}
	others := map[string]any{
		"items":        []AuthDataItem{item},
		"item pointer": &item,
		"digest":       item.Digest,
		"in a struct":  struct{ Answer MAA }{MAA{AuthDataItems: []AuthDataItem{item}}},
	}
	for name, v := range messages {
		out := jsonLog(v)
		for _, id := range []string{impi, impu} {
			if strings.Contains(out, id) {
				t.Errorf("%s log line has an identity: %s", name, out)
			}
		}
		others[name] = v
	}
	// The log line still says what the answer carried.
	if out := jsonLog(maa); !strings.Contains(out, `"auth_data_items":{"1":{"item_number":1,"scheme":"Digest-AKAv1-MD5"`) {
		t.Errorf("MAA log line lost its items: %s", out)
	}
	for name, v := range others {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: json.Marshal: %v", name, err)
		}
		for _, out := range []string{jsonLog(v), string(raw)} {
			for _, c := range credentials {
				if strings.Contains(out, c) {
					t.Errorf("%s leaks %q: %s", name, c, out)
				}
			}
		}
	}
}

// An item's XRES, CK and IK and its digest's HA1s print as their
// placeholder under these verbs, valid ones and invalid ones such as %p, %w
// and %t, which call no method and print the fields, in an item, its
// pointer, a slice, a map, the answer that holds it and the digest itself:
// neither as text, nor in hex of either case, nor as %d writes bytes (#570,
// #594).
func TestTheKeysOfAnItemNeverPrint(t *testing.T) {
	xres, ck, ik := seq(8, 0xa0), seq(16, 0xb0), seq(16, 0xc0)
	ha1, alternate := "0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	digest := DigestAuthenticate{Realm: realm, Algorithm: "MD5", QoP: "auth", HA1: secret.NewString(ha1),
		AlternateAlgorithm: "SHA-256", AlternateHA1: secret.NewString(alternate)}
	item := AuthDataItem{ItemNumber: 1, Scheme: SchemeDigestAKAv1MD5, Authenticate: seq(32, 0x10),
		Authorization: secret.NewKey(xres), ConfidentialityKey: secret.NewKey(ck), IntegrityKey: secret.NewKey(ik),
		Digest: &digest}
	maa := MAA{Answer: answer(ResultCode(diameter.ResultSuccess)), AuthDataItems: []AuthDataItem{item}}
	var forms []string
	for _, k := range [][]byte{xres, ck, ik, []byte(ha1), []byte(alternate)} {
		forms = append(forms, fmt.Sprintf("%x", k[:6]), fmt.Sprintf("%X", k[:6]), strings.Trim(fmt.Sprint(k[:6]), "[]"), string(k[:6]))
	}
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%t", "%x", "%X", "%o", "%O", "%b", "%p", "%w", "%c", "%U", "%e", "%f", "%g"}
	for _, verb := range verbs {
		for _, v := range []any{item, &item, []AuthDataItem{item}, map[string]AuthDataItem{"k": item}, maa, &maa, digest, &digest} {
			out := fmt.Sprintf(verb, v)
			for _, form := range forms {
				if strings.Contains(out, form) {
					t.Errorf("%s printed a key as %q: %s", verb, form, out)
				}
			}
		}
	}
}
