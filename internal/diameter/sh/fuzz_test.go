package sh

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

// FuzzParseData checks that whatever ParseData accepts marshals, parses back
// to the same data and marshals to the same bytes.
func FuzzParseData(f *testing.F) {
	f.Add([]byte(userData))
	f.Add([]byte(`<Sh-Data><RepositoryData><ServiceIndication> x&#xD;</ServiceIndication><SequenceNumber>+1</SequenceNumber><ServiceData>a<![CDATA[<b>]]></ServiceData></RepositoryData></Sh-Data>`))
	f.Add([]byte(`<!DOCTYPE s [<!ENTITY a "b">]><Sh-Data/>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := ParseData(data)
		if err != nil {
			return
		}
		out, err := d.Marshal()
		if err != nil {
			t.Fatalf("parsed data does not marshal: %v\n%+v", err, d)
		}
		if len(out) > MaxDataSize {
			return // longer escapes can push a document past the limit
		}
		back, err := ParseData(out)
		if err != nil {
			t.Fatalf("marshalled document does not parse: %v\n%s", err, out)
		}
		if !reflect.DeepEqual(back, d) {
			t.Fatalf("round trip changed the data:\n%+v\n%+v", d, back)
		}
		if again, _ := back.Marshal(); !bytes.Equal(again, out) {
			t.Fatalf("second marshal differs:\n%s\n%s", out, again)
		}
	})
}

// FuzzDecodeMSISDN checks that every accepted TBCD string is the only
// encoding of its number.
func FuzzDecodeMSISDN(f *testing.F) {
	f.Add([]byte{0x51, 0x55, 0x10, 0x00, 0x00, 0xf1})
	f.Add([]byte{0x21})
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		digits, err := DecodeMSISDN(b)
		if err != nil {
			return
		}
		again, err := EncodeMSISDN(digits)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("DecodeMSISDN(% x) = %s, which encodes as % x (%v)", b, digits, again, err)
		}
	})
}

var parsers = map[uint32][2]func(*diameter.Message) (any, error){
	CodeUserData:               {wrap(ParseUDR), wrap(ParseUDA)},
	CodeProfileUpdate:          {wrap(ParsePUR), wrap(ParsePUA)},
	CodeSubscribeNotifications: {wrap(ParseSNR), wrap(ParseSNA)},
	CodePushNotification:       {wrap(ParsePNR), wrap(ParsePNA)},
}

func wrap[T any](parse func(*diameter.Message) (T, error)) func(*diameter.Message) (any, error) {
	return func(m *diameter.Message) (any, error) { return parse(m) }
}

type requestMessage interface {
	Message(*diameter.Node) (*diameter.Message, error)
}

type answerMessage interface {
	Message(*diameter.Node, *diameter.Message) (*diameter.Message, error)
}

// FuzzParseCommands runs the parser of each Sh command on arbitrary
// messages; what a parser accepts must build into a message that parses to
// the same struct.
func FuzzParseCommands(f *testing.F) {
	as, hss := newNode(f, asHost), newNode(f, hssHost)
	id := UserIdentity{PublicIdentity: impu}
	add := func(m *diameter.Message, err error) *diameter.Message {
		f.Add(must(must(m, err).Encode()))
		return m
	}
	udr := add((&UDR{Request: asRequest("a;1"), UserIdentity: UserIdentity{MSISDN: msisdn}, ServiceIndications: []string{"x"},
		DataReferences: []DataReference{RefRepositoryData}, IdentitySets: []IdentitySet{AliasIdentities}}).Message(as))
	add((&UDA{Answer: cx.Answer{Result: cx.ResultCode(diameter.ResultSuccess)}, UserData: []byte("<Sh-Data/>")}).Message(hss, udr))
	pur := add((&PUR{Request: asRequest("a;2"), UserIdentity: id, DataReferences: []DataReference{RefRepositoryData}, UserData: []byte("x")}).Message(as))
	ref := RefRepositoryData
	add((&PUA{Answer: cx.Answer{Result: cx.ExperimentalResult(PriorUpdateInProgress)}, DataReference: &ref,
		RepositoryDataID: &RepositoryDataID{ServiceIndication: "x", SequenceNumber: 2}}).Message(hss, pur))
	snr := add((&SNR{Request: asRequest("a;3"), UserIdentity: id, SendDataIndication: true, OneTimeNotification: true,
		DataReferences: []DataReference{RefUEReachabilityForIP}}).Message(as))
	add((&SNA{Answer: cx.Answer{Result: cx.ResultCode(diameter.ResultSuccess)}, ExpiryTime: fixedClock{}.Now()}).Message(hss, snr))
	pnr := add((&PNR{Request: cx.Request{DestinationHost: asHost, DestinationRealm: realm}, UserIdentity: id, UserData: []byte("x")}).Message(hss))
	add((&PNA{Answer: cx.Answer{Result: cx.ResultCode(diameter.ResultSuccess)}}).Message(as, pnr))
	dict := testDictionary(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := diameter.DecodeMessage(b, dict, diameter.Limits{MaxMessageSize: 8 << 10})
		if err != nil {
			return
		}
		pair, ok := parsers[m.Code]
		if !ok {
			return
		}
		_, _ = pair[0](m)
		_, _ = pair[1](m)
		m.ApplicationID = ApplicationID
		parse := pair[1]
		if m.IsRequest() {
			parse = pair[0]
		}
		got, err := parse(m)
		if err != nil {
			return
		}
		envelope := reflect.ValueOf(got).Elem().Field(0)
		n, err := diameter.NewNode(diameter.Config{
			OriginHost:   envelope.FieldByName("OriginHost").String(),
			OriginRealm:  envelope.FieldByName("OriginRealm").String(),
			Applications: []diameter.Application{Application},
		})
		if err != nil {
			t.Fatalf("parsed origin is not usable: %v", err)
		}
		var out *diameter.Message
		switch x := got.(type) {
		case requestMessage:
			out, err = x.Message(n)
		case answerMessage:
			if a := envelope.Interface().(cx.Answer); a.Result.Vendor == 0 && diameter.IsProtocolError(a.Result.Code) {
				return
			}
			req := &diameter.Message{Flags: diameter.FlagRequest, Code: m.Code, ApplicationID: ApplicationID,
				AVPs: []*diameter.AVP{m.Find(diameter.AVPSessionID, 0)}}
			out, err = x.Message(n, req)
		}
		if err != nil {
			t.Fatalf("parsed struct does not build: %v\n%+v", err, got)
		}
		again, err := parse(transmit(t, out))
		if err != nil {
			t.Fatalf("rebuilt message does not parse: %v", err)
		}
		if !reflect.DeepEqual(got, again) {
			t.Fatalf("rebuilt message parses differently:\n%+v\n%+v", got, again)
		}
	})
}
