package cx

import (
	"reflect"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
)

// requestMessage and answerMessage are what every typed request and answer
// can do.
type requestMessage interface {
	Message(*diameter.Node) (*diameter.Message, error)
}

type answerMessage interface {
	Message(*diameter.Node, *diameter.Message) (*diameter.Message, error)
}

// parsers maps each command and direction to its parse function.
var parsers = map[uint32][2]func(*diameter.Message) (any, error){
	CodeUserAuthorization:       {wrap(ParseUAR), wrap(ParseUAA)},
	CodeServerAssignment:        {wrap(ParseSAR), wrap(ParseSAA)},
	CodeLocationInfo:            {wrap(ParseLIR), wrap(ParseLIA)},
	CodeMultimediaAuth:          {wrap(ParseMAR), wrap(ParseMAA)},
	CodeRegistrationTermination: {wrap(ParseRTR), wrap(ParseRTA)},
	CodePushProfile:             {wrap(ParsePPR), wrap(ParsePPA)},
}

func wrap[T any](parse func(*diameter.Message) (T, error)) func(*diameter.Message) (any, error) {
	return func(m *diameter.Message) (any, error) { return parse(m) }
}

func fuzzSeeds(tb testing.TB) [][]byte {
	scscf, hss := newNode(tb, scscfHost), newNode(tb, hssHost)
	var seeds [][]byte
	add := func(m *diameter.Message, err error) {
		b := must(must(m, err).Encode())
		seeds = append(seeds, b)
	}
	uar := must(sampleUAR().Message(scscf))
	add(uar, nil)
	add((&UAA{Answer: answer(ExperimentalResult(FirstRegistration)), ServerCapabilities: &ServerCapabilities{Mandatory: []uint32{1}, ServerNames: []string{scscfName}}}).Message(hss, uar))
	sar := must((&SAR{Request: request("s;1;1"), UserName: impi, PublicIdentities: []string{impu}, ServerName: scscfName, AssignmentType: Registration}).Message(scscf))
	add(sar, nil)
	add((&SAA{Answer: answer(ResultCode(diameter.ResultSuccess)), UserData: []byte("<IMSSubscription/>"), AssociatedIdentities: []string{impi},
		ChargingInformation: &ChargingInformation{PrimaryEventChargingFunctionName: "aaa://ocs.test"}}).Message(hss, sar))
	lir := must((&LIR{Request: request("s;1;2"), PublicIdentity: telURI, OriginatingRequest: true}).Message(scscf))
	add(lir, nil)
	add((&LIA{Answer: answer(ExperimentalResult(ErrorIdentityNotRegistered)), ServerName: scscfName}).Message(hss, lir))
	mar := must((&MAR{Request: request("s;1;3"), UserName: impi, PublicIdentity: impu, NumberAuthItems: 1, ServerName: scscfName,
		AuthDataItem: AuthDataItem{Scheme: SchemeSIPDigest}}).Message(scscf))
	add(mar, nil)
	add((&MAA{Answer: answer(ResultCode(diameter.ResultSuccess)), NumberAuthItems: 2, AuthDataItems: []AuthDataItem{
		{ItemNumber: 1, Scheme: SchemeDigestAKAv1MD5, Authenticate: seq(32, 0), Authorization: seq(8, 0), ConfidentialityKey: seq(16, 0), IntegrityKey: seq(16, 0)},
		{ItemNumber: 2, Scheme: SchemeSIPDigest, Digest: &DigestAuthenticate{Realm: realm, Algorithm: "MD5", QoP: "auth", HA1: "00"}},
	}}).Message(hss, mar))
	rtr := must((&RTR{Request: Request{DestinationHost: scscfHost, DestinationRealm: realm}, UserName: impi, PublicIdentities: []string{impu},
		DeregistrationReason: DeregistrationReason{Code: ServerChange, Info: "moved"}}).Message(hss))
	add(rtr, nil)
	add((&RTA{Answer: answer(ResultCode(diameter.ResultSuccess)), AssociatedIdentities: []string{}}).Message(scscf, rtr))
	ppr := must((&PPR{Request: Request{DestinationHost: scscfHost, DestinationRealm: realm}, UserName: impi, UserData: []byte("x"),
		AuthDataItem: &AuthDataItem{Digest: &DigestAuthenticate{Realm: realm, QoP: "auth", HA1: "00"}}}).Message(hss))
	add(ppr, nil)
	add((&PPA{Answer: answer(ExperimentalResult(ErrorNotSupportedUserData))}).Message(scscf, ppr))
	return seeds
}

// FuzzParseCommands decodes arbitrary messages and runs the parser of their
// command on them. No input may make a parser panic, a fault must come with
// a Failed-AVP the node can encode into its answer, and whatever a parser
// accepts must build again into a message that parses to the same struct.
func FuzzParseCommands(f *testing.F) {
	for _, s := range fuzzSeeds(f) {
		f.Add(s)
	}
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
		// Run both directions: a parser must also cope with the wrong one.
		_, _ = pair[0](m)
		_, _ = pair[1](m)
		m.ApplicationID = ApplicationID
		parse := pair[1]
		if m.IsRequest() {
			parse = pair[0]
		}
		got, err := parse(m)
		if err != nil {
			if derr, ok := err.(*diameter.Error); ok && derr.FailedAVP != nil {
				failed := &diameter.Message{AVPs: []*diameter.AVP{diameter.NewGrouped(diameter.AVPFailedAVP, diameter.FlagMandatory, 0, derr.FailedAVP)}}
				if _, err := failed.Encode(); err != nil {
					t.Fatalf("Failed-AVP of %v cannot be encoded: %v", derr, err)
				}
			}
			return
		}
		rebuilt, again := rebuild(t, m, got, parse)
		if rebuilt == nil {
			return
		}
		if !reflect.DeepEqual(got, again) {
			t.Fatalf("rebuilt message parses differently:\n%+v\n%+v", got, again)
		}
	})
}

// rebuild builds the parsed struct v into a message again, from a node with
// the origin v names, and parses the result.
func rebuild(t *testing.T, m *diameter.Message, v any, parse func(*diameter.Message) (any, error)) (*diameter.Message, any) {
	envelope := reflect.ValueOf(v).Elem().Field(0)
	host, realm := envelope.FieldByName("OriginHost").String(), envelope.FieldByName("OriginRealm").String()
	n, err := diameter.NewNode(diameter.Config{OriginHost: host, OriginRealm: realm, Applications: []diameter.Application{Application}})
	if err != nil {
		t.Fatalf("parsed origin %q/%q is not usable: %v", host, realm, err)
	}
	var out *diameter.Message
	switch x := v.(type) {
	case requestMessage:
		out, err = x.Message(n)
	case answerMessage:
		if a := envelope.Interface().(Answer); a.Result.Vendor == 0 && diameter.IsProtocolError(a.Result.Code) {
			return nil, nil // answered by the node, not built by this package
		}
		req := &diameter.Message{Flags: diameter.FlagRequest, Code: m.Code, ApplicationID: m.ApplicationID,
			AVPs: []*diameter.AVP{m.Find(diameter.AVPSessionID, 0)}}
		out, err = x.Message(n, req)
	}
	if err != nil {
		t.Fatalf("parsed struct does not build: %v\n%+v", err, v)
	}
	again, err := parse(transmit(t, out))
	if err != nil {
		t.Fatalf("rebuilt message does not parse: %v", err)
	}
	return out, again
}
