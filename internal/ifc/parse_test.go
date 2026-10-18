package ifc

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Test identities use the reserved test network (MCC 001, MNC 01) and the
// fictional +1 555 01xx numbers on .github/allowed-test-identifiers.txt.
const (
	domain = "ims.mnc001.mcc001.3gppnetwork.org"
	impi   = "001010000000001@" + domain
	impu   = "sip:+15550100001@" + domain
	tel    = "tel:+15550100001"
	rcsAS  = "sip:rcs-as." + domain + ";lr"
	chatAS = "sip:chatbot-as." + domain
)

// fullDocument uses every element the package models. It is laid out the way
// HSSs commonly indent, with white space around the identity values.
const fullDocument = `<?xml version="1.0" encoding="UTF-8"?>
<IMSSubscription xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="CxDataType.xsd">
  <PrivateID>` + impi + `</PrivateID>
  <ServiceProfile>
    <PublicIdentity>
      <Identity>
        ` + impu + `
      </Identity>
      <Extension>
        <IdentityType>0</IdentityType>
        <Extension>
          <DisplayName>Alice</DisplayName>
          <AliasIdentityGroupID>alias-1</AliasIdentityGroupID>
        </Extension>
      </Extension>
    </PublicIdentity>
    <PublicIdentity>
      <BarringIndication>true</BarringIndication>
      <Identity>` + tel + `</Identity>
    </PublicIdentity>
    <CoreNetworkServicesAuthorization>
      <SubscribedMediaProfileId>0</SubscribedMediaProfileId>
    </CoreNetworkServicesAuthorization>
    <InitialFilterCriteria>
      <Priority>10</Priority>
      <TriggerPoint>
        <ConditionTypeCNF>1</ConditionTypeCNF>
        <SPT>
          <Group>0</Group>
          <Method>MESSAGE</Method>
        </SPT>
        <SPT>
          <Group>0</Group>
          <Method>INVITE</Method>
        </SPT>
        <SPT>
          <ConditionNegated>0</ConditionNegated>
          <Group>1</Group>
          <SIPHeader>
            <Header>Accept-Contact</Header>
            <Content>3gpp-service\.ims\.icsi\.oma\.cpm</Content>
          </SIPHeader>
        </SPT>
        <SPT>
          <ConditionNegated>1</ConditionNegated>
          <Group>2</Group>
          <SessionCase>2</SessionCase>
        </SPT>
      </TriggerPoint>
      <ApplicationServer>
        <ServerName>` + rcsAS + `</ServerName>
        <DefaultHandling index="0">1</DefaultHandling>
        <ServiceInfo> chat </ServiceInfo>
      </ApplicationServer>
      <ProfilePartIndicator>0</ProfilePartIndicator>
    </InitialFilterCriteria>
    <InitialFilterCriteria>
      <Priority>20</Priority>
      <TriggerPoint>
        <ConditionTypeCNF>false</ConditionTypeCNF>
        <SPT>
          <Group>0</Group>
          <Group>1</Group>
          <Method>REGISTER</Method>
          <Extension>
            <RegistrationType>0</RegistrationType>
            <RegistrationType>2</RegistrationType>
          </Extension>
        </SPT>
        <SPT>
          <Group>1</Group>
          <RequestURI>^chatbot\.</RequestURI>
        </SPT>
        <SPT>
          <Group>2</Group>
          <SessionDescription>
            <Line>m</Line>
            <Content>^message .* TCP/MSRP</Content>
          </SessionDescription>
        </SPT>
        <SPT>
          <Group>3</Group>
          <SIPHeader>
            <Header>Contact</Header>
          </SIPHeader>
        </SPT>
      </TriggerPoint>
      <ApplicationServer>
        <ServerName>` + chatAS + `</ServerName>
        <Extension>
          <IncludeRegisterRequest/>
          <IncludeRegisterResponse></IncludeRegisterResponse>
        </Extension>
      </ApplicationServer>
    </InitialFilterCriteria>
    <InitialFilterCriteria>
      <Priority>30</Priority>
      <ApplicationServer>
        <ServerName>` + rcsAS + `</ServerName>
      </ApplicationServer>
      <ProfilePartIndicator>1</ProfilePartIndicator>
    </InitialFilterCriteria>
    <Extension>
      <SharedIFCSetID>3</SharedIFCSetID>
      <SharedIFCSetID>7</SharedIFCSetID>
    </Extension>
  </ServiceProfile>
  <ServiceProfile>
    <PublicIdentity>
      <Identity>sip:chatbot!.*!@` + domain + `</Identity>
      <Extension>
        <IdentityType>2</IdentityType>
        <WildcardedPSI>sip:chatbot!.*!@` + domain + `</WildcardedPSI>
        <Extension>
          <Extension>
            <WildcardedIMPU>sip:bot!.*!@` + domain + `</WildcardedIMPU>
          </Extension>
        </Extension>
      </Extension>
    </PublicIdentity>
  </ServiceProfile>
</IMSSubscription>
`

func intp(n int) *int { return &n }

func regtype(t RegistrationType) *RegistrationType { return &t }

var fullSubscription = &Subscription{
	PrivateID: impi,
	ServiceProfiles: []ServiceProfile{
		{
			PublicIdentities: []PublicIdentity{
				{Identity: impu, IdentityType: IdentityPublicUser, DisplayName: "Alice", AliasIdentityGroupID: "alias-1"},
				{Identity: tel, BarringIndication: true},
			},
			CoreNetworkServicesAuthorization: &CoreNetworkServicesAuthorization{SubscribedMediaProfileID: intp(0)},
			InitialFilterCriteria: []FilterCriteria{
				{
					Priority: 10,
					TriggerPoint: &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{
						{Groups: []int{0}, Condition: Method("MESSAGE")},
						{Groups: []int{0}, Condition: Method("INVITE")},
						{Groups: []int{1}, Condition: SIPHeader{Header: "Accept-Contact", Content: `3gpp-service\.ims\.icsi\.oma\.cpm`}},
						{ConditionNegated: true, Groups: []int{2}, Condition: TerminatingUnregistered},
					}},
					ApplicationServer: ApplicationServer{ServerName: rcsAS, DefaultHandling: SessionTerminated, ServiceInfo: " chat "},
					ProfilePart:       ProfilePartRegistered,
				},
				{
					Priority: 20,
					TriggerPoint: &TriggerPoint{SPTs: []SPT{
						{Groups: []int{0, 1}, Condition: Method("REGISTER"), RegistrationTypes: []RegistrationType{InitialRegistration, DeRegistration}},
						{Groups: []int{1}, Condition: RequestURI(`^chatbot\.`)},
						{Groups: []int{2}, Condition: SessionDescription{Line: "m", Content: "^message .* TCP/MSRP"}},
						{Groups: []int{3}, Condition: SIPHeader{Header: "Contact"}},
					}},
					ApplicationServer: ApplicationServer{ServerName: chatAS, IncludeRegisterRequest: true, IncludeRegisterResponse: true},
				},
				{
					Priority:          30,
					ApplicationServer: ApplicationServer{ServerName: rcsAS},
					ProfilePart:       ProfilePartUnregistered,
				},
			},
			SharedIFCSetIDs: []int{3, 7},
		},
		{
			PublicIdentities: []PublicIdentity{{
				Identity:       "sip:chatbot!.*!@" + domain,
				IdentityType:   IdentityWildcardedPSI,
				WildcardedPSI:  "sip:chatbot!.*!@" + domain,
				WildcardedIMPU: "sip:bot!.*!@" + domain,
			}},
		},
	},
}

func mustParse(t *testing.T, doc string) *Subscription {
	t.Helper()
	s, err := ParseSubscription([]byte(doc))
	if err != nil {
		t.Fatalf("ParseSubscription: %v", err)
	}
	return s
}

func TestEveryModelledElementIsParsed(t *testing.T) {
	if got := mustParse(t, fullDocument); !reflect.DeepEqual(got, fullSubscription) {
		t.Errorf("parsed:\n%+v\nwant:\n%+v", got, fullSubscription)
	}
}

func TestMarshalledSubscriptionParsesBackUnchanged(t *testing.T) {
	out, err := fullSubscription.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out), `<?xml version="1.0" encoding="UTF-8"?>`) {
		t.Errorf("no XML declaration: %.60s", out)
	}
	if got := mustParse(t, string(out)); !reflect.DeepEqual(got, fullSubscription) {
		t.Errorf("round trip:\n%+v\nwant:\n%+v", got, fullSubscription)
	}
}

func TestMarshalWritesElementsInSchemaOrder(t *testing.T) {
	out := string(mustMarshal(t, fullSubscription))
	for _, seq := range [][]string{
		{"<PrivateID>", "<ServiceProfile>"},
		{"<BarringIndication>1</BarringIndication>", "<Identity>tel:"},
		{"<PublicIdentity>", "<CoreNetworkServicesAuthorization>", "<InitialFilterCriteria>", "<SharedIFCSetID>"},
		{"<Priority>10</Priority>", "<TriggerPoint>", "<ApplicationServer>", "<ProfilePartIndicator>0</ProfilePartIndicator>"},
		{"<ConditionNegated>1</ConditionNegated>", "<Group>2</Group>", "<SessionCase>2</SessionCase>"},
		{"<ServerName>", "<DefaultHandling>1</DefaultHandling>", "<ServiceInfo>"},
		{"<IdentityType>2</IdentityType>", "<WildcardedPSI>", "<WildcardedIMPU>"},
	} {
		last := -1
		for _, s := range seq {
			i := strings.Index(out, s)
			if i <= last {
				t.Errorf("%q is not after %q in\n%s", s, seq, out)
				break
			}
			last = i
		}
	}
	if strings.Contains(out, "<BarringIndication>0") || strings.Contains(out, "<IdentityType>0") {
		t.Errorf("default values were written:\n%s", out)
	}
}

func mustMarshal(t *testing.T, s *Subscription) []byte {
	t.Helper()
	out, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestWhiteSpaceIsCollapsedOnlyWhereTheSchemaTypeCollapsesIt(t *testing.T) {
	s := mustParse(t, doc(`<InitialFilterCriteria><Priority> 5 </Priority><TriggerPoint><ConditionTypeCNF>
		1 </ConditionTypeCNF><SPT><Group> 0</Group><Method> INVITE</Method></SPT></TriggerPoint>
		<ApplicationServer><ServerName> `+rcsAS+` </ServerName></ApplicationServer></InitialFilterCriteria>`))
	fc := s.ServiceProfiles[0].InitialFilterCriteria[0]
	if fc.Priority != 5 || !fc.TriggerPoint.ConditionTypeCNF || fc.ApplicationServer.ServerName != rcsAS {
		t.Errorf("collapsed values = %+v", fc)
	}
	// Method is an xs:string: its white space is the HSS's and stays.
	if m := fc.TriggerPoint.SPTs[0].Condition; m != Method(" INVITE") {
		t.Errorf("Method = %q, want it unchanged", m)
	}
}

// doc wraps criteria in the smallest valid subscription.
func doc(criteria string) string {
	return `<IMSSubscription><PrivateID>` + impi + `</PrivateID><ServiceProfile><PublicIdentity><Identity>` +
		impu + `</Identity></PublicIdentity>` + criteria + `</ServiceProfile></IMSSubscription>`
}

func TestElementsOutsideTheModelledSubsetAreSkipped(t *testing.T) {
	s := mustParse(t, "\xef\xbb\xbf"+`<IMSSubscription><PrivateID>`+impi+`</PrivateID>
		<ServiceProfile><PublicIdentity><Identity>`+impu+`</Identity>
		<Extension><Extension><Extension><ServiceLevelTraceInfo>x</ServiceLevelTraceInfo>
		<Extension><ExtendedPriority><PriorityNamespace>wps</PriorityNamespace></ExtendedPriority></Extension>
		</Extension></Extension></Extension></PublicIdentity></ServiceProfile>
		<Extension><IMSI>001010000000001</IMSI><Extension><ReferenceLocationInformation/></Extension></Extension>
		</IMSSubscription>`)
	want := &Subscription{PrivateID: impi, ServiceProfiles: []ServiceProfile{{PublicIdentities: []PublicIdentity{{Identity: impu}}}}}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("got %+v", s)
	}
}

func TestDocumentTypeDeclarationsAreRejected(t *testing.T) {
	for name, d := range map[string]string{
		"plain DOCTYPE":    `<!DOCTYPE IMSSubscription>` + doc(""),
		"external entity":  `<!DOCTYPE s [<!ENTITY x SYSTEM "file:///etc/passwd">]>` + strings.Replace(doc(""), impi, "&x;", 1),
		"entity expansion": `<!DOCTYPE s [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]>` + strings.Replace(doc(""), impi, "&b;", 1),
		"after a comment":  `<!-- HSS --><!DOCTYPE IMSSubscription SYSTEM "CxDataType.dtd">` + doc(""),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSubscription([]byte(d)); !errors.Is(err, ErrDTD) {
				t.Errorf("err = %v, want ErrDTD", err)
			}
		})
	}
}

func TestDocumentsOverTheSizeLimitAreRejectedUnread(t *testing.T) {
	big := doc(strings.Repeat(" ", MaxDocumentSize))
	if _, err := ParseSubscription([]byte(big)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("err = %v, want ErrTooLarge", err)
	}
}

// TestAMaximumSizeDocumentParses fills the limit with filter criteria, the
// most expensive content to convert, to show the parser copes with the
// largest document it accepts.
func TestAMaximumSizeDocumentParses(t *testing.T) {
	var b strings.Builder
	for i := 0; ; i++ {
		fc := `<InitialFilterCriteria><Priority>` + strconv.Itoa(i) + `</Priority><TriggerPoint><ConditionTypeCNF>1</ConditionTypeCNF>` +
			`<SPT><Group>0</Group><Group>1</Group><SIPHeader><Header>a</Header><Content>b</Content></SIPHeader></SPT></TriggerPoint>` +
			`<ApplicationServer><ServerName>sip:a</ServerName></ApplicationServer></InitialFilterCriteria>`
		if len(doc(b.String()+fc)) > MaxDocumentSize {
			break
		}
		b.WriteString(fc)
	}
	s := mustParse(t, doc(b.String()))
	if n := len(s.ServiceProfiles[0].InitialFilterCriteria); n < 400 {
		t.Fatalf("only %d criteria", n)
	}
	if _, err := Compile(s.ServiceProfiles[0].InitialFilterCriteria); err != nil {
		t.Fatal(err)
	}
}

func TestMalformedDocumentsAreRejected(t *testing.T) {
	const as = `<ApplicationServer><ServerName>sip:as</ServerName></ApplicationServer>`
	ifcWith := func(inner string) string {
		return doc(`<InitialFilterCriteria><Priority>1</Priority>` + inner + `</InitialFilterCriteria>`)
	}
	trigger := func(spts string) string {
		return ifcWith(`<TriggerPoint><ConditionTypeCNF>1</ConditionTypeCNF>` + spts + `</TriggerPoint>` + as)
	}
	tests := map[string]string{
		"not XML":                       "subscription",
		"empty":                         "",
		"wrong root":                    `<Sh-Data/>`,
		"two roots":                     doc("") + doc(""),
		"text outside the root":         doc("") + "x",
		"undefined entity":              strings.Replace(doc(""), impi, "&x;", 1),
		"repeated attribute":            `<IMSSubscription a="1" a="2"/>`,
		"nested too deep":               doc(strings.Repeat("<x>", maxDepth) + strings.Repeat("</x>", maxDepth)),
		"no PrivateID":                  `<IMSSubscription><ServiceProfile><PublicIdentity><Identity>` + impu + `</Identity></PublicIdentity></ServiceProfile></IMSSubscription>`,
		"two PrivateIDs":                strings.Replace(doc(""), "<ServiceProfile>", "<PrivateID>"+impi+"</PrivateID><ServiceProfile>", 1),
		"empty PrivateID":               strings.Replace(doc(""), impi, "  ", 1),
		"no ServiceProfile":             `<IMSSubscription><PrivateID>` + impi + `</PrivateID></IMSSubscription>`,
		"no PublicIdentity":             `<IMSSubscription><PrivateID>` + impi + `</PrivateID><ServiceProfile/></IMSSubscription>`,
		"PublicIdentity without one":    `<IMSSubscription><PrivateID>` + impi + `</PrivateID><ServiceProfile><PublicIdentity/></ServiceProfile></IMSSubscription>`,
		"two Identity elements":         strings.Replace(doc(""), "</PublicIdentity>", "<Identity>"+tel+"</Identity></PublicIdentity>", 1),
		"BarringIndication yes":         strings.Replace(doc(""), "<Identity>", "<BarringIndication>yes</BarringIndication><Identity>", 1),
		"IdentityType 5":                strings.Replace(doc(""), "</PublicIdentity>", "<Extension><IdentityType>5</IdentityType></Extension></PublicIdentity>", 1),
		"two PublicIdentity extensions": strings.Replace(doc(""), "</PublicIdentity>", "<Extension/><Extension/></PublicIdentity>", 1),
		"two CNSA":                      doc(`<CoreNetworkServicesAuthorization/><CoreNetworkServicesAuthorization/>`),
		"negative media profile":        doc(`<CoreNetworkServicesAuthorization><SubscribedMediaProfileId>-1</SubscribedMediaProfileId></CoreNetworkServicesAuthorization>`),
		"negative shared iFC set":       doc(`<Extension><SharedIFCSetID>-3</SharedIFCSetID></Extension>`),
		"no Priority":                   doc(`<InitialFilterCriteria>` + as + `</InitialFilterCriteria>`),
		"negative Priority":             doc(`<InitialFilterCriteria><Priority>-1</Priority>` + as + `</InitialFilterCriteria>`),
		"Priority beyond int":           doc(`<InitialFilterCriteria><Priority>99999999999999999999</Priority>` + as + `</InitialFilterCriteria>`),
		"Priority not a number":         doc(`<InitialFilterCriteria><Priority>first</Priority>` + as + `</InitialFilterCriteria>`),
		"no ApplicationServer":          ifcWith(""),
		"two ApplicationServers":        ifcWith(as + as),
		"no ServerName":                 ifcWith(`<ApplicationServer/>`),
		"DefaultHandling 2":             ifcWith(`<ApplicationServer><ServerName>sip:as</ServerName><DefaultHandling>2</DefaultHandling></ApplicationServer>`),
		"two IncludeRegisterRequest":    ifcWith(`<ApplicationServer><ServerName>sip:as</ServerName><Extension><IncludeRegisterRequest/><IncludeRegisterRequest/></Extension></ApplicationServer>`),
		"ProfilePartIndicator 2":        ifcWith(as + `<ProfilePartIndicator>2</ProfilePartIndicator>`),
		"two TriggerPoints":             ifcWith(`<TriggerPoint><ConditionTypeCNF>1</ConditionTypeCNF><SPT><Group>0</Group><Method>A</Method></SPT></TriggerPoint><TriggerPoint/>` + as),
		"TriggerPoint without SPT":      trigger(""),
		"TriggerPoint without CNF flag": ifcWith(`<TriggerPoint><SPT><Group>0</Group><Method>A</Method></SPT></TriggerPoint>` + as),
		"SPT without Group":             trigger(`<SPT><Method>INVITE</Method></SPT>`),
		"SPT with a negative Group":     trigger(`<SPT><Group>-1</Group><Method>INVITE</Method></SPT>`),
		"SPT without condition":         trigger(`<SPT><Group>0</Group></SPT>`),
		"SPT with two conditions":       trigger(`<SPT><Group>0</Group><Method>INVITE</Method><RequestURI>x</RequestURI></SPT>`),
		"SessionCase 5":                 trigger(`<SPT><Group>0</Group><SessionCase>5</SessionCase></SPT>`),
		"SIPHeader without Header":      trigger(`<SPT><Group>0</Group><SIPHeader><Content>x</Content></SIPHeader></SPT>`),
		"SIPHeader with two Contents":   trigger(`<SPT><Group>0</Group><SIPHeader><Header>a</Header><Content>x</Content><Content>y</Content></SIPHeader></SPT>`),
		"SessionDescription no Line":    trigger(`<SPT><Group>0</Group><SessionDescription><Content>x</Content></SessionDescription></SPT>`),
		"RegistrationType 3":            trigger(`<SPT><Group>0</Group><Method>REGISTER</Method><Extension><RegistrationType>3</RegistrationType></Extension></SPT>`),
		"ConditionNegated maybe":        trigger(`<SPT><ConditionNegated>maybe</ConditionNegated><Group>0</Group><Method>A</Method></SPT>`),
	}
	for name, d := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseSubscription([]byte(d))
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
			if strings.Contains(err.Error(), "15550100001") || strings.Contains(err.Error(), "001010000000001") {
				t.Errorf("error quotes the document: %v", err)
			}
		})
	}
}

func TestMarshalRefusesWhatTheParserWouldRefuse(t *testing.T) {
	valid := func() *Subscription {
		return &Subscription{PrivateID: impi, ServiceProfiles: []ServiceProfile{{
			PublicIdentities: []PublicIdentity{{Identity: impu}},
			InitialFilterCriteria: []FilterCriteria{{
				Priority:          1,
				TriggerPoint:      &TriggerPoint{SPTs: []SPT{{Groups: []int{0}, Condition: Method("MESSAGE")}}},
				ApplicationServer: ApplicationServer{ServerName: rcsAS},
			}},
		}}}
	}
	if _, err := valid().Marshal(); err != nil {
		t.Fatalf("valid subscription refused: %v", err)
	}
	fc := func(s *Subscription) *FilterCriteria { return &s.ServiceProfiles[0].InitialFilterCriteria[0] }
	spt := func(s *Subscription) *SPT { return &fc(s).TriggerPoint.SPTs[0] }
	for name, edit := range map[string]func(*Subscription){
		"no PrivateID":          func(s *Subscription) { s.PrivateID = "" },
		"PrivateID with spaces": func(s *Subscription) { s.PrivateID = " " + impi },
		"no ServiceProfile":     func(s *Subscription) { s.ServiceProfiles = nil },
		"no PublicIdentity":     func(s *Subscription) { s.ServiceProfiles[0].PublicIdentities = nil },
		"control character":     func(s *Subscription) { s.ServiceProfiles[0].PublicIdentities[0].DisplayName = "A\x00" },
		"invalid UTF-8":         func(s *Subscription) { spt(s).Condition = Method("\xff") },
		"IdentityType 9":        func(s *Subscription) { s.ServiceProfiles[0].PublicIdentities[0].IdentityType = 9 },
		"negative media profile": func(s *Subscription) {
			s.ServiceProfiles[0].CoreNetworkServicesAuthorization = &CoreNetworkServicesAuthorization{intp(-1)}
		},
		"negative shared set":      func(s *Subscription) { s.ServiceProfiles[0].SharedIFCSetIDs = []int{-1} },
		"negative priority":        func(s *Subscription) { fc(s).Priority = -1 },
		"ProfilePart 7":            func(s *Subscription) { fc(s).ProfilePart = 7 },
		"no ServerName":            func(s *Subscription) { fc(s).ApplicationServer.ServerName = "" },
		"DefaultHandling 3":        func(s *Subscription) { fc(s).ApplicationServer.DefaultHandling = 3 },
		"empty trigger point":      func(s *Subscription) { fc(s).TriggerPoint.SPTs = nil },
		"SPT without group":        func(s *Subscription) { spt(s).Groups = nil },
		"SPT with negative group":  func(s *Subscription) { spt(s).Groups = []int{-2} },
		"SPT without condition":    func(s *Subscription) { spt(s).Condition = nil },
		"SessionCase 9":            func(s *Subscription) { spt(s).Condition = SessionCase(9) },
		"RegistrationType 4":       func(s *Subscription) { spt(s).RegistrationTypes = []RegistrationType{4} },
		"header with a NUL":        func(s *Subscription) { spt(s).Condition = SIPHeader{Header: "a\x00"} },
		"SDP content with a NUL":   func(s *Subscription) { spt(s).Condition = SessionDescription{Line: "m", Content: "\x00"} },
		"RequestURI with a NUL":    func(s *Subscription) { spt(s).Condition = RequestURI("\x00") },
		"ServiceInfo with a NUL":   func(s *Subscription) { fc(s).ApplicationServer.ServiceInfo = "\x00" },
		"WildcardedPSI with space": func(s *Subscription) { s.ServiceProfiles[0].PublicIdentities[0].WildcardedPSI = "a b " },
	} {
		t.Run(name, func(t *testing.T) {
			s := valid()
			edit(s)
			if _, err := s.Marshal(); !errors.Is(err, ErrMalformed) {
				t.Errorf("err = %v, want ErrMalformed", err)
			}
		})
	}
}
