package sh

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// chatSettings is the kind of service data rcs-as keeps: its own namespace
// and markup, which the HSS stores without reading.
const chatSettings = `<rcs:settings xmlns:rcs="urn:example:rcs-as"><rcs:store-and-forward days="7"/>a &amp; b</rcs:settings>`

const userData = `<?xml version="1.0" encoding="UTF-8"?>
<Sh-Data>
  <PublicIdentifiers>
    <IMSPublicIdentity> ` + impu + ` </IMSPublicIdentity>
    <IMSPublicIdentity>tel:+15550100001</IMSPublicIdentity>
    <MSISDN>15550100001</MSISDN>
    <Extension><IdentityType>0</IdentityType></Extension>
  </PublicIdentifiers>
  <RepositoryData>
    <ServiceIndication>rcs-chat</ServiceIndication>
    <SequenceNumber>41</SequenceNumber>
    <ServiceData>` + chatSettings + `</ServiceData>
  </RepositoryData>
  <RepositoryData>
    <ServiceIndication>rcs-ft</ServiceIndication>
    <SequenceNumber>65535</SequenceNumber>
    <ServiceData/>
  </RepositoryData>
  <RepositoryData>
    <ServiceIndication>rcs-bot</ServiceIndication>
    <SequenceNumber>0</SequenceNumber>
  </RepositoryData>
  <Sh-IMS-Data><IMSUserState>1</IMSUserState></Sh-IMS-Data>
</Sh-Data>
`

var parsedUserData = &Data{
	PublicIdentifiers: &PublicIdentifiers{
		IMSPublicIdentities: []string{impu, "tel:+15550100001"},
		MSISDNs:             []string{msisdn},
	},
	RepositoryData: []RepositoryData{
		{ServiceIndication: "rcs-chat", SequenceNumber: 41, ServiceData: &ServiceData{InnerXML: []byte(chatSettings)}},
		{ServiceIndication: "rcs-ft", SequenceNumber: 65535, ServiceData: &ServiceData{InnerXML: []byte{}}},
		{ServiceIndication: "rcs-bot"},
	},
}

func TestShDataSubsetIsParsedAndTheRestSkipped(t *testing.T) {
	got, err := ParseData([]byte(userData))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, parsedUserData) {
		t.Errorf("parsed:\n%+v\nwant:\n%+v", got, parsedUserData)
	}
}

func TestShDataRoundTripKeepsServiceDataByteForByte(t *testing.T) {
	out, err := parsedUserData.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "<ServiceData>"+chatSettings+"</ServiceData>") {
		t.Errorf("ServiceData was rewritten:\n%s", out)
	}
	back, err := ParseData(out)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, parsedUserData) {
		t.Errorf("round trip:\n%+v\nwant:\n%+v", back, parsedUserData)
	}
	if empty, _ := (&Data{}).Marshal(); !strings.HasSuffix(string(empty), "<Sh-Data></Sh-Data>") {
		t.Errorf("empty Sh-Data = %s", empty)
	}
}

func TestMalformedShDataIsRejected(t *testing.T) {
	repo := func(inner string) string { return `<Sh-Data><RepositoryData>` + inner + `</RepositoryData></Sh-Data>` }
	tests := map[string]struct {
		doc  string
		want error
	}{
		"DOCTYPE":                    {`<!DOCTYPE Sh-Data [<!ENTITY x SYSTEM "file:///etc/passwd">]><Sh-Data>&x;</Sh-Data>`, ErrDTD},
		"DOCTYPE inside ServiceData": {repo(`<ServiceIndication>a</ServiceIndication><SequenceNumber>1</SequenceNumber><ServiceData><!DOCTYPE x></ServiceData>`), ErrDTD},
		"too large":                  {`<Sh-Data>` + strings.Repeat(" ", MaxDataSize) + `</Sh-Data>`, ErrTooLarge},
		"wrong root":                 {`<IMSSubscription/>`, ErrMalformed},
		"not XML":                    {`Sh-Data`, ErrMalformed},
		"two PublicIdentifiers":      {`<Sh-Data><PublicIdentifiers/><PublicIdentifiers/></Sh-Data>`, ErrMalformed},
		"empty IMSPublicIdentity":    {`<Sh-Data><PublicIdentifiers><IMSPublicIdentity> </IMSPublicIdentity></PublicIdentifiers></Sh-Data>`, ErrMalformed},
		"no ServiceIndication":       {repo(`<SequenceNumber>1</SequenceNumber>`), ErrMalformed},
		"no SequenceNumber":          {repo(`<ServiceIndication>a</ServiceIndication>`), ErrMalformed},
		"SequenceNumber 65536":       {repo(`<ServiceIndication>a</ServiceIndication><SequenceNumber>65536</SequenceNumber>`), ErrMalformed},
		"SequenceNumber negative":    {repo(`<ServiceIndication>a</ServiceIndication><SequenceNumber>-1</SequenceNumber>`), ErrMalformed},
		"two ServiceData":            {repo(`<ServiceIndication>a</ServiceIndication><SequenceNumber>1</SequenceNumber><ServiceData/><ServiceData/>`), ErrMalformed},
		"nested too deep":            {repo(`<ServiceIndication>a</ServiceIndication><SequenceNumber>1</SequenceNumber><ServiceData>` + strings.Repeat("<a>", maxDepth) + strings.Repeat("</a>", maxDepth) + `</ServiceData>`), ErrMalformed},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseData([]byte(tc.doc)); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestMarshalRefusesServiceDataThatIsNotSelfContainedXML(t *testing.T) {
	for name, inner := range map[string]string{
		"closes ServiceData": `</ServiceData><Injected/><ServiceData>`,
		"unclosed element":   `<a>`,
		"document type":      `<!DOCTYPE a><a/>`,
		"undefined entity":   `&x;`,
		"stray markup":       `a < b`,
	} {
		d := &Data{RepositoryData: []RepositoryData{{ServiceIndication: "rcs-chat", ServiceData: &ServiceData{InnerXML: []byte(inner)}}}}
		if out, err := d.Marshal(); err == nil {
			t.Errorf("%s: marshalled as %s", name, out)
		}
	}
	for name, d := range map[string]*Data{
		"sequence out of range":     {RepositoryData: []RepositoryData{{ServiceIndication: "a", SequenceNumber: 70000}}},
		"control character":         {RepositoryData: []RepositoryData{{ServiceIndication: "a\x01"}}},
		"identity with white space": {PublicIdentifiers: &PublicIdentifiers{IMSPublicIdentities: []string{" " + impu}}},
		"MSISDN with a NUL":         {PublicIdentifiers: &PublicIdentifiers{MSISDNs: []string{"1\x00"}}},
	} {
		if _, err := d.Marshal(); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}

func TestMarshalRefusesShDataTheParserRefuses(t *testing.T) {
	big := []byte("<x>" + strings.Repeat("y", 40<<10) + "</x>")
	deep := []byte(strings.Repeat("<e>", maxDepth-1) + strings.Repeat("</e>", maxDepth-1))
	for name, tc := range map[string]struct {
		d    *Data
		want error
	}{
		"two entries over MaxDataSize": {&Data{RepositoryData: []RepositoryData{
			{ServiceIndication: "a", ServiceData: &ServiceData{InnerXML: big}},
			{ServiceIndication: "b", ServiceData: &ServiceData{InnerXML: big}},
		}}, ErrTooLarge},
		// ServiceData sits three levels down, so content that is fine
		// on its own is too deep in the document.
		"ServiceData nested to the limit": {&Data{RepositoryData: []RepositoryData{
			{ServiceIndication: "a", ServiceData: &ServiceData{InnerXML: deep}},
		}}, ErrMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := tc.d.Marshal()
			if !errors.Is(err, tc.want) {
				_, perr := ParseData(out)
				t.Fatalf("Marshal = %d bytes, %v (ParseData: %v); want %v", len(out), err, perr, tc.want)
			}
		})
	}
	// One entry of the same size fits, and reads back.
	one := &Data{RepositoryData: []RepositoryData{{ServiceIndication: "a", ServiceData: &ServiceData{InnerXML: big}}}}
	out, err := one.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseData(out); err != nil {
		t.Errorf("ParseData refuses what Marshal wrote: %v", err)
	}
}
