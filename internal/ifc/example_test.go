package ifc_test

import (
	"fmt"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

// message is how an S-CSCF might present a SIP request to the package.
type message struct {
	method, uri string
	headers     []ifc.HeaderField
}

func (m message) Method() string                  { return m.method }
func (m message) RequestURI() string              { return m.uri }
func (m message) HeaderFields() []ifc.HeaderField { return m.headers }
func (m message) SDPLines() []string              { return nil }

// The S-CSCF reads the profile from a Server-Assignment-Answer once, compiles
// the criteria of the served identity's service profile, and asks for the
// next application server of each originating request.
func Example() {
	userData := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<IMSSubscription>
  <PrivateID>001010000000001@ims.mnc001.mcc001.3gppnetwork.org</PrivateID>
  <ServiceProfile>
    <PublicIdentity><Identity>sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org</Identity></PublicIdentity>
    <InitialFilterCriteria>
      <Priority>10</Priority>
      <TriggerPoint>
        <ConditionTypeCNF>1</ConditionTypeCNF>
        <SPT><Group>0</Group><Method>MESSAGE</Method></SPT>
        <SPT><Group>0</Group><Method>INVITE</Method></SPT>
        <SPT><Group>1</Group><SIPHeader><Header>Accept-Contact</Header><Content>oma\.cpm</Content></SIPHeader></SPT>
      </TriggerPoint>
      <ApplicationServer>
        <ServerName>sip:rcs-as.ims.mnc001.mcc001.3gppnetwork.org;lr</ServerName>
        <DefaultHandling>1</DefaultHandling>
      </ApplicationServer>
    </InitialFilterCriteria>
  </ServiceProfile>
</IMSSubscription>`)
	sub, err := ifc.ParseSubscription(userData)
	if err != nil {
		fmt.Println(err)
		return
	}
	set, err := ifc.Compile(sub.ServiceProfiles[0].InitialFilterCriteria)
	if err != nil {
		fmt.Println(err)
		return
	}
	chat := message{
		method: "MESSAGE",
		uri:    "sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org",
		headers: []ifc.HeaderField{
			{Name: "Accept-Contact", Value: `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg"`},
		},
	}
	if fc, ok := set.Next(chat, ifc.Context{Case: ifc.Originating}, -1); ok {
		fmt.Println(fc.Priority, fc.ApplicationServer.ServerName)
	}
	// Output: 10 sip:rcs-as.ims.mnc001.mcc001.3gppnetwork.org;lr
}
