package cx

import (
	"fmt"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
)

// checkCommand returns an error unless m is a Cx request (or answer) with the
// command code, so that a parse function fed the wrong message says so
// instead of reporting missing AVPs.
func checkCommand(m *diameter.Message, code uint32, request bool) error {
	if m.ApplicationID == ApplicationID && m.Code == code && m.IsRequest() == request {
		return nil
	}
	return fmt.Errorf("cx: message is application %d command %d (R=%t), want Cx command %d (R=%t)",
		m.ApplicationID, m.Code, m.IsRequest(), code, request)
}

// errMissing reports a required field left empty when building a message.
// Sending the message anyway would only earn DIAMETER_MISSING_AVP from the
// peer, after a round trip, with less to go on.
func errMissing(command, field string) error {
	return fmt.Errorf("cx: %s has no %s", command, field)
}

// ServerCapabilities lets the I-CSCF choose an S-CSCF when the HSS has none
// assigned (TS 29.229 §6.3.4; the meaning of the capability numbers is
// operator-defined, TS 29.228 §6.7).
type ServerCapabilities struct {
	Mandatory   []uint32
	Optional    []uint32
	ServerNames []string
}

func (c *ServerCapabilities) avp() *diameter.AVP {
	var children []*diameter.AVP
	for _, v := range c.Mandatory {
		children = append(children, specMandatoryCapability.Unsigned32(v))
	}
	for _, v := range c.Optional {
		children = append(children, specOptionalCapability.Unsigned32(v))
	}
	for _, s := range c.ServerNames {
		children = append(children, specServerName.UTF8String(s))
	}
	return specServerCapabilities.Grouped(children...)
}

func readServerCapabilities(f *Fields) *ServerCapabilities {
	g := f.Grouped(specServerCapabilities, Optional)
	if g == nil {
		return nil
	}
	return &ServerCapabilities{
		Mandatory:   g.AllUnsigned32(specMandatoryCapability),
		Optional:    g.AllUnsigned32(specOptionalCapability),
		ServerNames: g.AllUTF8String(specServerName),
	}
}

// ChargingInformation names the charging functions of the user (TS 29.229
// §6.3.19). The names are DiameterURIs.
type ChargingInformation struct {
	PrimaryEventChargingFunctionName        string
	SecondaryEventChargingFunctionName      string
	PrimaryChargingCollectionFunctionName   string
	SecondaryChargingCollectionFunctionName string
}

func (c *ChargingInformation) avp() (*diameter.AVP, error) {
	var children []*diameter.AVP
	for _, v := range []struct {
		s     AVPSpec
		value string
	}{
		{specPrimaryEventChargingFn, c.PrimaryEventChargingFunctionName},
		{specSecondaryEventChargingFn, c.SecondaryEventChargingFunctionName},
		{specPrimaryChargingCollectionFn, c.PrimaryChargingCollectionFunctionName},
		{specSecondaryChargingCollectFn, c.SecondaryChargingCollectionFunctionName},
	} {
		if v.value == "" {
			continue
		}
		a := v.s.UTF8String(v.value)
		if _, err := a.DiameterURI(); err != nil {
			return nil, fmt.Errorf("cx: %s is not a DiameterURI", v.s.Name)
		}
		children = append(children, a)
	}
	return specChargingInformation.Grouped(children...), nil
}

func readChargingInformation(f *Fields) *ChargingInformation {
	g := f.Grouped(specChargingInformation, Optional)
	if g == nil {
		return nil
	}
	return &ChargingInformation{
		PrimaryEventChargingFunctionName:        g.DiameterURI(specPrimaryEventChargingFn, Optional),
		SecondaryEventChargingFunctionName:      g.DiameterURI(specSecondaryEventChargingFn, Optional),
		PrimaryChargingCollectionFunctionName:   g.DiameterURI(specPrimaryChargingCollectionFn, Optional),
		SecondaryChargingCollectionFunctionName: g.DiameterURI(specSecondaryChargingCollectFn, Optional),
	}
}

// associatedIdentities encodes the private identities of a subscription
// (TS 29.229 §6.3.33); nil means the AVP is absent.
func associatedIdentities(names []string) []*diameter.AVP {
	if names == nil {
		return nil
	}
	children := make([]*diameter.AVP, len(names))
	for i, n := range names {
		children[i] = specUserName.UTF8String(n)
	}
	return []*diameter.AVP{specAssociatedIdentities.Grouped(children...)}
}

func readAssociatedIdentities(f *Fields) []string {
	g := f.Grouped(specAssociatedIdentities, Optional)
	if g == nil {
		return nil
	}
	names := g.AllUTF8String(specUserName)
	if names == nil {
		names = []string{}
	}
	return names
}

func optionalUTF8(s AVPSpec, v string) []*diameter.AVP {
	if v == "" {
		return nil
	}
	return []*diameter.AVP{s.UTF8String(v)}
}

func optionalOctets(s AVPSpec, b []byte) []*diameter.AVP {
	if b == nil {
		return nil
	}
	return []*diameter.AVP{s.OctetString(b)}
}
