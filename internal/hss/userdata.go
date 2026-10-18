package hss

import (
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

// userData is the User-Data of an implicit registration set: the
// IMSSubscription document with the set's identities and the profile's
// criteria (TS 29.228 §6.5.1.4, §6.6). Every identity of a subscription
// shares one service profile, so the document has one ServiceProfile. A
// document beyond ifc.MaxDocumentSize fails with ifc.ErrTooLarge, which the
// caller answers with DIAMETER_ERROR_TOO_MUCH_DATA.
func userData(s *store.Subscription, set int, p *store.ServiceProfile) ([]byte, error) {
	sp := ifc.ServiceProfile{InitialFilterCriteria: p.Criteria}
	for _, m := range members(s, set) {
		sp.PublicIdentities = append(sp.PublicIdentities, ifc.PublicIdentity{
			Identity: m.IMPU, BarringIndication: m.Barred, IdentityType: m.Type,
		})
	}
	doc := ifc.Subscription{PrivateID: s.IMPI, ServiceProfiles: []ifc.ServiceProfile{sp}}
	return doc.Marshal()
}

// hasUnregisteredServices reports whether the profile has services for a
// user who is not registered, which decides LIR for an unregistered user
// (TS 29.228 §6.1.4.1 step 3) and whether the S-CSCF name is kept after a
// deregistration that offers to keep it. A criterion that belongs to the
// unregistered part of the profile, or to both parts, counts: the default
// RCS profile's criteria have no ProfilePartIndicator, so rcs-as stores
// messages for users who are offline (docs/architecture.md §5.2).
func hasUnregisteredServices(p *store.ServiceProfile) bool {
	for _, fc := range p.Criteria {
		if fc.ProfilePart != ifc.ProfilePartRegistered {
			return true
		}
	}
	return false
}

// capabilities is the Server-Capabilities of a subscription, or nil when
// any S-CSCF will do (TS 29.228 §6.7).
func (h *HSS) capabilities(p *store.ServiceProfile) *cx.ServerCapabilities {
	if len(p.MandatoryCapabilities) == 0 && len(p.OptionalCapabilities) == 0 && len(h.serverNames) == 0 {
		return nil
	}
	return &cx.ServerCapabilities{
		Mandatory:   append([]uint32(nil), p.MandatoryCapabilities...),
		Optional:    append([]uint32(nil), p.OptionalCapabilities...),
		ServerNames: append([]string(nil), h.serverNames...),
	}
}

// charging converts the stored charging information.
func charging(c *store.ChargingInformation) *cx.ChargingInformation {
	if c == nil {
		return nil
	}
	return &cx.ChargingInformation{
		PrimaryEventChargingFunctionName:        c.PrimaryEventChargingFunctionName,
		SecondaryEventChargingFunctionName:      c.SecondaryEventChargingFunctionName,
		PrimaryChargingCollectionFunctionName:   c.PrimaryChargingCollectionFunctionName,
		SecondaryChargingCollectionFunctionName: c.SecondaryChargingCollectionFunctionName,
	}
}
