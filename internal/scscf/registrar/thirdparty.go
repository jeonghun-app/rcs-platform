package registrar

import (
	"context"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// ThirdParty registers a user with the application servers whose criteria
// take its REGISTER (TS 24.229 §5.4.1.7); *routing.Router implements it.
// Registered must return at once: the REGISTER it is told of is answered
// after it, and an RTR or a sweep goes on.
type ThirdParty interface {
	Registered(ctx context.Context, r ThirdPartyRegistration)
}

// ThirdPartyRegistration is a registration the application servers are told
// of.
type ThirdPartyRegistration struct {
	// Set is the user's implicit registration set, and IMPU the identity
	// registered: the REGISTER's, or for an end the network made the one
	// the registration was made with (state.Registration.RegisteredAs).
	Set  state.SetKey
	IMPU string
	Type ifc.RegistrationType
	// Expires is how long the set stays registered: until its last live
	// binding expires, 0 once it has none.
	Expires time.Duration
	// Request and Response are the UE's REGISTER and the registrar's 200
	// for it, nil for an end the network made (a sweep, an RTR).
	Request  *sip.Request
	Response *sip.Response
	// Profile is the set's profile if the registrar has it at hand, as it
	// does when the set ends, after which the store has none.
	Profile *state.Profile
}

type noThirdParty struct{}

func (noThirdParty) Registered(context.Context, ThirdPartyRegistration) {}

// registeredFor is the third-party registration of the set after a REGISTER
// or an end, with bindings left.
func registeredFor(set state.SetKey, impu string, t ifc.RegistrationType, bindings []state.Contact, now time.Time) ThirdPartyRegistration {
	var expires time.Duration
	for _, c := range bindings {
		if d := c.Expires.Sub(now); d > expires {
			expires = d
		}
	}
	return ThirdPartyRegistration{Set: set, IMPU: impu, Type: t, Expires: expires}
}

// endedByNetwork tells the application servers of a set an RTR or a sweep
// ended: an unregistered user's record, which no REGISTER made, has none
// to tell.
func (g *Registrar) endedByNetwork(ctx context.Context, before *state.Registration, profile *state.Profile) {
	if len(before.Contacts) == 0 && !before.Unregistered.IsZero() {
		return
	}
	impu := before.RegisteredAs
	if impu == "" {
		impu = before.Key.IMPU
	}
	r := ThirdPartyRegistration{Set: before.Key, IMPU: impu, Type: ifc.DeRegistration, Profile: profile}
	g.cfg.ThirdParty.Registered(ctx, r)
}
