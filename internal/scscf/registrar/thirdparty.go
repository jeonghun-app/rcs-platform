package registrar

import (
	"context"
	"slices"
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
	// registered: the REGISTER's, or for the end of the set each one it was
	// registered under (state.Registration.RegisteredAs), told apart.
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
	for _, impu := range registeredIdentities(before, "") {
		r := ThirdPartyRegistration{Set: before.Key, IMPU: impu, Type: ifc.DeRegistration, Profile: profile}
		g.cfg.ThirdParty.Registered(ctx, r)
	}
}

// registeredIdentities are the identities reg's set was registered under
// and also, which the servers were told of: the set's default identity for
// a record saved before they were kept (#379 code review).
func registeredIdentities(reg *state.Registration, also string) []string {
	out := slices.Clone(reg.RegisteredAs)
	if also != "" && !slices.Contains(out, also) {
		out = append(out, also)
	}
	if len(out) == 0 {
		out = []string{reg.Key.IMPU}
	}
	return out
}

// withRegistered is registered with impu added, keeping only identities of
// the set, so that it holds at most the set's identities.
func withRegistered(registered []string, impu string, set []state.SetIdentity) []string {
	var out []string
	for _, r := range append(slices.Clone(registered), impu) {
		inSet := slices.ContainsFunc(set, func(id state.SetIdentity) bool { return id.IMPU == r })
		if inSet && !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}
