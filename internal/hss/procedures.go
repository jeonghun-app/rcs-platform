package hss

import (
	"slices"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
)

// The Cx procedures of TS 29.228 §6 as decisions over a subscription, kept
// apart from Diameter and the store so each rule is a table test. The
// handlers in cx.go have already checked that the identities exist and
// belong together (step 1 to 3 of each procedure); the functions here apply
// the remaining steps. Where a function changes s, the handler writes s
// back conditional on the version it read.
//
// The model has one IMPI per subscription and one S-CSCF name per
// subscription (package store), which removes the branches for public
// identities shared by several IMPIs. IMS restoration (TS 23.380) and
// emergency registration are not supported, so their branches are left out
// as the procedures allow.

func success() cx.Result { return cx.ResultCode(diameter.ResultSuccess) }

// uarOutcome is what a UAA carries besides the result.
type uarOutcome struct {
	result       cx.Result
	serverName   string
	capabilities bool
}

// decideUAR applies TS 29.228 §6.1.1.1 steps 4 to 6 for the identity impu
// of s. Roaming is not restricted: the platform serves its home network
// only (docs/hss.md).
func decideUAR(s *store.Subscription, impu string, typ cx.UserAuthorizationType) uarOutcome {
	id := s.Identity(impu)
	// Step 4: a barred identity may register only together with an identity
	// of its set that is not barred.
	if id.Barred && defaultIdentity(s, id.ImplicitSet) == "" {
		return uarOutcome{result: cx.ResultCode(diameter.ResultAuthorizationRejected)}
	}
	switch typ {
	case cx.AuthorizeRegistrationAndCapabilities:
		return uarOutcome{result: success(), capabilities: true}
	case cx.AuthorizeDeregistration:
		if id.State.Served() || (s.AuthPending && s.ServerName != "") {
			return uarOutcome{result: success(), serverName: s.ServerName}
		}
		return uarOutcome{result: cx.ExperimentalResult(cx.ErrorIdentityNotRegistered)}
	}
	// REGISTRATION. With one S-CSCF name per subscription, "an identity of
	// the subscription is registered or unregistered, or authentication is
	// pending" is exactly "a name is stored".
	if s.ServerName != "" {
		return uarOutcome{result: cx.ExperimentalResult(cx.SubsequentRegistration), serverName: s.ServerName}
	}
	return uarOutcome{result: cx.ExperimentalResult(cx.FirstRegistration), capabilities: true}
}

// applyMAR applies TS 29.228 §6.3.1 step 5 and reports whether s changed: a
// registered identity served by the requesting S-CSCF keeps its state;
// otherwise the S-CSCF name is stored and authentication is pending.
func applyMAR(s *store.Subscription, impu, serverName string) bool {
	if s.Identity(impu).State == store.Registered && s.ServerName == serverName {
		return false
	}
	changed := s.ServerName != serverName || !s.AuthPending
	s.ServerName, s.AuthPending = serverName, true
	return changed
}

// singleIdentityAssignment reports whether a Server-Assignment-Type needs
// exactly one Public-Identity (TS 29.228 Table 6.1.2.1).
func singleIdentityAssignment(t cx.ServerAssignmentType) bool {
	switch t {
	case cx.TimeoutDeregistration, cx.UserDeregistration, cx.DeregistrationTooMuchData,
		cx.TimeoutDeregistrationStoreServerName, cx.UserDeregistrationStoreServerName,
		cx.AdministrativeDeregistration:
		return false
	}
	return true
}

// sarOutcome is what an SAA carries besides the result.
type sarOutcome struct {
	result cx.Result
	// userData asks for User-Data and Charging-Information of the
	// implicit registration set of the request's identity.
	userData bool
	// serverName is the stored name, sent back when it is not the
	// requester's (TS 29.228 Table 6.1.2.2).
	serverName string
	changed    bool
}

// applySAR applies TS 29.228 §6.1.2.1 step 5 and §8.1.2 to s. impus are the
// request's identities, canonical and known to belong to s; for the types
// that need one identity there is exactly one. keepName is the HSS's
// decision for the *_STORE_SERVER_NAME types: keep the name when the profile
// has services for an unregistered user, so terminating requests reach the
// S-CSCF that still holds the profile.
func applySAR(s *store.Subscription, impus []string, r *cx.SAR, keepName bool) sarOutcome {
	before := clone(s)
	out := sarOutcome{result: success()}
	if s.ServerName != "" && s.ServerName != r.ServerName {
		// §8.1.2: the name is not overwritten, and the requester learns which
		// S-CSCF holds the user.
		if r.AssignmentType == cx.NoAssignment {
			return sarOutcome{result: cx.ResultCode(diameter.ResultUnableToComply)}
		}
		return sarOutcome{result: cx.ExperimentalResult(cx.ErrorIdentityAlreadyRegistered), serverName: s.ServerName}
	}
	wantData := r.UserDataAlreadyAvailable != cx.UserDataAlreadyAvailable
	if len(impus) > 0 {
		// The S-CSCF may not hold the set's latest User-Data, whatever it
		// says: a change's pushes for it ran out of time (#491). §6.6 lets
		// the HSS download the profile all the same.
		if i := slices.Index(s.StaleSets, s.Identity(impus[0]).ImplicitSet); i >= 0 {
			switch r.AssignmentType {
			case cx.Registration, cx.ReRegistration, cx.UnregisteredUser, cx.NoAssignment:
				wantData = true
				s.StaleSets = slices.Delete(slices.Clone(s.StaleSets), i, i+1)
			}
		}
	}
	switch r.AssignmentType {
	case cx.Registration, cx.ReRegistration:
		setState(s, s.Identity(impus[0]).ImplicitSet, store.Registered)
		s.ServerName, s.AuthPending = r.ServerName, false
		out.userData = wantData
	case cx.UnregisteredUser:
		// Without restoration support a registered identity becomes
		// unregistered too.
		setState(s, s.Identity(impus[0]).ImplicitSet, store.Unregistered)
		s.ServerName = r.ServerName
		out.userData = wantData
	case cx.NoAssignment:
		if s.ServerName != r.ServerName {
			return sarOutcome{result: cx.ResultCode(diameter.ResultUnableToComply)}
		}
		out.userData = wantData
	case cx.TimeoutDeregistration, cx.UserDeregistration, cx.DeregistrationTooMuchData, cx.AdministrativeDeregistration:
		for _, set := range targetSets(s, impus) {
			setState(s, set, store.NotRegistered)
		}
		if !served(s) {
			s.AuthPending = false
		}
		clearServerIfIdle(s)
	case cx.TimeoutDeregistrationStoreServerName, cx.UserDeregistrationStoreServerName:
		for _, set := range targetSets(s, impus) {
			if keepName {
				if members(s, set)[0].State == store.Registered {
					setState(s, set, store.Unregistered)
				}
			} else {
				setState(s, set, store.NotRegistered)
			}
		}
		if !keepName {
			if !served(s) {
				s.AuthPending = false
			}
			clearServerIfIdle(s)
			out.result = cx.ExperimentalResult(cx.SuccessServerNameNotStored)
		}
	case cx.AuthenticationFailure, cx.AuthenticationTimeout:
		s.AuthPending = false
		if s.Identity(impus[0]).State == store.NotRegistered {
			clearServerIfIdle(s)
		}
	default:
		return sarOutcome{result: cx.ExperimentalResult(cx.ErrorInAssignmentType)}
	}
	out.changed = !sameState(before, s)
	return out
}

// targetSets returns the implicit registration sets a deregistration
// affects: those of the identities given, or every set when none is
// (TS 29.228 §6.5.1.2).
func targetSets(s *store.Subscription, impus []string) []int {
	seen := map[int]bool{}
	var sets []int
	add := func(set int) {
		if !seen[set] {
			seen[set] = true
			sets = append(sets, set)
		}
	}
	if len(impus) == 0 {
		for _, p := range s.PublicIdentities {
			add(p.ImplicitSet)
		}
		return sets
	}
	for _, impu := range impus {
		add(s.Identity(impu).ImplicitSet)
	}
	return sets
}

// sameState reports whether two copies of a subscription have the same Cx
// state.
func sameState(a, b *store.Subscription) bool {
	if a.ServerName != b.ServerName || a.AuthPending != b.AuthPending || !slices.Equal(a.StaleSets, b.StaleSets) {
		return false
	}
	for i := range a.PublicIdentities {
		if a.PublicIdentities[i].State != b.PublicIdentities[i].State {
			return false
		}
	}
	return true
}

// lirOutcome is what an LIA carries besides the result.
type lirOutcome struct {
	result       cx.Result
	serverName   string
	capabilities bool
}

// decideLIR applies TS 29.228 §6.1.4.1 step 3 for the identity impu of s.
func decideLIR(s *store.Subscription, impu string, originating, unregisteredServices bool) lirOutcome {
	if s.Identity(impu).State.Served() {
		return lirOutcome{result: success(), serverName: s.ServerName}
	}
	if !unregisteredServices && !originating {
		return lirOutcome{result: cx.ExperimentalResult(cx.ErrorIdentityNotRegistered)}
	}
	if s.ServerName != "" {
		return lirOutcome{result: success(), serverName: s.ServerName}
	}
	return lirOutcome{result: cx.ExperimentalResult(cx.UnregisteredService), capabilities: true}
}
