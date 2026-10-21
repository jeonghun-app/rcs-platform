package routing

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// maxCachedServices bounds the compiled iFC sets kept: compiling one costs
// up to ifc.MaxSetCompileCost, which a request should not pay every time.
const maxCachedServices = 4096

// errBadProfile is a stored profile whose iFC cannot be read or compiled:
// the registrar stored what the HSS sent, which a later change to the
// limits may refuse.
var errBadProfile = errors.New("routing: the served user's profile cannot be used")

// servicesKey names one compiled set: the profile of a set as received,
// and the identity whose service profile it is.
type servicesKey struct {
	set      state.SetKey
	received int64
	impu     string
}

// services caches compiled iFC sets. Its fields are guarded by mu.
type services struct {
	mu   sync.Mutex
	sets map[servicesKey]*ifc.Set
}

// servicesOf is the compiled iFC of impu in the profile of set (TS 29.228
// Annex E): the criteria of the service profile that lists impu, empty if
// the set has no profile or no criteria for it.
func (rt *Router) servicesOf(ctx context.Context, set state.SetKey, impu string) (*ifc.Set, error) {
	p, err := rt.cfg.Store.Profile(ctx, set, rt.cfg.Now())
	switch {
	case errors.Is(err, state.ErrNotFound):
		rt.count("routing.no_profile")
		return &ifc.Set{}, nil
	case err != nil:
		return nil, err
	}
	return rt.servicesIn(p, impu)
}

// servicesIn is the compiled iFC of impu in the profile p.
func (rt *Router) servicesIn(p *state.Profile, impu string) (*ifc.Set, error) {
	k := servicesKey{set: p.Key, received: p.Received.UnixNano(), impu: impu}
	rt.svc.mu.Lock()
	cached := rt.svc.sets[k]
	rt.svc.mu.Unlock()
	if cached != nil {
		return cached, nil
	}
	sub, err := ifc.ParseSubscription(p.UserData)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errBadProfile, err)
	}
	var criteria []ifc.FilterCriteria
	for _, sp := range sub.ServiceProfiles {
		for _, id := range sp.PublicIdentities {
			if c, ok := identity.CanonicalIMPU(id.Identity); ok && c == impu {
				criteria = sp.InitialFilterCriteria
			}
		}
	}
	compiled, err := ifc.Compile(criteria)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errBadProfile, err)
	}
	rt.svc.mu.Lock()
	if rt.svc.sets == nil || len(rt.svc.sets) >= maxCachedServices {
		// Profiles change rarely, so starting afresh costs a few compiles.
		rt.svc.sets = map[servicesKey]*ifc.Set{}
	}
	rt.svc.sets[k] = compiled
	rt.svc.mu.Unlock()
	return compiled, nil
}
