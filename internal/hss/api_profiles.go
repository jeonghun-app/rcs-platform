package hss

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/jeonghun-app/rcs-platform/internal/hss/ifcjson"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

type profileJSON struct {
	ID                    string              `json:"id"`
	InitialFilterCriteria []ifcjson.Criterion `json:"initial_filter_criteria"`
	MandatoryCapabilities []uint32            `json:"mandatory_capabilities,omitempty"`
	OptionalCapabilities  []uint32            `json:"optional_capabilities,omitempty"`
	// Version is read-only.
	Version int64 `json:"version,omitempty"`
}

// profileResponseJSON is a profile as returned, with the warnings of the
// request that wrote it.
type profileResponseJSON struct {
	profileJSON
	Warnings []string `json:"warnings,omitempty"`
}

func profileResponse(p *store.ServiceProfile, warnings []string) profileResponseJSON {
	return profileResponseJSON{
		profileJSON: profileJSON{
			ID: p.ID, InitialFilterCriteria: ifcjson.FromIFC(p.Criteria),
			MandatoryCapabilities: p.MandatoryCapabilities, OptionalCapabilities: p.OptionalCapabilities,
			Version: p.Version,
		},
		Warnings: warnings,
	}
}

// costWarnings estimates a profile's cost (TS 29.228 Annex F matching, as
// internal/ifc charges it) against the reference requests: a profile that
// needs more than half of the S-CSCF's default budget is accepted with a
// warning, returned and logged, because a client sending somewhat larger
// requests than the reference ones would push it over.
func (a *API) costWarnings(p *store.ServiceProfile) []string {
	err := checkWork(p.Criteria, ifc.Limits{MaxWork: ifc.DefaultMaxWork / 2})
	if err == nil {
		return nil
	}
	w := "initial_filter_criteria: more than half of the S-CSCF's default work budget is needed: " + err.Error()
	a.h.metrics.Count("profile.costly", 1)
	a.h.log.Warn("costly service profile", slog.String("profile", pii.Redact(p.ID)), slog.String("warning", w))
	return []string{w}
}

// profileFromJSON validates a profile as the S-CSCF will use it, and refuses
// with 400 one it could not: the criteria must compile (ifcjson.ToIFC), the
// reference requests of reference.go must evaluate within the default work
// budget in every session case (the error names the limit reached), and the
// User-Data of a subscription at the model's limits with this profile must
// fit ifc.MaxDocumentSize, so that no SAR for it fails with
// DIAMETER_ERROR_TOO_MUCH_DATA.
func profileFromJSON(in *profileJSON) (*store.ServiceProfile, error) {
	if err := ValidProfileID(in.ID); err != nil {
		return nil, fail(http.StatusBadRequest, "id: "+err.Error())
	}
	if in.Version != 0 {
		return nil, fail(http.StatusBadRequest, "version: read-only; use If-Match")
	}
	if len(in.MandatoryCapabilities) > store.MaxCapabilities || len(in.OptionalCapabilities) > store.MaxCapabilities {
		return nil, fail(http.StatusBadRequest, "capabilities: at most 32 of each")
	}
	criteria, err := ifcjson.ToIFC(in.InitialFilterCriteria)
	if err != nil {
		return nil, fail(http.StatusBadRequest, "initial_filter_criteria: "+strings.TrimPrefix(err.Error(), ifcjson.ErrInvalid.Error()+": "))
	}
	if err := checkWork(criteria, ifc.Limits{}); err != nil {
		return nil, fail(http.StatusBadRequest, "initial_filter_criteria: "+err.Error())
	}
	p := &store.ServiceProfile{
		ID: in.ID, Criteria: criteria,
		MandatoryCapabilities: in.MandatoryCapabilities, OptionalCapabilities: in.OptionalCapabilities,
	}
	if _, err := userData(largestSubscription(), 0, p); err != nil {
		if errors.Is(err, ifc.ErrTooLarge) {
			return nil, fail(http.StatusBadRequest, "initial_filter_criteria: too large for the User-Data of a full subscription (MaxDocumentSize)")
		}
		return nil, fail(http.StatusBadRequest, "initial_filter_criteria: cannot be sent as User-Data")
	}
	return p, nil
}

// largestSubscription is a stand-in at the model's limits, for sizing
// User-Data.
func largestSubscription() *store.Subscription {
	s := &store.Subscription{IMPI: strings.Repeat("u", store.MaxIdentityLength-12) + "@example.org"}
	for i := range store.MaxPublicIdentities {
		s.PublicIdentities = append(s.PublicIdentities, store.PublicIdentity{
			IMPU: fmt.Sprintf("sip:%s%02d@example.org", strings.Repeat("u", store.MaxIdentityLength-18), i),
		})
	}
	return s
}

func (a *API) createProfile(w http.ResponseWriter, r *http.Request, _ Scope) error {
	var in profileJSON
	if err := decodeBody(w, r, maxProfileBody, &in); err != nil {
		return err
	}
	p, err := profileFromJSON(&in)
	if err != nil {
		return err
	}
	saved, err := a.h.store.CreateProfile(r.Context(), p)
	if err != nil {
		return err
	}
	w.Header().Set("Location", "/v1/service-profiles/"+saved.ID)
	w.Header().Set("ETag", etag(saved.Version))
	writeJSON(w, http.StatusCreated, profileResponse(saved, a.costWarnings(saved)))
	return nil
}

func (a *API) profileID(r *http.Request) (string, error) {
	id := r.PathValue("id")
	if err := ValidProfileID(id); err != nil {
		return "", fail(http.StatusBadRequest, "id: "+err.Error())
	}
	return id, nil
}

func (a *API) getProfile(w http.ResponseWriter, r *http.Request, _ Scope) error {
	id, err := a.profileID(r)
	if err != nil {
		return err
	}
	p, err := a.h.store.Profile(r.Context(), id)
	if err != nil {
		return err
	}
	w.Header().Set("ETag", etag(p.Version))
	writeJSON(w, http.StatusOK, profileResponse(p, nil))
	return nil
}

// putProfile replaces a profile and pushes it to the S-CSCF of every
// subscription using it that is served (TS 29.228 §6.6.1). The pushes run in
// the background: a shared profile may serve millions of subscribers.
func (a *API) putProfile(w http.ResponseWriter, r *http.Request, _ Scope) error {
	id, err := a.profileID(r)
	if err != nil {
		return err
	}
	want, err := ifMatch(r)
	if err != nil {
		return err
	}
	var in profileJSON
	if err := decodeBody(w, r, maxProfileBody, &in); err != nil {
		return err
	}
	if in.ID == "" {
		in.ID = id
	}
	if in.ID != id {
		return fail(http.StatusBadRequest, "id: differs from the path")
	}
	p, err := profileFromJSON(&in)
	if err != nil {
		return err
	}
	saved, err := a.replaceProfile(r.Context(), p, want)
	if err != nil {
		return err
	}
	a.fanout(id)
	w.Header().Set("ETag", etag(saved.Version))
	writeJSON(w, http.StatusOK, profileResponse(saved, a.costWarnings(saved)))
	return nil
}

// replaceProfile writes p over the stored profile: over the version want,
// or, when want is 0, over whatever is stored, retrying a lost race.
func (a *API) replaceProfile(ctx context.Context, p *store.ServiceProfile, want int64) (*store.ServiceProfile, error) {
	for range maxUpdateAttempts {
		cur, err := a.h.store.Profile(ctx, p.ID)
		if err != nil {
			return nil, err
		}
		if want != 0 && cur.Version != want {
			return nil, errPrecondition
		}
		p.Version = cur.Version
		saved, err := a.h.store.UpdateProfile(ctx, p)
		switch {
		case errors.Is(err, store.ErrConflict) && want != 0:
			return nil, errPrecondition
		case errors.Is(err, store.ErrConflict):
			continue
		}
		return saved, err
	}
	return nil, errContention
}

func (a *API) deleteProfile(w http.ResponseWriter, r *http.Request, _ Scope) error {
	id, err := a.profileID(r)
	if err != nil {
		return err
	}
	want, err := ifMatch(r)
	if err != nil {
		return err
	}
	p, err := a.h.store.Profile(r.Context(), id)
	if err != nil {
		return err
	}
	if want != 0 && p.Version != want {
		return errPrecondition
	}
	if err := a.h.store.DeleteProfile(r.Context(), p); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return errPrecondition
		}
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// fanout pushes profile id to every served subscription using it, in the
// background. A newer change of the same profile cancels a fan-out still
// running, since every PPR reads the profile when it is sent.
func (a *API) fanout(id string) {
	if a.notifier == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closing.Err() != nil {
		return
	}
	if cancel, ok := a.fanouts[id]; ok {
		cancel()
	}
	ctx, cancel := context.WithCancel(a.closing)
	a.fanouts[id] = cancel
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer cancel()
		n, err := a.pushProfile(ctx, id)
		a.mu.Lock()
		if ctx.Err() == nil {
			delete(a.fanouts, id)
		}
		a.mu.Unlock()
		a.h.metrics.Count("push.fanout.subscriptions", int64(n))
		switch {
		case err != nil && ctx.Err() == nil:
			a.h.log.Warn("profile push stopped early", slog.String("profile", pii.Redact(id)),
				slog.Int("notified", n), slog.String("error", pii.Redact(err.Error())))
		case a.closing.Err() != nil:
			// Some subscribers have the old profile until they register
			// again; the operator may want to apply the change once more.
			a.h.log.Info("profile push cut short by shutdown", slog.String("profile", pii.Redact(id)), slog.Int("notified", n))
		}
	}()
}

// pushProfile walks the subscriptions of a profile page by page and sends
// their PPRs with a bounded number of workers. It reads the profile once: a
// later change of it cancels this fan-out and starts another. It returns how
// many subscriptions it notified.
func (a *API) pushProfile(ctx context.Context, id string) (int, error) {
	p, err := a.h.store.Profile(ctx, id)
	if err != nil {
		return 0, err
	}
	jobs := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	count := 0
	for range a.workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for impi := range jobs {
				if a.pushOne(ctx, impi, p) {
					mu.Lock()
					count++
					mu.Unlock()
				}
			}
		}()
	}
	err = func() error {
		defer close(jobs)
		cursor := ""
		for {
			page, err := a.h.store.SubscriptionsByProfile(ctx, id, cursor, store.MaxPageSize)
			if err != nil {
				return err
			}
			for _, impi := range page.IMPIs {
				select {
				case jobs <- impi:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			if page.Next == "" {
				return nil
			}
			cursor = page.Next
		}
	}()
	wg.Wait()
	return count, err
}

// pushOne sends the PPRs of one subscription, reading it afresh: the listing
// is eventually consistent, and the subscription may have moved to another
// profile since.
func (a *API) pushOne(ctx context.Context, impi string, p *store.ServiceProfile) bool {
	s, err := a.h.store.Subscription(ctx, impi)
	if err != nil || s.Profile != p.ID {
		return false
	}
	pushes := profilePushes(s)
	if len(pushes) == 0 {
		return false
	}
	pctx, cancel := context.WithTimeout(ctx, a.pushTimeout)
	defer cancel()
	a.h.notify(pctx, a.notifier, s, p, pushes)
	return true
}
