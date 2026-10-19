package hss

import (
	"context"
	"errors"
	"log/slog"
	"reflect"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// What the S-CSCF must be told when provisioning changes a subscription it
// serves (TS 29.228 §6.5.2, §6.6.1). The HSS changes the stored state in the
// same write as the provisioning change and sends the requests after the
// write, so a failure to reach an S-CSCF never undoes the change: the user
// picks it up at the next registration, at the latest when it expires.

// push is one HSS-initiated request to send.
type push struct {
	deregister bool
	reason     cx.ReasonCode
	// impus lists the identities an RTR deregisters; none means all.
	impus []string
	// set is the implicit registration set whose User-Data a PPR carries,
	// or -1 for a PPR without User-Data.
	set      int
	charging bool
	digest   bool
}

// reconcile sets the registration state of next, a provisioned replacement
// of old, and returns what to send (TS 29.228 §6.5.2.1):
//
//   - a served set left without identities is deregistered (RTR,
//     PERMANENT_TERMINATION) — a PPR cannot empty a set;
//   - a served set whose default identity changes is deregistered (RTR,
//     SERVER_CHANGE) so the user registers again — a PPR must not change it;
//   - any other served set whose identities, barring or profile change gets
//     its new User-Data (PPR); identities added to it take its state;
//   - a change of charging information alone is a PPR without User-Data
//     (§6.5.2.3).
//
// Sets that were not served stay or become not registered.
func reconcile(old, next *store.Subscription, profileChanged bool) []push {
	state := map[int]store.RegistrationState{}
	for _, p := range old.PublicIdentities {
		state[p.ImplicitSet] = p.State
	}
	for i := range next.PublicIdentities {
		next.PublicIdentities[i].State = store.NotRegistered
	}
	chargingChanged := !reflect.DeepEqual(old.Charging, next.Charging)
	var pushes []push
	pprSent := false
	for _, set := range targetSets(old, nil) {
		if !state[set].Served() {
			continue
		}
		was, now := members(old, set), members(next, set)
		switch {
		case len(now) == 0:
			pushes = append(pushes, push{deregister: true, reason: cx.PermanentTermination, impus: impusOf(was), set: -1})
		case defaultIdentity(old, set) != defaultIdentity(next, set):
			pushes = append(pushes, push{deregister: true, reason: cx.ServerChange, impus: impusOf(was), set: -1})
		default:
			setState(next, set, state[set])
			if profileChanged || !sameMembers(was, now) {
				pushes = append(pushes, push{set: set, charging: chargingChanged})
				pprSent = true
			}
		}
	}
	if chargingChanged && !pprSent && served(next) {
		pushes = append(pushes, push{set: -1, charging: true})
	}
	clearServerIfIdle(next)
	return pushes
}

func impusOf(ids []store.PublicIdentity) []string {
	out := make([]string, len(ids))
	for i, p := range ids {
		out[i] = p.IMPU
	}
	return out
}

func sameMembers(a, b []store.PublicIdentity) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].IMPU != b[i].IMPU || a[i].Barred != b[i].Barred || a[i].Type != b[i].Type {
			return false
		}
	}
	return true
}

// profilePushes are the PPRs for a subscription whose shared profile
// changed: one per served implicit registration set (§6.6.1).
func profilePushes(s *store.Subscription) []push {
	var pushes []push
	for _, set := range targetSets(s, nil) {
		if members(s, set)[0].State.Served() {
			pushes = append(pushes, push{set: set})
		}
	}
	return pushes
}

// digestPushes is the PPR for a changed SIP Digest credential (TS 29.228
// §6.5.2.4): pushed when an identity is registered, or authentication is
// pending with the old one.
func digestPushes(s *store.Subscription) []push {
	for _, p := range s.PublicIdentities {
		if p.State == store.Registered {
			return []push{{set: -1, digest: true}}
		}
	}
	if s.AuthPending {
		return []push{{set: -1, digest: true}}
	}
	return nil
}

// deletePushes deregisters a deleted subscription that an S-CSCF serves:
// every identity, permanently (§6.1.3).
func deletePushes(s *store.Subscription) []push {
	if !served(s) {
		return nil
	}
	return []push{{deregister: true, reason: cx.PermanentTermination, set: -1}}
}

// notify sends pushes for s, whose profile is p (needed for User-Data).
// Failures are logged and counted, not returned: the stored change stands.
func (h *HSS) notify(ctx context.Context, n Notifier, s *store.Subscription, p *store.ServiceProfile, pushes []push) {
	if n == nil {
		return
	}
	for _, ps := range pushes {
		err := h.send(ctx, n, s, p, ps)
		if err != nil {
			kind := "ppr"
			if ps.deregister {
				kind = "rtr"
			}
			h.log.Warn("could not notify the S-CSCF of a provisioning change",
				pii.Identity("impi", s.IMPI), slog.String("request", kind), slog.String("error", pii.Redact(err.Error())))
		}
		var rejected *RejectedError
		if !ps.deregister && errors.As(err, &rejected) {
			h.pprRejected(ctx, n, s, rejected.Result)
		}
	}
}

// pprRejected acts on a PPA failure as TS 29.228 §6.2.2.1 asks of an HSS
// without restoration support:
//
//   - DIAMETER_ERROR_USER_UNKNOWN: the S-CSCF has lost the user, so the
//     HSS's registration state is wrong; every identity becomes not
//     registered (there is no other registered IMPI to retry with).
//   - DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA or TOO_MUCH_DATA: the S-CSCF
//     keeps the old data and the HSS deregisters the user with
//     SERVER_CHANGE, setting the state to not registered, so that the user
//     registers again and gets an S-CSCF that takes the new data.
func (h *HSS) pprRejected(ctx context.Context, n Notifier, s *store.Subscription, r cx.Result) {
	if r.Vendor != cx.Vendor3GPP {
		return
	}
	switch r.Code {
	case cx.ErrorUserUnknown, cx.ErrorNotSupportedUserData, cx.ErrorTooMuchData:
	default:
		return
	}
	_, err := h.update(ctx, s.IMPI, func(cur *store.Subscription) error {
		if !served(cur) && !cur.AuthPending && cur.ServerName == "" {
			return errUnchanged
		}
		for i := range cur.PublicIdentities {
			cur.PublicIdentities[i].State = store.NotRegistered
		}
		cur.AuthPending, cur.ServerName = false, ""
		return nil
	})
	if err != nil {
		h.log.Warn("could not mark a user the S-CSCF refused as not registered", pii.Identity("impi", s.IMPI),
			slog.String("error", pii.Redact(err.Error())))
		return
	}
	if r.Code == cx.ErrorUserUnknown {
		h.metrics.Count("push.ppr.user_unknown", 1)
		return
	}
	h.metrics.Count("push.ppr.data_refused", 1)
	err = n.Deregister(ctx, &cx.RTR{UserName: s.IMPI, DeregistrationReason: cx.DeregistrationReason{Code: cx.ServerChange}})
	if err != nil {
		h.log.Warn("could not deregister a user whose S-CSCF refused new data", pii.Identity("impi", s.IMPI),
			slog.String("error", pii.Redact(err.Error())))
	}
}

func (h *HSS) send(ctx context.Context, n Notifier, s *store.Subscription, p *store.ServiceProfile, ps push) error {
	if ps.deregister {
		return n.Deregister(ctx, &cx.RTR{
			UserName: s.IMPI, PublicIdentities: ps.impus,
			DeregistrationReason: cx.DeregistrationReason{Code: ps.reason},
		})
	}
	r := &cx.PPR{UserName: s.IMPI}
	if ps.set >= 0 {
		if p == nil {
			return errors.New("hss: the service profile could not be read for User-Data")
		}
		data, err := userData(s, ps.set, p)
		if errors.Is(err, ifc.ErrTooLarge) {
			h.metrics.Count("userdata.too_large", 1)
		}
		if err != nil {
			return err
		}
		r.UserData = data
	}
	if ps.charging {
		r.ChargingInformation = charging(s.Charging)
	}
	if ps.digest {
		item, err := h.digestItem(s)
		if err != nil {
			return err
		}
		r.AuthDataItem = &item
	}
	if r.UserData == nil && r.ChargingInformation == nil && r.AuthDataItem == nil {
		return nil // charging information was removed: nothing to push
	}
	return n.PushProfile(ctx, r)
}
