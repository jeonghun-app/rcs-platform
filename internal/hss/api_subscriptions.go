package hss

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/milenage"
)

// The JSON forms of docs/api/hss.yaml. Request and response
// types are separate from the store's, so the wire format is stable and a
// response can only carry what is listed here: no secret has a field.

type identityJSON struct {
	IMPU         string `json:"impu"`
	Barred       bool   `json:"barred"`
	IdentityType string `json:"identity_type,omitempty"`
	ImplicitSet  int    `json:"implicit_set"`
	// RegistrationState is read-only.
	RegistrationState string `json:"registration_state,omitempty"`
}

type chargingJSON struct {
	PrimaryEventChargingFunctionName        string `json:"primary_event_charging_function_name,omitempty"`
	SecondaryEventChargingFunctionName      string `json:"secondary_event_charging_function_name,omitempty"`
	PrimaryChargingCollectionFunctionName   string `json:"primary_charging_collection_function_name,omitempty"`
	SecondaryChargingCollectionFunctionName string `json:"secondary_charging_collection_function_name,omitempty"`
}

// subscriptionRequest is the body of POST and PUT.
type subscriptionRequest struct {
	IMPI                string         `json:"impi"`
	IMSI                string         `json:"imsi,omitempty"`
	PublicIdentities    []identityJSON `json:"public_identities"`
	ServiceProfile      string         `json:"service_profile,omitempty"`
	ChargingInformation *chargingJSON  `json:"charging_information,omitempty"`
	// ACSManaged hands the subscription's credentials to acs.
	ACSManaged bool `json:"acs_managed"`
}

type credentialsJSON struct {
	AKA       bool `json:"aka"`
	IMSDigest bool `json:"ims_digest"`
	FTDigest  bool `json:"ft_digest"`
}

type subscriptionResponse struct {
	IMPI                  string          `json:"impi"`
	IMSI                  string          `json:"imsi,omitempty"`
	PublicIdentities      []identityJSON  `json:"public_identities"`
	ServiceProfile        string          `json:"service_profile"`
	ChargingInformation   *chargingJSON   `json:"charging_information,omitempty"`
	ACSManaged            bool            `json:"acs_managed"`
	Credentials           credentialsJSON `json:"credentials"`
	ServerName            string          `json:"server_name,omitempty"`
	AuthenticationPending bool            `json:"authentication_pending"`
	Version               int64           `json:"version"`
}

const identityTypePublicUser = "PUBLIC_USER_IDENTITY"

func (a *API) response(s *store.Subscription) subscriptionResponse {
	out := subscriptionResponse{
		IMPI: s.IMPI, IMSI: s.IMSI, ServiceProfile: s.Profile, ServerName: s.ServerName,
		AuthenticationPending: s.AuthPending, Version: s.Version, ACSManaged: s.ACSManaged,
		Credentials: credentialsJSON{
			AKA:       s.AKA != nil,
			IMSDigest: s.DigestFor(a.h.imsRealm) != nil,
			FTDigest:  a.h.ftRealm != "" && s.DigestFor(a.h.ftRealm) != nil,
		},
	}
	for _, p := range s.PublicIdentities {
		out.PublicIdentities = append(out.PublicIdentities, identityJSON{
			IMPU: p.IMPU, Barred: p.Barred, IdentityType: identityTypePublicUser,
			ImplicitSet: p.ImplicitSet, RegistrationState: p.State.String(),
		})
	}
	if c := s.Charging; c != nil {
		out.ChargingInformation = &chargingJSON{
			c.PrimaryEventChargingFunctionName, c.SecondaryEventChargingFunctionName,
			c.PrimaryChargingCollectionFunctionName, c.SecondaryChargingCollectionFunctionName,
		}
	}
	return out
}

// maxImplicitSet bounds the implicit set numbers; they are labels, and a
// subscription has at most store.MaxPublicIdentities sets.
const maxImplicitSet = 1 << 16

// apply validates the provisioned fields of a request and copies them into
// s, leaving the Cx state and the credentials alone.
func (a *API) apply(req *subscriptionRequest, s *store.Subscription) error {
	if req.IMSI != "" {
		if err := identity.ValidIMSI(req.IMSI); err != nil {
			return fail(http.StatusBadRequest, "imsi: "+err.Error())
		}
	}
	if n := len(req.PublicIdentities); n == 0 || n > store.MaxPublicIdentities {
		return fail(http.StatusBadRequest, "public_identities: 1 to 32 are required")
	}
	ids := make([]store.PublicIdentity, 0, len(req.PublicIdentities))
	seen := map[string]bool{}
	for i, p := range req.PublicIdentities {
		where := "public_identities[" + strconv.Itoa(i) + "]"
		impu, ok := identity.CanonicalIMPU(p.IMPU)
		switch {
		case !ok:
			return fail(http.StatusBadRequest, where+".impu: "+identity.ErrIMPU.Error())
		case seen[impu]:
			return fail(http.StatusBadRequest, where+".impu: listed twice")
		case p.IdentityType != "" && p.IdentityType != identityTypePublicUser:
			return fail(http.StatusBadRequest, where+".identity_type: only PUBLIC_USER_IDENTITY is supported")
		case p.ImplicitSet < 0 || p.ImplicitSet > maxImplicitSet:
			return fail(http.StatusBadRequest, where+".implicit_set: out of range")
		case p.RegistrationState != "":
			return fail(http.StatusBadRequest, where+".registration_state: read-only")
		}
		seen[impu] = true
		ids = append(ids, store.PublicIdentity{IMPU: impu, Barred: p.Barred, ImplicitSet: p.ImplicitSet})
	}
	profile := req.ServiceProfile
	if profile == "" {
		profile = a.defaultProfile
	}
	if err := ValidProfileID(profile); err != nil {
		return fail(http.StatusBadRequest, "service_profile: "+err.Error())
	}
	var ch *store.ChargingInformation
	if c := req.ChargingInformation; c != nil {
		names := []string{c.PrimaryEventChargingFunctionName, c.SecondaryEventChargingFunctionName,
			c.PrimaryChargingCollectionFunctionName, c.SecondaryChargingCollectionFunctionName}
		for _, n := range names {
			if n != "" && !isDiameterURI(n) {
				return fail(http.StatusBadRequest, "charging_information: names must be aaa:// or aaas:// DiameterURIs")
			}
		}
		// TS 29.228 Table 6.1.2.2: a primary function is required.
		if names[0] == "" && names[2] == "" {
			return fail(http.StatusBadRequest, "charging_information: a primary event or collection function is required")
		}
		ch = &store.ChargingInformation{
			PrimaryEventChargingFunctionName: names[0], SecondaryEventChargingFunctionName: names[1],
			PrimaryChargingCollectionFunctionName: names[2], SecondaryChargingCollectionFunctionName: names[3],
		}
	}
	// Identities keep their state where they stay; reconcile decides.
	for i := range ids {
		if old := s.Identity(ids[i].IMPU); old != nil {
			ids[i].State = old.State
		}
	}
	s.IMSI, s.PublicIdentities, s.Profile, s.Charging, s.ACSManaged = req.IMSI, ids, profile, ch, req.ACSManaged
	return nil
}

// isDiameterURI checks the form of a DiameterURI (RFC 6733 §4.3.1) loosely:
// the scheme and an FQDN, as the charging names need.
func isDiameterURI(s string) bool {
	rest, ok := strings.CutPrefix(s, "aaa://")
	if !ok {
		rest, ok = strings.CutPrefix(s, "aaas://")
	}
	if !ok || len(s) > store.MaxIdentityLength {
		return false
	}
	host := rest
	if i := strings.IndexAny(rest, ":;"); i >= 0 {
		host = rest[:i]
	}
	if !identity.IsDomainName(host) {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if c := rest[i]; c <= ' ' || c >= 0x7f {
			return false
		}
	}
	return true
}

func (a *API) impi(r *http.Request) (string, error) {
	impi := r.PathValue("impi")
	if err := identity.ValidIMPI(impi); err != nil {
		return "", fail(http.StatusBadRequest, "impi: "+err.Error())
	}
	return impi, nil
}

func (a *API) createSubscription(w http.ResponseWriter, r *http.Request, _ Scope) error {
	var req subscriptionRequest
	if err := decodeBody(w, r, maxSubscriptionBody, &req); err != nil {
		return err
	}
	if err := identity.ValidIMPI(req.IMPI); err != nil {
		return fail(http.StatusBadRequest, "impi: "+err.Error())
	}
	s := &store.Subscription{IMPI: req.IMPI}
	if err := a.apply(&req, s); err != nil {
		return err
	}
	saved, err := a.h.store.CreateSubscription(r.Context(), s)
	if err != nil {
		return err
	}
	// An IMPI may hold '?' and '#' (RFC 7542), which a URL must escape.
	w.Header().Set("Location", "/v1/subscriptions/"+url.PathEscape(saved.IMPI))
	w.Header().Set("ETag", etag(saved.Version))
	writeJSON(w, http.StatusCreated, a.response(saved))
	return nil
}

func (a *API) getSubscription(w http.ResponseWriter, r *http.Request, caller Scope) error {
	impi, err := a.impi(r)
	if err != nil {
		return err
	}
	s, err := a.h.store.Subscription(r.Context(), impi)
	if err != nil {
		return err
	}
	if err := managedByACS(caller, s); err != nil {
		return err
	}
	w.Header().Set("ETag", etag(s.Version))
	writeJSON(w, http.StatusOK, a.response(s))
	return nil
}

func (a *API) putSubscription(w http.ResponseWriter, r *http.Request, _ Scope) error {
	impi, err := a.impi(r)
	if err != nil {
		return err
	}
	want, err := ifMatch(r)
	if err != nil {
		return err
	}
	var req subscriptionRequest
	if err := decodeBody(w, r, maxSubscriptionBody, &req); err != nil {
		return err
	}
	if req.IMPI != "" && req.IMPI != impi {
		return fail(http.StatusBadRequest, "impi: differs from the path")
	}
	var pushes []push
	saved, err := a.h.update(r.Context(), impi, func(s *store.Subscription) error {
		if want != 0 && s.Version != want {
			return errPrecondition
		}
		old := clone(s)
		if err := a.apply(&req, s); err != nil {
			return err
		}
		pushes = reconcile(old, s, old.Profile != s.Profile)
		return nil
	})
	if err != nil {
		return err
	}
	a.notifyChange(r, saved, pushes)
	w.Header().Set("ETag", etag(saved.Version))
	writeJSON(w, http.StatusOK, a.response(saved))
	return nil
}

// notifyChange sends what a stored change requires of the S-CSCF.
func (a *API) notifyChange(r *http.Request, s *store.Subscription, pushes []push) {
	if len(pushes) == 0 {
		return
	}
	ctx, cancel := a.pushContext(r)
	defer cancel()
	var p *store.ServiceProfile
	if needsProfile(pushes) {
		// Without the profile only the RTRs can go; h.send reports the PPRs.
		p, _ = a.h.store.Profile(ctx, s.Profile)
	}
	a.h.notify(ctx, a.notifier, s, p, pushes)
}

func needsProfile(pushes []push) bool {
	for _, p := range pushes {
		if !p.deregister && p.set >= 0 {
			return true
		}
	}
	return false
}

func (a *API) deleteSubscription(w http.ResponseWriter, r *http.Request, _ Scope) error {
	impi, err := a.impi(r)
	if err != nil {
		return err
	}
	want, err := ifMatch(r)
	if err != nil {
		return err
	}
	deleted, err := a.h.delete(r.Context(), impi, want)
	if err != nil {
		return err
	}
	a.notifyChange(r, deleted, deletePushes(deleted))
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// delete deletes a subscription, retrying when a Cx write changes it in
// between, and returns it as it was deleted.
func (h *HSS) delete(ctx context.Context, impi string, want int64) (*store.Subscription, error) {
	defer h.lock(impi)()
	for attempt := 0; attempt < maxUpdateAttempts; attempt++ {
		s, err := h.store.Subscription(ctx, impi)
		if err != nil {
			return nil, err
		}
		if want != 0 && s.Version != want {
			return nil, errPrecondition
		}
		err = h.store.DeleteSubscription(ctx, s)
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		return s, err
	}
	return nil, errContention
}

// akaRequest is the body of PUT /aka. Exactly one of OPc and OP is given;
// OP is turned into OPc and forgotten (TS 35.206 §4).
type akaRequest struct {
	K   string `json:"k"`
	OPc string `json:"opc,omitempty"`
	OP  string `json:"op,omitempty"`
	AMF string `json:"amf,omitempty"`
	SQN string `json:"sqn,omitempty"`
}

// defaultAMF has the AMF separation bit clear and the other bits zero, the
// usual value for IMS (TS 33.102 Annex H leaves the rest to the operator).
var defaultAMF = [2]byte{0x80, 0x00}

func hexField(name, v string, n int) ([]byte, error) {
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != n {
		return nil, fail(http.StatusBadRequest, name+": must be "+strconv.Itoa(2*n)+" hexadecimal digits")
	}
	return b, nil
}

func (a *API) putAKA(w http.ResponseWriter, r *http.Request, _ Scope) error {
	impi, err := a.impi(r)
	if err != nil {
		return err
	}
	var req akaRequest
	if err := decodeBody(w, r, maxSmallBody, &req); err != nil {
		return err
	}
	k, err := hexField("k", req.K, milenage.KeySize)
	if err != nil {
		return err
	}
	defer clear(k)
	var opc [milenage.KeySize]byte
	switch {
	case (req.OPc == "") == (req.OP == ""):
		return fail(http.StatusBadRequest, "exactly one of opc and op is required")
	case req.OPc != "":
		b, err := hexField("opc", req.OPc, milenage.KeySize)
		if err != nil {
			return err
		}
		opc = [milenage.KeySize]byte(b)
		clear(b)
	default:
		b, err := hexField("op", req.OP, milenage.KeySize)
		if err != nil {
			return err
		}
		opc = milenage.DeriveOPc([milenage.KeySize]byte(k), [milenage.KeySize]byte(b))
		clear(b)
	}
	defer clear(opc[:])
	amf := defaultAMF
	if req.AMF != "" {
		b, err := hexField("amf", req.AMF, milenage.AMFSize)
		if err != nil {
			return err
		}
		amf = [2]byte(b)
	}
	var sqn *uint64
	if req.SQN != "" {
		b, err := hexField("sqn", req.SQN, milenage.SQNSize)
		if err != nil {
			return err
		}
		v := uint64(milenage.SQNFromBytes([milenage.SQNSize]byte(b)))
		sqn = &v
	}
	_, err = a.h.update(r.Context(), impi, func(s *store.Subscription) error {
		next := uint64(0)
		switch {
		case sqn != nil:
			next = *sqn
		case s.AKA != nil:
			next = s.AKA.SQN // re-keying keeps the counter unless told
		}
		aka, err := a.h.sealAKA(impi, [milenage.KeySize]byte(k), opc, amf, next)
		if err != nil {
			return err
		}
		s.AKA = aka
		return nil
	})
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
