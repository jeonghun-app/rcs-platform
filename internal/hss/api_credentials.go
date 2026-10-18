package hss

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// passwordBytes is the entropy of an issued password: 192 bits, above the
// 128 ADR 0007 asks for, as 32 base64url characters that any client can
// store and type.
const passwordBytes = 24

type issuedCredential struct {
	IMPI string `json:"impi"`
	// Username is the Digest user name: the IMPI.
	Username string `json:"username"`
	Realm    string `json:"realm"`
	Password string `json:"password"`
}

// issueIMSCredential generates the SIP Digest password of the IMS realm
// (TS 24.229 §5.1.1.2.3: the IMPI is the user name) and stores only its HA1.
// The password is in this response and nowhere else; acs hands it to the
// client (ADR 0006). A registered user's S-CSCF gets the new HA1 by PPR
// (TS 29.228 §6.5.2.4).
func (a *API) issueIMSCredential(w http.ResponseWriter, r *http.Request, caller Scope) error {
	return a.issue(w, r, caller, a.h.imsRealm, true)
}

// issueFTCredential generates the HTTP Digest password of the FT realm,
// which acs provisions as the FT content server user and password (RCC.14)
// and ft-server verifies through getFTCredential.
func (a *API) issueFTCredential(w http.ResponseWriter, r *http.Request, caller Scope) error {
	if a.h.ftRealm == "" {
		return fail(http.StatusNotImplemented, "this HSS has no FT realm (HSS_FT_REALM)")
	}
	return a.issue(w, r, caller, a.h.ftRealm, false)
}

func (a *API) issue(w http.ResponseWriter, r *http.Request, caller Scope, realm string, pushToSCSCF bool) error {
	impi, err := a.impi(r)
	if err != nil {
		return err
	}
	raw := make([]byte, passwordBytes)
	if _, err := io.ReadFull(a.h.rand, raw); err != nil {
		return fmt.Errorf("hss: reading a password: %w", err)
	}
	password := []byte(base64.RawURLEncoding.EncodeToString(raw))
	clear(raw)
	defer clear(password)
	var pushes []push
	saved, err := a.h.update(r.Context(), impi, func(s *store.Subscription) error {
		if err := managedByACS(caller, s); err != nil {
			return err
		}
		d, err := a.h.sealDigest(impi, realm, password)
		if err != nil {
			return err
		}
		setDigest(s, d)
		pushes = nil
		if pushToSCSCF {
			pushes = digestPushes(s)
		}
		return nil
	})
	if err != nil {
		return err
	}
	a.notifyChange(r, saved, pushes)
	writeJSON(w, http.StatusCreated, issuedCredential{IMPI: impi, Username: impi, Realm: realm, Password: string(password)})
	return nil
}

type ftCredential struct {
	IMPI      string `json:"impi"`
	IMPU      string `json:"impu"`
	Realm     string `json:"realm"`
	Algorithm string `json:"algorithm"`
	HA1       string `json:"ha1"`
}

// getFTCredential answers ft-server's lookup (the contract of
// docs/api/hss.yaml): the HA1 of the FT credential for the
// algorithm asked for, and the IMPU that owns the subscriber's files, the
// first identity that is not barred. A subscription with none of those is
// unknown to ft-server: 404 either way.
func (a *API) getFTCredential(w http.ResponseWriter, r *http.Request, _ Scope) error {
	impi, err := a.impi(r)
	if err != nil {
		return err
	}
	var alg digest.Algorithm
	switch q := r.URL.Query()["algorithm"]; {
	case len(q) == 1 && q[0] == string(digest.MD5):
		alg = digest.MD5
	case len(q) == 1 && q[0] == string(digest.SHA256):
		alg = digest.SHA256
	default:
		return fail(http.StatusBadRequest, "algorithm: one of MD5 and SHA-256 is required")
	}
	notFound := fail(http.StatusNotFound, "no FT credential")
	if a.h.ftRealm == "" {
		return notFound
	}
	s, err := a.h.store.Subscription(r.Context(), impi)
	if err != nil {
		return err
	}
	d := s.DigestFor(a.h.ftRealm)
	owner := ""
	for _, p := range s.PublicIdentities {
		if !p.Barred {
			owner = p.IMPU
			break
		}
	}
	if d == nil || owner == "" {
		return notFound
	}
	ha1, err := a.h.openHA1(s.IMPI, d, alg)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, ftCredential{IMPI: s.IMPI, IMPU: owner, Realm: d.Realm, Algorithm: string(alg), HA1: ha1})
	return nil
}
