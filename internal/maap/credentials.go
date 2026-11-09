package maap

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
)

// credentialAPI is the operator's credential routes,
// /v1/chatbots/{id}/credentials (ADR 0009 §7): issue the next, switch,
// revoke the old. The secret is in the issue's answer only; the store
// keeps its digest, and no answer or log line carries either after.
type credentialAPI struct {
	registry store.Registry
	creds    store.Credentials
	// random is crypto/rand.Reader but in tests.
	random io.Reader
	now    func() time.Time
}

// mountCredentials serves ca's routes on a, for the operator only.
func (a *internalAPI) mountCredentials(ca *credentialAPI) {
	a.route("POST /v1/chatbots/{id}/credentials", "issue_credential", scopeOperator, ca.issue)
	a.route("GET /v1/chatbots/{id}/credentials", "list_credentials", scopeOperator, ca.list)
	a.route("DELETE /v1/chatbots/{id}/credentials/{key_id}", "revoke_credential", scopeOperator, ca.revoke)
}

// secretBytes is a secret's length: 256 random bits (ADR 0009 §7).
const secretBytes = 32

var keyIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// issued is the answer to an issue: the bearer token, <key ID>.<secret>,
// shown this once.
type issued struct {
	KeyID   string    `json:"key_id"`
	Token   string    `json:"token"`
	Created time.Time `json:"created"`
}

// listed is a credential as the list shows it, without its digest.
type listed struct {
	KeyID    string    `json:"key_id"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"last_used,omitzero"`
}

// issue gives the chatbot a new credential under the registration read, so
// that a deletion meanwhile refuses it: 201, or 409 with two live.
func (ca *credentialAPI) issue(c *call) error {
	id, err := c.chatbotID()
	if err != nil {
		return err
	}
	ctx := c.r.Context()
	ch, err := ca.registry.Chatbot(ctx, id)
	if err != nil {
		return c.storeError(err, false)
	}
	raw := make([]byte, 16+secretBytes)
	if _, err := io.ReadFull(ca.random, raw); err != nil {
		return fail(http.StatusInternalServerError, "no random secret could be drawn")
	}
	keyID, secret := keyIDEncoding.EncodeToString(raw[:16]), base64.RawURLEncoding.EncodeToString(raw[16:])
	cred := store.Credential{
		KeyID: keyID, Chatbot: id, Registration: ch.Registration,
		Digest: sha256.Sum256([]byte(secret)), Created: store.Seconds(ca.now()),
	}
	err = ca.creds.Issue(ctx, cred)
	if errors.Is(err, store.ErrTooMany) {
		return fail(http.StatusConflict, "the chatbot has two live credentials: revoke one first")
	}
	if err != nil {
		return c.storeError(err, true)
	}
	c.audit = append(c.audit, slog.String("key_id", keyID))
	writeJSON(c.w, http.StatusCreated, issued{KeyID: keyID, Token: keyID + "." + secret, Created: cred.Created})
	return nil
}

// list answers the chatbot's live credentials, oldest first, by key ID.
func (ca *credentialAPI) list(c *call) error {
	id, err := c.chatbotID()
	if err != nil {
		return err
	}
	ctx := c.r.Context()
	if _, err := ca.registry.Chatbot(ctx, id); err != nil {
		return c.storeError(err, false)
	}
	creds, err := ca.creds.ChatbotCredentials(ctx, id)
	if err != nil {
		return c.credentialError(err)
	}
	out := make([]listed, 0, len(creds))
	for _, cr := range creds {
		out = append(out, listed{KeyID: cr.KeyID, Created: cr.Created, LastUsed: cr.LastUsed})
	}
	writeJSON(c.w, http.StatusOK, map[string][]listed{"credentials": out})
	return nil
}

// revoke deletes the credential at once in the store: 204, also for a
// slot a revoke cut short left, or 404 when the chatbot has none with the
// key ID, which a repeat of a revoke whose answer was lost gets too. It
// does not read the chatbot, so that what a deletion left can be revoked
// too.
func (ca *credentialAPI) revoke(c *call) error {
	id, err := c.chatbotID()
	if err != nil {
		return err
	}
	keyID := c.r.PathValue("key_id")
	if !store.ValidKeyID(keyID) {
		return fail(http.StatusNotFound, "the chatbot has no credential with this key ID")
	}
	c.audit = append(c.audit, slog.String("key_id", keyID))
	err = ca.creds.Revoke(c.r.Context(), id, keyID)
	if errors.Is(err, store.ErrNotFound) {
		return fail(http.StatusNotFound, "the chatbot has no credential with this key ID")
	}
	if err != nil {
		return c.credentialError(err)
	}
	c.w.WriteHeader(http.StatusNoContent)
	return nil
}

// credentialError answers an error of the credentials store. Its
// ErrInvalid is a stored credential this release cannot read, damaged or
// written by a newer one: maap's fault, 500, never the request's (#745
// review). The rest is answered as for the registry.
func (c *call) credentialError(err error) error {
	if !errors.Is(err, store.ErrInvalid) {
		return c.storeError(err, false)
	}
	c.audit = append(c.audit, slog.String("store_error", err.Error()))
	return &apiError{status: http.StatusInternalServerError, message: "a stored credential cannot be read"}
}
