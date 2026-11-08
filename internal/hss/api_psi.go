package hss

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// psiRequest is the body of PUT /v1/chatbot-psi: the PSI only. The AS name
// comes from HSS_RCS_AS_URI and the activation state is always active
// (ADR 0009 §3), so a request cannot route the range elsewhere.
type psiRequest struct {
	PSI string `json:"psi"`
}

type psiResponse struct {
	PSI        string `json:"psi"`
	ServerName string `json:"server_name"`
	Active     bool   `json:"active"`
	Version    int64  `json:"version"`
}

func writePSI(w http.ResponseWriter, status int, p *store.WildcardedPSI) {
	w.Header().Set("ETag", etag(p.Version))
	writeJSON(w, status, psiResponse{PSI: p.PSI, ServerName: p.ServerName, Active: p.Active, Version: p.Version})
}

func (a *API) getChatbotPSI(w http.ResponseWriter, r *http.Request, _ Scope) error {
	p, err := a.h.store.WildcardedPSI(r.Context())
	if err != nil {
		return err
	}
	writePSI(w, http.StatusOK, p)
	return nil
}

// putChatbotPSI writes the one wildcarded PSI, creating it (201) or
// replacing it (200). With If-Match it replaces only that version. A write
// that loses to another task's reads again, as subscription writes do.
func (a *API) putChatbotPSI(w http.ResponseWriter, r *http.Request, _ Scope) error {
	if a.chatbotDomain.Name() == "" {
		return fail(http.StatusConflict, "RCS_CHATBOT_DOMAIN is unset: hss has no chatbot range")
	}
	want, err := ifMatch(r)
	if err != nil {
		return err
	}
	var req psiRequest
	if err := decodeBody(w, r, maxSmallBody, &req); err != nil {
		return err
	}
	if _, err := parseChatbotRange(req.PSI, a.chatbotDomain); err != nil {
		return fail(http.StatusBadRequest, "psi: "+err.Error())
	}
	next := &store.WildcardedPSI{PSI: req.PSI, ServerName: a.chatbotAS, Active: true}
	for attempt := 0; attempt < maxUpdateAttempts; attempt++ {
		cur, err := a.h.store.WildcardedPSI(r.Context())
		switch {
		case errors.Is(err, store.ErrNotFound):
			cur = nil
		case err != nil:
			return err
		}
		if want != 0 && (cur == nil || cur.Version != want) {
			return errPrecondition
		}
		saved, err := a.h.store.PutWildcardedPSI(r.Context(), cur, next)
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrExists) {
			continue
		}
		if err != nil {
			return err
		}
		// The audit line shows the change (#679): before and after,
		// through pii like every URI, so a PSI that names a chatbot is
		// masked, its hint still telling one value from another.
		status, before := http.StatusCreated, slog.String("psi_before", "")
		if cur != nil {
			status, before = http.StatusOK, pii.URI("psi_before", cur.PSI)
		}
		noteAudit(r, before, pii.URI("psi_after", saved.PSI), slog.Int64("psi_version", saved.Version))
		writePSI(w, status, saved)
		return nil
	}
	return errContention
}
