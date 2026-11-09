package maap

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
)

// chatbotAPI is the operator's registry routes, /v1/chatbots[/{id}] (ADR
// 0009 §7): the operator fixes everything a chatbot is, and every change
// adds its values before and after to the request's audit line, as
// store.AuditChanges writes them (the lead's decision on #709).
type chatbotAPI struct {
	decoder  *decoder
	registry store.Registry
	// domain is RCS_CHATBOT_DOMAIN: a URI is registered only in its normal
	// form at this host, which the registry, knowing no setting, cannot
	// check.
	domain chatbot.Domain
	rules  fieldRules
}

// mountChatbots serves cb's routes on a, for the operator only.
func (a *internalAPI) mountChatbots(cb *chatbotAPI) {
	a.route("POST /v1/chatbots", "register_chatbot", scopeOperator, cb.register)
	a.route("GET /v1/chatbots/{id}", "read_chatbot", scopeOperator, cb.read)
}

// register stores a new chatbot, active, with its URI in normal form: 201
// with the chatbot, or 409 when its ID or URI is taken or its ID was a
// deleted chatbot's.
func (cb *chatbotAPI) register(c *call) error {
	var b chatbotBody
	if err := cb.decoder.decode(c, maxOperatorBody, &b); err != nil {
		return err
	}
	if !validID(b.ID) {
		return fail(http.StatusBadRequest, "id is not 1–64 letters, digits, - or _")
	}
	c.audit = append(c.audit, slog.String("chatbot", b.ID))
	uri, err := cb.domain.Normalise(b.URI)
	if err != nil {
		// The error names the rule broken, never the URI.
		return fail(http.StatusBadRequest, "uri: "+err.Error())
	}
	ch := store.Chatbot{ID: b.ID, URI: uri, State: store.Active}
	if err := cb.rules.apply(&ch, b); err != nil {
		return err
	}
	c.releaseBody()
	got, err := cb.registry.Register(c.r.Context(), ch)
	if err != nil {
		return c.storeError(err, true)
	}
	c.audit = append(c.audit, store.AuditChanges(store.Chatbot{}, got)...)
	c.w.Header().Set("Location", "/v1/chatbots/"+got.ID)
	writeJSON(c.w, http.StatusCreated, got)
	return nil
}

// read answers the chatbot with the path's ID.
func (cb *chatbotAPI) read(c *call) error {
	id, err := c.chatbotID()
	if err != nil {
		return err
	}
	got, err := cb.registry.Chatbot(c.r.Context(), id)
	if err != nil {
		return c.storeError(err, false)
	}
	writeJSON(c.w, http.StatusOK, got)
	return nil
}

// chatbotID returns the path's chatbot ID and names it in the audit line;
// an ID no chatbot can have is 404, and is not logged.
func (c *call) chatbotID() (string, error) {
	id := c.r.PathValue("id")
	if !validID(id) {
		return "", fail(http.StatusNotFound, "no chatbot has this ID")
	}
	c.audit = append(c.audit, slog.String("chatbot", id))
	return id, nil
}

func validID(id string) bool {
	const idBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	return id != "" && len(id) <= store.MaxIDBytes && strings.Trim(id, idBytes) == ""
}

// storeError answers a registry error (the #708 handovers on #709). A
// write's ErrInvalid is a record this API let through, so the request's
// fault; a read's is a damaged record, or one a newer release wrote, so
// maap's. Anything else is the store failing, 503: the operator repeats
// the request. The error, which names the operation and an AWS error code
// only, joins the audit line of a 5xx.
func (c *call) storeError(err error, write bool) error {
	var ae *apiError
	switch {
	case errors.Is(err, store.ErrNotFound):
		return fail(http.StatusNotFound, "no chatbot has this ID")
	case errors.Is(err, store.ErrExists):
		return fail(http.StatusConflict, "a chatbot with this ID is registered")
	case errors.Is(err, store.ErrDeleted):
		return fail(http.StatusConflict, "this ID was a deleted chatbot's, and an ID is never registered again")
	case errors.Is(err, store.ErrURITaken):
		return fail(http.StatusConflict, "another chatbot holds this URI")
	case errors.Is(err, store.ErrConflict):
		return fail(http.StatusConflict, "the chatbot changed meanwhile; read it and try again")
	case errors.Is(err, store.ErrInvalid) && write:
		return fail(http.StatusBadRequest, "the chatbot breaks a rule of the registry")
	case errors.Is(err, store.ErrInvalid):
		ae = &apiError{status: http.StatusInternalServerError, message: "the stored chatbot cannot be read"}
	default:
		ae = &apiError{http.StatusServiceUnavailable, "the registry is unavailable; try again", "1"}
	}
	c.audit = append(c.audit, slog.String("store_error", err.Error()))
	return ae
}
