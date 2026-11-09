package maap

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
)

// maxChangeAttempts bounds how often a change is applied again to a fresh
// read when another write came first. A change sets values rather than
// adding to them, so applying it to the newer record is what the operator
// asked; past the bound the answer is 409.
const maxChangeAttempts = 3

// deleteBudget bounds the other tables' deletions within one request,
// under the internal listener's 30 s write timeout (#753 review: a
// chatbot with many aliases outran it, and the operator saw a dropped
// connection). Past it the answer is 503 with Retry-After, and the next
// request goes on where this one stopped, since each table deletes what
// it still finds.
const deleteBudget = 20 * time.Second

// change sets the fields the body gives (PATCH): 200 with the chatbot. The
// ID and URI never change: a chatbot that needs another URI is deleted and
// registered again (the lead's decision on #708). The body's slot is held
// over one registry read, since the rules between fields need the record.
func (cb *chatbotAPI) change(c *call) error {
	id, err := c.chatbotID()
	if err != nil {
		return err
	}
	var b chatbotBody
	if err := cb.decoder.decode(c, maxOperatorBody, &b); err != nil {
		return err
	}
	if b.ID != "" || b.URI != "" {
		return fail(http.StatusBadRequest, "id and uri never change: delete the chatbot and register it again")
	}
	return cb.update(c, id, func(ch *store.Chatbot) error { return cb.rules.apply(ch, b) })
}

// setState returns the handler that suspends or resumes a chatbot: only
// its state changes, and a suspended chatbot keeps its record (ADR 0009
// §11).
func (cb *chatbotAPI) setState(s store.State) handler {
	return func(c *call) error {
		id, err := c.chatbotID()
		if err != nil {
			return err
		}
		return cb.update(c, id, func(ch *store.Chatbot) error { ch.State = s; return nil })
	}
}

// update applies edit to the chatbot as read and writes it on the
// condition of that read, again from a fresh read if another write came
// first.
func (cb *chatbotAPI) update(c *call, id string, edit func(*store.Chatbot) error) error {
	ctx := c.r.Context()
	for attempt := 1; ; attempt++ {
		old, err := cb.registry.Chatbot(ctx, id)
		if err != nil {
			return c.storeError(err, false)
		}
		next := old
		if err := edit(&next); err != nil {
			return err
		}
		c.releaseBody()
		got, err := cb.registry.Update(ctx, old, next)
		if errors.Is(err, store.ErrConflict) && attempt < maxChangeAttempts {
			continue
		}
		if err != nil {
			return c.storeError(err, true)
		}
		c.audit = append(c.audit, store.AuditChanges(old, got)...)
		writeJSON(c.w, http.StatusOK, got)
		return nil
	}
}

// remove deletes the chatbot, which frees its URI and leaves its ID never
// to be registered again, then every item another table keeps of it: 204,
// also for a chatbot already gone. The registry's deletion either finishes
// or fails, and so does each table's; one that runs out of deleteBudget
// stops between items. So a 503 part way is answered by sending the
// request again, which goes on with the rest (#708 handover).
func (cb *chatbotAPI) remove(c *call) error {
	id, err := c.chatbotID()
	if err != nil {
		return err
	}
	ctx := c.r.Context()
	// Read only for the audit line: a repeat finds nothing, and a record
	// this release cannot read is deleted all the same.
	old, err := cb.registry.Chatbot(ctx, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrInvalid) {
		return c.storeError(err, false)
	}
	if err != nil {
		old = store.Chatbot{}
	}
	if err := cb.registry.DeleteChatbot(ctx, id); err != nil {
		return c.storeError(err, false)
	}
	if old.ID != "" {
		c.audit = append(c.audit, store.AuditChanges(old, store.Chatbot{})...)
	}
	dctx, cancel := context.WithTimeout(ctx, cmp.Or(cb.deleteBudget, deleteBudget))
	defer cancel()
	for _, d := range cb.deleters {
		err := d.DeleteChatbot(dctx, id)
		switch {
		case err != nil && errors.Is(err, context.DeadlineExceeded) && dctx.Err() != nil && ctx.Err() == nil:
			c.audit = append(c.audit, slog.Bool("deletion_unfinished", true))
			return &apiError{http.StatusServiceUnavailable, "the deletion is not finished; send it again", "1"}
		case err != nil:
			return c.storeError(err, false)
		}
	}
	c.w.WriteHeader(http.StatusNoContent)
	return nil
}
