// Package regevent is the S-CSCF's notifier of the reg event package (RFC
// 3680, TS 24.229 §5.4.2.1): it answers SUBSCRIBE requests for the state of a
// registration, from the P-CSCF that serves it and from the UE itself, and
// sends NOTIFY requests when the registration changes.
//
// A subscription is a state.Subscription in the store every scscf instance
// shares, so any instance answers a refresh and notifies a change. Its
// dialog is stored with it, and its NOTIFY CSeq and reginfo version come
// from the store's atomic NextNotify, so two instances never send the same
// pair (ADR 0005). NextNotify takes the version of the set's record the
// NOTIFY was read from and refuses an older one than the last, so a NOTIFY
// with a higher version never carries an older state.
//
// Who may subscribe (TS 24.229 §5.4.2.1.1): the P-CSCF, whose
// P-Asserted-Identity is the Path URI it put on a live binding of the
// registration (§5.2.3), or the UE, whose P-Asserted-Identity is one of the
// set's identities not barred. Anyone else gets 403, as does a SUBSCRIBE
// beyond Config.MaxPerSet; one beyond Config.MaxPerSubscriber replaces the
// subscriber's oldest. A subscription watches the set, by its key and
// incarnation, that the identity was in when it was made, and ends, with a
// NOTIFY that says terminated, deactivated, when that set's record goes,
// the identity leaves it, it has no live binding, the UE's own binding
// goes, or the P-CSCF serves none of its bindings; a NOTIFY never carries
// another set's state, nor bindings to a P-CSCF that is not on them.
//
// An in-dialog SUBSCRIBE, a refresh or Expires 0, must match a stored
// subscription's dialog (Call-ID, tags, Event id and a CSeq above the
// last) or gets 481. A P-CSCF's must also assert the Path of a live binding,
// which becomes its subscriber; a UE's needs no asserted identity.
//
// Every NOTIFY carries the full state of the implicit registration set
// (RFC 3680 §5.2, state "full"), as the store has it when the NOTIFY is
// numbered: a registration per public identity that is not barred (TS
// 24.229 §5.4.1.2.2), with a contact per binding, and what the change
// ended, once, with the event that ended it. A full document lets any
// instance notify without knowing what a subscriber last got, and a NOTIFY
// that is lost is made good by the next. Only a document beyond
// reginfo.MaxDocumentSize is sent partial, with what changed. A contact's
// id is made from the binding (its +sip.instance and reg-id, or its URI and
// flow) and the address-of-record, so it is unique in the document and the
// same in every NOTIFY. A read of the store that fails sends no NOTIFY:
// the next carries the state.
//
// The NOTIFYs of a change go out on Config.Workers workers, so that the
// request that changed the set is answered first; beyond Config.Queue
// waiting, they are dropped and counted.
//
// The package sends nothing itself: Sender carries a request to the next
// hop of its dialog in a client transaction, which cmd/scscf provides.
package regevent
