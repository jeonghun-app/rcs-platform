// Package regevent is the S-CSCF's notifier of the reg event package (RFC
// 3680, TS 24.229 §5.4.2.1): it answers SUBSCRIBE requests for the state of a
// registration, from the P-CSCF that serves it and from the UE itself, and
// sends NOTIFY requests when the registration changes.
//
// A subscription is a state.Subscription in the store every scscf instance
// shares, so any instance answers a refresh and notifies a change. Its
// dialog is stored with it, and its NOTIFY CSeq and reginfo version come
// from the store's atomic NextNotify, so two instances never send the same
// pair (ADR 0005).
//
// Who may subscribe (TS 24.229 §5.4.2.1.1): the P-CSCF, whose
// P-Asserted-Identity is the Path URI it put on a live binding of the
// registration (§5.2.3), or the UE, whose P-Asserted-Identity is one of the
// set's public identities. Anyone else gets 403. An in-dialog SUBSCRIBE, a
// refresh or Expires 0, must match a stored subscription's dialog (Call-ID,
// tags and a CSeq not below the last) and its subscriber, or gets 481.
//
// Every NOTIFY carries the full state of the implicit registration set
// (RFC 3680 §5.2, state "full"): a registration per public identity that is
// not barred (TS 24.229 §5.4.1.2.2), with a contact per binding, and the
// contacts that just ended, once, with the event that ended them. A full
// document lets any instance notify without knowing what a subscriber last
// got, and a NOTIFY that is lost is made good by the next. A contact's id
// is made from the binding (its +sip.instance and reg-id, or its URI and
// flow) and the address-of-record, so it is unique in the document and the
// same in every NOTIFY.
//
// The package sends nothing itself: Sender carries a request to the next
// hop of its dialog in a client transaction, which cmd/scscf provides.
package regevent
