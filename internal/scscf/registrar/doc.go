// Package registrar is the S-CSCF's registrar (TS 24.229 §5.4.1): it
// authenticates a REGISTER with IMS AKA or SIP Digest, tells the HSS it
// serves the user (SAR), keeps the bindings of every identity of the
// implicit registration set and the set's profile in internal/scscf/state,
// and answers with the bindings, the Service-Route back to the S-CSCF and the
// set's identities.
//
// Any scscf instance can serve any step: the challenge of a 401 is stored
// (ADR 0005) and taken by the instance the answer reaches, which deletes it
// on that first use, so a response is never checked twice. Digest nonces are
// authenticated with a key every instance shares.
//
// An implicit registration set has one record (state.Registration), which
// each of its identities points at, so a REGISTER for any of them, a
// deregistration and a sweep are each one save of it conditional on the
// version read; a REGISTER that loses reads the record again and applies its
// contacts to what won. A deregistration first claims the record for a lease
// without bindings, as a sweep does, then tells the HSS, then reads the
// record again: if another device registered meanwhile, it gives the set
// back to the HSS (SAR REGISTRATION), whose two SARs may have crossed;
// otherwise it deletes the record, the identities that still name it, and,
// if no one saved another since, the profile. A contact with +sip.instance
// replaces the bindings of its instance but for its other outbound flows;
// one without replaces the IMPI's earlier bindings without an instance (TS
// 24.229 §5.4.1.2.2 4A).
//
// Every REGISTER is authenticated unless Config.TrustIntegrityProtected lets
// a re-registration over a P-CSCF's protected connection go unchallenged.
// The CK and IK of an AKA vector are kept but not sent: the platform protects
// the client's connection with TLS, not the IPsec security association they
// are for, so there is no Security-Client negotiation either.
//
// The HSS's own requests are answered here too: an RTR deregisters the sets
// it names, a PPR replaces one set's profile and follows changes to the set
// (HandleRTR, HandlePPR). Sweeps (Sweep, RunSweeps) deregister what expired,
// registrations and unregistered users' records alike. Third-party
// registration and the reg event package come in later parts of #14.
//
// Logs carry no identity, nonce or credential.
package registrar
