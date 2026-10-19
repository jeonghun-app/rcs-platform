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
// authenticated with a key every instance shares. Bindings are saved
// conditional on the version read; a REGISTER that loses to another
// instance's reads the registration again and applies itself to that.
//
// Every REGISTER is authenticated unless Config.TrustIntegrityProtected lets
// a re-registration over a P-CSCF's protected connection go unchallenged.
// The CK and IK of an AKA vector are kept but not sent: the platform protects
// the client's connection with TLS, not the IPsec security association they
// are for, so there is no Security-Client negotiation either.
//
// Third-party registration, the reg event package and the deregistration
// sweeps come in later parts of #14, on top of this package.
//
// Logs carry no identity, nonce or credential.
package registrar
