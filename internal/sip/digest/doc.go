// Package digest implements Digest access authentication for SIP and HTTP:
// MD5 and SHA-256 (RFC 7616, applied to SIP by RFC 8760) and Digest AKA
// (RFC 3310), the form IMS AKA takes on the wire (TS 33.203 §6.1, TS 24.229
// §5.4.1.2).
//
// One implementation serves scscf (SIP registration with AKAv1-MD5 or a
// password), ft-server (HTTP, see VerifyHTTP and ChallengeHTTP) and the client
// side in tools/rcs-sim (Respond). Only the header field values are handled
// here, as strings: callers move them in and out of WWW-Authenticate,
// Authorization, Proxy-Authenticate or Proxy-Authorization.
//
// # Nonces
//
// MD5 and SHA-256 nonces are stateless: each carries its issue time and an HMAC
// under a key every instance of the service shares, so any instance can verify
// a nonce another instance issued (ADR 0005) and a nonce expires without a
// table. The one piece of state Digest needs, the highest nonce-count seen per
// (username, nonce), sits behind NonceCountStore so it can live in DynamoDB.
//
// An AKA nonce is, by default, exactly base64(RAND ‖ AUTN): the form deployed
// UE stacks decode, although RFC 3310 §3.2 allows server data after it. It
// needs no tag, because scscf keeps the vector (XRES, CK, IK) in its
// auth-challenges table keyed by IMPI and nonce, with an expiry, and passes
// XRES and that expiry to VerifyAKA. VerifyAKA refuses credentials after the
// expiry and keeps the nonce-count until then; scscf deletes the vector on
// the first success (ADR 0005). The opaque value, an HMAC of realm, algorithm
// and nonce, still shows that the nonce came from this realm's servers. A
// deployment that wants stateless checks on AKA nonces as well can opt in to
// server data (ServerConfig.AKAServerData), which appends the same issue time
// and tag.
//
// # Order of checks
//
// Check runs every test that needs no secret, so callers can run it before
// reading HA1 or the stored vector. Verify and VerifyAKA then compare the
// response, apply expiry (ErrStaleNonce only for a correct response, RFC 7616
// §3.3) and consume the nonce-count; VerifyAKA reports auts last. Answer
// every error except ErrStaleNonce and *SyncFailure the same way, so that a
// client learns nothing about which check failed or whether the user exists.
//
// # What is not supported
//
// qop=auth-int, the -sess algorithms, SHA-512-256 and the RFC 2069 form
// without qop are rejected: every challenge this package issues asks for
// qop=auth (RFC 8760 §2.6 makes qop mandatory for SIP), and nonce-count replay
// protection needs it. The one exception is on the client side: Respond
// answers an AKAv1-MD5 challenge that offers no qop in that form, since TS
// 24.229 §5.4.1.2.1A does not have an S-CSCF send qop. Other parameters are ignored, as RFC 7616 §3.3 and
// §3.4 require of unknown ones: userhash is not implemented, so a hashed
// username simply fails to verify, and the security agreement parameters (ck,
// ik, integrity-protected, which P-CSCF adds per TS 24.229 §5.2.2) are left
// to that feature.
//
// Passwords, HA1 values, RES and the nonce key are secrets: no error carries
// one and every type that holds one formats as a redacted placeholder.
// Credentials and Challenge write their wire form with Header; their String,
// fmt and slog forms are summaries without the username (for IMS, the
// IMSI-based IMPI) or the nonce. Nonces are not secret but must not be
// logged either.
package digest
