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
// A Server's nonces are stateless: each carries its issue time and an HMAC
// under a key every instance of the service shares, so any instance can verify
// a nonce another instance issued (ADR 0005) and a nonce expires without a
// table. The one piece of state Digest needs, the highest nonce-count seen per
// nonce, sits behind NonceCountStore so it can live in DynamoDB.
//
// An AKA nonce is RAND ‖ AUTN followed by the same issue time and HMAC as
// server data (RFC 3310 §3.2). The vector itself (XRES, CK, IK) is not in the
// nonce; scscf keeps it in its auth-challenges table and passes XRES to
// Verify as the password.
//
// # What is not supported
//
// qop=auth-int, the -sess algorithms, SHA-512-256, userhash and the RFC 2069
// form without qop are rejected: every challenge this package issues asks for
// qop=auth (RFC 8760 §2.6 makes qop mandatory for SIP), and nonce-count replay
// protection needs it. IPsec parameters (ck, ik, integrity-protected) belong to
// security agreement and are ignored.
//
// Passwords, HA1 values, RES and the nonce key are secrets: no error carries
// one and every type that holds one formats as a redacted placeholder. Nonces
// are not secret but must not be logged either.
package digest
