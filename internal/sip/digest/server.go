package digest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

// Verification outcomes. Callers answer ErrStaleNonce with a new challenge
// carrying stale=true and a *SyncFailure as its documentation says. Every
// other error, including a failed secret lookup, should get one and the same
// answer (a fresh challenge, or a rejection by local policy), so that a client
// cannot tell an unknown user from a wrong password.
var (
	// ErrRealmMismatch means the credentials name another realm.
	ErrRealmMismatch = errors.New("digest: credentials are for another realm")
	// ErrUnsupportedQOP means the credentials do not use qop=auth.
	ErrUnsupportedQOP = errors.New("digest: qop is not auth")
	// ErrInvalidNonce means the nonce or opaque was not issued by this server
	// for this realm and algorithm. The empty nonce of an IMS client's first
	// REGISTER gives it too, before any other check, so the caller simply
	// challenges.
	ErrInvalidNonce = errors.New("digest: nonce was not issued by this server")
	// ErrWrongResponse means the response does not match the secret.
	ErrWrongResponse = errors.New("digest: response does not match")
	// ErrStaleNonce means the response was right but the nonce has expired.
	ErrStaleNonce = errors.New("digest: nonce has expired")
	// ErrReplayed means the nonce-count is not greater than one already used
	// with this nonce (RFC 7616 §5.5).
	ErrReplayed = errors.New("digest: nonce count already used")
)

// SyncFailure is returned by VerifyAKA when an AKA client reported that the
// challenge's sequence number was not acceptable (RFC 3310 §3.4). The caller
// sends RAND ‖ AUTS to hss for resynchronisation (TS 33.203 §6.1.3, TS 29.228
// §6.3) and challenges again with the new vector.
//
// A SyncFailure is unauthenticated. RFC 3310 §3.4 has the client compute the
// response with the empty password, so anyone holding a challenge's nonce and
// opaque can produce one with any 14 bytes of AUTS. Each nonce-count works
// only once, and auts counts are kept apart from RES counts so that a forged
// auts cannot block the genuine answer. Only milenage.VerifyAUTS at hss
// (MAC-S under K) authenticates AUTS. Until that check passes the caller must
// change no registration. The pending vector is another matter: a caller
// that takes a challenge on its first use, as the S-CSCF does, has used it up
// before it can tell, so a forged auts costs the client one more challenge,
// and forging one needs the challenge's nonce and opaque. The caller must
// also rate-limit resynchronisation per IMPI, because each attempt costs a
// Cx round trip.
type SyncFailure struct {
	RAND [16]byte
	AUTS [14]byte
}

// Error implements error. It names no value: AUTS and RAND must not be logged.
func (e *SyncFailure) Error() string { return "digest: AKA client reported a synchronisation failure" }

// NonceCountStore records the highest nonce-count each user has used with
// each nonce, the only state Digest needs. Counts are kept per (username,
// nonce) because MD5 and SHA-256 nonces are not bound to a user: keyed by
// nonce alone, one user could exhaust the count of a nonce issued to another.
type NonceCountStore interface {
	// Advance records nc for (username, nonce) and reports true if nc is
	// greater than the nonce-count recorded so far (or none is); otherwise it
	// changes nothing and reports false. The comparison and the write must be
	// one atomic step across every instance sharing the store, for example a
	// DynamoDB conditional update. The entry must be kept until expires and
	// may be discarded after it: no credentials for the nonce verify later.
	Advance(ctx context.Context, username, nonce string, nc uint32, expires time.Time) (bool, error)
}

// DefaultNonceLifetime is used when ServerConfig.NonceLifetime is zero. A SIP
// client answers a challenge within seconds; an HTTP client reusing a nonce
// past the lifetime is re-challenged with stale=true and retries without user
// involvement.
const DefaultNonceLifetime = 5 * time.Minute

// MinNonceKeySize is the shortest nonce key NewServer accepts: the key of an
// HMAC-SHA-256 should be at least as long as its output.
const MinNonceKeySize = 32

// maxRealmLength keeps a realm well inside a header line.
const maxRealmLength = 512

// ServerConfig configures a Server.
type ServerConfig struct {
	// Realm is the protection space, for IMS the home network domain.
	Realm string
	// NonceKey authenticates nonces. Every instance serving the realm must
	// use the same key (ADR 0005). At least MinNonceKeySize bytes.
	NonceKey secret.Key
	// NonceLifetime is how long a nonce stays valid; DefaultNonceLifetime
	// when zero.
	NonceLifetime time.Duration
	// NonceCounts provides replay protection. Required.
	NonceCounts NonceCountStore
	// Now returns the current time; time.Now when nil.
	Now func() time.Time
	// Random supplies nonce randomness; crypto/rand.Reader when nil. It must be
	// safe for concurrent use.
	Random io.Reader
	// AKAServerData appends an issue time and an HMAC tag to AKA nonces as
	// RFC 3310 §3.2 server data, so that a forged nonce fails its tag before
	// the vector lookup and VerifyAKA applies the nonce lifetime as well as
	// the vector's. Off by default: many deployed UE stacks accept only the
	// bare base64(RAND ‖ AUTN). Every instance serving the realm must use the
	// same setting, because each accepts only the form it issues.
	AKAServerData bool
	// HTTPPathOnlyURI lets VerifyHTTP accept a uri that is the request
	// target's path without its query, which RFC 7616 §3.4.6 allows the
	// value to be (an absolute-path) and which some RCS clients send for
	// FT via HTTP info requests. Method and path stay bound by the response
	// and nonce-counts still cannot be reused; only the query is unsigned.
	// Any other mismatch is still ErrURIMismatch. Off by default.
	HTTPPathOnlyURI bool
}

// Server issues Digest challenges for one realm and verifies the answers. It
// is safe for concurrent use and formats as a redacted placeholder, because
// it holds the nonce key.
type Server struct {
	realm    string
	key      secret.Sealed[[]byte] // sealed so that a *Server nested anywhere cannot print it
	lifetime time.Duration
	counts   NonceCountStore
	now      func() time.Time
	random   io.Reader

	akaServerData   bool
	httpPathOnlyURI bool
}

// NewServer validates cfg and returns a Server.
func NewServer(cfg ServerConfig) (*Server, error) {
	switch {
	case cfg.Realm == "" || len(cfg.Realm) > maxRealmLength || !representable(cfg.Realm):
		return nil, errors.New("digest: realm must be 1 to 512 printable bytes")
	case cfg.NonceKey.Len() < MinNonceKeySize:
		return nil, fmt.Errorf("digest: nonce key must be at least %d bytes", MinNonceKeySize)
	case cfg.NonceLifetime < 0:
		return nil, errors.New("digest: nonce lifetime is negative")
	case cfg.NonceCounts == nil:
		return nil, errors.New("digest: a nonce count store is required for replay protection")
	}
	key := bytes.Clone(cfg.NonceKey.Reveal())
	s := &Server{
		realm:    cfg.Realm,
		key:      secret.Seal(&key),
		lifetime: cfg.NonceLifetime,
		counts:   cfg.NonceCounts,
		now:      cfg.Now,
		random:   cfg.Random,

		akaServerData:   cfg.AKAServerData,
		httpPathOnlyURI: cfg.HTTPPathOnlyURI,
	}
	if s.lifetime == 0 {
		s.lifetime = DefaultNonceLifetime
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.random == nil {
		s.random = rand.Reader
	}
	return s, nil
}

// Realm returns the realm the server challenges for.
func (s *Server) Realm() string { return s.realm }

// Challenge returns a new MD5 or SHA-256 challenge with qop=auth. Set stale
// when answering ErrStaleNonce (RFC 7616 §3.3).
func (s *Server) Challenge(alg Algorithm, stale bool) (Challenge, error) {
	if alg != MD5 && alg != SHA256 {
		return Challenge{}, ErrUnsupportedAlgorithm
	}
	nonce, err := s.newDigestNonce()
	if err != nil {
		return Challenge{}, fmt.Errorf("digest: generating a nonce: %w", err)
	}
	return s.challenge(alg, nonce, stale), nil
}

// AKAChallenge returns an AKAv1-MD5 challenge for one vector's RAND and AUTN
// (RFC 3310 §3.2, TS 24.229 §5.4.1.2.1A). The nonce is base64(RAND ‖ AUTN)
// unless ServerConfig.AKAServerData is set. The caller stores the vector under
// the IMPI and the returned nonce, with an expiry, and later passes both to
// VerifyAKA.
func (s *Server) AKAChallenge(rand, autn []byte, stale bool) (Challenge, error) {
	if len(rand) != randSize || len(autn) != autnSize {
		return Challenge{}, errors.New("digest: RAND and AUTN must be 16 bytes each")
	}
	return s.challenge(AKAv1MD5, s.newAKANonce(rand, autn), stale), nil
}

func (s *Server) challenge(alg Algorithm, nonce string, stale bool) Challenge {
	return Challenge{
		Realm:     s.realm,
		Nonce:     nonce,
		Opaque:    s.opaqueFor(alg, nonce),
		Algorithm: alg,
		QOP:       []string{QOPAuth},
		Stale:     stale,
	}
}

// ErrUseVerifyAKA is returned by Verify for AKAv1-MD5 credentials, which need
// the vector's expiry and so go through VerifyAKA.
var ErrUseVerifyAKA = fmt.Errorf("%w: verify AKAv1-MD5 with VerifyAKA", ErrUnsupportedAlgorithm)

// Verify checks MD5 or SHA-256 credentials sent with a request whose method is
// method (the SIP method, or the HTTP method for ft-server). nil means the
// client is authenticated and the nonce-count has been consumed. For
// AKAv1-MD5 credentials it returns ErrUseVerifyAKA. Call Check before looking
// up the secret.
//
// Verify does not compare c.URI with the request: in SIP the two may
// legitimately differ after forwarding, and whether to accept that is local
// policy (RFC 8760 §2.6). VerifyHTTP does compare them.
func (s *Server) Verify(ctx context.Context, method string, c Credentials, secret Secret) error {
	// An empty nonce falls through to precheck, so that a first REGISTER
	// gives ErrInvalidNonce whatever its algorithm.
	if c.Algorithm == AKAv1MD5 && c.Nonce != "" {
		return ErrUseVerifyAKA
	}
	issued, err := s.precheck(c)
	if err != nil {
		return err
	}
	return s.verifyDigest(ctx, method, c, secret, issued)
}

// VerifyAKA checks AKAv1-MD5 credentials against the vector the caller stored
// under c.Nonce when it issued the challenge (ADR 0005): xres is its XRES and
// expires the end of its life in auth-challenges. nil means the client is
// authenticated and the nonce-count has been consumed.
//
// Credentials are refused once expires has passed, and the nonce-count is
// kept until then, so they cannot be replayed for as long as the vector could
// be found. The caller must still delete the vector, with a conditional
// delete, on the first nil result (ADR 0005): that, not the nonce-count, is
// what makes a captured Authorization worthless across instances and
// restarts of the count store. With ServerConfig.AKAServerData the nonce's
// own lifetime applies as well, whichever ends first.
//
// Credentials carrying auts are checked against the empty password and
// reported as a *SyncFailure (RFC 3310 §3.4), which is unauthenticated: see
// SyncFailure. The order is: response, then expiry, then nonce-count, then
// auts. So an expired vector, or with AKAServerData an expired nonce, gives
// ErrStaleNonce rather than a SyncFailure, and a resent auts gives
// ErrReplayed; neither can drive resynchronisation.
func (s *Server) VerifyAKA(ctx context.Context, method string, c Credentials, xres []byte, expires time.Time) error {
	switch {
	case c.Algorithm != AKAv1MD5:
		return fmt.Errorf("%w: VerifyAKA needs AKAv1-MD5 credentials", ErrUnsupportedAlgorithm)
	case len(xres) == 0:
		return ErrNoSecret
	case expires.IsZero():
		return errors.New("digest: VerifyAKA needs the vector's expiry")
	}
	issued, err := s.precheck(c)
	if err != nil {
		return err
	}
	password := xres
	if len(c.AUTS) > 0 {
		password = nil
	}
	if err := s.checkResponse(method, c, ha1(AKAv1MD5, c.Username, c.Realm, password)); err != nil {
		return err
	}
	deadline := expires
	if !issued.IsZero() {
		if own := issued.Add(s.lifetime); own.Before(deadline) {
			deadline = own
		}
	}
	if s.now().After(deadline) {
		return ErrStaleNonce
	}
	// The count is consumed before a SyncFailure too, so that resending the
	// same auts credentials gets ErrReplayed instead of another Cx round trip.
	// consume keeps auts counts apart from RES counts (see autsCountPrefix).
	if err := s.consume(ctx, c, deadline); err != nil {
		return err
	}
	if len(c.AUTS) > 0 {
		// precheck has confirmed the nonce is an AKA nonce, so it holds RAND.
		rand, _, _ := ParseAKANonce(c.Nonce)
		return &SyncFailure{RAND: rand, AUTS: [14]byte(c.AUTS)}
	}
	return nil
}

// Check runs the checks Verify and VerifyAKA start with, the ones that need no
// secret: realm, algorithm, qop, nc and cnonce, the nonce's form and tag, and
// the opaque value. scscf calls it before reading HA1 or the stored vector, so
// a forged or foreign nonce costs no table read; Verify and VerifyAKA repeat
// it, which is cheap. Credentials with an empty nonce, such as an IMS
// client's first REGISTER (TS 24.229 §5.1.1.2.2, §5.1.1.2.3), give
// ErrInvalidNonce whatever else they lack.
func (s *Server) Check(c Credentials) error {
	_, err := s.precheck(c)
	return err
}

// precheck implements Check and returns the nonce's issue time, or the zero
// time for the default AKA form.
func (s *Server) precheck(c Credentials) (time.Time, error) {
	switch {
	case c.Nonce == "":
		return time.Time{}, ErrInvalidNonce
	case c.Realm != s.realm:
		return time.Time{}, ErrRealmMismatch
	case !c.Algorithm.supported():
		return time.Time{}, ErrUnsupportedAlgorithm
	case !strings.EqualFold(c.QOP, QOPAuth):
		return time.Time{}, ErrUnsupportedQOP
	case c.NC == 0 || c.CNonce == "":
		return time.Time{}, malformed("qop=auth credentials need nc and cnonce")
	case len(c.AUTS) > 0 && c.Algorithm != AKAv1MD5:
		return time.Time{}, malformed("auts outside Digest AKA")
	case len(c.AUTS) > 0 && len(c.AUTS) != 14:
		return time.Time{}, malformed("auts is not 14 bytes")
	}
	issued, err := s.checkNonce(c.Algorithm, c.Nonce)
	if err != nil {
		return time.Time{}, err
	}
	if subtle.ConstantTimeCompare([]byte(c.Opaque), []byte(s.opaqueFor(c.Algorithm, c.Nonce))) != 1 {
		return time.Time{}, ErrInvalidNonce
	}
	return issued, nil
}

// verifyDigest finishes Verify and VerifyHTTP once precheck has passed.
func (s *Server) verifyDigest(ctx context.Context, method string, c Credentials, secret Secret, issued time.Time) error {
	h, err := secret.ha1For(c.Algorithm, c.Username, c.Realm)
	if err != nil {
		return err
	}
	if err := s.checkResponse(method, c, h); err != nil {
		return err
	}
	deadline := issued.Add(s.lifetime)
	if s.now().After(deadline) {
		return ErrStaleNonce
	}
	return s.consume(ctx, c, deadline)
}

// checkResponse compares the client's request-digest with the one computed
// from h in constant time.
func (s *Server) checkResponse(method string, c Credentials, h string) error {
	want, _ := hex.DecodeString(response(c.Algorithm, h, c.Nonce, formatNC(c.NC), c.CNonce, c.QOP, method, c.URI))
	got, err := hex.DecodeString(c.Response)
	if err != nil || subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrWrongResponse
	}
	return nil
}

// autsCountPrefix puts the nonce-counts of auts credentials in their own key
// space. auts credentials need no secret (RFC 3310 §3.4: empty password), so
// anyone who saw the 401 can send them in the victim's name with
// nc=ffffffff; counted together with the RES answers, that would make the
// victim's genuine nc=00000001 a replay. Kept apart, a resent auts is still
// refused and a forged one cannot touch the RES path. NUL cannot occur in a
// parsed nonce, so the prefixed key cannot collide with a real one.
const autsCountPrefix = "auts\x00"

// consume records the nonce-count, keeping it until deadline, after which the
// credentials would be refused anyway.
func (s *Server) consume(ctx context.Context, c Credentials, deadline time.Time) error {
	nonce := c.Nonce
	if len(c.AUTS) > 0 {
		nonce = autsCountPrefix + nonce
	}
	fresh, err := s.counts.Advance(ctx, c.Username, nonce, c.NC, deadline)
	if err != nil {
		return fmt.Errorf("digest: recording the nonce count: %w", err)
	}
	if !fresh {
		return ErrReplayed
	}
	return nil
}

const redactedServer = "digest.Server{redacted}"

// String returns a fixed placeholder: the nonce key must not reach a log.
func (s *Server) String() string { return redactedServer }

// GoString returns the same placeholder as String.
func (s *Server) GoString() string { return redactedServer }

// Format makes every fmt verb produce the placeholder.
func (s *Server) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedServer) }
