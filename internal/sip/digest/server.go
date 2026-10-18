package digest

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Verification outcomes. Callers answer ErrStaleNonce with a new challenge
// carrying stale=true, a *SyncFailure with a challenge built from a
// resynchronised vector, and every other error with a fresh challenge (or a
// rejection, by local policy).
var (
	// ErrRealmMismatch means the credentials name another realm.
	ErrRealmMismatch = errors.New("digest: credentials are for another realm")
	// ErrUnsupportedQOP means the credentials do not use qop=auth.
	ErrUnsupportedQOP = errors.New("digest: qop is not auth")
	// ErrInvalidNonce means the nonce or opaque was not issued by this server
	// for this realm and algorithm, including the empty nonce of an IMS
	// client's first REGISTER.
	ErrInvalidNonce = errors.New("digest: nonce was not issued by this server")
	// ErrWrongResponse means the response does not match the secret.
	ErrWrongResponse = errors.New("digest: response does not match")
	// ErrStaleNonce means the response was right but the nonce has expired.
	ErrStaleNonce = errors.New("digest: nonce has expired")
	// ErrReplayed means the nonce-count is not greater than one already used
	// with this nonce (RFC 7616 §5.5).
	ErrReplayed = errors.New("digest: nonce count already used")
)

// SyncFailure is returned by Verify when an AKA client reported that the
// challenge's sequence number was not acceptable (RFC 3310 §3.4). The client
// is not authenticated. The caller sends RAND ‖ AUTS to hss for
// resynchronisation (TS 33.203 §6.1.3, TS 29.228 §6.3) and challenges again
// with the new vector.
type SyncFailure struct {
	RAND [16]byte
	AUTS [14]byte
}

// Error implements error. It names no value: AUTS and RAND must not be logged.
func (e *SyncFailure) Error() string { return "digest: AKA client reported a synchronisation failure" }

// NonceCountStore records the highest nonce-count used with each nonce, the
// only state Digest needs.
type NonceCountStore interface {
	// Advance records nc for nonce and reports true if nc is greater than the
	// nonce-count recorded so far (or none is); otherwise it changes nothing
	// and reports false. The comparison and the write must be one atomic step
	// across every instance sharing the store, for example a DynamoDB
	// conditional update. The entry may be discarded after expires.
	Advance(ctx context.Context, nonce string, nc uint32, expires time.Time) (bool, error)
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
	NonceKey []byte
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
	// RFC 3310 §3.2 server data, so that Verify can reject a forged or expired
	// AKA nonce without the vector store. Off by default: many deployed UE
	// stacks accept only the bare base64(RAND ‖ AUTN). Every instance serving
	// the realm must use the same setting, because each accepts only the form
	// it issues.
	AKAServerData bool
}

// Server issues Digest challenges for one realm and verifies the answers. It
// is safe for concurrent use and formats as a redacted placeholder, because
// it holds the nonce key.
type Server struct {
	realm    string
	key      []byte
	lifetime time.Duration
	counts   NonceCountStore
	now      func() time.Time
	random   io.Reader

	akaServerData bool
}

// NewServer validates cfg and returns a Server.
func NewServer(cfg ServerConfig) (*Server, error) {
	switch {
	case cfg.Realm == "" || len(cfg.Realm) > maxRealmLength || !representable(cfg.Realm):
		return nil, errors.New("digest: realm must be 1 to 512 printable bytes")
	case len(cfg.NonceKey) < MinNonceKeySize:
		return nil, fmt.Errorf("digest: nonce key must be at least %d bytes", MinNonceKeySize)
	case cfg.NonceLifetime < 0:
		return nil, errors.New("digest: nonce lifetime is negative")
	case cfg.NonceCounts == nil:
		return nil, errors.New("digest: a nonce count store is required for replay protection")
	}
	s := &Server{
		realm:    cfg.Realm,
		key:      append([]byte{}, cfg.NonceKey...),
		lifetime: cfg.NonceLifetime,
		counts:   cfg.NonceCounts,
		now:      cfg.Now,
		random:   cfg.Random,

		akaServerData: cfg.AKAServerData,
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
// (RFC 3310 §3.2, TS 24.229 §5.4.1.2.1). The nonce is base64(RAND ‖ AUTN)
// unless ServerConfig.AKAServerData is set. The caller stores the vector under
// the returned nonce.
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
		Opaque:    s.opaqueFor(nonce),
		Algorithm: alg,
		QOP:       []string{QOPAuth},
		Stale:     stale,
	}
}

// Verify checks credentials sent with a request whose method is method (the
// SIP method, or the HTTP method for ft-server). nil means the client is
// authenticated and the nonce-count has been consumed.
//
// For AKAv1-MD5, secret is Password(XRES) of the vector the caller stored
// under c.Nonce. With the default nonce form Verify cannot tell whether that
// vector is still current, so the caller must treat a nonce with no stored,
// unexpired vector as invalid (or stale, by its policy) and not call Verify;
// ErrStaleNonce then only arises with ServerConfig.AKAServerData. Credentials
// carrying auts are checked against the empty password and reported as a
// *SyncFailure (RFC 3310 §3.4).
//
// Verify does not compare c.URI with the request: in SIP the two may
// legitimately differ after forwarding, and whether to accept that is local
// policy (RFC 8760 §2.6). VerifyHTTP does compare them.
func (s *Server) Verify(ctx context.Context, method string, c Credentials, secret Secret) error {
	issued, err := s.precheck(c)
	if err != nil {
		return err
	}
	return s.verify(ctx, method, c, secret, issued)
}

// precheck does every check that needs no secret, so that a forged or foreign
// nonce costs no subscriber lookup.
func (s *Server) precheck(c Credentials) (time.Time, error) {
	switch {
	case c.Realm != s.realm:
		return time.Time{}, ErrRealmMismatch
	case !c.Algorithm.supported():
		return time.Time{}, ErrUnsupportedAlgorithm
	case !strings.EqualFold(c.QOP, QOPAuth):
		return time.Time{}, ErrUnsupportedQOP
	case c.NC == 0 || c.CNonce == "":
		return time.Time{}, malformed("qop=auth credentials need nc and cnonce")
	case c.AUTS != nil && c.Algorithm != AKAv1MD5:
		return time.Time{}, malformed("auts outside Digest AKA")
	case c.AUTS != nil && len(c.AUTS) != 14:
		return time.Time{}, malformed("auts is not 14 bytes")
	}
	issued, err := s.checkNonce(c.Algorithm, c.Nonce)
	if err != nil {
		return time.Time{}, err
	}
	if subtle.ConstantTimeCompare([]byte(c.Opaque), []byte(s.opaqueFor(c.Nonce))) != 1 {
		return time.Time{}, ErrInvalidNonce
	}
	return issued, nil
}

func (s *Server) verify(ctx context.Context, method string, c Credentials, secret Secret, issued time.Time) error {
	var h string
	if c.AUTS != nil {
		h = ha1(c.Algorithm, c.Username, c.Realm, nil)
	} else {
		var err error
		if h, err = secret.ha1For(c.Algorithm, c.Username, c.Realm); err != nil {
			return err
		}
	}
	want, _ := hex.DecodeString(response(c.Algorithm, h, c.Nonce, formatNC(c.NC), c.CNonce, c.QOP, method, c.URI))
	got, err := hex.DecodeString(c.Response)
	if err != nil || subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrWrongResponse
	}

	if c.AUTS != nil {
		// checkNonce has confirmed the nonce is an AKA nonce, so it holds RAND.
		rand, _, _ := ParseAKANonce(c.Nonce)
		return &SyncFailure{RAND: rand, AUTS: [14]byte(c.AUTS)}
	}
	expires := s.now().Add(s.lifetime) // default AKA nonce: no issue time, keep the count a lifetime
	if !issued.IsZero() {
		if s.now().Sub(issued) > s.lifetime {
			return ErrStaleNonce
		}
		expires = issued.Add(s.lifetime)
	}
	fresh, err := s.counts.Advance(ctx, c.Nonce, c.NC, expires)
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
