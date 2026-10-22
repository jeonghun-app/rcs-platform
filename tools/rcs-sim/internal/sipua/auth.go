package sipua

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"

	"github.com/jeonghun-app/rcs-platform/internal/milenage"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// The environment variables the credentials come from (#135), the client's
// and the peer's. They are read nowhere else, and their values reach no
// result line, log or error.
const (
	EnvAKAK        = "RCS_SIM_AKA_K"
	EnvAKAOPc      = "RCS_SIM_AKA_OPC"
	EnvSIPPassword = "RCS_SIM_SIP_PASSWORD"

	EnvPeerAKAK        = "RCS_SIM_PEER_AKA_K"
	EnvPeerAKAOPc      = "RCS_SIM_PEER_AKA_OPC"
	EnvPeerSIPPassword = "RCS_SIM_SIP_PEER_PASSWORD"
)

// CredentialEnv names the variables one subscriber's credentials come
// from. Each simulated subscriber has its own: one secret shared by two
// would hide a client that answers with the other's.
type CredentialEnv struct{ K, OPc, Password string }

// SelfEnv and PeerEnv are the client's variables and the peer's.
var (
	SelfEnv = CredentialEnv{K: EnvAKAK, OPc: EnvAKAOPc, Password: EnvSIPPassword}
	PeerEnv = CredentialEnv{K: EnvPeerAKAK, OPc: EnvPeerAKAOPc, Password: EnvPeerSIPPassword}
)

// Authentication errors.
var (
	// ErrNoUsableChallenge means a 401 or 407 offered no challenge these
	// credentials can answer: one for the home domain's realm, AKAv1-MD5
	// for AKA keys or MD5 or SHA-256 for a password, with qop=auth (AKA may
	// offer no qop).
	ErrNoUsableChallenge = errors.New("sipua: no challenge these credentials can answer")
	// ErrNetworkNotAuthenticated means AUTN did not verify with the card's
	// keys, or the nonce held no RAND and AUTN (TS 33.102 §6.3.3). The UA
	// reports it in one more REGISTER, with an empty response and no auts,
	// as TS 24.229 §5.1.1.5.3 has a UE do, and the answer to that is the
	// result: a *StatusError that wraps this error. For a simulator it
	// means the HSS holds other keys than the card.
	ErrNetworkNotAuthenticated = errors.New("sipua: AUTN did not verify: the challenge is not from the home network")
)

// Credentials authenticate a registration: a Digest password, or the K and
// OPc of an AKA card. Only made-up keys or the published test sets of TS
// 35.208 belong here, never a real SIM's. Every fmt, slog and JSON form is a
// placeholder, and the values sit behind a pointer, so a Credentials inside
// another value prints as an address at most. The zero value means none:
// the UA then answers no challenge.
type Credentials struct {
	p *credentials
}

type credentials struct {
	// impi is the private user identity, the Digest username (TS 24.229
	// §5.1.1.2.2, §5.1.1.2.3).
	impi     string
	password []byte
	card     *card
}

// card is the part of a USIM that AKA needs: the keys and the highest SQN
// it has accepted (TS 33.102 §6.3.3, Annex C).
type card struct {
	m       milenage.Milenage
	mu      sync.Mutex
	highest milenage.SQN
}

// DigestCredentials returns credentials that answer MD5 and SHA-256
// challenges with password. The bytes are copied.
func DigestCredentials(impi string, password []byte) (Credentials, error) {
	if impi == "" || len(password) == 0 {
		return Credentials{}, errors.New("sipua: Digest credentials need an IMPI and a password")
	}
	return Credentials{&credentials{impi: impi, password: append([]byte(nil), password...)}}, nil
}

// AKACredentials returns credentials that answer AKAv1-MD5 challenges as a
// card with keys k and opc that has accepted no SQN yet.
func AKACredentials(impi string, k, opc [milenage.KeySize]byte) (Credentials, error) {
	if impi == "" {
		return Credentials{}, errors.New("sipua: AKA credentials need an IMPI")
	}
	return Credentials{&credentials{impi: impi, card: &card{m: milenage.New(k, opc)}}}, nil
}

// DigestCredentialsFromEnv is DigestCredentials with the password from
// vars.Password. getenv is os.Getenv outside tests.
func DigestCredentialsFromEnv(impi string, vars CredentialEnv, getenv func(string) string) (Credentials, error) {
	p := getenv(vars.Password)
	if p == "" {
		return Credentials{}, errors.New("sipua: " + vars.Password + " is not set")
	}
	return DigestCredentials(impi, []byte(p))
}

// AKACredentialsFromEnv is AKACredentials with K and OPc from vars.K and
// vars.OPc, 32 hex digits each. getenv is os.Getenv outside tests.
func AKACredentialsFromEnv(impi string, vars CredentialEnv, getenv func(string) string) (Credentials, error) {
	k, err := hexKey(getenv, vars.K)
	if err != nil {
		return Credentials{}, err
	}
	opc, err := hexKey(getenv, vars.OPc)
	if err != nil {
		return Credentials{}, err
	}
	return AKACredentials(impi, k, opc)
}

// hexKey reads a 128-bit key. The error names the variable, never its value.
func hexKey(getenv func(string) string, name string) ([milenage.KeySize]byte, error) {
	var key [milenage.KeySize]byte
	v := getenv(name)
	if v == "" {
		return key, errors.New("sipua: " + name + " is not set")
	}
	if len(v) != 2*milenage.KeySize {
		return key, fmt.Errorf("sipua: %s is not %d hex digits", name, 2*milenage.KeySize)
	}
	if _, err := hex.Decode(key[:], []byte(v)); err != nil {
		return key, fmt.Errorf("sipua: %s is not %d hex digits", name, 2*milenage.KeySize)
	}
	return key, nil
}

func (c Credentials) set() bool { return c.p != nil }

const redactedCredentials = "sipua.Credentials{redacted}"

// String returns a fixed placeholder.
func (c Credentials) String() string { return redactedCredentials }

// GoString returns the same placeholder as String.
func (c Credentials) GoString() string { return redactedCredentials }

// Format makes every fmt verb produce the placeholder.
func (c Credentials) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedCredentials) }

// LogValue keeps log/slog handlers from serialising the fields.
func (c Credentials) LogValue() slog.Value { return slog.StringValue(redactedCredentials) }

// MarshalJSON emits the placeholder.
func (c Credentials) MarshalJSON() ([]byte, error) { return json.Marshal(redactedCredentials) }

// initialAuthorization is the Authorization of an unchallenged REGISTER:
// the IMPI and the home domain with an empty nonce and response, from
// which the S-CSCF learns which private identity registers (TS 24.229
// §5.1.1.2.2 for IMS AKA, §5.1.1.2.3 for SIP digest).
func (ua *UA) initialAuthorization(uri string) string {
	return digest.Credentials{Username: ua.cfg.Credentials.p.impi, Realm: ua.cfg.Realm, URI: uri}.Header()
}

// authAnswer is the answer to one challenge: the header field, and next,
// which gives its value for each REGISTER it goes in. A REGISTER after the
// first under the same nonce takes the next nonce-count and a new cnonce
// (RFC 7616 §3.4), or a proxy that checks them would take it for a replay.
// resync marks an answer with AUTS, after which the network challenges
// again; failure an answer that reports an AUTN that did not verify, after
// which nothing is answered.
type authAnswer struct {
	field           string
	next            func() (string, error)
	resync, failure bool
}

// fixed is an authAnswer.next for a value that does not change.
func fixed(v string) func() (string, error) { return func() (string, error) { return v, nil } }

// authorize answers the topmost usable challenge of a 401 or 407 to a
// REGISTER for uri (TS 24.229 §5.1.1.5.1, §5.1.1.5.4).
func (ua *UA) authorize(res *sip.Response, uri string) (authAnswer, error) {
	asked, a := "WWW-Authenticate", authAnswer{field: "Authorization"}
	if res.StatusCode == 407 {
		asked, a.field = "Proxy-Authenticate", "Proxy-Authorization"
	}
	c := ua.cfg.Credentials.p
	values := res.Header.Values(asked)
	if len(values) == 0 {
		// No challenge at all: the status is the whole answer.
		return a, &StatusError{Method: "REGISTER", Code: res.StatusCode}
	}
	ch, ok := firstUsable(values, c.card != nil, ua.cfg.Realm)
	if !ok {
		return a, &StatusError{Method: "REGISTER", Code: res.StatusCode, Err: ErrNoUsableChallenge}
	}
	var err error
	var password []byte
	p := digest.ClientParams{Username: c.impi, Method: "REGISTER", URI: uri}
	if c.card == nil {
		password = c.password
	} else if password, p.AUTS, err = c.card.answer(ch.Nonce); errors.Is(err, ErrNetworkNotAuthenticated) {
		// TS 24.229 §5.1.1.5.3: the network failed authentication, and
		// the UE says so in a further REGISTER with the challenge's
		// nonce, an empty response and no auts.
		a.next = fixed(digest.Credentials{Username: c.impi, Realm: ch.Realm, Nonce: ch.Nonce, URI: uri, Algorithm: digest.AKAv1MD5, Opaque: ch.Opaque}.Header())
		a.failure = true
		return a, nil
	} else if err != nil {
		return a, err
	}
	p.Password = secret.NewKey(password)
	a.resync = len(p.AUTS) > 0
	a.next = func() (string, error) {
		p.NC++
		cnonce, err := digest.NewCNonce(ua.cfg.Rand)
		if err != nil {
			return "", err
		}
		p.CNonce = cnonce
		creds, err := digest.Respond(ch, p)
		if err != nil {
			// Respond's errors name parameters, not values.
			return "", fmt.Errorf("sipua: answering the challenge: %w", err)
		}
		return creds.Header(), nil
	}
	return a, nil
}

// firstUsable returns the topmost challenge the credentials can answer
// (TS 24.229 §5.1.1.5.4, RFC 8760 §2.4). Only a challenge for realm,
// Config.Realm, is: an answer for another realm would hand whoever sent it
// a response computed from the home password, to guess it from offline.
// Digest needs qop=auth; AKA may offer no qop (§5.4.1.2.1A).
func firstUsable(values []string, aka bool, realm string) (digest.Challenge, bool) {
	for _, v := range values {
		ch, err := digest.ParseChallenge(v)
		if err != nil || !strings.EqualFold(ch.Realm, realm) {
			continue
		}
		auth := slices.ContainsFunc(ch.QOP, func(q string) bool { return strings.EqualFold(q, digest.QOPAuth) })
		switch ch.Algorithm {
		case digest.AKAv1MD5:
			if aka && (auth || len(ch.QOP) == 0) {
				return ch, true
			}
		case digest.MD5, digest.SHA256:
			if !aka && auth {
				return ch, true
			}
		}
	}
	return digest.Challenge{}, false
}

// answer does what the card does with an AKA nonce (TS 33.102 §6.3.3): it
// verifies AUTN, and then answers RES for a fresh SQN, which it now holds
// as its highest, or AUTS carrying its highest for a SQN it will not
// accept, so that the network resynchronises.
func (c *card) answer(nonce string) (res, auts []byte, err error) {
	rand, autn, err := digest.ParseAKANonce(nonce)
	if err != nil {
		// Without RAND and AUTN the network cannot be authenticated
		// either; it is answered the same way.
		return nil, nil, ErrNetworkNotAuthenticated
	}
	sqn, err := c.m.CheckAUTN(rand, autn)
	if err != nil {
		return nil, nil, ErrNetworkNotAuthenticated
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !milenage.Fresh(sqn, c.highest) {
		a := c.m.AUTS(rand, c.highest)
		return nil, a[:], nil
	}
	c.highest = sqn
	// RES depends on RAND alone (f2); SQN and AMF only shape AUTN.
	amf := [milenage.AMFSize]byte(autn[milenage.SQNSize : milenage.SQNSize+milenage.AMFSize])
	xres := c.m.Vector(rand, sqn, amf).XRES()
	return xres[:], nil, nil
}
